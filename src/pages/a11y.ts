/**
 * 無障礙掃描（axe-core）。
 *
 * 只報 serious／critical：axe 的 minor 有大量主觀項目，全報會把真正擋人的問題淹掉。
 * 對 aios 特別相關的是對比度與表單標籤——這套系統的使用者含非工程背景的長輩志工。
 */
import { finding, stopwatch } from "../core/findings.js";
import { join } from "../core/http.js";
import { SELECTORS, type RouteSpec } from "./routes.js";
import type { BrowserSession, PageLike } from "./browser.js";
import type { CheckResult, Finding, Severity, Surface } from "../core/types.js";

interface AxeViolation {
  id: string;
  impact?: string | null;
  help: string;
  description: string;
  helpUrl: string;
  nodes: Array<{ html?: string; target?: string[] }>;
}

/** axe 的 impact → 本系統的嚴重度。 */
function mapImpact(impact: string | null | undefined): Severity | null {
  switch (impact) {
    case "critical":
      return "high"; // a11y 的 critical 是「這類使用者完全無法使用」，但不是資安等級的 critical
    case "serious":
      return "medium";
    case "moderate":
      return "low";
    default:
      return null; // minor 不報
  }
}

export async function checkA11y(
  session: BrowserSession,
  surface: Surface,
  routes: RouteSpec[],
  options: { credentials?: { email: string; password: string } },
): Promise<CheckResult> {
  const elapsed = stopwatch();
  const base = { check: "a11y", category: "a11y" as const, surface: surface.id };

  if (!session.axeAvailable) {
    return {
      ...base,
      completed: false,
      skippedReason: "未安裝 @axe-core/playwright；無障礙掃描已跳過（這不代表通過）。",
      durationMs: elapsed(),
      findings: [],
    };
  }

  const { default: AxeBuilder } = (await import("@axe-core/playwright")) as {
    default: new (opts: { page: unknown }) => {
      withTags(tags: string[]): { analyze(): Promise<{ violations: AxeViolation[] }> };
    };
  };

  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  let page: PageLike;
  try {
    page = await session.newPage(surface);
  } catch (err) {
    return {
      ...base,
      completed: false,
      durationMs: elapsed(),
      findings,
      error: `無法開啟分頁：${err instanceof Error ? err.message : String(err)}`,
    };
  }

  if (options.credentials) {
    try {
      await page.goto(join(surface.origin, "/login"), { waitUntil: "domcontentloaded", timeout: 30_000 });
      await page.locator(SELECTORS.loginEmail).fill(options.credentials.email);
      await page.locator(SELECTORS.loginPassword).fill(options.credentials.password);
      await page.locator(SELECTORS.loginSubmit).click();
      await page.locator(SELECTORS.authenticated).waitFor({ state: "visible", timeout: 25_000 });
    } catch {
      /* 登入失敗已由 page-test 回報，這裡不重複；改以未登入狀態掃公開頁 */
    }
  }

  // 同一個違規規則會在多個路由重複出現，以 ruleId 聚合後只報一次，附上出現的路由。
  const byRule = new Map<string, { violation: AxeViolation; routes: string[]; nodes: string[] }>();
  /** 實際掃到的路由。0 代表這一輪根本沒掃到任何頁面。 */
  const scanned: string[] = [];
  const skippedRoutes: Array<{ route: string; reason: string }> = [];
  /** 被重導向到別處的路由（未登入時受保護頁一律導到 /login）。 */
  const redirectedRoutes: Array<{ route: string; landedOn: string }> = [];

  for (const route of routes) {
    const url = join(surface.origin, route.path);
    try {
      await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
      await page.locator(SELECTORS.shell).waitFor({ state: "attached", timeout: 15_000 });
    } catch (err) {
      // 頁面本身壞掉由 page-test 負責報告，但**這裡沒掃到**這件事必須留下來，
      // 否則「N 個頁面」這個敘述會沒有分母，零發現也會與「全部通過」無從區分。
      skippedRoutes.push({ route: route.path, reason: err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200) });
      continue;
    }

    // 實際落點才是這次掃的東西。
    //
    // 未登入時（TEST_EMAIL 沒設就是預設情況）受保護路由一律被導到 /login，於是同一個登入頁
    // 會被掃 N 次，同一筆違規也被記 N 次——報告會寫「color-contrast（5 個頁面）」並列出五條
    // 從來沒被掃到的路徑。那個數字與那份清單都是錯的。
    const landedPath = await page
      .evaluate(() => location.pathname)
      .catch(() => route.path);

    if (landedPath !== route.path) {
      redirectedRoutes.push({ route: route.path, landedOn: landedPath });
      // 已經掃過那個落點就不重複掃，也不重複計數。
      if (scanned.includes(landedPath)) continue;
    }

    const scanKey = landedPath;

    let results: { violations: AxeViolation[] };
    try {
      results = await new AxeBuilder({ page })
        .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
        .analyze();
    } catch (err) {
      skippedRoutes.push({ route: route.path, reason: `axe 掃描失敗：${err instanceof Error ? err.message.slice(0, 160) : String(err)}` });
      continue;
    }

    scanned.push(scanKey);

    for (const violation of results.violations) {
      if (mapImpact(violation.impact) === null) continue;
      const entry = byRule.get(violation.id) ?? { violation, routes: [], nodes: [] };
      if (!entry.routes.includes(scanKey)) entry.routes.push(scanKey);
      for (const node of violation.nodes.slice(0, 2)) {
        const snippet = (node.html ?? node.target?.join(" ") ?? "").slice(0, 160);
        if (snippet && !entry.nodes.includes(snippet)) entry.nodes.push(snippet);
      }
      byRule.set(violation.id, entry);
    }
  }

  for (const [ruleId, entry] of byRule) {
    const severity = mapImpact(entry.violation.impact);
    if (!severity) continue;
    findings.push(
      finding({
        ...base,
        id: `a11y.${ruleId}`,
        severity,
        title: `${surface.label}：${entry.violation.help}（${entry.routes.length} 個頁面）`,
        detail: `${entry.violation.description}\n受影響頁面：${entry.routes.join("、")}`,
        remediation: `依 axe 規則說明修正：${entry.violation.helpUrl}`,
        evidence: entry.nodes.slice(0, 4).join("\n"),
        where: entry.routes[0],
      }),
    );
  }

  facts.rulesViolated = [...byRule.keys()];
  facts.scannedRoutes = scanned;
  facts.skippedRoutes = skippedRoutes;
  facts.redirectedRoutes = redirectedRoutes;

  await page.close().catch(() => {});

  // 一條都沒掃到時，「零發現」與「全部通過」在報告上完全無法區分。
  if (scanned.length === 0) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `${routes.length} 條路由都無法載入或掃描，無障礙檢查實際未執行。` +
        (skippedRoutes[0] ? `第一條的原因：${skippedRoutes[0].reason}` : ""),
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
