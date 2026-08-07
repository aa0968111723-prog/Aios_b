/**
 * 頁面測試：在真實瀏覽器裡逐一巡覽路由，蒐集使用者實際會遇到的錯誤。
 *
 * 這裡刻意不驗「畫面長得對不對」（那需要 baseline 與人工判讀），而是驗**客觀可判定的壞掉**：
 *   - SPA 掛不起來 / 主內容永遠停在載入中
 *   - 未捕捉的 JS 例外、console.error
 *   - 資源載入失敗（404 的圖、掛掉的 chunk）、API 回 4xx/5xx
 *   - 破圖、橫向溢出、行動端觸控目標過小
 *
 * 為什麼「主內容停在載入中」要單獨判：ai_os 的 e2e 曾踩過固定等 700ms 就截圖，
 * 結果整組路由只截到 Suspense fallback 卻標記為通過——那份 baseline 比沒驗更危險。
 */
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { finding, stopwatch } from "../core/findings.js";
import { join } from "../core/http.js";
import { SELECTORS, type RouteSpec } from "./routes.js";
import type { BrowserSession, PageLike } from "./browser.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

export interface PageObservation {
  route: string;
  status: number | null;
  shellMounted: boolean;
  contentReady: boolean;
  title: string;
  consoleErrors: string[];
  pageErrors: string[];
  failedRequests: Array<{ url: string; reason: string }>;
  badResponses: Array<{ url: string; status: number }>;
  brokenImages: string[];
  horizontalOverflow: { scrollWidth: number; clientWidth: number } | null;
  smallTouchTargets: string[];
  missingH1: boolean;
  loadMs: number;
  redirectedTo: string | null;
}

/** 行動端的最小觸控目標（WCAG 2.2 AA 的 24px 是底線，實務上 44px 才好按）。 */
const MIN_TOUCH_PX = 44;

/** console 噪音過濾：這些不是站台的錯，報出來只會稀釋真正的問題。 */
const IGNORED_CONSOLE = [
  /favicon\.ico/i,
  /Download the React DevTools/i,
  /\[vite\] connect(ing|ed)/i,
  /ResizeObserver loop/i, // 瀏覽器本身的良性警告
];

function isNoise(text: string): boolean {
  return IGNORED_CONSOLE.some((p) => p.test(text));
}

/**
 * 巡覽單一路由並蒐集所有觀測值。
 *
 * 監聽器必須在 goto 之前掛好，否則載入初期的錯誤（最重要的那些）會漏掉。
 */
export async function visitRoute(page: PageLike, url: string, isMobile: boolean): Promise<PageObservation> {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const failedRequests: Array<{ url: string; reason: string }> = [];
  const badResponses: Array<{ url: string; status: number }> = [];

  page.on("console", ((msg: { type(): string; text(): string }) => {
    if (msg.type() !== "error") return;
    const text = msg.text();
    if (!isNoise(text)) consoleErrors.push(text.slice(0, 500));
  }) as never);

  page.on("pageerror", ((err: Error) => {
    pageErrors.push(`${err.name}: ${err.message}`.slice(0, 500));
  }) as never);

  page.on("requestfailed", ((req: { url(): string; failure(): { errorText: string } | null }) => {
    const reason = req.failure()?.errorText ?? "unknown";
    // 使用者主動取消（換頁）不是錯誤
    if (/ERR_ABORTED/.test(reason)) return;
    failedRequests.push({ url: req.url(), reason });
  }) as never);

  page.on("response", ((res: { url(): string; status(): number }) => {
    const status = res.status();
    if (status < 400) return;
    // 401 在未登入巡覽時是預期行為，由呼叫端依情境決定要不要當問題
    badResponses.push({ url: res.url(), status });
  }) as never);

  const startedAt = Date.now();
  let status: number | null = null;
  try {
    const response = (await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 })) as {
      status(): number;
    } | null;
    status = response?.status() ?? null;
  } catch {
    status = null;
  }

  // SPA 掛載：AppShell 無條件渲染，不等任何 API
  let shellMounted = true;
  try {
    await page.locator(SELECTORS.shell).waitFor({ state: "attached", timeout: 15_000 });
  } catch {
    shellMounted = false;
  }

  // 主內容就緒：只有 Suspense 的「載入中…」不算內容
  let contentReady = false;
  if (shellMounted) {
    try {
      await page.waitForFunction(
        () => {
          const main = document.querySelector("#main-content") ?? document.querySelector("main");
          if (!main) return false;
          const text = ((main as HTMLElement).innerText || "").trim();
          return text.length > 0 && !/^載入中…?$/.test(text);
        },
        undefined,
        { timeout: 20_000 },
      );
      contentReady = true;
    } catch {
      contentReady = false;
    }
  }

  const loadMs = Date.now() - startedAt;

  const dom = await page
    .evaluate(() => {
      const brokenImages = [...document.querySelectorAll("img")]
        .filter((img) => img.complete && img.naturalWidth === 0 && Boolean(img.getAttribute("src")))
        .map((img) => img.getAttribute("src") ?? "")
        .slice(0, 20);

      const root = document.documentElement;
      const overflow =
        root.scrollWidth > root.clientWidth + 1
          ? { scrollWidth: root.scrollWidth, clientWidth: root.clientWidth }
          : null;

      // 觸控目標：只看真的看得見、且是使用者會點的元素
      const smallTouchTargets = [...document.querySelectorAll("button, a[href], [role=button], input[type=checkbox]")]
        .filter((el) => {
          const rect = el.getBoundingClientRect();
          if (rect.width === 0 || rect.height === 0) return false;
          const style = getComputedStyle(el);
          if (style.visibility === "hidden" || style.display === "none") return false;
          return rect.width < 44 || rect.height < 44;
        })
        .slice(0, 15)
        .map((el) => {
          const rect = el.getBoundingClientRect();
          const label = (el.textContent || el.getAttribute("aria-label") || "").trim().slice(0, 30);
          return `${el.tagName.toLowerCase()}${label ? `「${label}」` : ""} ${Math.round(rect.width)}×${Math.round(rect.height)}`;
        });

      return {
        brokenImages,
        overflow,
        smallTouchTargets,
        missingH1: document.querySelectorAll("h1").length === 0,
        href: location.href,
      };
    })
    .catch(() => null);

  const title = await page.title().catch(() => "");

  return {
    route: url,
    status,
    shellMounted,
    contentReady,
    title,
    consoleErrors,
    pageErrors,
    failedRequests,
    badResponses,
    brokenImages: dom?.brokenImages ?? [],
    horizontalOverflow: dom?.overflow ?? null,
    smallTouchTargets: isMobile ? (dom?.smallTouchTargets ?? []) : [],
    missingH1: dom?.missingH1 ?? false,
    loadMs,
    redirectedTo: dom?.href && dom.href !== url ? dom.href : null,
  };
}

/**
 * 把觀測值翻成 Finding。
 *
 * 純函式，所以「什麼算壞掉」的規則可以離線測試——這是整個頁面測試最容易誤判的部分。
 * `authenticated` 決定 401 與「導向登入頁」要不要當問題：未登入巡覽受保護路由時，
 * 被導到登入頁是**正確行為**，報成錯誤會讓整份報告失去可信度。
 */
export function judgePage(
  obs: PageObservation,
  ctx: { surface: Surface; route: RouteSpec; authenticated: boolean },
): Finding[] {
  const base = { check: "page-test", category: "page" as const, surface: ctx.surface.id, where: obs.route };
  const out: Finding[] = [];
  const label = `${ctx.surface.label} ${ctx.route.label}（${ctx.route.path}）`;
  const gatedToLogin = !ctx.authenticated && ctx.route.requiresAuth;

  if (obs.status !== null && obs.status >= 500) {
    out.push(
      finding({
        ...base,
        id: `page.server-error.${ctx.route.path}`,
        severity: "critical",
        title: `${label}：伺服器回應 HTTP ${obs.status}`,
        detail: "使用者打開這個頁面會看到錯誤畫面，不是站台內容。",
        remediation: "查該路由的伺服器日誌，用回應中的 requestId 對應。",
      }),
    );
  }

  if (!obs.shellMounted) {
    out.push(
      finding({
        ...base,
        id: `page.shell-not-mounted.${ctx.route.path}`,
        severity: "critical",
        title: `${label}：SPA 未掛載`,
        detail:
          "應用外殼（div.app）在 15 秒內沒有出現。外殼不等任何 API，它掛不起來代表 JS bundle 載入失敗或執行時就爆了——使用者看到的是白畫面。",
        remediation: "看同頁的 JS 例外與載入失敗清單；多半是 chunk 404（部署不完整）或初始化程式碼拋錯。",
      }),
    );
    return out; // 外殼都沒有，後面的判定沒有意義
  }

  if (!obs.contentReady && !gatedToLogin) {
    out.push(
      finding({
        ...base,
        id: `page.content-stuck.${ctx.route.path}`,
        severity: "high",
        title: `${label}：主內容 20 秒內仍停在載入中`,
        detail:
          "外殼有掛起來，但主內容區始終只有載入中佔位。使用者體感是「這頁打不開」。成因通常是該頁的 chunk 載不到，或它依賴的查詢逾時。",
        remediation: "檢查該頁的 lazy chunk 是否存在，以及它首屏依賴的 API 回應時間。",
      }),
    );
  }

  for (const err of obs.pageErrors) {
    out.push(
      finding({
        ...base,
        id: `page.js-exception.${ctx.route.path}.${err.slice(0, 40)}`,
        severity: "high",
        title: `${label}：未捕捉的 JavaScript 例外`,
        detail: "頁面執行期拋出未處理的例外，該例外之後的互動邏輯很可能整段沒有執行（按鈕沒反應、資料不更新）。",
        remediation: "在瀏覽器 DevTools 重現並修正；若來自第三方套件，加上錯誤邊界避免整頁失效。",
        evidence: err,
      }),
    );
  }

  if (obs.consoleErrors.length > 0) {
    out.push(
      finding({
        ...base,
        id: `page.console-errors.${ctx.route.path}`,
        severity: "medium",
        title: `${label}：console 出現 ${obs.consoleErrors.length} 筆錯誤`,
        detail: "console 錯誤通常對應到沒被使用者看見的功能失效（請求失敗被吞掉、狀態沒更新）。",
        remediation: "逐條排除；把預期中的警告改成 warn 或加以處理，讓 error 保持在零。",
        evidence: obs.consoleErrors.slice(0, 5).join("\n"),
      }),
    );
  }

  const realBadResponses = obs.badResponses.filter((r) => {
    // 未登入巡覽受保護頁時，401/403 是預期的
    if (gatedToLogin && (r.status === 401 || r.status === 403)) return false;
    return true;
  });
  if (realBadResponses.length > 0) {
    const worst = Math.max(...realBadResponses.map((r) => r.status));
    out.push(
      finding({
        ...base,
        id: `page.bad-responses.${ctx.route.path}`,
        severity: worst >= 500 ? "high" : "medium",
        title: `${label}：${realBadResponses.length} 個請求失敗（最高 HTTP ${worst}）`,
        detail:
          "頁面載入過程有請求回傳錯誤狀態。即使畫面看起來正常，對應的區塊多半是空的或顯示舊資料。",
        remediation: "逐一檢視失敗的請求；5xx 查伺服器日誌，404 通常是路由或資源路徑錯誤。",
        evidence: realBadResponses.slice(0, 8).map((r) => `${r.status} ${r.url}`).join("\n"),
      }),
    );
  }

  if (obs.failedRequests.length > 0) {
    out.push(
      finding({
        ...base,
        id: `page.failed-requests.${ctx.route.path}`,
        severity: "medium",
        title: `${label}：${obs.failedRequests.length} 個資源載入失敗`,
        detail: "資源根本沒載到（連線層失敗，不是回錯誤碼），通常是 CDN 位置錯誤、被 CSP 擋下、或網域解析失敗。",
        remediation: "檢查這些網址是否在 CSP 的允許清單內，以及資源是否真的部署了。",
        evidence: obs.failedRequests.slice(0, 8).map((r) => `${r.reason} ${r.url}`).join("\n"),
      }),
    );
  }

  if (obs.brokenImages.length > 0) {
    out.push(
      finding({
        ...base,
        id: `page.broken-images.${ctx.route.path}`,
        severity: "low",
        title: `${label}：${obs.brokenImages.length} 張圖片顯示不出來`,
        detail: "圖片元素存在但載不到內容，畫面上是破圖或空白區塊。",
        remediation: "確認圖片路徑與素材是否仍存在（素材落地失敗時會出現這個症狀）。",
        evidence: obs.brokenImages.slice(0, 5).join("\n"),
      }),
    );
  }

  if (obs.horizontalOverflow) {
    out.push(
      finding({
        ...base,
        id: `page.overflow.${ctx.route.path}`,
        severity: ctx.surface.isMobile ? "medium" : "low",
        title: `${label}：版面橫向溢出（${obs.horizontalOverflow.scrollWidth} > ${obs.horizontalOverflow.clientWidth}）`,
        detail: ctx.surface.isMobile
          ? "手機上會出現左右滑動，內容被切掉，按鈕可能滑出畫面外按不到。"
          : "頁面出現非預期的水平捲軸，通常是某個固定寬度元素撐破容器。",
        remediation: "找出超寬元素（表格、程式碼區塊、長網址），加上 max-width 或 overflow-x: auto。",
      }),
    );
  }

  if (obs.smallTouchTargets.length > 0) {
    out.push(
      finding({
        ...base,
        id: `page.touch-targets.${ctx.route.path}`,
        severity: "low",
        title: `${label}：${obs.smallTouchTargets.length} 個觸控目標小於 ${MIN_TOUCH_PX}px`,
        detail: "手機上太小的按鈕容易誤觸旁邊的元素，對手指較大或手部不便的使用者尤其明顯。",
        remediation: "把可點擊區域的最小尺寸提高到 44×44px（可用 padding 或偽元素擴大點擊範圍）。",
        evidence: obs.smallTouchTargets.slice(0, 8).join("\n"),
      }),
    );
  }

  if (!obs.title.trim()) {
    out.push(
      finding({
        ...base,
        id: `page.no-title.${ctx.route.path}`,
        severity: "low",
        title: `${label}：頁面沒有標題`,
        detail: "分頁標籤、瀏覽紀錄與螢幕閱讀器都靠 title 辨識頁面；空標題讓使用者無法分辨開了哪幾頁。",
        remediation: "每個路由設定描述性的 document.title。",
      }),
    );
  }

  if (obs.missingH1 && obs.contentReady) {
    out.push(
      finding({
        ...base,
        id: `page.no-h1.${ctx.route.path}`,
        severity: "low",
        title: `${label}：頁面沒有 h1 標題`,
        detail: "螢幕閱讀器使用者靠標題階層快速定位；缺 h1 時必須逐項聽完整頁內容才能找到主題。",
        remediation: "每頁提供唯一且描述性的 h1。",
      }),
    );
  }

  if (obs.loadMs > 10_000) {
    out.push(
      finding({
        ...base,
        id: `page.slow.${ctx.route.path}`,
        severity: "medium",
        title: `${label}：載入耗時 ${(obs.loadMs / 1000).toFixed(1)} 秒`,
        detail: "超過 10 秒才有內容，多數使用者在這之前就會認定系統壞了而離開或重整。",
        remediation: "檢查首屏依賴的查詢數量與 bundle 體積。",
      }),
    );
  }

  return out;
}

export async function checkPages(
  session: BrowserSession,
  surface: Surface,
  routes: RouteSpec[],
  options: {
    credentials?: { email: string; password: string };
    screenshots: boolean;
    outDir: string;
  },
): Promise<CheckResult> {
  const elapsed = stopwatch();
  const base = { check: "page-test", category: "page" as const, surface: surface.id };
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

  // ── 登入（可選）─────────────────────────────────────────────────────────
  let authenticated = false;
  if (options.credentials) {
    try {
      await page.goto(join(surface.origin, "/login"), { waitUntil: "domcontentloaded", timeout: 30_000 });
      await page.locator(SELECTORS.loginEmail).fill(options.credentials.email);
      await page.locator(SELECTORS.loginPassword).fill(options.credentials.password);
      await page.locator(SELECTORS.loginSubmit).click();
      await page.locator(SELECTORS.authenticated).waitFor({ state: "visible", timeout: 25_000 });
      authenticated = true;
    } catch {
      // 登入失敗必須是一筆 finding，不能靜靜地退回未登入巡覽——
      // 否則報告會顯示「受保護頁面都正常導向登入頁」，看起來全綠，實際什麼都沒驗到。
      findings.push(
        finding({
          ...base,
          id: "page.login-failed",
          severity: "high",
          title: `${surface.label}：測試帳號登入失敗`,
          detail:
            "提供了帳密但無法完成登入，因此所有需要登入的頁面都沒有真正被測到。可能是帳密錯誤、帳號被鎖、或登入流程本身壞了。",
          remediation: "確認測試帳號可用；若手動登入正常，代表這一端（UA／視窗）的登入流程有問題，需要優先排查。",
          where: join(surface.origin, "/login"),
        }),
      );
    }
  }
  facts.authenticated = authenticated;

  if (options.screenshots) {
    await mkdir(path.join(options.outDir, "screenshots", surface.id), { recursive: true }).catch(() => {});
  }

  const observations: PageObservation[] = [];
  for (const route of routes) {
    const url = join(surface.origin, route.path);
    const obs = await visitRoute(page, url, surface.isMobile);
    observations.push(obs);
    findings.push(...judgePage(obs, { surface, route, authenticated }));

    if (options.screenshots) {
      const name = route.path === "/" ? "home" : route.path.replace(/^\//, "").replace(/\//g, "-");
      await page
        .screenshot({
          path: path.join(options.outDir, "screenshots", surface.id, `${name}.png`),
          fullPage: false,
        })
        .catch(() => {});
    }
  }

  facts.routes = observations.map((o) => ({
    route: o.route,
    status: o.status,
    shellMounted: o.shellMounted,
    contentReady: o.contentReady,
    loadMs: o.loadMs,
  }));

  await page.close().catch(() => {});
  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
