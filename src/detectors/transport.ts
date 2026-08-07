/**
 * 傳輸層與標頭檢測。
 *
 * 一次抓首頁回應，同時餵給三個純分析器（標頭、CSP、Cookie），再加上只有連線層看得到的判定：
 * http→https 導向、混合內容、meta CSP 與標頭 CSP 打架。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import { analyzeCookies } from "./cookies.js";
import { analyzeSecurityHeaders, headersToObject } from "./headers.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

/** 從 HTML 抓出 http:// 的子資源引用（混合內容）。只看會被瀏覽器實際載入的屬性。 */
export function findMixedContent(html: string): string[] {
  const hits = new Set<string>();
  const pattern = /\b(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
  for (const match of html.matchAll(pattern)) {
    const url = match[1];
    if (!url) continue;
    // localhost 的 http 引用在本機測試是正常的，不算混合內容問題。
    if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(url)) continue;
    hits.add(url);
  }
  return [...hits];
}

/**
 * 抓 <meta http-equiv="Content-Security-Policy" content="…">。
 *
 * 屬性值必須以「同種引號」界定再回頭配對：CSP 內容本身充滿單引號（'self'、'none'），
 * 用 [^"']* 會在第一個 'self' 的引號就截斷，拿到半截政策後續分析全錯。
 */
export function findMetaCsp(html: string): string | null {
  const match = /<meta[^>]+http-equiv\s*=\s*["']content-security-policy["'][^>]*>/i.exec(html);
  if (!match) return null;
  return /content\s*=\s*(["'])(.*?)\1/is.exec(match[0])?.[2] ?? null;
}

export async function checkTransport(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "transport", category: "security" as const, surface: surface.id };

  const origin = new URL(surface.origin);
  const https = origin.protocol === "https:";
  const rootUrl = join(surface.origin, "/");

  const res = await tryProbe(rootUrl, { surface, timeoutMs, followRedirects: 3 });
  if (isProbeFailure(res)) {
    return {
      ...base,
      completed: false,
      skippedReason: `首頁無法連線：${res.error}`,
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  const headers = headersToObject(res.headers);
  facts.status = res.status;
  facts.contentType = headers["content-type"] ?? null;
  facts.redirects = res.redirects;

  // 回應不是應用送的（被代理／閘道攔下）就必須停手，不能把中介層的裸回應
  // 當成站台的安全設定來評分——那會產出一整份看似嚴重卻完全無效的報告。
  if (looksLikeGatewayInterception({ status: res.status, body: res.body, contentType: facts.contentType as string ?? "" })) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `首頁回應 HTTP ${res.status} 且內容不像應用回應，判定為中介層（代理／WAF／平台閘道）攔截。` +
        "安全標頭分析已略過——中介層的回應不代表站台設定。請從能直連目標的網路環境重跑。",
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  findings.push(...analyzeSecurityHeaders(headers, { surface: surface.id, where: rootUrl, https }));
  findings.push(...analyzeCookies(res.setCookies, { surface: surface.id, where: rootUrl, https }));

  // ── http → https 導向 ───────────────────────────────────────────────────
  if (https) {
    const insecure = `http://${origin.host}${origin.pathname}`;
    const plain = await tryProbe(insecure, { surface, timeoutMs, followRedirects: 0 });
    if (!isProbeFailure(plain)) {
      const location = plain.headers.get("location");
      const redirectsToHttps = plain.status >= 300 && plain.status < 400 && location?.startsWith("https://");
      if (!redirectsToHttps) {
        findings.push(
          finding({
            ...base,
            id: "transport.no-https-redirect",
            severity: plain.status === 200 ? "high" : "medium",
            title: "以 http 連線未被導向 https",
            detail:
              plain.status === 200
                ? "站台直接以未加密連線提供內容，同網路的人可以讀取甚至竄改流量，登入憑證會以明文送出。"
                : `以 http 連線回應 HTTP ${plain.status}，沒有導向到 https；使用者手打網址或用舊書籤時會撞牆而非被安全地接住。`,
            remediation: "在反向代理或應用層加上永久導向（308）到 https，並確認 HSTS 已啟用。",
            evidence: `HTTP ${plain.status}${location ? ` → ${location}` : ""}`,
            where: insecure,
          }),
        );
      } else {
        facts.httpsRedirect = `${plain.status} → ${location}`;
      }
    }
    // 連不上 http（連線被拒）是可接受的結果：代表根本沒開 80 埠。
  }

  // ── 混合內容 ────────────────────────────────────────────────────────────
  if (https && (headers["content-type"] ?? "").includes("html")) {
    const mixed = findMixedContent(res.body);
    if (mixed.length > 0) {
      findings.push(
        finding({
          ...base,
          id: "transport.mixed-content",
          severity: "medium",
          title: `首頁含 ${mixed.length} 個 http 子資源（混合內容）`,
          detail:
            "瀏覽器會封鎖或降級這些資源，畫面可能缺圖／缺樣式；被封鎖前的請求也可能被中間人替換成惡意內容。",
          remediation: "把這些引用改成 https 或相對路徑。",
          evidence: mixed.slice(0, 5).join("\n"),
          where: rootUrl,
        }),
      );
    }

    // meta CSP 與標頭 CSP 並存時，兩者取交集，容易造成「以為放行了卻被擋」的難查問題。
    const metaCsp = findMetaCsp(res.body);
    if (metaCsp && headers["content-security-policy"]) {
      findings.push(
        finding({
          ...base,
          id: "transport.duplicate-csp",
          severity: "low",
          title: "同時存在 meta CSP 與標頭 CSP",
          detail: "兩份政策會取交集生效，實際限制比任一份都嚴，日後放寬標頭卻沒效果時極難排查。",
          remediation: "只保留標頭版本（伺服器側），移除 HTML 裡的 meta CSP。",
          evidence: metaCsp.slice(0, 200),
          where: rootUrl,
        }),
      );
    }
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
