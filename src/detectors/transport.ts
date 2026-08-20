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

/** 會被瀏覽器當成子資源載入的標籤。`<a>` 不在其中——那是導覽連結，不是子資源。 */
const SUBRESOURCE_TAGS = /<(?:img|script|iframe|audio|video|source|embed|object|track)\b[^>]*>/gi;
/** `<link>` 只有這些 rel 會實際載入資源；`alternate`／`canonical` 之類不算。 */
const LOADING_LINK_REL = /rel\s*=\s*["']?[^"'>]*\b(stylesheet|preload|prefetch|icon|manifest|modulepreload)\b/i;

/**
 * 從 HTML 抓出 http:// 的子資源引用（混合內容）。
 *
 * 必須先認標籤再看屬性。舊版只用 `(src|href|action)=` 比對，於是頁尾一條指向合作夥伴的
 * `<a href="http://…">` 就會被報成「首頁含 1 個 http 子資源（混合內容）」，detail 還寫著
 * 「瀏覽器會封鎖或降級這些資源」——而瀏覽器對一般連結什麼都不會做。這種說錯話的告警，
 * 讀者只要抓到一次就不會再相信整份報告。
 */
export function findMixedContent(html: string): string[] {
  const hits = new Set<string>();

  const collect = (tag: string, attrs: RegExp) => {
    for (const match of tag.matchAll(attrs)) {
      const url = match[1];
      if (!url) continue;
      // localhost 的 http 引用在本機測試是正常的，不算混合內容問題。
      if (/^http:\/\/(localhost|127\.0\.0\.1|\[::1\])/i.test(url)) continue;
      hits.add(url);
    }
  };

  const loadable = /\b(?:src|data|poster|srcset)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
  for (const match of html.matchAll(SUBRESOURCE_TAGS)) collect(match[0], loadable);

  for (const match of html.matchAll(/<link\b[^>]*>/gi)) {
    if (!LOADING_LINK_REL.test(match[0])) continue;
    collect(match[0], /\bhref\s*=\s*["'](http:\/\/[^"']+)["']/gi);
  }

  // 表單送到 http 端點同樣是明文外洩，而且送的是使用者輸入。
  for (const match of html.matchAll(/<form\b[^>]*>/gi)) {
    collect(match[0], /\baction\s*=\s*["'](http:\/\/[^"']+)["']/gi);
  }

  return [...hits];
}

/** 本機位址。只有這裡的 http 是正常的測試情境，其餘 http 目標都該被指出來。 */
export function isLocalHost(hostname: string): boolean {
  return /^(localhost|127\.0\.0\.1|\[?::1\]?|0\.0\.0\.0)$/i.test(hostname) || /\.local$/i.test(hostname);
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

  // https 要看**實際落點**，不是設定裡寫的那個 origin。
  // 分析的標頭來自重導向後的那個回應，所以判準也必須跟著走到那裡：
  // 以 http 目標起跑但被導向 https 時，HSTS 與 Cookie Secure 都該照常判定。
  const landed = (() => {
    try {
      return new URL(res.url);
    } catch {
      return origin;
    }
  })();
  const https = landed.protocol === "https:";
  const local = isLocalHost(landed.hostname);

  const headers = headersToObject(res.headers);
  facts.status = res.status;
  facts.contentType = headers["content-type"] ?? null;
  facts.redirects = res.redirects;
  facts.landedOn = landed.toString();

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

  const isHtml = (headers["content-type"] ?? "").includes("html");
  const metaCsp = isHtml ? findMetaCsp(res.body) : null;

  findings.push(...analyzeSecurityHeaders(headers, { surface: surface.id, where: rootUrl, https, metaCsp }));
  findings.push(...analyzeCookies(res.setCookies, { surface: surface.id, where: rootUrl, https }));

  // ── 明文提供服務 ────────────────────────────────────────────────────────
  //
  // 這一段過去不存在，於是 `--target http://staging.example.com` 會讓 HSTS、Cookie Secure、
  // http→https 導向、混合內容四項全部靜默跳過，而檢查仍回報 completed: true。
  // 一個完全沒有 TLS 的站台會拿到一份幾乎全綠的資安報告。
  if (!https && !local) {
    findings.push(
      finding({
        ...base,
        id: "transport.plaintext",
        severity: "high",
        title: "站台以未加密連線提供服務",
        detail:
          `${landed.origin} 全程走 http。同網路的人可以讀取甚至竄改流量，登入憑證以明文送出；` +
          "也因為沒有 TLS，HSTS 與 Cookie Secure 這些判定在本輪都失去意義而未執行——" +
          "這份報告的資安結論不適用於一個沒有加密的部署。",
        remediation: "為這個部署啟用 https（反向代理簽發憑證即可），並把 http 永久導向過去。",
        evidence: `最終落點：${landed.toString()}`,
        where: rootUrl,
      }),
    );
  }

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
  if (https && isHtml) {
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
  }

  // meta CSP 與標頭 CSP 並存時，兩者取交集，容易造成「以為放行了卻被擋」的難查問題。
  // 這與是不是 https 無關，所以不放在上面的 https 區塊裡。
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

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
