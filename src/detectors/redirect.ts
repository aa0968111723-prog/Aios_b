/**
 * 開放重導向檢測。
 *
 * 單看一條「會把使用者送到別的網站」的路由，很難覺得它有多嚴重：它不外洩資料，也不改動任何東西。
 * 但它是釣魚與 OAuth 憑證竊取的標準第一步——攻擊者發出去的連結網域是**自家的**，
 * 使用者掃一眼就信任它，郵件過濾器與聊天軟體的連結掃描也信任它（網域信譽是乾淨的），
 * 點下去卻在瀏覽器裡落到攻擊者的站，那裡擺著一份一模一樣的登入頁。
 * OAuth 更直接：授權碼是送到 `redirect_uri` 的，只要那個參數能被塞進外部網址，
 * 換到手的就不是使用者的登入，而是攻擊者手上一組有效憑證。
 *
 * aios 有登入流程，也有 `?next=` 這類「登入完把你送回原本那頁」的回跳參數，
 * 正是最容易出這個問題的地方：回跳值天生就是使用者可控的網址，
 * 而正確寫法（只收相對路徑）與錯誤寫法（拿到什麼就 302 過去）在程式碼上往往只差一行。
 *
 * ── 請求量的取捨 ───────────────────────────────────────────────────────────
 * 探測面是「路徑 × 參數」的乘積，很容易失控。這裡刻意壓成 2 條路徑（`/` 與 `/login`）
 * × 15 個參數 = 30 個 GET，而且序列送出。理由：
 *   1. 參數清單只收實務上真的常見的名字。為了多蓋那 1% 的冷門命名把請求量翻倍，
 *      換來的是把檢測系統自己變成目標站的流量來源——檢測不該污染它要測量的東西。
 *   2. 全部是 GET，且送出去的目標指向一個保證不存在的網域，不會有任何副作用；
 *      3xx 本身就是證據，所以完全不跟隨（followRedirects: 0），永遠不會真的連出去。
 *   3. 不並行。30 個併發請求打在登入頁上很可能觸發速率限制，之後的檢查會拿到一整排 429，
 *      報告就變成在測我們自己造成的壅塞。
 *
 * ── 降噪 ───────────────────────────────────────────────────────────────────
 * 登入頁的正常回跳（302 到 `/dashboard`、或到自家網域）會直接撞上這個檢查，
 * 所以判定一律以「落點主機是不是我們送出去的那個外部探針主機」為準：
 * 落在自家網域、相對路徑、或參數根本沒被採用，全都不報。
 * 少了這道，每一個有回跳功能的站都會亮一整排紅燈，而一份充滿假警報的報告等於沒有報告。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

/**
 * 送出去的探針目標。
 *
 * `.invalid` 是 RFC 2606 保留的頂級網域，保證永遠不會解析到任何真實主機——
 * 就算站台真的把我們送出去，也不會有第三方收到這個請求。
 * 值刻意寫死不用亂數：finding id 與證據要能跨次執行重現，測試才驗得起來，
 * 維運者也才能拿這個字串去存取紀錄裡撈出「這是掃描器，不是攻擊」。
 */
export const EVIL_REDIRECT_TARGET = "https://sentinel-redirect-probe.invalid/probe";

/** 探針目標的主機部分。判定看的是落點主機，不是整串網址。 */
export const EVIL_REDIRECT_HOST = "sentinel-redirect-probe.invalid";

/**
 * 常見的回跳參數名。
 *
 * 涵蓋三種來源：框架慣例（next、continue）、OAuth／OIDC 規格（redirect_uri）、
 * 以及自己手寫回跳時最常取的名字（returnTo、to、r）。
 * 大小寫變體只列駝峰版，因為多數後端的 query 解析是大小寫敏感的，全小寫版已經在清單裡。
 */
export const REDIRECT_PARAMS: readonly string[] = [
  "next",
  "redirect",
  "redirect_uri",
  "redirect_url",
  "returnTo",
  "return_to",
  "returnUrl",
  "url",
  "continue",
  "dest",
  "destination",
  "target",
  "r",
  "to",
  "callback",
];

/** 受測路徑：站台根與登入頁。回跳參數幾乎都掛在這兩處。 */
const AUDIT_PATHS = ["/", "/login"];

/** 每次探針最多讀回來的內文量。夠看完 <head> 與行內腳本，又不會把整包 bundle 拉進記憶體。 */
const BODY_SCAN_LIMIT = 64 * 1024;

/** 證據片段的長度上限。報告要能重現，但不需要整頁 HTML。 */
const SNIPPET_LIMIT = 200;

export interface RedirectObservation {
  /** 這次測的是哪個回跳參數。 */
  param: string;
  /** 實際送出的完整網址（含探針參數）。同時是 finding 的 where，所以必須是穩定值。 */
  requestUrl: string;
  /** 塞進參數裡的目標值。 */
  sentTarget: string;
  status: number;
  /** Location 標頭原始值；沒有就是 null。 */
  location: string | null;
  /** 回應內文（已截斷至 `BODY_SCAN_LIMIT`）；空內文為 null。 */
  bodySnippet: string | null;
}

/** 主機正規化：大小寫不是語意的一部分，結尾的根網域點（`a.test.`）也不是。 */
function normalizeHost(host: string): string {
  return host.toLowerCase().replace(/\.(?=(:\d+)?$)/, "");
}

/**
 * 把 Location 解析成「瀏覽器實際上會連到的主機」。
 *
 * 這個函式是整個偵測器的核心，因為開放重導向的漏網之魚幾乎都出在這一步：
 * 驗證邏輯用字串前綴去判斷「是不是自家網址」，而瀏覽器用的是 URL 規範。兩者不一致的地方就是洞。
 * 一律交給 WHATWG URL 解析，得到的就是瀏覽器的答案，具體涵蓋：
 *   - 協定相對 `//evil.test/x`：最常被漏掉的一種，因為過濾器多半只擋 `http://` 開頭。
 *   - 反斜線變體 `/\evil.test`：URL 規範在 http(s) 這類特殊 scheme 下把 `\` 視同 `/`，
 *     於是它和 `//evil.test` 等價；只檢查「開頭是不是單一斜線」的驗證會整個被繞過。
 *   - 使用者名稱混淆 `https://自家網域@evil.test`：`@` 前面全是認證資訊，瀏覽器連的是 evil.test，
 *     但 `startsWith("https://自家網域")` 會回 true。
 *
 * 解析不出來（畸形、空值、或 `javascript:` 這種根本沒有主機的 scheme）一律回 host: null。
 * 這裡不能回空字串——空字串拿去跟自家網域比會得到「不同」，然後被當成導向外部，那是憑空捏造的發現。
 */
export function resolveLocation(location: string, requestUrl: string): { host: string | null; raw: string } {
  const trimmed = location.trim();
  if (!trimmed) return { host: null, raw: location };
  try {
    const url = new URL(trimmed, requestUrl);
    if (!url.host) return { host: null, raw: location };
    return { host: normalizeHost(url.host), raw: location };
  } catch {
    return { host: null, raw: location };
  }
}

/**
 * 是不是同一台主機。
 *
 * 刻意只認**完全相同**，不做後綴比對——後綴比對正是這類漏洞最經典的錯誤修法：
 * `host.endsWith("example.com")` 會把攻擊者自己註冊的 `evil-example.com`，
 * 以及被接管或可自助註冊的子網域 `evil.example.com`，全部當成自家網域。
 * 判定端若也用後綴，就會親手把最該被抓出來的那一類靜靜吞掉。
 * 代價是：真的把使用者導去自家其他子網域（`app.example.com`）時這裡會報，
 * 這是刻意的取捨——那條路徑同樣值得有人看一眼確認它是白名單裡的。
 */
export function isSameHost(a: string, b: string): boolean {
  return normalizeHost(a) === normalizeHost(b);
}

/**
 * 落點是不是我們送出去的那個探針主機。
 *
 * 這裡反而允許子網域（`x.sentinel-redirect-probe.invalid`），因為有些站會把收到的值
 * 塞進自己的前綴或後綴再導出去。比對對象是我們自己的保留網域，不可能誤傷真實流量，
 * 所以放寬是安全的——放寬自家網域的比對才會出事，兩者的風險方向剛好相反。
 */
function isProbeTargetHost(host: string, evilHost: string): boolean {
  const target = normalizeHost(evilHost);
  const actual = normalizeHost(host);
  return actual === target || actual.endsWith(`.${target}`);
}

/** 取出證據片段：壓掉換行與多餘空白，讓它在報告裡佔一行就好。 */
function snippetAround(body: string, at: number, length: number): string {
  const start = Math.max(0, at - 80);
  return body
    .slice(start, at + length + 80)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, SNIPPET_LIMIT);
}

/**
 * 找出「回 200，但頁面自己把使用者送出去」的寫法。
 *
 * 只做字串特徵比對，不執行 JS——執行未知站台的腳本是把檢測器變成攻擊面，代價遠大於多抓幾個案例。
 * 但特徵比對必須做到位：**不能只看探針主機有沒有出現在內文裡**。
 * `<meta http-equiv="refresh" content="0;url=/login?next=https://探針主機/">` 的實際落點是自家的 /login，
 * 探針主機只是它的查詢字串；用 includes 判定會產生一整批假警報。
 * 所以這裡把導向目標整串抽出來，交給 `resolveLocation` 算出瀏覽器真正會連到的主機再比對。
 *
 * 已知的涵蓋範圍：字面值的目標抓得到，字串串接（`location.href = base + next`）抓不到。
 * 那類寫法沒有靜態可信的答案，寧可漏也不要猜——猜出來的 medium 會消耗掉讀者對整份報告的信任。
 */
export function findClientRedirect(
  body: string,
  requestUrl: string,
  evilHost: string,
): { kind: "meta" | "script"; target: string; snippet: string } | null {
  // ── meta refresh ────────────────────────────────────────────────────────
  for (const tag of body.matchAll(/<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi)) {
    const text = tag[0];
    if (!text) continue;
    // content 屬性用同種引號界定再回頭配對；網址裡的分號與引號都可能把粗糙的 regex 截斷。
    const content = /content\s*=\s*(["'])(.*?)\1/is.exec(text)?.[2] ?? text;
    const target = /url\s*=\s*["']?\s*([^"'\s>]+)/i.exec(content)?.[1];
    if (!target) continue;
    const host = resolveLocation(target, requestUrl).host;
    if (host && isProbeTargetHost(host, evilHost)) {
      return { kind: "meta", target, snippet: snippetAround(body, tag.index ?? 0, text.length) };
    }
  }

  // ── location 賦值 ───────────────────────────────────────────────────────
  // 涵蓋 location.href=／location.replace(／location.assign(／window.location=／document.location=。
  const pattern =
    /(?:window\s*\.|document\s*\.)?location(?:\s*\.\s*(?:href|replace|assign))?\s*(?:=|\(\s*)\s*(["'`])([^"'`]*)\1/gi;
  for (const hit of body.matchAll(pattern)) {
    const target = hit[2];
    if (!target) continue;
    const host = resolveLocation(target, requestUrl).host;
    if (host && isProbeTargetHost(host, evilHost)) {
      return { kind: "script", target, snippet: snippetAround(body, hit.index ?? 0, hit[0]?.length ?? 0) };
    }
  }

  return null;
}

/**
 * 找出「值被原樣寫回頁面」的情形。
 *
 * 先把回應內文裡對**請求網址本身**的回聲（canonical link、og:url 這類把當前網址整串印出來的標籤）
 * 移除再找。理由是降噪：那種回聲對 15 個參數都會成立，會一次生出 15 筆一模一樣的 low，
 * 而它們講的其實是同一件事（框架把網址印出來了），不是 15 個問題。
 * 扣掉自我回聲之後還找得到，才代表這個參數的值真的被單獨處理並寫進頁面。
 */
export function findReflection(body: string, requestUrl: string, evilHost: string): string | null {
  const url = new URL(requestUrl);
  const echoes = [requestUrl, `${url.pathname}${url.search}`];
  let scanned = body;
  for (const echo of echoes) {
    // HTML 屬性裡的 & 常被逸出成 &amp;，兩種寫法都要當成同一段自我回聲扣掉。
    for (const variant of new Set([echo, echo.replace(/&/g, "&amp;")])) {
      scanned = scanned.split(variant).join(" ");
    }
  }
  const at = scanned.toLowerCase().indexOf(evilHost.toLowerCase());
  if (at < 0) return null;
  return snippetAround(scanned, at, evilHost.length);
}

export function analyzeRedirect(
  obs: RedirectObservation,
  ctx: { surface: SurfaceId; originHost: string; evilHost: string },
): Finding[] {
  const base = { check: "redirect", category: "security" as const, surface: ctx.surface, where: obs.requestUrl };

  // ── 3xx：判定完全由 Location 決定 ───────────────────────────────────────
  // 瀏覽器不會渲染 3xx 的內文，所以那裡的 meta refresh 或反射對使用者是不存在的，一律不看。
  if (obs.status >= 300 && obs.status < 400) {
    if (!obs.location) return []; // 3xx 卻沒有 Location：畸形回應，沒有落點可判，不臆測
    const target = resolveLocation(obs.location, obs.requestUrl);
    // 解析不出主機、落在自家網域、或參數根本沒被採用——這三種都是正確行為，不報。
    if (!target.host) return [];
    if (isSameHost(target.host, ctx.originHost)) return [];
    if (!isProbeTargetHost(target.host, ctx.evilHost)) return [];

    return [
      finding({
        ...base,
        id: `redirect.open.${obs.param}`,
        severity: "high",
        title: `\`?${obs.param}\` 可把使用者導向任意外部網站（開放重導向）`,
        detail:
          `送出 \`${obs.param}=${obs.sentTarget}\` 後，站台回 HTTP ${obs.status} 並把使用者導向 ${target.host}——` +
          "一個完全不屬於這個部署的主機。攻擊者可以做出一條網域看起來完全正確的連結，" +
          "使用者信任它、郵件過濾器與聊天軟體的連結掃描也信任它（自家網域的信譽是乾淨的），" +
          "點下去卻落在對方架的假登入頁上。這是釣魚最省力的起手式。" +
          (obs.param === "redirect_uri" || obs.param === "callback"
            ? "而且這個參數名就是 OAuth／OIDC 的授權碼回傳點：能被導向外部，等於授權碼會直接送到攻擊者手上，" +
              "換到的是一組有效憑證，不需要使用者再輸入任何東西。"
            : "若同一個參數也用在登入後的回跳上，攻擊者還能等使用者登入完成才把他丟出去，可信度更高。"),
        remediation:
          "回跳目標只接受相對路徑：必須以單一 `/` 開頭，且第二個字元不是 `/` 或 `\\`（擋掉 `//evil` 與 `/\\evil`），" +
          "並且拒絕含 `@`、`:` 與換行的值；判斷「是不是自家網址」要用 URL 解析後的 host 做**完全比對**，" +
          "不要用字串前綴或 endsWith。更穩的做法是把回跳目標存在伺服器端會話裡，網址上只帶一個索引鍵。" +
          "OAuth 的 redirect_uri 一律用事先註冊的完整字串比對，不做任何前綴或萬用字元匹配。",
        evidence:
          `送出：${obs.param}=${obs.sentTarget}\n` +
          `HTTP ${obs.status}\nLocation: ${target.raw}\n實際落點主機：${target.host}`,
      }),
    ];
  }

  if (!obs.bodySnippet) return [];

  // ── 內文層導向（回 200 但頁面自己把人送出去）────────────────────────────
  const client = findClientRedirect(obs.bodySnippet, obs.requestUrl, ctx.evilHost);
  if (client) {
    return [
      finding({
        ...base,
        id: `redirect.open-meta.${obs.param}`,
        severity: "medium",
        title: `\`?${obs.param}\` 透過頁面內容把使用者導向外部網站`,
        detail:
          `站台回 HTTP ${obs.status}（不是 3xx），但回應內文裡有` +
          (client.kind === "meta" ? "一段 meta refresh" : "一段 location 賦值") +
          `，目標解析後落在 ${ctx.evilHost}。對使用者來說結果和 302 一樣：他會落在攻擊者的站上，只是慢一拍。` +
          "危險的是這種寫法在存取紀錄與只看 3xx 的掃描器眼裡是一片乾淨的 200，通常沒有人會發現。" +
          "等級比 3xx 版低一階，是因為它需要瀏覽器解析頁面才會發生，而且本檢查是用字串特徵判定、" +
          "沒有實際執行 JS，理論上仍有誤判空間——附上的 evidence 就是給人核對用的。",
        remediation:
          "驗證與 3xx 版完全相同：只接受相對路徑，判斷自家網址要用 URL 解析後的 host 完全比對。" +
          "客戶端導向不會因為「發生在瀏覽器裡」就比較安全，該做的檢查一樣都不能少。",
        evidence: `送出：${obs.param}=${obs.sentTarget}\n導向目標：${client.target}\n${client.snippet}`,
      }),
    ];
  }

  // ── 純反射 ──────────────────────────────────────────────────────────────
  const reflected = findReflection(obs.bodySnippet, obs.requestUrl, ctx.evilHost);
  if (reflected) {
    return [
      finding({
        ...base,
        id: `redirect.reflected.${obs.param}`,
        severity: "low",
        title: `\`?${obs.param}\` 的值原樣出現在回應內文`,
        detail:
          `站台回 HTTP ${obs.status}，沒有 Location，也沒有偵測到 meta refresh 或 location 賦值——` +
          "**這不等於已經可以利用**，是體質提醒：一個使用者可控的完整外部網址被原樣帶進了頁面。" +
          "只要日後有任何一段前端程式拿它去做導向，或它被填進某個 href、某個 form action，" +
          "這裡就會直接變成開放重導向，而那次改動看起來只是一行無害的功能調整。" +
          "也有可能它只是被回填到自家表單的 hidden input（那是正常設計）——" +
          "從回應內文無法可靠分辨這兩者，所以維持 low 不升級，由人看 evidence 決定。",
        remediation:
          "值寫進頁面前先驗證它是相對路徑，並做 HTML 逸出；只是要把它傳到下一步的話，" +
          "改存伺服器端會話、網址上只帶索引鍵，頁面上就不會出現任何使用者可控的網址。",
        evidence: `送出：${obs.param}=${obs.sentTarget}\n${reflected}`,
      }),
    ];
  }

  return [];
}

export async function checkRedirect(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "redirect", category: "security" as const, surface: surface.id };
  const originHost = new URL(surface.origin).host;
  /** 每條路徑的狀態碼分布。30 筆逐條列出會把 facts 灌成噪音，這裡只留看得出樣貌的摘要。 */
  const statusCounts: Record<string, Record<string, number>> = {};
  /** 值得逐條記下來的觀測：3xx（有落點可看）與連不上的。其餘用上面的分布表代表。 */
  const notable: Record<string, string> = {};
  /** 真的拿到應用層回應的次數。全 0＝這一輪什麼都沒驗到。 */
  let answered = 0;

  for (const path of AUDIT_PATHS) {
    const counts: Record<string, number> = {};
    statusCounts[path] = counts;

    for (const param of REDIRECT_PARAMS) {
      const url = new URL(join(surface.origin, path));
      url.searchParams.set(param, EVIL_REDIRECT_TARGET);
      const requestUrl = url.toString();

      const res = await tryProbe(requestUrl, {
        surface,
        timeoutMs,
        followRedirects: 0, // 3xx 本身就是證據；跟隨下去只會真的往外連一次，毫無收穫
        maxBodyBytes: BODY_SCAN_LIMIT,
      });

      if (isProbeFailure(res)) {
        notable[`${path}?${param}`] = `未判定：${res.error}`;
        continue;
      }

      const contentType = res.headers.get("content-type") ?? "";
      // 中介層（代理／WAF／平台閘道）攔截時整組跳過。中介層對這種帶外部網址的參數
      // 特別容易直接擋掉，而它擋掉的是我們、不是攻擊者；拿它的回應當「站台沒有這個問題」
      // 就是把「沒測到」講成「沒問題」——這裡寧可整組標成未執行。
      if (looksLikeGatewayInterception({ status: res.status, body: res.body, contentType })) {
        facts.statusCounts = statusCounts;
        facts.notable = notable;
        facts.probeTarget = EVIL_REDIRECT_TARGET;
        return {
          ...base,
          completed: false,
          skippedReason:
            `探測 ${path}?${param} 時收到 HTTP ${res.status}，內容不像應用回應，判定為中介層（代理／WAF／平台閘道）攔截。` +
            "帶外部網址的查詢參數最容易被中介層直接擋下，這一輪測到的是中介層而不是站台，" +
            "整組回跳參數探測已略過——請從能直連目標的網路環境重跑。",
          durationMs: elapsed(),
          findings: [],
          facts,
        };
      }

      answered += 1;
      const status = String(res.status);
      counts[status] = (counts[status] ?? 0) + 1;

      const location = res.headers.get("location");
      if (location) notable[`${path}?${param}`] = `HTTP ${res.status} → ${location}`;

      findings.push(
        ...analyzeRedirect(
          {
            param,
            requestUrl,
            sentTarget: EVIL_REDIRECT_TARGET,
            status: res.status,
            location,
            bodySnippet: res.body.length > 0 ? res.body : null,
          },
          { surface: surface.id, originHost, evilHost: EVIL_REDIRECT_HOST },
        ),
      );
    }
  }

  facts.probeTarget = EVIL_REDIRECT_TARGET;
  facts.requests = AUDIT_PATHS.length * REDIRECT_PARAMS.length;
  facts.answered = answered;
  facts.statusCounts = statusCounts;
  facts.notable = notable;

  // 一次應用層回應都沒拿到：回 completed: true 加空 findings 會在報告上變成一個綠燈，
  // 而那個綠燈的真正意思是「我們沒測」。
  if (answered === 0) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `${AUDIT_PATHS.length} 條路徑 × ${REDIRECT_PARAMS.length} 個回跳參數全部沒有得到回應（連線失敗或逾時）。` +
        "本輪未驗到任何回跳行為——請確認目標可連線後重跑。",
      durationMs: elapsed(),
      findings: [],
      facts,
    };
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
