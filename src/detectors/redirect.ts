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
 *
 * ── 涵蓋率：什麼叫「這一輪真的測到了」 ─────────────────────────────────────
 * 每一次探針都先被 `classifyRedirectProbe` 分成四種結局，因為它們在報告上代表完全不同的事：
 * 站台答了（可以判定）、這條路徑上沒東西（404／405，站台明確說了「這裡沒有」）、
 * 中介層代答（我們根本沒碰到站台）、以及連不上。
 * 判定順序刻意讓 404／405 走在中介層判定**之前**——`looksLikeGatewayInterception` 是為首頁設計的，
 * 首頁回 4xx 幾乎一定是被攔了，但 express 與 nginx 的預設 404 頁同樣長得「不像應用回應」。
 * 反過來套用的代價很具體：`/login` 在這個部署上剛好不是伺服器路由（SPA 前端路由、或叫 `/sign-in`）時，
 * 一個再平常不過的 404 會把整項檢查標成「被中介層攔截」，連 `/` 上已經測到的真發現一起丟掉。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";
import { looksLikeSpaFallback } from "./disclosure.js";

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

/**
 * 「這條路徑上沒有東西可測」的狀態碼。
 *
 * 404／410 是站台對「有沒有這個資源」最明確的否定答覆；405／501 則是「有這條路由但不收 GET」
 * （POST-only 的登入端點就長這樣）。三者都不是問題，也都不代表我們被誰擋住了——
 * 它們是站台親自答的，只是答案裡沒有可判定的重導向行為。
 */
const ABSENT_STATUSES = new Set([404, 405, 410, 501]);

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
  const hostOf = (url: URL): { host: string | null; raw: string } =>
    url.host ? { host: normalizeHost(url.host), raw: location } : { host: null, raw: location };
  try {
    return hostOf(new URL(trimmed, requestUrl));
  } catch {
    // 基準網址畸形時 WHATWG URL 會連帶讓絕對網址一起解析失敗。
    // 落點是絕對網址的話，答案其實不需要基準——為了一個壞掉的 requestUrl 就把已經看得見的
    // 外部主機丟掉，是自己製造漏報。所以退一步再解析一次。
    try {
      return hostOf(new URL(trimmed));
    } catch {
      return { host: null, raw: location };
    }
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
  const target = normalizeHost(evilHost.trim());
  if (!target) return false; // 空的比對目標會讓下面兩條規則變成亂數，寧可什麼都不認
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
 * 回應內文裡「對請求網址本身的回聲」有哪些寫法。
 *
 * canonical link、`<base>`、把當前查詢字串原樣接上去的 form action——框架很愛把當前網址印回頁面。
 * 那種回聲對 15 個參數都會成立，會一次生出 15 筆一模一樣的 low，
 * 而它們講的其實是同一件事（框架把網址印出來了），不是 15 個問題。
 *
 * 兩種編碼都要列出來，這一點是實測出來的：我們送出去的是百分號編碼版
 * （`next=https%3A%2F%2F…`，`searchParams.set` 的結果），但伺服器手上拿到的是**解碼後**的值
 * （`req.query.next`），印回頁面時多半也是解碼的。只扣掉編碼版，等於兩種回聲只擋住一種，
 * 另一種會在每個把網址印回來的正常站台上炸出一整排假警報。
 */
function echoesOfRequestUrl(requestUrl: string): string[] {
  const out = new Set<string>();
  const add = (value: string): void => {
    if (!value) return;
    out.add(value);
    // HTML 屬性裡的 & 常被逸出成 &amp;，兩種寫法都是同一段自我回聲。
    out.add(value.replace(/&/g, "&amp;"));
  };
  const decoded = (value: string): string => {
    try {
      return decodeURIComponent(value);
    } catch {
      return value; // 落單的 % 會讓 decodeURIComponent 丟例外；那不是判定失敗的理由
    }
  };

  add(requestUrl);
  add(decoded(requestUrl));
  try {
    const url = new URL(requestUrl);
    const pathAndQuery = `${url.pathname}${url.search}`;
    add(pathAndQuery);
    add(decoded(pathAndQuery));
  } catch {
    // requestUrl 畸形時只比對整串。這個函式是純函式，呼叫端給什麼都不該讓整輪檢查爆掉。
  }
  // 長的先扣：短回聲先被遮掉會把包住它的長回聲切斷，兩段殘骸反而都比對不上。
  return [...out].sort((a, b) => b.length - a.length);
}

/** 用等長空白遮蔽而不是刪除，讓索引維持與原始內文一一對應。 */
function blankOut(haystack: string, needle: string): string {
  if (!needle || !haystack.includes(needle)) return haystack;
  return haystack.split(needle).join(" ".repeat(needle.length));
}

/**
 * 找出「值被原樣寫回頁面」的情形。
 *
 * 先把對請求網址本身的回聲遮掉再找：扣掉自我回聲之後還找得到，
 * 才代表這個參數的值真的被單獨處理並寫進頁面。
 * 遮蔽用等長空白而不是直接刪除，是為了讓 evidence 能從**原始內文**取片段——
 * 附上一段被剪過的 HTML，維運者拿去搜尋原始碼會找不到，那樣的證據等於沒有證據。
 */
export function findReflection(body: string, requestUrl: string, evilHost: string): string | null {
  const needle = evilHost.trim().toLowerCase();
  // 空的比對目標會讓 indexOf 回 0，於是每一個 200 回應都長出一筆「反射」。
  // 憑空生出來的發現比漏報更傷：沒有人查得出它從哪來，只會學會不要相信這份報告。
  if (!needle) return null;

  let scanned = body;
  for (const echo of echoesOfRequestUrl(requestUrl)) scanned = blankOut(scanned, echo);

  const at = scanned.toLowerCase().indexOf(needle);
  if (at < 0) return null;
  return snippetAround(body, at, needle.length);
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
          `站台回 HTTP ${obs.status}——不是 3xx，瀏覽器不會據此導向，內文裡也沒有偵測到 meta refresh 或 location 賦值。` +
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

/**
 * 一次探針的四種結局。
 *
 * 「站台答了」與「中間有人代答」必須分開，否則這個檢查會用最糟的方式說謊：
 * 拿中介層的罐頭錯誤頁當成「站台沒有這個問題」。
 * `absent` 又必須跟 `intercepted` 分開，否則會用另一種方式說謊：
 * 拿一個再平常不過的 404 當成「我們被擋住了」，把整項檢查連同已測到的發現一起丟掉。
 */
export type RedirectProbeState =
  | { state: "answered"; spaFallback: boolean; reason: string }
  | { state: "absent"; reason: string }
  | { state: "intercepted"; reason: string }
  | { state: "unreachable"; reason: string };

/**
 * 判斷一次探針的結果代表什麼。純函式，測試不需要網路。
 *
 * 順序是刻意的，理由與 wellknown 的取檔判定同源：404／405 這類「這裡沒有東西」要走在
 * 中介層判定**之前**。`looksLikeGatewayInterception` 的判準是「4xx／5xx 且內容不像應用回應」，
 * 而 express 與 nginx 的預設 404 頁正好完全命中——先套它，每一個正常的 404 都會被講成「沒測到」。
 *
 * SPA 兜底頁的判定則要走在中介層判定**之後**：`looksLikeSpaFallback` 只認 HTML 型別加 doctype，
 * 而 WAF 的封鎖頁同樣是帶 doctype 的 HTML。順序反過來，中介層攔截就會被誤讀成「站台正常回應」。
 */
export function classifyRedirectProbe(
  input: { error: string } | { status: number; body: string; contentType: string },
): RedirectProbeState {
  if ("error" in input) return { state: "unreachable", reason: `未拿到回應：${input.error}` };
  if (ABSENT_STATUSES.has(input.status)) {
    return { state: "absent", reason: `HTTP ${input.status}（站台答了，但這條路徑上沒有可判定的回跳行為）` };
  }
  if (looksLikeGatewayInterception(input)) {
    return {
      state: "intercepted",
      reason: `HTTP ${input.status} 且內容不像應用回應，研判為中介層（代理／WAF／平台閘道）攔截`,
    };
  }
  const spaFallback = looksLikeSpaFallback(input.body, input.contentType);
  return {
    state: "answered",
    spaFallback,
    reason: `HTTP ${input.status}${spaFallback ? "（SPA 兜底 index.html）" : ""}`,
  };
}

/** 一輪探測的結局統計。 */
export interface RedirectCoverage {
  answered: number;
  absent: number;
  intercepted: number;
  unreachable: number;
}

export type RedirectCoverageVerdict = { completed: true } | { completed: false; skippedReason: string };

/**
 * 這一輪到底算不算「測過了」。純函式，測試不需要網路。
 *
 * 只要有任何一次探針拿到站台自己的回應，這項檢查就是跑過了——即使其他路徑被擋掉或不存在。
 * 這一條刻意不寫成「有任何一次被攔截就整組跳過」：那樣一個 404 或一條被 WAF 特別關照的路徑，
 * 就足以把另一條路徑上已經測到的真發現整包丟掉，而丟掉真發現的代價遠大於少標一次跳過。
 *
 * 反過來，一次都沒拿到站台的回應時絕不可以回 completed: true 加空 findings——
 * 那在報告上會變成一個綠燈，而那個綠燈的真正意思是「我們沒測」。
 */
export function decideRedirectCoverage(tally: RedirectCoverage): RedirectCoverageVerdict {
  if (tally.answered > 0) return { completed: true };

  const total = tally.absent + tally.intercepted + tally.unreachable;
  if (total === 0) {
    return { completed: false, skippedReason: "沒有送出任何回跳參數探針，本輪未驗到任何回跳行為。" };
  }

  const parts: string[] = [];
  if (tally.intercepted > 0) parts.push(`中介層攔截 ${tally.intercepted} 次`);
  if (tally.absent > 0) parts.push(`路徑不存在或不接受 GET ${tally.absent} 次`);
  if (tally.unreachable > 0) parts.push(`連不上或逾時 ${tally.unreachable} 次`);

  const tail =
    tally.intercepted > 0
      ? "帶外部網址的查詢參數最容易被中介層直接擋下，這一輪測到的是中介層而不是站台——請從能直連目標的網路環境重跑。"
      : tally.absent >= tally.unreachable
        ? "受測路徑上沒有任何一處被實際測到。這不代表站台沒有開放重導向，只代表回跳參數不在 / 與 /login 這兩條路徑上——請確認登入頁的實際路徑後重跑。"
        : "請確認目標可連線後重跑。";

  return {
    completed: false,
    skippedReason: `${total} 次探測沒有任何一次拿到可判定的應用層回應（${parts.join("、")}）。${tail}`,
  };
}

export async function checkRedirect(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "redirect", category: "security" as const, surface: surface.id };
  const originHost = new URL(surface.origin).host;

  /** 每條路徑的狀態碼分布。30 筆逐條列出會把 facts 灌成噪音，這裡只留看得出樣貌的摘要。 */
  const statusCounts: Record<string, Record<string, number>> = {};
  /** 值得逐條記下來的觀測：3xx（有落點可看）、被攔截的、以及連不上的。其餘用上面的分布表代表。 */
  const notable: Record<string, string> = {};
  /** 每條路徑一句話的涵蓋率註記。facts 沒有欄位說明，所以話要寫在值裡面。 */
  const pathNotes: Record<string, string> = {};
  const tally: RedirectCoverage = { answered: 0, absent: 0, intercepted: 0, unreachable: 0 };

  for (const path of AUDIT_PATHS) {
    const counts: Record<string, number> = {};
    statusCounts[path] = counts;
    let answeredHere = 0;
    let spaHere = 0;

    for (const param of REDIRECT_PARAMS) {
      const url = new URL(join(surface.origin, path));
      url.searchParams.set(param, EVIL_REDIRECT_TARGET);
      const requestUrl = url.toString();
      const label = `${path}?${param}`;

      const res = await tryProbe(requestUrl, {
        surface,
        timeoutMs,
        followRedirects: 0, // 3xx 本身就是證據；跟隨下去只會真的往外連一次，毫無收穫
        maxBodyBytes: BODY_SCAN_LIMIT,
      });

      // 送不出去也交給同一個判讀函式，措辭才只有一個來源——facts 與 skippedReason 各講各的，
      // 讀者就得自己猜兩段話是不是在講同一件事。
      if (isProbeFailure(res)) {
        tally.unreachable += 1;
        notable[label] = classifyRedirectProbe({ error: res.error }).reason;
        continue;
      }

      // 狀態碼分布要涵蓋每一次回應，包含被攔截與不存在的那些。
      // 只統計「判得動」的那部分，會讓讀者以為所有探針都得到了可判定的答覆。
      const status = String(res.status);
      counts[status] = (counts[status] ?? 0) + 1;

      const contentType = res.headers.get("content-type") ?? "";
      const verdict = classifyRedirectProbe({ status: res.status, body: res.body, contentType });
      if (verdict.state !== "answered") {
        tally[verdict.state] += 1;
        // absent 是最常見也最無趣的結局（那條路徑上沒東西），逐條列出只會把 facts 灌成噪音，
        // 而它已經由狀態碼分布表代表了。另外兩種的意思是「這一次我們沒測到」，必須逐條看得見。
        if (verdict.state !== "absent") notable[label] = verdict.reason;
        continue;
      }

      tally.answered += 1;
      answeredHere += 1;
      if (verdict.spaFallback) spaHere += 1;

      const location = res.headers.get("location");
      if (location) notable[label] = `HTTP ${res.status} → ${location}`;

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

    // 整條路徑都只回 SPA 兜底頁時要說出來：伺服器端確實沒有處理這些參數（那是真的觀測），
    // 但那條路徑上的回跳邏輯全在瀏覽器裡執行，本輪一行都沒碰到。
    // 不寫出來，讀者會把「伺服器沒有伺服器端開放重導向」讀成「這個站的回跳是安全的」。
    if (answeredHere > 0 && spaHere === answeredHere) {
      pathNotes[path] = "全部回應都是 SPA 兜底 index.html——伺服器端沒有處理任何回跳參數；前端路由的回跳行為本輪未涵蓋。";
    }
  }

  facts.probeTarget = EVIL_REDIRECT_TARGET;
  facts.requests = AUDIT_PATHS.length * REDIRECT_PARAMS.length;
  facts.answered = tally.answered;
  facts.coverage = tally;
  facts.statusCounts = statusCounts;
  facts.notable = notable;
  if (Object.keys(pathNotes).length > 0) facts.pathNotes = pathNotes;

  const coverage = decideRedirectCoverage(tally);
  if (!coverage.completed) {
    return { ...base, completed: false, skippedReason: coverage.skippedReason, durationMs: elapsed(), findings: [], facts };
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
