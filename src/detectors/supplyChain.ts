/**
 * 前端供應鏈檢測（第三方子資源盤點）。
 *
 * 頁面上每一支第三方腳本，在瀏覽器裡握有的權限與自家程式**完全相同**：
 * 可以讀整份 DOM、讀 localStorage 裡的登入權杖、改寫任何送出的請求。
 * 換句話說，第三方 CDN 被入侵時，站台自己一行程式都沒改就已經被接管
 * （polyfill.io 事件是最近的實例：網域易主後，同一個網址開始對部分訪客送出惡意腳本）。
 *
 * 既有的 CSP 檢查看的是「政策允許誰」，那是理論上的上界；這裡回答的是另一個問題——
 * **實際上到底載了誰**。兩者都需要：政策再嚴，也擋不住一支早就寫進白名單、
 * 內容卻在對方那邊被換掉的腳本。
 *
 * 限制（必須寫出來，否則讀者會把這份盤點當成完整清單）：
 * 這裡只解析**初始 HTML**。由 JS 動態插入的 <script>（標籤管理器、A/B 工具、
 * 依使用者條件才載入的 SDK）在這裡一律看不到——那是 pages 端頁面測試（真的開瀏覽器）的守備範圍。
 *
 * 解析的準則只有一條：**瀏覽器真的會去載的才算**。
 * 所以 <base> 會改變相對路徑的解析基準、內嵌腳本的內容是純文字（裡面的 "<script src=…" 只是字串）、
 * type 不是 JS 的 <script> 是資料區塊不會被下載——這些都照瀏覽器的規則走。
 * 偏離它的每一處，最後都會變成一筆修不掉（或不該修）的假警報。
 *
 * 判定全寫成純函式（extractSubresources／analyzeSubresources），網路 I/O 只在 checkSupplyChain。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

export interface Subresource {
  kind: "script" | "stylesheet";
  /** 解析成絕對網址後的引用（相對路徑已用頁面網址／<base> 補齊）。 */
  url: string;
  /** 主機名（小寫）。data:／blob: 這類非網路來源沒有主機，為 null。 */
  host: string | null;
  /** integrity 原值；沒有屬性或值為空都算沒有（空字串不會驗證任何東西），為 null。 */
  integrity: string | null;
  /**
   * crossorigin 原值。**沒有屬性是 null，屬性存在但沒給值是空字串**（等同 anonymous）。
   * 兩者意義完全相反，混為一談會把設定正確的資源誤報成壞掉的。
   */
  crossorigin: string | null;
  /**
   * 是不是 `<script type="module">`。
   *
   * 為什麼這件事要記下來：module 腳本**一律以 CORS 模式取得**，crossorigin 屬性在它身上
   * 只決定要不要夾帶憑證。所以「有 integrity 卻沒有 crossorigin」這條規則對 module 不成立——
   * 照報會在報告裡寫下一句不實的話（「瀏覽器會直接拒絕載入」），而讀者只要抓到一次
   * 說錯話的告警，就不會再相信整份報告。
   */
  isModule: boolean;
  isThirdParty: boolean;
  isInsecure: boolean;
}

/** 每個主機的盤點小計。checkSupplyChain 的 facts 與盤點證據都用這個。 */
export interface HostInventory {
  host: string;
  thirdParty: boolean;
  scripts: number;
  stylesheets: number;
  /** 其中有帶 integrity 的數量。 */
  withIntegrity: number;
  insecure: number;
}

/**
 * 本機位址。https 頁面引用 http://localhost 不算混合內容——瀏覽器把 loopback
 * 視為可信來源不會擋，開發環境也常態如此，報出來只是噪音。
 */
const LOOPBACK = /^(?:localhost|127\.\d+\.\d+\.\d+|\[::1\])$/i;

/**
 * 內容天生會變動、因此設計上就無法套 SRI 的服務。
 *
 * 不用來降低嚴重度——風險並沒有比較小；只用來在證據裡註明「硬加 integrity 不是解法」，
 * 免得維運者花一整天去試一個不可能成功的修法，最後乾脆把這條規則整個關掉。
 */
const MUTABLE_SCRIPT_HOSTS = [
  "googletagmanager.com",
  "google-analytics.com",
  "googleadservices.com",
  "connect.facebook.net",
  "static.hotjar.com",
  "cdn.segment.com",
  "js.stripe.com",
  "clarity.ms",
  "posthog.com",
  "sentry-cdn.com",
];

function looksLikeMutableScriptHost(host: string): boolean {
  return MUTABLE_SCRIPT_HOSTS.some((known) => host === known || host.endsWith(`.${known}`));
}

/** HTML 規格認定為「JavaScript」的 MIME 型別（含一票歷史寫法，實務上還看得到）。 */
const JS_MIME =
  /^(?:text\/(?:javascript\d*|ecmascript|jscript|livescript|x-javascript|x-ecmascript)|application\/(?:javascript|ecmascript|x-javascript|x-ecmascript))$/;

/**
 * 這個 `<script>` 的 type 會讓瀏覽器真的去下載並執行嗎？
 *
 * 沒有 type 或 type 是 JS／module 才會；其餘（application/ld+json、text/template、
 * importmap⋯⋯）是**資料區塊**，瀏覽器連請求都不會送。把資料區塊算成子資源，
 * 會產生一筆「請幫這個第三方腳本加上 SRI」的告警，而那支腳本根本沒有被載入過。
 */
function isExecutableScriptType(rawType: string | undefined): boolean {
  const type = (rawType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  return type === "" || type === "module" || JS_MIME.test(type);
}

/**
 * 找出開始標籤的結尾 `>`，掃描時尊重引號。
 *
 * 不用 /<script[^>]*>/ 的理由有兩個：屬性值裡可以合法出現 `>`（查詢字串），
 * 以及這裡吃的是遠端回來的 HTML——巢狀量詞的正規表示式在惡意輸入下會退化成災難，
 * 一個資安工具不該有這種面。手寫掃描是線性的。
 */
function findTagEnd(html: string, from: number): number {
  let quote: string | null = null;
  for (let i = from; i < html.length; i += 1) {
    const ch = html[i];
    if (ch === undefined) break;
    if (quote !== null) {
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") quote = ch;
    else if (ch === ">") return i;
  }
  return -1;
}

/** `</script` 的位置（找不到回 -1）。內嵌腳本的內容到這裡為止都是純文字。 */
function findScriptTextEnd(html: string, from: number): number {
  const closing = /<\/script(?=[\s/>])/gi;
  closing.lastIndex = from;
  return closing.exec(html)?.index ?? -1;
}

/**
 * 拆一段屬性文字成 name → value。
 *
 * 屬性名一律轉小寫（HTML 屬性不分大小寫），值保留原樣（網址與雜湊都區分大小寫）。
 * 重複屬性取第一個，與瀏覽器行為一致。
 */
function parseAttributes(source: string): Map<string, string> {
  const attrs = new Map<string, string>();
  const pattern = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  for (const match of source.matchAll(pattern)) {
    const name = match[1]?.toLowerCase();
    if (name === undefined) continue;
    // 無引號的值：把結尾的 `/` 拿掉，否則 <script src=/a.js/> 會被讀成路徑多一個斜線。
    const bare = match[4] === undefined ? undefined : match[4].replace(/\/$/, "");
    const value = match[2] ?? match[3] ?? bare ?? "";
    if (!attrs.has(name)) attrs.set(name, value);
  }
  return attrs;
}

/** 屬性值裡的 `&amp;` 是 HTML 轉義，還原後才是真正會被請求的網址。 */
function decodeAttrValue(raw: string): string {
  return raw.replace(/&amp;/gi, "&");
}

/**
 * 把一個引用轉成 Subresource。
 *
 * `base` 是相對路徑的解析基準（可能被 <base> 改掉），`page` 永遠是頁面本身的網址——
 * 同源與否要跟**頁面的來源**比，那件事不會因為 <base> 而改變。
 */
function toSubresource(
  kind: Subresource["kind"],
  rawUrl: string,
  attrs: Map<string, string>,
  base: URL,
  page: URL,
): Subresource | null {
  const trimmed = decodeAttrValue(rawUrl).trim();
  if (trimmed === "") return null;

  let resolved: URL;
  try {
    resolved = new URL(trimmed, base);
  } catch {
    return null; // 解析不出來的引用（樣板變數沒被取代之類）不猜，也不讓檢查器崩掉
  }

  const networked = resolved.protocol === "http:" || resolved.protocol === "https:";
  const host = networked ? resolved.hostname.toLowerCase() : null;
  // integrity="" 不會驗證任何東西，等同沒有；當成「有」會把壞掉的設定報成安全的。
  const integrity = (attrs.get("integrity") ?? "").trim();

  return {
    kind,
    url: resolved.toString(),
    host,
    integrity: integrity === "" ? null : integrity,
    crossorigin: attrs.get("crossorigin") ?? null,
    isModule: kind === "script" && (attrs.get("type") ?? "").trim().toLowerCase() === "module",
    // 子網域也算第三方：cdn.example.com 指向誰、由誰控制，跟主網域是兩件事，
    // 而「自家網域 CNAME 到外部服務」正是這類供應鏈事故最常見的形狀。
    isThirdParty: host !== null && host !== page.hostname.toLowerCase(),
    isInsecure: resolved.protocol === "http:" && !LOOPBACK.test(host ?? ""),
  };
}

/** 同一份引用（欄位完全相同）在 HTML 裡重複出現時的識別鍵。 */
function subresourceKey(r: Subresource): string {
  return [r.kind, r.url, r.integrity ?? "", r.crossorigin ?? "", r.isModule].join("\n");
}

/**
 * 從 HTML 取出會被瀏覽器載入的子資源。
 *
 * 容忍實務上會遇到的所有寫法：屬性順序任意、單雙引號或無引號、標籤與屬性大小寫混雜、
 * self-closing、屬性間換行。無 src 的內嵌 <script> 不是子資源（它的風險屬於 CSP 的守備範圍），略過。
 */
export function extractSubresources(html: string, pageUrl: string): Subresource[] {
  let page: URL;
  try {
    page = new URL(pageUrl);
  } catch {
    return []; // 沒有可靠的基準網址就無法判斷同源，寧可不盤點也不要盤錯
  }

  // 註解掉的標籤瀏覽器不會載入，當然也不該進盤點。不先剝掉的話，
  // 留在註解裡的舊 CDN 會變成一筆永遠「修不掉」的假警報。
  const source = html.replace(/<!--[\s\S]*?-->/g, "");

  const out: Subresource[] = [];
  const seen = new Set<string>();
  /**
   * 收下一筆引用；完全相同的重複只留一次。
   *
   * 瀏覽器對同一個網址只會取一次，把重複的標記算成兩支，會讓「腳本 2」與
   *「N 個子資源以 http 載入」這種數字虛胖。只折疊每個欄位都一樣的重複——
   * 屬性有差異（一處有 integrity、一處沒有）是真的兩種寫法，兩筆都得留著。
   */
  const collect = (item: Subresource | null): void => {
    if (item === null) return;
    const key = subresourceKey(item);
    if (seen.has(key)) return;
    seen.add(key);
    out.push(item);
  };
  const opener = /<(script|link|base)(?=[\s/>])/gi;

  // 相對路徑的解析基準。<base href> 之前的引用仍以頁面網址解析（瀏覽器是邊解析邊發請求的），
  // 而且依規格只有**第一個**帶 href 的 <base> 生效。
  let resolveBase = page;
  let baseLocked = false;
  // 文件裡已經沒有 </script> 了。掃描位置只會往前走，所以一旦找不到收尾，後面也不可能再有——
  // 不記下來的話，一份塞滿 <script src=x> 卻沒有任何收尾的頁面會讓每個標籤都往文件尾掃一遍
  // （實測 2 萬個標籤要 3.7 秒）。受測站不該有能力拖住掃描自己的工具。
  let noMoreScriptEnd = false;

  let match: RegExpExecArray | null = opener.exec(source);
  while (match !== null) {
    const tag = match[1]?.toLowerCase();
    const attrStart = match.index + match[0].length;
    const tagEnd = findTagEnd(source, attrStart);
    if (tagEnd < 0) {
      // 標籤沒有收尾（HTML 被截斷或引號沒配對）就不猜這一個，但後面照掃：
      // 為了一段壞掉的標記而放棄整份文件，換來的是一張看起來很乾淨的空清單。
      match = opener.exec(source);
      continue;
    }
    // 屬性值裡的字串（`src="x?q=<link"`）不該被當成下一個標籤，所以掃描直接跳到標籤結尾之後。
    opener.lastIndex = tagEnd + 1;

    const attrs = parseAttributes(source.slice(attrStart, tagEnd));

    if (tag === "base") {
      const href = attrs.get("href");
      if (!baseLocked && href !== undefined && href.trim() !== "") {
        try {
          resolveBase = new URL(decodeAttrValue(href).trim(), page);
          baseLocked = true;
        } catch {
          // 壞掉的 base 沿用頁面網址，跟瀏覽器一樣
        }
      }
    } else if (tag === "script") {
      const src = attrs.get("src");
      // 內嵌腳本的內容是純文字：裡面出現的 "<script src=…"、'<link rel=stylesheet…'
      // 只是字串（document.write 的老式廣告碼、樣板字串都會長這樣），
      // 不跳過就會把它們盤點成真的第三方資源——一筆查不到出處、也修不掉的假警報。
      const textEnd = noMoreScriptEnd ? -1 : findScriptTextEnd(source, tagEnd + 1);
      if (textEnd >= 0) opener.lastIndex = textEnd;
      else noMoreScriptEnd = true;

      // type 不是 JS 的 <script> 是資料區塊，瀏覽器根本不會去下載 src。
      if (src !== undefined && isExecutableScriptType(attrs.get("type"))) {
        collect(toSubresource("script", src, attrs, resolveBase, page));
      }
    } else {
      // <link> 只有 stylesheet 會被套用；preload／icon／manifest 不在這次盤點的範圍。
      const rel = (attrs.get("rel") ?? "").toLowerCase().split(/\s+/);
      const href = attrs.get("href");
      if (rel.includes("stylesheet") && href !== undefined) {
        collect(toSubresource("stylesheet", href, attrs, resolveBase, page));
      }
    }

    match = opener.exec(source);
  }

  return out;
}

/**
 * 依主機彙總。
 *
 * 排序是刻意的：evidence 每次執行都長一樣，跨次比對才不會把「順序變了」看成「內容變了」。
 */
export function inventoryByHost(resources: Subresource[]): HostInventory[] {
  const byHost = new Map<string, HostInventory>();
  for (const r of resources) {
    if (r.host === null) continue; // data:／blob: 沒有可盤點的對象
    const entry = byHost.get(r.host) ?? {
      host: r.host,
      thirdParty: r.isThirdParty,
      scripts: 0,
      stylesheets: 0,
      withIntegrity: 0,
      insecure: 0,
    };
    if (r.kind === "script") entry.scripts += 1;
    else entry.stylesheets += 1;
    if (r.integrity !== null) entry.withIntegrity += 1;
    if (r.isInsecure) entry.insecure += 1;
    byHost.set(r.host, entry);
  }
  return [...byHost.values()].sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));
}

function describeHost(entry: HostInventory): string {
  const parts: string[] = [];
  if (entry.scripts > 0) parts.push(`腳本 ${entry.scripts}`);
  if (entry.stylesheets > 0) parts.push(`樣式 ${entry.stylesheets}`);
  const total = entry.scripts + entry.stylesheets;
  return `${entry.host} — ${parts.join("、")}（SRI ${entry.withIntegrity}／${total}）`;
}

/** 證據清單只列前幾筆並註明還有多少：一長串網址會讓人直接跳過整筆發現。 */
function evidenceList(lines: string[], limit = 8): string {
  if (lines.length <= limit) return lines.join("\n");
  return [...lines.slice(0, limit), `（另有 ${lines.length - limit} 筆未列出）`].join("\n");
}

export function analyzeSubresources(
  resources: Subresource[],
  ctx: { surface: SurfaceId; where: string; https: boolean },
): Finding[] {
  const base = { check: "supply-chain", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  // ── http 子資源 ─────────────────────────────────────────────────────────
  // 只在頁面本身是 https 時成立。http 頁面載 http 資源是「整站沒加密」的一部分，
  // 那件事由 transport 檢查負責講；在這裡重複報只會讓同一個問題在報告上出現兩次。
  if (ctx.https) {
    const insecure = resources.filter((r) => r.isInsecure);
    if (insecure.length > 0) {
      out.push(
        finding({
          ...base,
          id: "supply-chain.insecure-subresource",
          severity: "high",
          title: `${insecure.length} 個子資源以 http 載入`,
          detail:
            "https 頁面上的 http 子資源會被瀏覽器當成混合內容擋下——結果是功能整段消失或畫面缺樣式，而且錯誤只出現在使用者的 console，站方通常最後才知道。" +
            "沒被擋下的情況更糟：任何在網路路徑上的人（公共 Wi-Fi、被劫持的 DNS、電信中間盒）都能替換內容，而替換掉一支腳本就等於接管整個頁面。",
          remediation:
            "把引用改成 https；若對方不支援 https，代表這個供應商的安全水準已經不適合放在正式站上，應該換掉或改為自行代管。",
          evidence: evidenceList(
            insecure.map((r) => `${r.kind === "script" ? "腳本" : "樣式"}：${r.url}`),
          ),
        }),
      );
    }
  }

  // ── 第三方 SRI ──────────────────────────────────────────────────────────
  // 同源子資源刻意不報：那是自家部署的產物，威脅模型裡沒有「自己竄改自己」這一項，
  // 硬要上 SRI 只會讓每次發版都得同步更新雜湊，換來的是零風險降低。
  const thirdParty = resources.filter((r) => r.isThirdParty);
  // 用 flatMap 收斂而不是 `r.host as string`：型別斷言會讓一筆 host 為 null 的異常輸入
  // 變成 `supply-chain.script-no-sri.null` 這種假 id，而 id 是抑制清單與跨次比對的鍵。
  const hosts = [...new Set(thirdParty.flatMap((r) => (r.host === null ? [] : [r.host])))].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );

  for (const host of hosts) {
    const owned = thirdParty.filter((r) => r.host === host);
    const scriptsNoSri = owned.filter((r) => r.kind === "script" && r.integrity === null);
    const stylesNoSri = owned.filter((r) => r.kind === "stylesheet" && r.integrity === null);
    // 跨來源資源要通過 SRI 驗證必須以 CORS 模式取得，所以這條只對第三方成立；
    // 同源資源沒有 crossorigin 也驗得起來，拿去報會是純噪音。
    // module 也排除：它本來就走 CORS，缺 crossorigin 不會被拒載（見 Subresource.isModule）。
    const sriNoCors = owned.filter((r) => r.integrity !== null && r.crossorigin === null && !r.isModule);

    if (scriptsNoSri.length > 0) {
      const mutableNote = looksLikeMutableScriptHost(host)
        ? "（此服務的腳本內容會持續更新，通常無法提供固定雜湊——這裡要評估的是必要性，不是補 integrity）"
        : "";
      out.push(
        finding({
          ...base,
          id: `supply-chain.script-no-sri.${host}`,
          severity: "medium",
          title: `第三方腳本未使用 SRI（${host}）`,
          detail:
            "這支腳本與自家程式擁有完全相同的權限：能讀整份 DOM、能讀 localStorage 裡的登入權杖、能改寫任何送出的請求。" +
            "SRI（integrity 雜湊）讓瀏覽器在檔案內容與雜湊對不上時直接拒絕執行，是對抗 CDN 被入侵最直接的手段——" +
            "對方帳號被盜或網域易主時，站台不必改任何一行程式就能擋下來。\n" +
            "限制要誠實講：內容本來就會變動的腳本（分析工具、標籤管理器、A/B 測試）每次更新雜湊都會變，設計上就無法套 SRI。" +
            "這種情況正確的做法不是硬加，而是回頭問「這個第三方還需要嗎、能不能自行代管一個固定版本」。",
          remediation:
            "版本固定的函式庫：改用釘住版本號的網址，並加上 integrity 與 crossorigin=\"anonymous\"。" +
            "內容會變動的服務：改為自行代管固定版本，或在確認必要性後把「接受這個風險」與理由明確記錄下來。",
          evidence: evidenceList([...scriptsNoSri.map((r) => r.url), ...(mutableNote ? [mutableNote] : [])]),
        }),
      );
    }

    if (stylesNoSri.length > 0) {
      out.push(
        finding({
          ...base,
          id: `supply-chain.stylesheet-no-sri.${host}`,
          severity: "low",
          title: `第三方樣式表未使用 SRI（${host}）`,
          detail:
            "樣式表被換掉的攻擊面比腳本小——它不能直接執行 JS。但仍然做得到事：屬性選擇器搭配 background-image 可以把輸入框裡的內容一個字元一個字元外送，" +
            "整頁改版做釣魚介面也只需要 CSS。判為 low 是因為要成災需要更多條件，不是因為它安全。",
          remediation:
            "釘住版本並加上 integrity 與 crossorigin=\"anonymous\"；字型／樣式服務若無法提供固定雜湊，考慮把檔案自行代管。",
          evidence: evidenceList(stylesNoSri.map((r) => r.url)),
        }),
      );
    }

    if (sriNoCors.length > 0) {
      out.push(
        finding({
          ...base,
          id: `supply-chain.sri-without-crossorigin.${host}`,
          severity: "medium",
          title: `有 integrity 卻沒有 crossorigin（${host}）`,
          detail:
            "跨來源資源要通過 SRI 驗證必須以 CORS 模式取得；少了 crossorigin 屬性，瀏覽器拿不到可驗證的回應，於是**直接拒絕載入**這個資源。" +
            "這是「以為加了防護，實際上把功能弄壞了」的典型：失敗是靜默的（只在 console 留一行），而且開發者自己的頁面常因為快取而看起來正常，" +
            "最後只有部分使用者遇到功能消失，卻沒有人把它跟這行 HTML 連在一起。",
          remediation:
            "補上 crossorigin=\"anonymous\"（需要帶憑證的情況才用 use-credentials），並確認對方回應帶有 Access-Control-Allow-Origin。",
          evidence: evidenceList(sriNoCors.map((r) => r.url)),
        }),
      );
    }
  }

  // ── 盤點 ────────────────────────────────────────────────────────────────
  // 即使每一支都有 SRI 也照樣輸出：清單本身就是價值，讓人有機會定期問
  //「這個當初為了什麼加的、現在還需要嗎」。沒有第三方時不輸出——沒有對象可問。
  if (thirdParty.length > 0) {
    const summary = inventoryByHost(thirdParty);
    out.push(
      finding({
        ...base,
        id: "supply-chain.third-party-inventory",
        severity: "info",
        title: `第三方子資源盤點：${summary.length} 個來源、${thirdParty.length} 個檔案`,
        detail:
          "這是頁面實際載入的第三方來源清單。列出來本身就是目的：每一個來源都握有與自家程式相同的權限，" +
          "而「當初為了某個需求加的、現在還在不在用」這種問題，只有定期看清單才會被問出來。\n" +
          "注意涵蓋範圍：這份盤點只看初始 HTML 裡的引用，由 JS 動態插入的腳本不在其中——把它當成完整清單會低估實際的曝險面。",
        remediation:
          "定期檢視這份清單：移除不再需要的來源；必要的來源釘住版本並加上 SRI；無法套 SRI 的則改為自行代管，或把接受風險的理由記錄下來。",
        evidence: evidenceList(summary.map(describeHost), 20),
      }),
    );
  }

  return out;
}

export async function checkSupplyChain(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "supply-chain", category: "security" as const, surface: surface.id };

  const rootUrl = join(surface.origin, "/");
  // 只送一個 GET：盤點需要的素材全在首頁 HTML 裡，沒有理由對受測站多加任何負載。
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

  const contentType = res.headers.get("content-type") ?? "";
  facts.status = res.status;
  facts.contentType = contentType || null;
  facts.finalUrl = res.url;
  facts.truncated = res.truncated;

  // 中介層（代理／WAF／平台閘道）的裸回應上當然一支第三方腳本都沒有。
  // 照樣分析會產出一份「乾淨」的盤點，那比沒有盤點更糟——它會讓人以為查過了。
  if (looksLikeGatewayInterception({ status: res.status, body: res.body, contentType })) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `首頁回應 HTTP ${res.status} 且內容不像應用回應，判定為中介層攔截。` +
        "子資源盤點已略過——中介層的頁面不是站台的頁面。請從能直連目標的網路環境重跑。",
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  // 只有 2xx 才代表「首頁真的把內容給我們了」。
  //
  // 3xx：跟隨上限用完仍在導向，手上這份是中繼回應（常常還帶著 text/html 的一行導向頁）。
  // 4xx／5xx：拿到的是錯誤頁或整站的登入牆——SPA 的錯誤頁還會長得跟首頁一模一樣，
  // 所以 looksLikeGatewayInterception 不會攔下它。
  // 兩種情況照樣解析都會得到一份幾乎空的清單，再以 completed: true 送出去，
  // 讀者看到的是「這個站沒有第三方資源」，而事實是我們根本沒讀到首頁。
  if (res.status < 200 || res.status >= 300) {
    const isRedirect = res.status >= 300 && res.status < 400;
    return {
      ...base,
      completed: false,
      skippedReason:
        `首頁回應 HTTP ${res.status}（最後停在 ${res.url}），拿到的不是首頁內容，因此沒有盤點。` +
        (isRedirect
          ? `已跟隨 ${res.redirects.length} 次重導向仍未落地，請確認首頁的導向設定是否成環或過長。`
          : "站台可能正在故障，或整站需要登入才看得到首頁；請在首頁能正常取得時重跑。"),
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  if (!/html/i.test(contentType)) {
    return {
      ...base,
      completed: false,
      skippedReason: `首頁的 content-type 是「${contentType || "（未提供）"}」而不是 HTML，沒有子資源可盤點。`,
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  // HTML 被讀取上限截斷時，後半段的 <script> 全都看不到。
  // 這種情況下的盤點必然不完整，而一份不完整卻被當成完整的清單，正是這套系統最該避免的產物。
  if (res.truncated) {
    return {
      ...base,
      completed: false,
      skippedReason:
        "首頁 HTML 超過讀取上限被截斷，後半段的子資源無法解析。" +
        "不完整的盤點會被誤讀成完整清單，因此這次不輸出結果。",
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  const resources = extractSubresources(res.body, res.url);
  const https = new URL(res.url).protocol === "https:";
  const summary = inventoryByHost(resources);

  facts.subresources = resources.length;
  facts.hosts = summary;
  facts.thirdPartyHosts = summary.filter((h) => h.thirdParty).map((h) => h.host);

  findings.push(...analyzeSubresources(resources, { surface: surface.id, where: res.url, https }));

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
