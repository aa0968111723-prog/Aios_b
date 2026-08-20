/**
 * well-known 檔案檢測（robots.txt 與 /.well-known/security.txt）。
 *
 * 這兩份是站台對外的公告，方向卻相反。
 *
 * robots.txt 常年被當成「藏起來的路徑清單」——實際效果剛好相反。它是一份公開文件，
 * 任何人都能直接讀，把 `Disallow: /admin-panel` 寫進去等於幫攻擊者做完了目錄探勘：
 * 對方連猜都不用猜，第一件事就是抓這份檔案。
 *
 * security.txt（RFC 9116）決定的則是「有人發現漏洞時，能不能找到你」。沒有它，
 * 善意的通報者在找不到聯絡窗口之後通常就放棄了；而惡意的那位不會放棄，只是不會通知你。
 *
 * 這個偵測器的頭號陷阱是 SPA 兜底：aios 是 SPA，對 `/robots.txt` 這種不存在的路徑
 * 一樣會回 HTTP 200 加 index.html。若照「200＝檔案存在」判定，這裡會產生一整排
 * 「robots.txt 存在且內容異常」的假警報。所以每一次取檔都必須先過兜底與中介層攔截排除。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import { looksLikeSpaFallback } from "./disclosure.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

/**
 * SPA 兜底頁判定沿用 disclosure 的那一份，不在這裡重寫。
 *
 * 理由不是省事：兜底判準是「什麼樣的回應算不算真的有這個檔案」這件事的**唯一定義**，
 * 兩份實作只要有一天分岔，同一個站就會在 disclosure 說「沒有這個檔案」、在這裡說「有」，
 * 而報告的讀者無從得知哪一邊才對。重新匯出是為了讓本模組的使用者不必知道它原本住在哪裡。
 */
export { looksLikeSpaFallback };

/**
 * Disallow 路徑裡看到就該回頭確認授權的關鍵字。
 *
 * 這份清單刻意保守——寧可漏掉幾條，也不要對 `/search`、`/api` 這種正常的排除規則噴紅。
 * 這一項本來就只有 low，靠量取勝毫無意義，只會稀釋讀者對整份報告的信任。
 */
export const SENSITIVE_ROBOTS_KEYWORDS: readonly string[] = [
  "admin",
  "administrator",
  "phpmyadmin",
  "internal",
  "intranet",
  "backup",
  "config",
  "private",
  "secret",
  "credential",
  "debug",
  "staging",
  "api-key",
  "apikey",
  "dump",
  ".env",
  ".git",
];

/**
 * 關鍵字比對用的樣式。
 *
 * 前後都要求非字母邊界，是為了不讓 `dev` 咬到 `/devices`、`config` 咬到 `/configurator`；
 * 只額外放行一個結尾的 `s`，因為 `/api-keys`、`/backups` 這種複數寫法太常見，漏掉它們
 * 等於這條規則在真實站台上大半時間不會動。
 */
function keywordPattern(keyword: string): RegExp {
  const escaped = keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(?<![a-z0-9])${escaped}s?(?![a-z])`, "i");
}

/** 找出 Disallow 清單裡看起來敏感的路徑；一條路徑只回報第一個命中的關鍵字。 */
export function findSensitiveDisallows(paths: string[]): Array<{ path: string; keyword: string }> {
  const hits: Array<{ path: string; keyword: string }> = [];
  for (const path of paths) {
    for (const keyword of SENSITIVE_ROBOTS_KEYWORDS) {
      if (!keywordPattern(keyword).test(path)) continue;
      hits.push({ path, keyword });
      break;
    }
  }
  return hits;
}

export interface RobotsAnalysis {
  present: boolean;
  disallowed: string[];
  sitemaps: string[];
  allowsAll: boolean;
}

/** 去掉 `#` 之後的註解。robots.txt 的註解可以出現在行中任何位置，不是只有行首。 */
function stripRobotsComment(line: string): string {
  const hash = line.indexOf("#");
  return hash === -1 ? line : line.slice(0, hash);
}

/**
 * 解析 robots.txt。
 *
 * 容錯優先：真實站台的這份檔案是人手寫的，CRLF、大小寫混用、行內註解、多個
 * User-agent 區塊全都會出現。解析器嚴格一點的代價不是「報錯」，而是**靜靜地少讀幾行**，
 * 於是一條寫在第二個區塊裡的 `Disallow: /admin` 從來沒被看見。
 *
 * `present` 的定義是「有沒有任何一行是可辨識的指令」，而不是「HTTP 有沒有回 200」。
 * 這是對 SPA 兜底的第二層保險：index.html 裡沒有 `Disallow:` 這種行，於是就算兜底判定
 * 哪天失手，這裡仍然會判成「沒有 robots.txt」，而不是「有一份內容很奇怪的 robots.txt」。
 * 全空或只有註解的檔案同樣算沒有——它與不放這份檔案的實際效果完全相同（全站可爬）。
 */
export function parseRobots(body: string): RobotsAnalysis {
  const disallowed = new Set<string>();
  const sitemaps: string[] = [];
  let present = false;
  /** 目前這一組規則掛在哪些 User-agent 底下。 */
  let agents: string[] = [];
  /** 上一行是不是 User-agent——連續的 User-agent 行屬於同一組，中間插進規則就換組。 */
  let inAgentBlock = false;
  /** 對 `*`（也就是一般爬蟲）是否存在任何路徑限制。 */
  let wildcardRestricted = false;

  for (const rawLine of body.split(/\r?\n/)) {
    const line = stripRobotsComment(rawLine).trim();
    if (!line) continue;
    const colon = line.indexOf(":");
    // 用第一個冒號切：Sitemap 的值本身是網址，含有 `https:`，整行 split 會拆壞。
    if (colon <= 0) continue;
    const field = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();

    switch (field) {
      case "user-agent": {
        if (!inAgentBlock) agents = [];
        inAgentBlock = true;
        agents.push(value.toLowerCase());
        present = true;
        break;
      }
      case "disallow": {
        inAgentBlock = false;
        present = true;
        // `Disallow:` 空值在規格上代表「什麼都不擋」，不是一條限制，不能收進清單。
        if (!value) break;
        disallowed.add(value);
        // 沒出現過 User-agent 就直接寫規則是不合規的寫法，但現實中有；
        // 這種檔案對所有爬蟲都生效，所以當成 `*` 處理，而不是整組丟掉。
        if (agents.length === 0 || agents.includes("*")) wildcardRestricted = true;
        break;
      }
      case "sitemap": {
        // Sitemap 不屬於任何 User-agent 區塊，所以不影響目前的分組狀態。
        present = true;
        if (value) sitemaps.push(value);
        break;
      }
      case "allow":
      case "crawl-delay":
      case "host": {
        inAgentBlock = false;
        present = true;
        break;
      }
      default:
        break;
    }
  }

  return { present, disallowed: [...disallowed], sitemaps, allowsAll: !wildcardRestricted };
}

export function analyzeRobots(analysis: RobotsAnalysis, ctx: { surface: SurfaceId; where: string }): Finding[] {
  const base = { check: "wellknown", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  if (!analysis.present) {
    out.push(
      finding({
        ...base,
        id: "wellknown.robots.missing",
        severity: "info",
        title: "沒有 robots.txt",
        detail:
          "**缺少 robots.txt 不構成資安問題**。爬蟲在沒有這份檔案時的預設行為就是全站可爬，" +
          "而真正需要保護的路徑本來就該靠授權擋住，不是靠一份公開文件請對方不要看。" +
          "這一筆只是記錄站台目前的對外公告狀態，方便日後比對「是誰在什麼時候放上去的」。",
        remediation:
          "不需要為了資安而補。只有在確實有不想被搜尋引擎收錄的公開頁面（預備環境、列印版、分頁參數）時才放一份，" +
          "而且只列無害的路徑。",
        evidence: "GET /robots.txt 沒有取得可解析的內容",
      }),
    );
    return out;
  }

  const hits = findSensitiveDisallows(analysis.disallowed);
  if (hits.length > 0) {
    out.push(
      finding({
        ...base,
        id: "wellknown.robots.sensitive-paths",
        severity: "low",
        title: `robots.txt 列出 ${hits.length} 條看起來敏感的路徑`,
        detail:
          "robots.txt 是公開文件，任何人都讀得到，包括寫爬蟲的人與掃描器。把管理後台、內部工具、備份或組態路徑" +
          "寫進 Disallow，等於直接把目錄探勘的結果送給對方——那正是攻擊者拿到網域後的第一個動作。" +
          "**robots.txt 從來不是存取控制**，它只是對守規矩的爬蟲提出的請求；不守規矩的那些連讀都不會讀。" +
          "所以這裡真正要問的不是「該不該寫在這」，而是：這些路徑在未登入時擋得住嗎？",
        remediation:
          "先確認這些路徑在未登入狀態下真的會被擋（401/403，而不是靠沒人知道網址）；" +
          "接著把它們從 robots.txt 移掉，改用回應標頭 `X-Robots-Tag: noindex` 或頁面層的 meta robots 來阻擋收錄——" +
          "那不需要把路徑公告在一份人人可讀的檔案裡。",
        evidence: hits
          .slice(0, 10)
          .map((h) => `Disallow: ${h.path}（命中關鍵字：${h.keyword}）`)
          .join("\n"),
      }),
    );
  }

  return out;
}

export interface SecurityTxtAnalysis {
  present: boolean;
  /** 欄位名一律小寫；同名欄位依出現順序累積（RFC 9116 允許重複，例如多個 Contact）。 */
  fields: Record<string, string[]>;
  /** Expires 的原始字串值（未解析）；沒有這個欄位時為 null。 */
  expires: string | null;
}

/**
 * 解析 security.txt（RFC 9116 的 `Field: value` 格式）。
 *
 * 欄位名大小寫不敏感，同名欄位可重複——`Contact` 寫三行是規格鼓勵的做法（依偏好排序），
 * 只留最後一筆會讓報告漏掉其他窗口。
 *
 * 額外處理 PGP 簽章外殼：RFC 9116 鼓勵對這份檔案簽章，簽過的檔案外面會多一層
 * `-----BEGIN PGP SIGNED MESSAGE-----` 與 armor 標頭（`Hash: SHA256`）。不剝掉的話，
 * 那個 `Hash:` 會被當成一個正常欄位混進 fields，簽章區塊裡的 `Version:` 也一樣——
 * 判定不會出錯，但報告上會出現站台根本沒寫的欄位，讀者會開始懷疑其他數字。
 */
export function parseSecurityTxt(body: string): SecurityTxtAnalysis {
  let text = body;

  const signedAt = text.indexOf("-----BEGIN PGP SIGNED MESSAGE-----");
  if (signedAt !== -1) {
    // cleartext 簽章格式：armor 標頭與內文之間固定隔一個空行，內文從空行之後開始。
    const bodyStart = text.slice(signedAt).search(/\r?\n\r?\n/);
    if (bodyStart !== -1) text = text.slice(signedAt + bodyStart);
  }
  const signatureAt = text.indexOf("-----BEGIN PGP SIGNATURE-----");
  if (signatureAt !== -1) text = text.slice(0, signatureAt);

  const fields: Record<string, string[]> = {};
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    // 欄位名限定為字母開頭的 token，是為了不讓 HTML（`<title>Aios: 首頁</title>`）
    // 或簽章區塊的 base64 被誤讀成欄位——那會讓一個根本不是 security.txt 的回應「解析成功」。
    const match = /^([A-Za-z][A-Za-z0-9-]*)\s*:\s*(.*)$/.exec(line);
    const name = match?.[1]?.toLowerCase();
    const value = match?.[2]?.trim();
    if (!name || !value) continue;
    (fields[name] ??= []).push(value);
  }

  return { present: Object.keys(fields).length > 0, fields, expires: fields.expires?.[0] ?? null };
}

/** Expires 轉 Date；格式不合回 null——寧可說「判不出來」，也不要拿 NaN 去比大小。 */
function parseExpiresDate(value: string | null): Date | null {
  if (!value) return null;
  const date = new Date(value.trim());
  return Number.isNaN(date.getTime()) ? null : date;
}

export function analyzeSecurityTxt(
  analysis: SecurityTxtAnalysis,
  ctx: { surface: SurfaceId; where: string; now: Date },
): Finding[] {
  const base = { check: "wellknown", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  if (!analysis.present) {
    out.push(
      finding({
        ...base,
        id: "wellknown.security-txt.missing",
        severity: "low",
        title: "沒有 /.well-known/security.txt",
        detail:
          "security.txt（RFC 9116）決定的是「有人發現漏洞時，找不找得到你」。沒有它，善意的通報者" +
          "在翻完頁尾與 GitHub 之後通常就放棄了——而惡意的那位不會放棄，他只是不會通知你。" +
          "這不是一個可被直接利用的漏洞，但它讓「外部回報」這條最便宜的防線整條失效：" +
          "問題照樣存在，只是你要等到它被利用之後才知道。",
        remediation:
          "在 /.well-known/security.txt 放一份純文字檔，至少寫 `Contact:`（mailto: 或回報表單網址）與 " +
          "`Expires:`（RFC 3339 時間，建議一年內），並在到期前設一個會吵人的提醒。",
        evidence: "GET /.well-known/security.txt 沒有取得可解析的內容",
      }),
    );
    return out;
  }

  const fieldNames = Object.keys(analysis.fields).join(", ") || "（無）";

  if (!analysis.fields.contact?.length) {
    out.push(
      finding({
        ...base,
        id: "wellknown.security-txt.no-contact",
        severity: "low",
        title: "security.txt 缺少 Contact 欄位",
        detail:
          "Contact 是 RFC 9116 唯一的必填欄位，也是這份檔案存在的全部理由。少了它，這份檔案只證明" +
          "「有人放過一個檔案」，通報者仍然不知道該寄給誰——結果與沒有這份檔案相同，只是多花了對方一次點擊。",
        remediation:
          "加上 `Contact: mailto:security@你的網域` 或回報表單網址；可以寫多行，依你希望對方優先使用的順序排列。",
        evidence: `目前的欄位：${fieldNames}`,
      }),
    );
  }

  const expiresAt = parseExpiresDate(analysis.expires);
  if (expiresAt && expiresAt.getTime() <= ctx.now.getTime()) {
    out.push(
      finding({
        ...base,
        id: "wellknown.security-txt.expired",
        severity: "low",
        title: `security.txt 已於 ${analysis.expires} 過期`,
        detail:
          "RFC 9116 明定過期的 security.txt 不應被信任，通報方的工具會直接忽略它——等於沒有這份檔案。" +
          "而且它會過期，通常也代表裡面的信箱已經沒有人在維護：通報寄過去之後石沉大海，比找不到窗口更糟。",
        remediation:
          "更新 Expires（建議一年內），順手確認 Contact 的信箱真的還有人收信；把下次更新排進行事曆，別依賴下一次掃描才發現。",
        evidence: `Expires: ${analysis.expires}\n檢測時間：${ctx.now.toISOString()}`,
      }),
    );
  } else if (!expiresAt) {
    // 沒有 Expires 與 Expires 解析不出來，對讀到這份檔案的人來說是同一件事：
    // 都沒有可用的有效期。所以合在同一筆，但用 evidence 把實際觀測到的值講清楚。
    out.push(
      finding({
        ...base,
        id: "wellknown.security-txt.no-expires",
        severity: "info",
        title: "security.txt 缺少可用的 Expires 欄位",
        detail:
          "Expires 是 RFC 9116 的必填欄位，用途是讓讀到這份檔案的人知道裡面的資訊還算不算數。" +
          "缺少它（或值不是 RFC 3339 格式而解析不出來）時，通報者無從判斷這份聯絡資訊是上個月還是五年前留下的。" +
          "這本身不是資安缺陷，所以只記錄、不升級。",
        remediation: "加上 `Expires: 2027-01-01T00:00:00Z` 這類 RFC 3339 時間，並在到期前更新。",
        evidence: analysis.expires ? `Expires: ${analysis.expires}（無法解析為時間）` : `目前的欄位：${fieldNames}`,
      }),
    );
  }

  return out;
}

/**
 * 一次取檔的三種結局。
 *
 * `absent`（確定沒有）與 `unverified`（沒測到）必須分開：前者可以放心地記一筆 info，
 * 後者不能——把「沒測到」寫成「沒有這份檔案」，正是這類工具最常見的說謊方式。
 */
export type WellKnownFileState =
  | { state: "present"; body: string }
  | { state: "absent"; reason: string }
  | { state: "unverified"; reason: string };

/**
 * 判斷一次取檔的結果代表什麼。純函式，測試不需要網路。
 *
 * 順序是刻意的：404／410 要先於中介層判定。`looksLikeGatewayInterception` 是為首頁設計的——
 * 首頁回 4xx 幾乎一定是代理或 WAF 攔了下來，但對一支具體檔案而言，404 正是伺服器對
 * 「有沒有這份檔案」最明確的否定答覆。不先攔下來就套那條判準，每一個正常的 404 都會被
 * 講成「沒測到」，這一項於是永遠不會有結論。
 */
export function classifyWellKnownFile(input: { status: number; body: string; contentType: string }): WellKnownFileState {
  if (input.status === 404 || input.status === 410) return { state: "absent", reason: `HTTP ${input.status}` };
  if (looksLikeGatewayInterception(input)) {
    return {
      state: "unverified",
      reason: `HTTP ${input.status} 且內容不像應用回應，判定為中介層（代理／WAF／平台閘道）攔截`,
    };
  }
  if (input.status === 200) {
    // SPA 對未知路徑一律回 index.html 200。這不是「有這份檔案」，是「這個站沒有這份檔案」。
    if (looksLikeSpaFallback(input.body, input.contentType)) {
      return { state: "absent", reason: "HTTP 200 但回的是 SPA 兜底 index.html" };
    }
    return { state: "present", body: input.body };
  }
  return { state: "unverified", reason: `HTTP ${input.status}` };
}

export async function checkWellKnown(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "wellknown", category: "security" as const, surface: surface.id };
  const now = new Date();

  /**
   * 取一份 well-known 檔案。
   *
   * 跟隨少量重導向，是因為這兩個路徑常被靜態層以 301 正規化（apex→www、補尾斜線）；
   * 完全不跟隨會把「其實有」讀成「沒有」。上限壓在 2 跳，避免被導進登入流程繞圈。
   */
  const fetchFile = async (path: string): Promise<WellKnownFileState> => {
    const res = await tryProbe(join(surface.origin, path), {
      surface,
      timeoutMs,
      followRedirects: 2,
      maxBodyBytes: 64 * 1024,
    });
    if (isProbeFailure(res)) return { state: "unverified", reason: `無法連線：${res.error}` };
    return classifyWellKnownFile({
      status: res.status,
      body: res.body,
      contentType: res.headers.get("content-type") ?? "",
    });
  };

  // 序列送出，兩個請求。檢測系統不該讓自己成為目標站當下最吵的那個訪客。
  const robotsUrl = join(surface.origin, "/robots.txt");
  const robots = await fetchFile("/robots.txt");
  if (robots.state === "unverified") {
    // 沿用 cors 的寫法：facts 裡也要看得出「沒觀測到」與「觀測到沒有」的差別。
    facts.robots = { url: robotsUrl, state: `未觀測（${robots.reason}）` };
  } else {
    const analysis = robots.state === "present" ? parseRobots(robots.body) : parseRobots("");
    facts.robots = {
      url: robotsUrl,
      state: robots.state === "present" ? "已取得" : `不存在（${robots.reason}）`,
      present: analysis.present,
      disallowed: analysis.disallowed,
      sitemaps: analysis.sitemaps,
      allowsAll: analysis.allowsAll,
    };
    findings.push(...analyzeRobots(analysis, { surface: surface.id, where: robotsUrl }));
  }

  const securityUrl = join(surface.origin, "/.well-known/security.txt");
  const securityTxt = await fetchFile("/.well-known/security.txt");
  if (securityTxt.state === "unverified") {
    facts.securityTxt = { url: securityUrl, state: `未觀測（${securityTxt.reason}）` };
  } else {
    const analysis = securityTxt.state === "present" ? parseSecurityTxt(securityTxt.body) : parseSecurityTxt("");
    facts.securityTxt = {
      url: securityUrl,
      state: securityTxt.state === "present" ? "已取得" : `不存在（${securityTxt.reason}）`,
      present: analysis.present,
      fields: Object.keys(analysis.fields),
      expires: analysis.expires,
    };
    findings.push(...analyzeSecurityTxt(analysis, { surface: surface.id, where: securityUrl, now }));
  }

  // 兩份都沒測到＝這一項這輪什麼也沒驗證。回 completed: true 加零發現，
  // 讀者會理解成「兩份檔案都查過了」——那是這份報告能犯的最嚴重的錯。
  if (robots.state === "unverified" && securityTxt.state === "unverified") {
    return {
      ...base,
      completed: false,
      skippedReason: `robots.txt 與 security.txt 都無法確認（${robots.reason}；${securityTxt.reason}）。請從能直連目標的網路環境重跑。`,
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
