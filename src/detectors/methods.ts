/**
 * HTTP 方法稽核。
 *
 * 反向代理與框架常常留下沒有人在用的方法，兩個特別值得測：
 *
 * TRACE 會把收到的請求原樣回吐。只要頁面上有一個 XSS 或可控的第三方腳本，攻擊者就能發一個
 * TRACE 再從回應內文讀出瀏覽器自動夾帶的 Cookie（Cross-Site Tracing）——這正是 HttpOnly
 * 想擋卻擋不住的路徑，因為值從頭到尾沒有經過 document.cookie。
 *
 * OPTIONS 的 Allow 標頭則會主動告訴攻擊者「這個端點還收 PUT／DELETE」，
 * 省下他們逐一試探的工夫，也常常是「某條路由忘了關掉寫入方法」被看見的第一個徵兆。
 *
 * ── 這個偵測器的紅線 ────────────────────────────────────────────────────────
 * 只送 OPTIONS 與 TRACE，絕不實際送出 PUT／DELETE／PATCH／POST 到真實端點。
 * 那類請求可能真的改到正式資料——為了讓報告多一行結論而動到使用者的資料是本末倒置。
 * 所以危險方法一律改用 OPTIONS 回應的 Allow 標頭判定，而且報告裡必須講清楚那是
 * 「標頭的自述」而非「已證實可用」；判定不到就誠實標成未判定（`methods.trace.unknown`），
 * 不猜、也不試。檢測系統不該污染它要測量的東西。
 *
 * ── 降噪 ────────────────────────────────────────────────────────────────────
 * 1. 代理與 WAF 常常自己回 405／403 給 TRACE。那是中介層的行為不是站台的，
 *    用 `looksLikeGatewayInterception` 排掉，否則報告會把中介層的設定寫成站台的體質。
 * 2. SPA 的 catch-all 路由會對任何方法回 index.html 200，TRACE 也不例外。
 *    那不是站台支援 TRACE，只是兜底路由接走了；照 200 判定會產出整排假的 medium。
 *    這種回應一律歸到「未判定」——它既不是有問題，也不是沒問題。
 * 3. Node／undici 的 fetch 依 Fetch 規範把 TRACE 列為禁用方法，請求在送出前就被自己擋下。
 *    那是**我們這端的限制**，不是站台拒絕了 TRACE，兩者在報告裡必須看得出差別，
 *    否則讀者會以為這條路已經查過而且是安全的。
 *
 * 上面三種情況都會落到 `methods.trace.unknown`，但確切原因逐路徑寫進 `facts.observed`，
 * 而且 remediation 會給出可以直送 TRACE 的補驗指令——「沒測到」要留下能接續的線索。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import { looksLikeSpaFallback } from "./disclosure.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

/**
 * TRACE 探針標頭。回應內文出現這個值＝伺服器把請求原樣回吐了。
 *
 * 值刻意寫死不用亂數：id 與判定要能跨次執行重現，測試也才有辦法離線驗；
 * 而且維運者要能拿這個字串直接去存取紀錄裡撈出「這是掃描器發的，不是攻擊」。
 */
export const TRACE_PROBE_HEADER = "x-sentinel-probe";
export const TRACE_PROBE_TOKEN = "aios-sentinel-trace-echo";

/** 代表性路徑：站台根、健康檢查、以及資料主要出口。三條就夠看出方法設定的樣貌，不必掃全站。 */
const AUDIT_PATHS = ["/", "/api/health", "/api/v1/databases"];

/** 會改動資料的方法。這裡只從 Allow 標頭認人，永遠不會真的送出去。 */
const WRITE_METHODS = ["PUT", "DELETE", "PATCH"];

/** 超過這個數量就算「沒有人縮限過路由」。GET／HEAD／POST／OPTIONS 加上一兩個特例已經很寬了。 */
const VERBOSE_ALLOW_THRESHOLD = 6;

/** 附在報告上的回應片段長度。夠看出是不是回吐即可，不必把整份回應搬進報告。 */
const SNIPPET_CHARS = 200;

export interface MethodObservation {
  /** 觀測的路徑（不含站台位址）。 */
  path: string;
  /** OPTIONS 回應的 Allow 原始值；null＝沒有這個標頭，或這次沒問到站台本身。 */
  allow: string | null;
  /** TRACE 回應的狀態碼；null＝未判定（連不上、被中介層攔下、執行環境拒送、或落到 SPA 兜底頁）。 */
  traceStatus: number | null;
  /** TRACE 回應內文是否含我們送出的探針值——回吐成立才構成 Cross-Site Tracing。 */
  traceEchoesRequest: boolean;
  /** TRACE 回應內文片段，附在報告上供重現。 */
  traceBodySnippet: string | null;
}

/**
 * 一次 TRACE 探針到底測到了什麼。
 *
 * 三種狀態刻意分開，因為它們在報告上的意義完全不同：
 * `answered` 是站台自己的答覆（可以據以判定）；`shadowed` 是應用有回但被 catch-all 兜底頁
 * 蓋住（我們看不到站台怎麼處理 TRACE，但站台確實活著）；`unreachable` 是根本沒問到站台。
 * 混成一個布林值，就會出現「代理擋掉」被寫成「站台拒絕 TRACE」這種最糟的誤述。
 */
export type TraceProbeState =
  | { state: "answered"; status: number; echoed: boolean; snippet: string | null }
  | { state: "shadowed"; reason: string; snippet: string | null }
  | { state: "unreachable"; reason: string; snippet: string | null };

/** 一次 OPTIONS 探針的結果。`answered` 才有資格拿 Allow 去判定。 */
export type AllowProbeState =
  | { state: "answered"; allow: string | null; note: string }
  | { state: "unverified"; reason: string };

/** 探針的原始素材：不是失敗訊息，就是一份真的收到的回應。 */
type ProbeOutcome<T> = { error: string } | T;

/**
 * 正規化 Allow 標頭。
 *
 * 大小寫與空白都不是語意的一部分（RFC 9110 的 method 是大小寫敏感的 token，但實務上
 * 各家代理回的大小寫並不一致），統一成大寫再比對，否則 `put` 會漏掉。
 * 去重是因為經過多層代理時同一個方法被列兩次很常見，那不代表它比較危險。
 * 順序照伺服器寫的順序保留——證據要能跟原始標頭一眼對得起來。
 */
export function parseAllowHeader(value: string | null): string[] {
  if (!value) return [];
  const out: string[] = [];
  for (const part of value.split(",")) {
    const method = part.trim().toUpperCase();
    if (!method) continue;
    if (out.includes(method)) continue;
    out.push(method);
  }
  return out;
}

/** 回應內文是否含我們剛送出的探針值。固定字串＋大小寫不敏感，避免中介層改寫大小寫就漏掉。 */
function echoesProbeToken(body: string): boolean {
  return body.toLowerCase().includes(TRACE_PROBE_TOKEN.toLowerCase());
}

function snippetOf(body: string): string | null {
  return body.slice(0, SNIPPET_CHARS) || null;
}

/**
 * 判斷一次 TRACE 探針的結果代表什麼。純函式，測試不需要網路。
 *
 * 順序是刻意的，而且**回吐排在所有排除規則之前**：兜底的 index.html 是建置產物、
 * 代理的錯誤頁是罐頭字串，兩者都不可能含有我們幾毫秒前才送出去的探針值。
 * 反過來說，只要內文出現那個值，就代表請求被原樣寫了回來——這是已經測到的高嚴重度事實，
 * 先套排除規則會把它降級成「未判定」，等於把測到的問題講成沒測到。
 */
export function classifyTraceProbe(
  input: ProbeOutcome<{ status: number; body: string; contentType: string }>,
): TraceProbeState {
  if ("error" in input) {
    // 送不出去有兩種：站台連不上，或執行環境自己拒絕送（Node 的 fetch 禁用 TRACE）。
    // 兩種都不是站台的答覆，原文照抄讓讀者自己分辨，不要替它下結論。
    return { state: "unreachable", reason: `TRACE 送不出或連不上：${input.error}`, snippet: null };
  }

  const snippet = snippetOf(input.body);
  if (echoesProbeToken(input.body)) {
    return { state: "answered", status: input.status, echoed: true, snippet };
  }
  if (looksLikeGatewayInterception(input)) {
    return {
      state: "unreachable",
      reason: `HTTP ${input.status} 且內容不像應用回應，研判為中介層（代理／WAF／平台閘道）攔截`,
      snippet,
    };
  }
  if (looksLikeSpaFallback(input.body, input.contentType)) {
    return {
      state: "shadowed",
      reason: `HTTP ${input.status} 回的是 SPA 兜底頁（catch-all 接走，不代表站台處理了 TRACE）`,
      snippet,
    };
  }
  return { state: "answered", status: input.status, echoed: false, snippet };
}

/**
 * 判斷一次 OPTIONS 探針的結果代表什麼。純函式，測試不需要網路。
 *
 * 帶了 Allow 就一律採信，即使狀態碼是 4xx：RFC 9110 規定回 405 時必須附上 Allow，
 * 而中介層的罐頭錯誤頁並不知道這條路由收哪些方法，也就寫不出這個標頭。
 * 先套中介層排除規則會把整份檢查最可靠的一次自述直接丟掉——那是白白製造漏報。
 */
export function classifyAllowProbe(
  input: ProbeOutcome<{ status: number; body: string; contentType: string; allow: string | null }>,
): AllowProbeState {
  if ("error" in input) return { state: "unverified", reason: `OPTIONS 送不出或連不上：${input.error}` };

  if (parseAllowHeader(input.allow).length > 0) {
    return { state: "answered", allow: input.allow, note: `HTTP ${input.status}，Allow: ${input.allow}` };
  }
  if (looksLikeGatewayInterception(input)) {
    return {
      state: "unverified",
      reason: `HTTP ${input.status} 且內容不像應用回應，研判為中介層（代理／WAF／平台閘道）攔截`,
    };
  }
  // 「觀測到沒有 Allow」與「根本沒觀測到」在報告上是兩件事，facts 也必須分得開，
  // 否則讀者會把一次失敗的探針讀成「站台沒有宣告任何方法」。
  return { state: "answered", allow: null, note: `HTTP ${input.status}，回應沒有可解析的 Allow 標頭` };
}

/** 回應片段優先，沒有內文就退回狀態碼；兩者都沒有時寧可不附證據，也不要印出「HTTP null」。 */
function traceEvidence(obs: MethodObservation): string | undefined {
  if (obs.traceBodySnippet) return obs.traceBodySnippet;
  if (obs.traceStatus !== null) return `HTTP ${obs.traceStatus}`;
  return undefined;
}

export function analyzeMethods(
  obs: MethodObservation,
  ctx: { surface: SurfaceId; where: string; isApi: boolean },
): Finding[] {
  const base = { check: "methods", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  // ── TRACE ───────────────────────────────────────────────────────────────
  // 三條判定互斥：回吐 > 未判定 > 單純可用。
  //
  // 回吐排最前面是因為它是**唯一一條靠內文成立的判定**：看得到探針值就代表請求真的被寫了回來，
  // 那不可能是「沒測到」。同一件事也不重複報——有回吐就不再補一筆 enabled，
  // 否則讀者會以為是兩個問題，較輕的那筆還會稀釋掉真正要修的那筆。
  if (obs.traceEchoesRequest) {
    out.push(
      finding({
        ...base,
        id: "methods.trace.echo",
        severity: "high",
        title: "TRACE 會把請求原樣回吐（Cross-Site Tracing）",
        detail:
          "伺服器把收到的請求標頭完整寫回回應內文。頁面上只要有一個 XSS 或可控的第三方腳本，攻擊者就能發一個 TRACE，" +
          "再從回應裡讀出瀏覽器自動夾帶的 Cookie 與 Authorization——這些值從來沒有經過 document.cookie，" +
          "所以 HttpOnly 完全擋不住這條路。這比「TRACE 開著」嚴重一階，因為竊取管道已經成立，不需要再等別的條件。",
        remediation:
          "在反向代理與應用層都明確拒絕 TRACE（回 405），兩層都要關——只擋一層的話，日後流量繞過那一層就整個失效。",
        evidence: traceEvidence(obs),
      }),
    );
  } else if (obs.traceStatus === null) {
    out.push(
      finding({
        ...base,
        id: "methods.trace.unknown",
        severity: "info",
        title: "TRACE 方法未判定",
        detail:
          "這一次沒有拿到站台自己對 TRACE 的回應：可能被中介層（代理／WAF）擋掉、落到 SPA 的 catch-all 路由，" +
          "或是執行環境本身依 Fetch 規範拒絕送出 TRACE（Node 的 fetch 就是如此）。每個路徑的確切原因記在本檢查的 " +
          "facts.observed。這裡刻意記成「未判定」而不是通過——沒測到永遠不等於沒問題，寫成綠燈會讓人以為這條路已經查過了。",
        remediation:
          `想補驗就用能直送這個方法的工具跑一次（curl -X TRACE <url> -H "${TRACE_PROBE_HEADER}: ${TRACE_PROBE_TOKEN}"），` +
          "看回應內文有沒有把該標頭念回來。若 TRACE 目前是靠中介層擋掉的，仍應在來源站台上直接關閉：" +
          "中介層改設定或被繞過時，站台不該只剩那一層防護。",
        evidence: traceEvidence(obs),
      }),
    );
  } else if (obs.traceStatus >= 200 && obs.traceStatus < 300) {
    out.push(
      finding({
        ...base,
        id: "methods.trace.enabled",
        severity: "medium",
        title: `TRACE 方法可用（HTTP ${obs.traceStatus}）`,
        detail:
          "站台接受 TRACE 並回成功。這次的回應沒有把我們送出的探針標頭念回來，所以還沒構成 Cross-Site Tracing，" +
          "但一個正常功能完全用不到的方法留在線上，等於留著一條隨時可能因為框架或中介層改版就變成可回吐的路徑。",
        remediation: "在反向代理或應用層明確拒絕 TRACE（回 405），路由只保留實際會用到的方法。",
        evidence: traceEvidence(obs),
      }),
    );
  }

  // ── Allow ───────────────────────────────────────────────────────────────
  const allowed = parseAllowHeader(obs.allow);
  if (allowed.length === 0) return out; // 沒有 Allow 就沒有可判定的素材，不臆測

  const write = allowed.filter((method) => WRITE_METHODS.includes(method));
  if (write.length > 0) {
    out.push(
      finding({
        ...base,
        id: "methods.dangerous-allowed",
        severity: "medium",
        title: `Allow 標頭宣告接受寫入方法（${write.join("、")}）`,
        detail:
          `OPTIONS 回應自述這個端點接受 ${write.join("、")}。要講清楚的是：這是 Allow 標頭的自述，` +
          "不代表未授權的人真的能用。本檢查刻意不去實際送出這些請求驗證——PUT／DELETE／PATCH 打在正式端點上" +
          "可能真的改到使用者的資料，為了讓報告多一行結論而動到資料是本末倒置。" +
          (ctx.isApi
            ? "這條是 API 路徑，寫入方法若沒有認證與授權把關，等於把改資料的入口寫在門口的告示牌上。"
            : "這條不是 API 路徑，寫入方法多半來自框架或靜態伺服器的預設值，但仍要確認它不會意外接受覆寫或上傳。") +
          "請人工確認這些方法都在認證與授權保護之下。",
        remediation:
          "路由層只註冊實際會用到的方法，其餘一律回 405；並逐一確認 PUT／DELETE／PATCH 端點前面都掛了認證與授權中介層。",
        evidence: `Allow: ${obs.allow}`,
      }),
    );
  }

  if (allowed.length > VERBOSE_ALLOW_THRESHOLD) {
    out.push(
      finding({
        ...base,
        id: "methods.allow-verbose",
        severity: "low",
        title: `Allow 標頭一次列出 ${allowed.length} 個方法`,
        detail:
          "一次列出這麼多方法，通常代表沒有人縮限過這條路由，而是照著框架或靜態伺服器的預設全開。" +
          "它本身不是攻擊路徑，但把「用的是哪一套框架、預設長什麼樣」直接送給偵察方，" +
          "也代表這個端點的方法白名單從來沒有被檢視過——真正的問題往往就藏在那份沒人看過的清單裡。",
        remediation: "只註冊實際使用的方法（多數端點是 GET／HEAD／POST／OPTIONS），把沒用到的從路由表移除。",
        evidence: `Allow: ${obs.allow}`,
      }),
    );
  }

  return out;
}

export async function checkMethods(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "methods", category: "security" as const, surface: surface.id };
  const observed: Record<string, { allow: string | null; options: string; trace: string }> = {};
  const observations: MethodObservation[] = [];
  /** 至少有一次探針真的問到站台本身的路徑數。全 0＝這一輪什麼都沒驗到。 */
  let reachedApp = 0;

  // 逐條路徑、逐個請求地跑，不並行：這是要拿來當基準的量測，不該自己在目標上製造尖峰流量。
  for (const path of AUDIT_PATHS) {
    const url = join(surface.origin, path);

    // ── OPTIONS：只問「你收哪些方法」，本身不會改動任何東西 ──────────────
    const optionsProbe = await tryProbe(url, {
      surface,
      timeoutMs,
      method: "OPTIONS",
      followRedirects: 0,
      maxBodyBytes: 8 * 1024,
    });
    const allowState = classifyAllowProbe(
      isProbeFailure(optionsProbe)
        ? { error: optionsProbe.error }
        : {
            status: optionsProbe.status,
            body: optionsProbe.body,
            contentType: optionsProbe.headers.get("content-type") ?? "",
            allow: optionsProbe.headers.get("allow"),
          },
    );

    // ── TRACE：帶固定探針標頭，回應內文出現它就是原樣回吐 ────────────────
    const traceProbe = await tryProbe(url, {
      surface,
      timeoutMs,
      method: "TRACE",
      headers: { [TRACE_PROBE_HEADER]: TRACE_PROBE_TOKEN },
      followRedirects: 0,
      maxBodyBytes: 16 * 1024,
    });
    const traceState = classifyTraceProbe(
      isProbeFailure(traceProbe)
        ? { error: traceProbe.error }
        : {
            status: traceProbe.status,
            body: traceProbe.body,
            contentType: traceProbe.headers.get("content-type") ?? "",
          },
    );

    // 只要其中一個探針拿到了應用層的回應，這條路徑就算真的驗過了。
    // SPA 兜底頁雖然遮住了 TRACE 的處理方式，但它證明應用還活著，所以一樣算數。
    if (allowState.state === "answered" || traceState.state !== "unreachable") reachedApp += 1;

    observed[path] = {
      allow: allowState.state === "answered" ? allowState.allow : null,
      options: allowState.state === "answered" ? allowState.note : `未觀測：${allowState.reason}`,
      trace:
        traceState.state === "answered"
          ? `HTTP ${traceState.status}${traceState.echoed ? "（回吐請求標頭）" : ""}`
          : `未判定：${traceState.reason}`,
    };
    observations.push({
      path,
      allow: allowState.state === "answered" ? allowState.allow : null,
      traceStatus: traceState.state === "answered" ? traceState.status : null,
      traceEchoesRequest: traceState.state === "answered" && traceState.echoed,
      traceBodySnippet: traceState.snippet,
    });
  }

  facts.observed = observed;
  facts.traceProbe = `${TRACE_PROBE_HEADER}: ${TRACE_PROBE_TOKEN}`;
  facts.reachedApp = reachedApp;

  // 每一條路徑的兩個探針都沒問到站台本身＝這一輪沒有驗到任何方法設定。
  // 這種情況回 completed: true 加空 findings 會變成一個綠燈，而那個綠燈的意思其實是「我們沒測」。
  if (reachedApp === 0) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `${AUDIT_PATHS.length} 個路徑的 OPTIONS 與 TRACE 都沒有得到應用層回應（連線失敗，或被中介層／WAF 攔下）。` +
        "本輪未實際驗到任何方法設定——請從能直連目標的網路環境重跑。",
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  for (const obs of observations) {
    findings.push(
      ...analyzeMethods(obs, {
        surface: surface.id,
        where: join(surface.origin, obs.path),
        isApi: obs.path.startsWith("/api/"),
      }),
    );
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
