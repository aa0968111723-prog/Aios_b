/**
 * 登入速率限制檢測。
 *
 * 沒有速率限制的登入端點，等於把「試到對為止」這件事外包給攻擊者的頻寬。
 * 外洩密碼庫的撞庫攻擊完全不需要技巧，也不需要漏洞：攻擊者拿別站外洩的帳密清單逐筆重放，
 * 能不能進來只取決於他手上的字典有多大、以及對方有沒有設限。密碼強度政策擋不住這件事，
 * 因為被重放的本來就是使用者自己設的、在別處已經外洩的那組正確密碼。
 *
 * ── 這個偵測器預設不執行 ──────────────────────────────────────────────────
 * 它會對登入端點送出數次失敗嘗試，而失敗嘗試在真實系統上是有後果的：
 * 有帳號鎖定機制的系統可能因此把使用者鎖在門外；有告警的系統會收到一次假的攻擊事件，
 * 而值班的人得花時間確認那不是真的入侵。掃描器造成這兩種後果都是不可接受的。
 *
 * 所以它必須由使用者明確授權（`--probe-rate-limit`）才跑，預設回 `completed: false`
 * 加上清楚的 skippedReason——這正是本專案「沒測到 ≠ 沒問題」的一致做法：
 * 報告上會留下「這項沒跑、以及為什麼沒跑」，而不是一個看起來很安心的綠燈。
 *
 * ── 啟用後的自我約束 ──────────────────────────────────────────────────────
 * 1. 只用一定不存在的探測帳號（`sentinel-probe-…@invalid.test`）。絕不用 TEST_EMAIL
 *    或任何可能真的存在的帳號——那正是會鎖住真人（或真測試帳號）的那條路。
 * 2. 序列送出、每次之間留間隔，次數上限寫死。傷害隨次數線性上升，所以次數本身要克制。
 * 3. 觀測到 429 就立刻停止：目的已經達成，繼續送只是替對方製造負載與告警。
 * 4. 這是全專案唯一會送 POST 到真實端點的偵測器。它之所以被允許，是因為送的是
 *    「一定會失敗的登入」——不會建立、修改或刪除任何資料，而且要有人明確授權。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "../core/http.js";
import { looksLikeSpaFallback } from "./disclosure.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

/**
 * 預設嘗試次數。
 *
 * 6 次是刻意挑的：常見的限制器門檻落在 5 次（express-rate-limit 的範例、多數雲端 WAF 的預設），
 * 所以 6 次足以讓「有設限」的站台把 429 吐出來；同時 6 次失敗登入不足以觸發多數帳號鎖定政策
 * （通常 10 次以上），而且用的還是一個不存在的帳號，鎖也鎖不到任何人。
 * 再多送幾次能買到的資訊很有限，付出的卻是實實在在的負載與告警——克制本身就是設計的一部分。
 */
export const DEFAULT_ATTEMPTS = 6;

/** 次數上限。這個檢查的傷害隨次數線性上升，所以即使呼叫端要求更多也不照做。 */
export const MAX_ATTEMPTS = 10;

/** 預設登入端點。回 404 時代表這個位址上沒掛登入，那是「未判定」而不是「沒有速率限制」。 */
export const DEFAULT_LOGIN_PATH = "/api/auth/login";

/**
 * 探測用帳號。網域固定用保留字 `.invalid`（RFC 2606），保證不可能對應到任何真實信箱：
 * 這樣就算站台有「登入失敗通知信」也不會寄給任何人，更不會鎖到誰的帳號。
 * 值寫死不用亂數，是因為維運者要能拿這個字串直接去存取紀錄裡把掃描認出來。
 */
export const PROBE_EMAIL = "sentinel-probe-aios@invalid.test";
export const PROBE_PASSWORD = "sentinel-probe-invalid-password";

/**
 * 探針標記標頭。
 *
 * 這個檢查會在對方的日誌裡留下一串失敗登入，看起來就像一次撞庫。帶上固定標記，
 * 值班的人才能在三分鐘內確認「這是排程掃描，不是攻擊」，而不是被迫走一次事件應變流程。
 */
export const PROBE_HEADER = "x-sentinel-probe";
export const PROBE_TOKEN = "aios-sentinel-rate-limit";

/** 每次嘗試之間的間隔。不是為了規避限制，而是不要對小型部署造成突發負載。 */
const ATTEMPT_INTERVAL_MS = 400;

/**
 * 登入失敗時「正常且正確」的狀態碼。只有落在這個集合裡的回應能拿來判定速率限制——
 * 其餘狀態（404／5xx／200）代表我們根本沒問到認證邏輯，那是未判定，不是沒問題。
 */
const FAILURE_STATUSES = new Set([400, 401, 403, 422]);

/**
 * 這幾個狀態一定是**應用自己**回的：沒有中介層會拿 400／401／422 來擋人
 * （代理、WAF、平台閘道用的是 403、502、503）。
 *
 * 分出這個集合是為了 `looksLikeLoginEndpoint`：那裡不能對這些狀態動用攔截啟發式。
 * `looksLikeGatewayInterception` 找的是 SPA 外殼或 `error`／`ok`／`code` 欄位，
 * 而一個再正常不過的登入端點，對錯誤憑證常常只回一個空 body 的 401，
 * 或 `{"message":"帳號或密碼錯誤"}`——兩者都不含那些特徵，於是會被判成「被攔截」。
 * 後果是整項檢查在最標準的登入端點上直接跳過，而且沒有人會發現：跳過看起來永遠無害。
 */
const APP_ONLY_FAILURE_STATUSES = new Set([400, 401, 422]);

/**
 * 要下「沒有速率限制」這個結論，至少需要幾筆樣本。
 *
 * 一兩次失敗就說對方沒設限是不誠實的：現實中不存在第 2 次就啟動的限制器，
 * 所以樣本不足時只能說未判定。這個方向的保守是必要的——`absent` 是 high，
 * 而一筆站不住腳的 high 會讓整份報告的可信度一起陪葬。
 */
const MIN_CONCLUSIVE_ATTEMPTS = 3;

/** 退避判定的參數。理由見 `looksLikeBackoff`。 */
const BACKOFF_MIN_SAMPLES = 3;
const BACKOFF_TOTAL_RATIO = 2;
const BACKOFF_MIN_DELTA_MS = 250;
const BACKOFF_STEP_RATIO = 1.2;

/**
 * 這一次探測用的是哪一種帳號。
 *
 * `nonexistent`＝一定不存在的探測帳號；`possible`＝呼叫端指定、可能真的存在的帳號。
 * 兩者都送過才有辦法判定使用者列舉（同樣是錯密碼，狀態碼會不會因帳號存在與否而不同）。
 *
 * `checkRateLimit` 只會產生 `nonexistent` 的樣本——拿可能存在的帳號去試錯密碼，
 * 正是會鎖住真人帳號的那條路，這個偵測器不走。所以使用者列舉這一條在自動流程裡
 * 永遠不會有結論，這是刻意的：沒有資料就不報，不猜。
 */
export type ProbeAccountKind = "nonexistent" | "possible";

/** 標頭值是否真的有內容。空字串等同沒有——把 `Retry-After: ` 當成證據會憑空生出一筆正面觀測。 */
function present(value: string | null): boolean {
  return (value ?? "").trim() !== "";
}

export interface RateLimitSample {
  /** 第幾次嘗試（從 1 起算）。報告要能說出「第幾次才被擋下來」。 */
  attempt: number;
  status: number;
  /** `Retry-After` 原始值；null＝沒有這個標頭。 */
  retryAfter: string | null;
  /** `RateLimit-Remaining`／`X-RateLimit-Remaining` 原始值；null＝沒有這個標頭。 */
  rateLimitRemaining: string | null;
  durationMs: number;
  /** 這次用的帳號種類。省略＝呼叫端沒有分辨，使用者列舉就無從判定（也就不報）。 */
  accountKind?: ProbeAccountKind;
}

export interface RateLimitOptions {
  /** 是否已獲得明確授權。預設 false——這個檢查會在對方系統上留下失敗登入紀錄。 */
  enabled: boolean;
  attempts?: number;
  loginPath?: string;
}

/**
 * 這個回應到底是不是登入端點回的。
 *
 * 拉成純函式，是因為它是本檢查最關鍵、也最容易兩邊都判錯的一個決定：
 * 判成「不是」會讓整項靜靜跳過（一份看起來無害的報告，其實什麼都沒測）；
 * 判成「是」則會把中介層的封鎖頁當成登入失敗，最後報出一筆不存在的 high。
 *
 * 判準，依序：
 * - 404／405／501：這個位址上沒掛登入，或它不收 POST。
 * - 400／401／422：一定是應用回的，直接採信（理由見 `APP_ONLY_FAILURE_STATUSES`）。
 * - SPA 兜底頁：Vite 對未知路徑一律回 index.html，那正是「這裡什麼都沒有」的長相。
 * - 其餘狀態（含 403）才交給攔截啟發式。403 特別曖昧：它既是某些站台的「憑證不對」，
 *   也是防火牆最愛用的封鎖碼，所以要求回應內容看起來確實出自應用才採信——
 *   把 WAF 的封鎖頁收進樣本，會讓連續 6 次封鎖被報成「連續 6 次失敗都沒有被限制」。
 */
export function looksLikeLoginEndpoint(res: { status: number; body: string; contentType: string }): boolean {
  if (res.status === 404 || res.status === 405 || res.status === 501) return false;
  if (APP_ONLY_FAILURE_STATUSES.has(res.status)) return true;
  if (looksLikeSpaFallback(res.body, res.contentType)) return false;
  return !looksLikeGatewayInterception(res);
}

/**
 * 從回應標頭取出「剩餘可用次數」。
 *
 * 三種寫法都要認：`RateLimit-Remaining`（IETF draft-6，express-rate-limit 的預設）、
 * `X-RateLimit-Remaining`（舊慣例），以及 draft-7／8 把三個值併成一行的
 * `RateLimit: limit=5, remaining=3, reset=60`。少認最後那種的代價很具體：
 * 一個用新版標頭、門檻又設得比本輪次數高的站台，會完全看不到限制器的痕跡，
 * 於是一份有防護的部署被報成 `absent`（high）。
 */
export function readRateLimitRemaining(get: (name: string) => string | null): string | null {
  const direct = get("ratelimit-remaining") ?? get("x-ratelimit-remaining");
  if (present(direct)) return direct;
  // 只取 remaining 這一項；正則沒有巢狀量詞，畸形輸入不會造成災難性回溯。
  const combined = get("ratelimit") ?? "";
  return /(?:^|[,;\s])remaining\s*=\s*(\d+)/i.exec(combined)?.[1] ?? null;
}

/**
 * 回應時間是不是隨著失敗次數拉長（指數退避）。
 *
 * 為什麼要判這個：不是每個限制器都回 429，有一類實作選擇「每次失敗就多等一會兒」，
 * 對攻擊者的效果一樣好，卻不會在狀態碼上留下痕跡。漏掉它會讓一個防護得宜的站台
 * 被報成「完全沒有速率限制」——這種假警報比漏報更傷，因為修的人會發現無事可修。
 *
 * 判準刻意用「倍率 ＋ 絕對差 ＋ 趨勢」三個條件同時成立：
 * - 倍率：基準延遲因網路而異，只有相對變化才有意義。
 * - 絕對差：20 ms → 45 ms 這種抖動在網路上太常見，不能算退避。
 * - 趨勢：只有最後一次特別慢，多半是一次連線抖動而不是退避；退避會一路變慢。
 *   這一條特別重要，因為判成「有退避」會輸出一筆正面觀測，而錯誤的正面觀測
 *   會給人不該有的安心感。
 */
export function looksLikeBackoff(durations: number[]): boolean {
  if (durations.length < BACKOFF_MIN_SAMPLES) return false;
  const first = durations[0];
  const last = durations[durations.length - 1];
  if (first === undefined || last === undefined) return false;
  if (last < first * BACKOFF_TOTAL_RATIO) return false;
  if (last - first < BACKOFF_MIN_DELTA_MS) return false;

  let rising = 0;
  for (let i = 1; i < durations.length; i += 1) {
    const prev = durations[i - 1];
    const current = durations[i];
    if (prev === undefined || current === undefined) continue;
    if (current >= prev * BACKOFF_STEP_RATIO) rising += 1;
  }
  return rising >= Math.ceil((durations.length - 1) / 2);
}

type ThrottleSignal =
  | { kind: "status-429"; sample: RateLimitSample }
  | { kind: "retry-after"; sample: RateLimitSample }
  | { kind: "ratelimit-header"; sample: RateLimitSample };

/**
 * 找出「限制器確實存在」的直接證據。
 *
 * 順序即強度：429 是被實際擋下（最強），Retry-After 次之，
 * RateLimit 標頭只代表端點宣告了限制器、本輪並未觸發（最弱，但仍然是證據）。
 */
function findThrottleSignal(samples: RateLimitSample[]): ThrottleSignal | null {
  const blocked = samples.find((s) => s.status === 429);
  if (blocked) return { kind: "status-429", sample: blocked };
  const retry = samples.find((s) => present(s.retryAfter));
  if (retry) return { kind: "retry-after", sample: retry };
  const announced = samples.find((s) => present(s.rateLimitRemaining));
  if (announced) return { kind: "ratelimit-header", sample: announced };
  return null;
}

/** 把每次嘗試攤成可貼回報告的一行行證據；重現與人工複驗都靠它。 */
function formatSamples(samples: RateLimitSample[]): string {
  return samples
    .map((s) => {
      const extra = [
        present(s.retryAfter) ? `Retry-After: ${s.retryAfter}` : null,
        present(s.rateLimitRemaining) ? `RateLimit-Remaining: ${s.rateLimitRemaining}` : null,
      ].filter(Boolean);
      return `#${s.attempt} HTTP ${s.status}（${s.durationMs} ms）${extra.length > 0 ? ` ${extra.join(" ")}` : ""}`;
    })
    .join("\n");
}

/**
 * 使用者列舉：同樣是錯的密碼，回應會不會因為帳號存不存在而不同。
 *
 * 只有呼叫端真的送過兩種帳號才有素材，否則一律不報——把「沒送過」講成「沒問題」，
 * 跟把「沒測到」講成「沒問題」是同一個錯誤。
 */
function analyzeEnumeration(
  samples: RateLimitSample[],
  base: { check: string; category: "security"; surface: SurfaceId; where: string },
): Finding[] {
  const byKind = new Map<ProbeAccountKind, Set<number>>();
  for (const sample of samples) {
    const kind = sample.accountKind;
    if (!kind) continue;
    // 這裡收的範圍比 FAILURE_STATUSES 寬，因為同一個狀態碼在兩個問題上的意義不同：
    // 對速率限制而言 404 代表「沒問到認證邏輯」（不可判定），但對使用者列舉而言，
    //「不存在的帳號回 404、存在的帳號回 401」正是最經典的洩漏樣態，那筆 404 就是證據本身。
    // 排除 429（那時擋人的是限制器，與帳號無關）與 5xx／2xx（伺服器出錯或根本沒走到認證判斷）。
    if (sample.status < 400 || sample.status >= 500 || sample.status === 429) continue;
    const bucket = byKind.get(kind) ?? new Set<number>();
    bucket.add(sample.status);
    byKind.set(kind, bucket);
  }

  const nonexistent = byKind.get("nonexistent");
  const possible = byKind.get("possible");
  if (!nonexistent || !possible || nonexistent.size === 0 || possible.size === 0) return [];

  const left = [...nonexistent].sort((a, b) => a - b);
  const right = [...possible].sort((a, b) => a - b);
  if (left.join(",") === right.join(",")) return [];

  return [
    finding({
      ...base,
      id: "rate-limit.login.error-leak",
      severity: "medium",
      title: "登入失敗的狀態碼會因帳號是否存在而不同（使用者列舉）",
      detail:
        `不存在的帳號拿到 HTTP ${left.join("／")}，可能存在的帳號拿到 HTTP ${right.join("／")}——` +
        "兩次送的都是錯的密碼，差別只在帳號。攻擊者因此不必猜任何密碼，就能把「哪些信箱在這個系統有註冊」" +
        "一批批問出來：那份名單直接餵給精準釣魚，也讓後續撞庫只打在真的存在的帳號上，成本大幅下降。" +
        "對使用者而言，這還額外洩漏了「這個人有用這個服務」這件事本身。",
      remediation:
        "帳號不存在與密碼錯誤一律回同一個狀態碼與同一段訊息（例如統一回 401「帳號或密碼錯誤」）；" +
        "同時留意回應時間——只有存在的帳號才走雜湊比對的話，時間差一樣會洩漏答案，" +
        "必要時對不存在的帳號也跑一次假的雜湊運算。",
      evidence: `不存在帳號：HTTP ${left.join("、")}\n可能存在帳號：HTTP ${right.join("、")}`,
    }),
  ];
}

/**
 * 判定登入端點有沒有速率限制。純函式：不碰網路、不碰檔案系統，規則因此能離線測。
 *
 * 主判定只會有一筆，三種結論互斥：有直接證據＝`present`、樣本問不到認證邏輯＝`inconclusive`、
 * 全部都是同一種失敗又毫無退避＝`absent`。使用者列舉（`error-leak`）是另一件獨立的事，
 * 可以和其中任何一種並存。
 */
export function analyzeRateLimit(
  samples: RateLimitSample[],
  ctx: { surface: SurfaceId; where: string; attempts: number },
): Finding[] {
  const base = { check: "rate-limit", category: "security" as const, surface: ctx.surface, where: ctx.where };
  // 主判定排在前面：讀者先要知道「有沒有速率限制」，使用者列舉是另一件獨立的事。
  return [...judgeRateLimit(samples, ctx, base), ...analyzeEnumeration(samples, base)];
}

function judgeRateLimit(
  samples: RateLimitSample[],
  ctx: { surface: SurfaceId; where: string; attempts: number },
  base: { check: string; category: "security"; surface: SurfaceId; where: string },
): Finding[] {
  const inconclusive = (reason: string, remediation: string): Finding =>
    finding({
      ...base,
      id: "rate-limit.login.inconclusive",
      severity: "info",
      title: "登入速率限制未判定",
      detail:
        `${reason}本輪沒有拿到可用來判定的樣本，所以這裡記成「未判定」而不是通過——` +
        "找不到登入端點、或端點回了我們讀不懂的東西，都不等於「這個站沒有速率限制」，" +
        "更不等於「這個站有速率限制」。寫成任何一邊都是在報告上編造一個沒有觀測支撐的結論。",
      remediation,
      evidence: samples.length > 0 ? formatSamples(samples) : undefined,
    });

  if (samples.length === 0) {
    return [
      inconclusive(
        "這一輪完全沒有取得任何回應（連線失敗，或檢查在送出前就停手）。",
        "確認目標可連線後重跑；或人工用一個不存在的帳號連續輸入錯誤密碼數次，看是否會出現 429 或明顯變慢。",
      ),
    ];
  }

  const signal = findThrottleSignal(samples);
  if (signal) {
    const positive = {
      "status-429": {
        title: `登入端點有速率限制（第 ${signal.sample.attempt} 次嘗試被擋下，HTTP 429）`,
        detail:
          `連續失敗到第 ${signal.sample.attempt} 次時，端點回了 HTTP 429 把後續請求擋下來。` +
          "這代表撞庫沒有辦法用頻寬硬推——攻擊者每分鐘能試的次數被限制器決定，而不是被他自己的機器決定。",
      },
      "retry-after": {
        title: `登入端點有速率限制（第 ${signal.sample.attempt} 次嘗試回了 Retry-After）`,
        detail:
          `第 ${signal.sample.attempt} 次嘗試的回應帶了 Retry-After，代表端點在要求呼叫端等待後再試。` +
          "狀態碼雖然不是 429，但限制機制確實在運作，而且還明確告訴了客戶端要等多久。",
      },
      "ratelimit-header": {
        title: "登入端點宣告了速率限制（RateLimit 標頭），本輪未觸發",
        detail:
          `回應帶有 RateLimit-Remaining 標頭，代表端點前面掛著限制器；只是在授權的 ${ctx.attempts} 次之內沒有把它觸發。` +
          "這是「有防護」的證據，但沒有驗到它的門檻——門檻若設得比撞庫實際會用的速率還寬鬆，防護的意義會打折。",
      },
    }[signal.kind];

    return [
      finding({
        ...base,
        id: "rate-limit.login.present",
        severity: "info",
        title: positive.title,
        detail:
          `${positive.detail}這一筆是正面觀測，刻意寫進報告：一份只有壞消息的報告，` +
          "會讓維運者無從知道哪些防護真的在線上運作，也就沒辦法在某次改版把它弄掉時發現它不見了。" +
          "有觀測紀錄，才有辦法比對出「上次有、這次沒有」。",
        remediation:
          "維持現狀，並把這個行為納入迴歸測試（連續 N 次失敗登入應得到 429）。" +
          "另外確認兩件事：限制是否同時綁「來源 IP」與「帳號」兩把鍵——只綁 IP 擋不住分散來源的撞庫，" +
          "只綁帳號則會讓攻擊者用同一個 IP 掃過所有帳號；以及 429 的門檻不會把打錯密碼的正常使用者擋在門外。",
        evidence: formatSamples(samples),
      }),
    ];
  }

  const unusable = samples.filter((s) => !FAILURE_STATUSES.has(s.status));
  if (unusable.length > 0) {
    const statuses = [...new Set(unusable.map((s) => s.status))].sort((a, b) => a - b);
    return [
      inconclusive(
        `有 ${unusable.length} 次嘗試回的是 HTTP ${statuses.join("／")}，不是登入失敗該有的狀態` +
          "（可能是這個位址上沒有登入端點、端點自己出錯、或請求被中介層攔下）。",
        `確認登入端點的實際路徑與請求格式後，用 --probe-rate-limit 重跑（可用 loginPath 指到正確位址）；` +
          "若目標本來就沒有自建登入（例如改用第三方身分提供者），請改為確認該提供者的登入限制設定。",
      ),
    ];
  }

  const distinct = [...new Set(samples.map((s) => s.status))].sort((a, b) => a - b);
  if (distinct.length > 1) {
    return [
      inconclusive(
        `同樣的失敗輸入拿到不一致的狀態碼（HTTP ${distinct.join("／")}），無法判斷那是限制器介入、` +
          "還是端點對相同請求本來就回不同結果。",
        "先確認端點對同一種失敗輸入的回應是否穩定，再重跑本檢查；不一致本身也值得追查，" +
          "它常常是前面多了一層我們不知道的中介層。",
      ),
    ];
  }

  if (samples.length < MIN_CONCLUSIVE_ATTEMPTS) {
    return [
      inconclusive(
        `只送出 ${samples.length} 次就結束（授權 ${ctx.attempts} 次），樣本不足以支撐「沒有速率限制」這個結論——` +
          "現實中不存在第二次就啟動的限制器。",
        "確認檢查為什麼提早停止（見本檢查的 facts），排除後重跑。",
      ),
    ];
  }

  if (looksLikeBackoff(samples.map((s) => s.durationMs))) {
    const firstMs = samples[0]?.durationMs ?? 0;
    const lastMs = samples[samples.length - 1]?.durationMs ?? 0;
    return [
      finding({
        ...base,
        id: "rate-limit.login.present",
        severity: "info",
        title: "登入端點疑似有失敗退避（回應時間隨嘗試次數拉長）",
        detail:
          `回應時間從第 1 次的 ${firstMs} ms 一路拉長到第 ${samples.length} 次的 ${lastMs} ms，` +
          "這是「每次失敗就多等一會兒」這類退避機制的典型痕跡：狀態碼沒有變，但攻擊者的實際嘗試速率被壓下去了。" +
          "要說清楚的是，這筆的證據是時間而不是明確的 429，強度比較弱——" +
          "伺服器單純變慢（負載、冷啟動）也會長這樣，所以這裡寫「疑似」，" +
          "並且刻意不把它報成「沒有速率限制」：在證據不足時往嚴重的一邊猜，就是製造假警報。",
        remediation:
          "人工確認這個變慢是不是刻意的退避（看登入端點是否掛了失敗計數／延遲中介層）。" +
          "若是，建議同時回 429 與 Retry-After——明確的狀態碼才擋得住不看回應時間的自動化工具，" +
          "也才有辦法被監控與迴歸測試驗證。若不是，那就是登入端點在連續請求下會變慢，本身值得追查。",
        evidence: formatSamples(samples),
      }),
    ];
  }

  const status = distinct[0] ?? 0;
  return [
    finding({
      ...base,
      id: "rate-limit.login.absent",
      severity: "high",
      title: `登入端點連續 ${samples.length} 次失敗都沒有被限制`,
      detail:
        `連續 ${samples.length} 次錯誤登入全部拿到 HTTP ${status}：沒有出現 429、沒有 Retry-After、` +
        "沒有任何 RateLimit 標頭，回應時間也沒有隨次數拉長。這代表登入端點對「同一個來源在幾秒內連續試」" +
        "沒有任何反制，撞庫能跑多快只取決於攻擊者的頻寬。外洩密碼庫的重放不需要技巧也不需要漏洞，" +
        "唯一的門檻就是對方有沒有設限——這裡沒有。" +
        `另外要誠實說明觀測範圍：本輪只送了 ${samples.length} 次，看不到門檻更高（例如 20 次才啟動）的限制器；` +
        "但那種門檻對撞庫的幫助本來就很有限，因為攻擊者每個帳號只會試少數幾組最常見的密碼。",
      remediation:
        "在登入端點前加上失敗計數限制，並且同時綁「來源 IP」與「目標帳號」兩把鍵" +
        "（例如同一 IP 每分鐘 5 次、同一帳號連續失敗 5 次後逐次拉長等待），超限回 429 並附 Retry-After。" +
        "只綁 IP 擋不住來源分散在大量住宅 IP 的撞庫；只綁帳號則擋不住同一台機器掃過整份名單。" +
        "另外建議對「短時間內大量失敗登入」發出告警，並對高風險登入要求第二因素——" +
        "限制的目的是把攻擊成本拉高到不划算，不是把它變成不可能。",
      evidence: formatSamples(samples),
    }),
  ];
}

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export async function checkRateLimit(
  surface: Surface,
  timeoutMs: number,
  options: RateLimitOptions,
): Promise<CheckResult> {
  const elapsed = stopwatch();
  const facts: Record<string, unknown> = {};
  const base = { check: "rate-limit", category: "security" as const, surface: surface.id };
  const attempts = Math.max(1, Math.min(MAX_ATTEMPTS, Math.trunc(options.attempts ?? DEFAULT_ATTEMPTS)));
  const loginPath = options.loginPath ?? DEFAULT_LOGIN_PATH;
  const url = join(surface.origin, loginPath);

  facts.loginPath = loginPath;
  facts.attemptsAuthorized = attempts;
  facts.probeAccount = PROBE_EMAIL;
  facts.probeMarker = `${PROBE_HEADER}: ${PROBE_TOKEN}`;

  // 預設不執行。這裡不是「懶得跑」，而是這個檢查本身有副作用，副作用要由人決定要不要承擔。
  if (!options.enabled) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `此檢查會對登入端點送出 ${attempts} 次失敗嘗試，可能觸發帳號鎖定或資安告警，需以 --probe-rate-limit 明確授權。` +
        "未授權時一律不送——也因此本輪完全沒有驗證登入端點的速率限制，這一項既不是通過也不是失敗。",
      durationMs: elapsed(),
      findings: [],
      facts,
    };
  }

  const samples: RateLimitSample[] = [];
  let stoppedEarly: string | null = null;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    // 序列送出，絕不並行：並行會讓「第幾次觸發」失去意義，也會在小型部署上造成突發負載，
    // 更會讓回應時間受排隊效應污染而看起來像退避。
    if (attempt > 1) await sleep(ATTEMPT_INTERVAL_MS);

    const res = await tryProbe(url, {
      surface,
      timeoutMs,
      method: "POST",
      headers: { "content-type": "application/json", [PROBE_HEADER]: PROBE_TOKEN },
      body: JSON.stringify({ email: PROBE_EMAIL, password: PROBE_PASSWORD }),
      followRedirects: 0,
      maxBodyBytes: 8 * 1024,
    });

    if (isProbeFailure(res)) {
      stoppedEarly = `第 ${attempt} 次連線失敗：${res.error}`;
      break;
    }

    const contentType = res.headers.get("content-type") ?? "";

    // 第一次嘗試同時擔任「這個位址上到底有沒有登入端點」的探測。
    //
    // 為什麼不先用 GET 探一次：POST-only 的登入路由對 GET 多半回 404，或直接落到 SPA 的
    // catch-all 回 index.html 200——這兩種回應與「這裡什麼都沒掛」長得一模一樣，
    // 用它來決定要不要繼續，會在真的有登入端點時整項跳過。所以寧可花掉一次真實嘗試：
    // 一次失敗登入鎖不到任何人（帳號本來就不存在），而端點不在時我們立刻停手，不硬把剩下的次數送完。
    if (attempt === 1) {
      const missing =
        res.status === 404 ||
        res.status === 405 ||
        res.status === 501 ||
        looksLikeSpaFallback(res.body, contentType) ||
        looksLikeGatewayInterception({ status: res.status, body: res.body, contentType });
      if (missing) {
        facts.firstResponse = `HTTP ${res.status}\n${res.body.slice(0, 200)}`;
        return {
          ...base,
          completed: false,
          skippedReason:
            `登入端點 ${loginPath} 的第一次探測回 HTTP ${res.status}，內容不像登入端點的回應` +
            "（可能是路徑不同、由第三方身分提供者接手、或請求被中介層攔下）。" +
            `已立刻停手，未送出其餘 ${attempts - 1} 次嘗試。本輪未判定速率限制——` +
            "找不到登入端點絕不等於沒有速率限制。",
          durationMs: elapsed(),
          findings: [],
          facts,
        };
      }
      facts.firstResponse = `HTTP ${res.status}\n${res.body.slice(0, 200)}`;
    }

    samples.push({
      attempt,
      status: res.status,
      retryAfter: res.headers.get("retry-after"),
      rateLimitRemaining: res.headers.get("ratelimit-remaining") ?? res.headers.get("x-ratelimit-remaining"),
      durationMs: res.durationMs,
      accountKind: "nonexistent",
    });

    // 觀測到 429 就立刻停止：要看的東西已經看到了，繼續送只是替對方製造負載與告警。
    if (res.status === 429) {
      stoppedEarly = `第 ${attempt} 次已觀測到 HTTP 429，停止後續嘗試`;
      break;
    }

    // 回應既不是登入失敗、也不是限制——再送下去也判不出東西，一樣停手。
    // 判定交給 analyzeRateLimit，它會據此回未判定而不是硬給結論。
    if (!FAILURE_STATUSES.has(res.status)) {
      stoppedEarly = `第 ${attempt} 次回 HTTP ${res.status}（非登入失敗狀態），停止後續嘗試`;
      break;
    }
  }

  facts.attemptsSent = samples.length;
  facts.samples = samples;
  facts.stoppedEarly = stoppedEarly;

  // 一次都沒送成＝這一輪什麼都沒測到。回 completed: true 加空 findings 會變成綠燈，
  // 而那個綠燈的意思其實是「我們沒測」。
  if (samples.length === 0) {
    return {
      ...base,
      completed: false,
      skippedReason: `${stoppedEarly ?? "沒有取得任何回應"}——本輪未實際驗到登入端點的速率限制。`,
      durationMs: elapsed(),
      findings: [],
      facts,
    };
  }

  return {
    ...base,
    completed: true,
    durationMs: elapsed(),
    findings: analyzeRateLimit(samples, { surface: surface.id, where: url, attempts }),
    facts,
  };
}
