import { describe, expect, it } from "vitest";
import {
  analyzeRateLimit,
  DEFAULT_ATTEMPTS,
  looksLikeBackoff,
  looksLikeLoginEndpoint,
  readRateLimitRemaining,
  type RateLimitSample,
} from "../src/detectors/rateLimit.js";

const ctx = { surface: "web" as const, where: "https://example.test/api/auth/login", attempts: DEFAULT_ATTEMPTS };
const ids = (findings: ReturnType<typeof analyzeRateLimit>) => findings.map((f) => f.id);

/** 一次「登入失敗、沒有任何限制跡象」的樣本，各測試只覆寫自己關心的欄位。 */
function sample(attempt: number, patch: Partial<RateLimitSample> = {}): RateLimitSample {
  return { attempt, status: 401, retryAfter: null, rateLimitRemaining: null, durationMs: 120, ...patch };
}

/** 連續 n 次相同的失敗回應（回應時間平穩，模擬完全沒有反制的端點）。 */
function series(count: number, patch: Partial<RateLimitSample> = {}): RateLimitSample[] {
  return Array.from({ length: count }, (_, i) => sample(i + 1, patch));
}

describe("analyzeRateLimit：沒有速率限制", () => {
  it("連續 6 次 401、時間平穩＝absent（high）", () => {
    const findings = analyzeRateLimit(series(6), ctx);
    expect(findings.find((f) => f.id === "rate-limit.login.absent")?.severity).toBe("high");
  });

  // 有些端點把「帳號或密碼錯誤」寫成 400；那一樣是登入失敗，判定不該因此改變。
  it("連續 400 也算同一種失敗狀態，一樣報 absent", () => {
    expect(ids(analyzeRateLimit(series(5, { status: 400 }), ctx))).toContain("rate-limit.login.absent");
  });

  it("absent 的證據逐次列出狀態與耗時，讓人能照著重現", () => {
    const evidence = analyzeRateLimit(series(3), ctx).find((f) => f.id === "rate-limit.login.absent")?.evidence;
    expect(evidence).toContain("#1 HTTP 401");
    expect(evidence).toContain("#3 HTTP 401");
  });

  // 網路抖動讓最後一次特別慢是常態；把它當成退避會憑空生出一筆正面觀測，
  // 而錯誤的正面觀測會給人不該有的安心感。
  it("只有最後一次變慢（單一抖動）不算退避，仍報 absent", () => {
    const samples = [sample(1, { durationMs: 100 }), sample(2, { durationMs: 100 }), sample(3, { durationMs: 105 }), sample(4, { durationMs: 900 })];
    expect(ids(analyzeRateLimit(samples, ctx))).toContain("rate-limit.login.absent");
  });
});

describe("analyzeRateLimit：防護確實在運作（正面觀測）", () => {
  // 報告不能只有壞消息：維運者要知道哪些防護在線上，才有辦法在它某天消失時發現。
  it("出現 429 就報 present（info），並記下第幾次觸發", () => {
    const samples = [...series(3), sample(4, { status: 429 })];
    const hit = analyzeRateLimit(samples, ctx).find((f) => f.id === "rate-limit.login.present");
    expect(hit?.severity).toBe("info");
    expect(hit?.title).toContain("第 4 次");
    expect(ids(analyzeRateLimit(samples, ctx))).not.toContain("rate-limit.login.absent");
  });

  it("狀態仍是 401 但帶了 Retry-After，一樣算限制在運作", () => {
    const samples = [...series(2), sample(3, { retryAfter: "30" })];
    const hit = analyzeRateLimit(samples, ctx).find((f) => f.id === "rate-limit.login.present");
    expect(hit?.title).toContain("Retry-After");
    expect(ids(analyzeRateLimit(samples, ctx))).not.toContain("rate-limit.login.absent");
  });

  // 限制器存在但門檻比本輪次數高時，只有標頭看得出來。少了這條會把有防護的站報成 absent。
  it("RateLimit-Remaining 標頭代表端點宣告了限制器，不可報 absent", () => {
    const findings = analyzeRateLimit(series(6, { rateLimitRemaining: "42" }), ctx);
    expect(ids(findings)).toContain("rate-limit.login.present");
    expect(ids(findings)).not.toContain("rate-limit.login.absent");
  });

  it("空字串標頭不算證據（Retry-After: 空值不能生出一筆正面觀測）", () => {
    const findings = analyzeRateLimit(series(4, { retryAfter: "  ", rateLimitRemaining: "" }), ctx);
    expect(ids(findings)).toContain("rate-limit.login.absent");
  });

  // 不是每個限制器都回 429；「每次失敗多等一會兒」對攻擊者的效果一樣好。
  it("回應時間一路遞增＝有退避，報 present 而不是 absent", () => {
    const samples = [
      sample(1, { durationMs: 120 }),
      sample(2, { durationMs: 260 }),
      sample(3, { durationMs: 540 }),
      sample(4, { durationMs: 1100 }),
    ];
    const findings = analyzeRateLimit(samples, ctx);
    expect(ids(findings)).toContain("rate-limit.login.present");
    expect(ids(findings)).not.toContain("rate-limit.login.absent");
    expect(findings.find((f) => f.id === "rate-limit.login.present")?.title).toContain("退避");
  });

  it("毫秒級的正常抖動不算遞增，仍報 absent", () => {
    const samples = [
      sample(1, { durationMs: 110 }),
      sample(2, { durationMs: 128 }),
      sample(3, { durationMs: 119 }),
      sample(4, { durationMs: 141 }),
    ];
    expect(ids(analyzeRateLimit(samples, ctx))).toContain("rate-limit.login.absent");
  });
});

describe("analyzeRateLimit：未判定", () => {
  // 「找不到登入端點」與「沒有速率限制」是完全不同的兩件事，混為一談會誤導讀者去修一個不存在的問題。
  it("404 樣本報 inconclusive，絕不可報 absent", () => {
    const findings = analyzeRateLimit(series(4, { status: 404 }), ctx);
    expect(findings.find((f) => f.id === "rate-limit.login.inconclusive")?.severity).toBe("info");
    expect(ids(findings)).not.toContain("rate-limit.login.absent");
  });

  it("端點自己 5xx 也是未判定——那是站台壞了，不是限制器不存在", () => {
    const findings = analyzeRateLimit(series(3, { status: 503 }), ctx);
    expect(ids(findings)).toEqual(["rate-limit.login.inconclusive"]);
  });

  it("空樣本不會 crash，回一筆 inconclusive", () => {
    const findings = analyzeRateLimit([], ctx);
    expect(ids(findings)).toEqual(["rate-limit.login.inconclusive"]);
    expect(findings[0]?.evidence).toBeUndefined();
  });

  // 現實中不存在第二次就啟動的限制器，樣本太少就下 high 的結論站不住腳。
  it("樣本不足（2 次）報 inconclusive 而不是 absent", () => {
    const findings = analyzeRateLimit(series(2), ctx);
    expect(ids(findings)).toEqual(["rate-limit.login.inconclusive"]);
  });

  it("失敗樣本中混進 404（端點中途換行為）＝未判定", () => {
    const samples = [...series(3), sample(4, { status: 404 })];
    expect(ids(analyzeRateLimit(samples, ctx))).toEqual(["rate-limit.login.inconclusive"]);
  });

  it("同樣輸入卻拿到 401 與 400 兩種狀態，不臆測、報未判定", () => {
    const samples = [sample(1), sample(2, { status: 400 }), sample(3), sample(4, { status: 400 })];
    const findings = analyzeRateLimit(samples, ctx);
    expect(ids(findings)).toEqual(["rate-limit.login.inconclusive"]);
    expect(findings[0]?.detail).toContain("400");
  });

  it("混合 401 與 429 時，429 這個直接證據優先於一切", () => {
    const samples = [sample(1), sample(2, { status: 429 })];
    expect(ids(analyzeRateLimit(samples, ctx))).toEqual(["rate-limit.login.present"]);
  });
});

describe("analyzeRateLimit：使用者列舉", () => {
  it("兩種帳號拿到不同狀態碼＝error-leak（medium）", () => {
    const samples = [
      sample(1, { accountKind: "nonexistent", status: 404 }),
      sample(2, { accountKind: "possible", status: 401 }),
    ];
    // 上面的 404 讓主判定停在未判定，但使用者列舉是獨立的一件事，仍然要報。
    const findings = analyzeRateLimit(samples, ctx);
    expect(findings.find((f) => f.id === "rate-limit.login.error-leak")?.severity).toBe("medium");
  });

  it("兩種帳號拿到相同狀態碼＝正確行為，不報", () => {
    const samples = [
      ...series(3, { accountKind: "nonexistent" }),
      ...series(3, { accountKind: "possible" }),
    ];
    expect(ids(analyzeRateLimit(samples, ctx))).not.toContain("rate-limit.login.error-leak");
  });

  // 呼叫端沒送兩種帳號就沒有素材。把「沒送過」講成「沒問題」與把「沒測到」講成「沒問題」是同一個錯誤。
  it("只有一種帳號（自動流程的常態）就不報，沒有資料不猜", () => {
    const findings = analyzeRateLimit(series(6, { accountKind: "nonexistent" }), ctx);
    expect(ids(findings)).not.toContain("rate-limit.login.error-leak");
    expect(ids(findings)).toContain("rate-limit.login.absent");
  });

  it("完全沒有標記帳號種類時也不報", () => {
    expect(ids(analyzeRateLimit(series(6), ctx))).not.toContain("rate-limit.login.error-leak");
  });

  it("使用者列舉與主判定可以並存，主判定排在前面", () => {
    const samples = [
      ...series(3, { accountKind: "nonexistent", status: 401 }),
      ...series(3, { accountKind: "possible", status: 403 }),
    ];
    const findings = analyzeRateLimit(samples, ctx);
    // 401／403 混雜使主判定停在未判定；列舉那筆則獨立成立。
    expect(ids(findings)).toEqual(["rate-limit.login.inconclusive", "rate-limit.login.error-leak"]);
  });
});

describe("analyzeRateLimit：發現的形狀", () => {
  it("每一筆發現都有修法——包含 info 的正面觀測", () => {
    const cases = [series(6), [...series(2), sample(3, { status: 429 })], series(3, { status: 404 }), []];
    for (const samples of cases) {
      for (const f of analyzeRateLimit(samples, ctx)) {
        expect(f.remediation, `${f.id} 缺 remediation`).toBeTruthy();
      }
    }
  });

  // id 是跨次執行比對與抑制清單的鍵，不可含時間戳、次數或任何隨機值。
  it("id 穩定：同樣的觀測換一組耗時仍是同一個 id", () => {
    const a = ids(analyzeRateLimit(series(6, { durationMs: 90 }), ctx));
    const b = ids(analyzeRateLimit(series(6, { durationMs: 137 }), ctx));
    expect(a).toEqual(b);
    expect(a).toEqual(["rate-limit.login.absent"]);
  });

  it("每一筆都帶 where 與 check，報告才知道這是哪個端點上的哪一項檢查", () => {
    for (const f of analyzeRateLimit(series(6), ctx)) {
      expect(f.where).toBe(ctx.where);
      expect(f.check).toBe("rate-limit");
      expect(f.category).toBe("security");
      expect(f.surface).toBe("web");
    }
  });
});

/**
 * 登入端點判定。
 *
 * 這是本檢查最關鍵、也最容易兩邊都判錯的一個決定：
 * 判成「不是登入端點」會讓整項靜靜跳過（一份看起來無害的報告，其實什麼都沒測）；
 * 判成「是」則會把中介層的封鎖頁當成登入失敗，最後報出一筆不存在的 high。
 */
describe("looksLikeLoginEndpoint", () => {
  const res = (over: Partial<{ status: number; body: string; contentType: string }>) => ({
    status: 401,
    body: "",
    contentType: "application/json",
    ...over,
  });

  it("空 body 的 401 是最標準的登入失敗——不能被攔截啟發式吃掉", () => {
    expect(looksLikeLoginEndpoint(res({ status: 401, body: "" }))).toBe(true);
  });

  it("只有訊息、沒有 error/ok/code 欄位的 401 也算", () => {
    expect(looksLikeLoginEndpoint(res({ status: 401, body: '{"message":"帳號或密碼錯誤"}' }))).toBe(true);
  });

  it.each([400, 422])("HTTP %i 一定是應用回的，直接採信", (status) => {
    expect(looksLikeLoginEndpoint(res({ status }))).toBe(true);
  });

  it.each([404, 405, 501])("HTTP %i 代表這個位址上沒掛登入", (status) => {
    expect(looksLikeLoginEndpoint(res({ status }))).toBe(false);
  });

  it("SPA 兜底頁代表「這裡什麼都沒有」", () => {
    const spa = '<!doctype html><html><body><div id="root"></div></body></html>';
    expect(looksLikeLoginEndpoint(res({ status: 200, body: spa, contentType: "text/html" }))).toBe(false);
  });

  it("403 曖昧：內容像應用回應才採信", () => {
    expect(looksLikeLoginEndpoint(res({ status: 403, body: '{"error":"invalid credentials"}' }))).toBe(true);
  });

  it("403 的 WAF 封鎖頁不算——把它收進樣本，會讓連續封鎖被報成「沒有速率限制」", () => {
    expect(looksLikeLoginEndpoint(res({ status: 403, body: "Forbidden", contentType: "text/plain" }))).toBe(false);
  });
});

/**
 * 速率限制標頭的判讀。
 *
 * 少認 draft-7／8 的合併寫法，代價是一個有防護、門檻又設得比本輪次數高的站台
 * 會完全看不到限制器的痕跡，於是被報成 `absent`（high）。
 */
describe("readRateLimitRemaining", () => {
  const from = (headers: Record<string, string>) => (name: string) => headers[name] ?? null;

  it("認得 IETF draft-6 的 RateLimit-Remaining", () => {
    expect(readRateLimitRemaining(from({ "ratelimit-remaining": "3" }))).toBe("3");
  });

  it("認得舊慣例的 X-RateLimit-Remaining", () => {
    expect(readRateLimitRemaining(from({ "x-ratelimit-remaining": "0" }))).toBe("0");
  });

  it("認得 draft-7／8 把三個值併成一行的寫法", () => {
    expect(readRateLimitRemaining(from({ ratelimit: "limit=5, remaining=3, reset=60" }))).toBe("3");
  });

  it("空字串等同沒有——把空標頭當成證據會憑空生出一筆正面觀測", () => {
    expect(readRateLimitRemaining(from({ "ratelimit-remaining": "   " }))).toBeNull();
  });

  it("完全沒有這類標頭時回 null", () => {
    expect(readRateLimitRemaining(from({}))).toBeNull();
  });

  it("合併寫法裡的 limit 不會被誤讀成 remaining", () => {
    expect(readRateLimitRemaining(from({ ratelimit: "limit=5" }))).toBeNull();
  });
});

/**
 * 指數退避的判定。
 *
 * 退避是速率限制的另一種樣貌（不回 429，改成越試越慢）。判太鬆會把網路抖動講成防護，
 * 於是一個完全沒設限的登入端點被判成安全——那是這裡最該避免的方向。
 */
describe("looksLikeBackoff", () => {
  it("樣本太少不判定——兩次之間的差異解釋不了任何事", () => {
    expect(looksLikeBackoff([100, 900])).toBe(false);
  });

  it("穩定遞增且總幅度夠大時判為有退避", () => {
    expect(looksLikeBackoff([100, 400, 1200])).toBe(true);
  });

  it("平坦的回應時間不是退避", () => {
    expect(looksLikeBackoff([120, 118, 125, 122])).toBe(false);
  });

  it("倍率夠但絕對差距太小時不算——那只是網路抖動", () => {
    expect(looksLikeBackoff([10, 20, 40])).toBe(false);
  });

  it("只有最後一次暴衝、中間沒有遞增趨勢時不算", () => {
    expect(looksLikeBackoff([100, 90, 95, 100, 3000])).toBe(false);
  });

  it("空陣列不會爆", () => {
    expect(looksLikeBackoff([])).toBe(false);
  });
});
