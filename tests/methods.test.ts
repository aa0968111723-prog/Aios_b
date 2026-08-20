import { afterEach, describe, expect, it, vi } from "vitest";
import {
  TRACE_PROBE_HEADER,
  TRACE_PROBE_TOKEN,
  analyzeMethods,
  checkMethods,
  classifyAllowProbe,
  classifyTraceProbe,
  parseAllowHeader,
  type MethodObservation,
} from "../src/detectors/methods.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const apiCtx = { surface: "web" as const, where: "https://example.test/api/v1/databases", isApi: true };
const siteCtx = { surface: "web" as const, where: "https://example.test/", isApi: false };

/** 一筆「什麼都沒觀測到」的基準，各測試只覆寫自己關心的欄位。 */
function observe(patch: Partial<MethodObservation> = {}): MethodObservation {
  return {
    path: "/api/v1/databases",
    allow: null,
    traceStatus: null,
    traceEchoesRequest: false,
    traceBodySnippet: null,
    ...patch,
  };
}

const ids = (findings: ReturnType<typeof analyzeMethods>) => findings.map((f) => f.id);

/** SPA 兜底頁的最小樣貌：catch-all 路由對任何方法都會回這個。 */
const SPA_FALLBACK = '<!doctype html><html><body><div id="root"></div></body></html>';

/** 真正的回吐長什麼樣：伺服器把整個請求（含我們的探針標頭）寫回內文。 */
const ECHO_BODY = `TRACE /api/health HTTP/1.1\r\nHost: example.test\r\n${TRACE_PROBE_HEADER}: ${TRACE_PROBE_TOKEN}\r\n`;

describe("parseAllowHeader", () => {
  it("拆開逗號分隔並統一成大寫", () => {
    expect(parseAllowHeader("get, post, options")).toEqual(["GET", "POST", "OPTIONS"]);
  });

  it("去掉方法之間的多餘空白與換行（代理折行時常見）", () => {
    expect(parseAllowHeader("GET ,\tHEAD,\r\n POST")).toEqual(["GET", "HEAD", "POST"]);
  });

  // 多層代理各自補一次 Allow 時同一個方法會出現兩遍，那不代表它比較危險，
  // 不去重會讓「方法數異常多」的判定被重複值灌爆。
  it("重複的方法只留一次", () => {
    expect(parseAllowHeader("GET, get, GET, PUT")).toEqual(["GET", "PUT"]);
  });

  it("連續逗號不會變成空字串方法", () => {
    expect(parseAllowHeader("GET,,POST,")).toEqual(["GET", "POST"]);
  });

  it("只有逗號與空白時回空陣列（不會產出一堆空方法）", () => {
    expect(parseAllowHeader(" , ,, ")).toEqual([]);
  });

  it("沒有 Allow 標頭（null／空字串）回空陣列，而不是丟例外", () => {
    expect(parseAllowHeader(null)).toEqual([]);
    expect(parseAllowHeader("")).toEqual([]);
    expect(parseAllowHeader("   ")).toEqual([]);
  });

  // 證據欄會原樣附上 Allow 原始值，讀者要能一眼對得起來，所以順序不可以被重排。
  it("保留伺服器寫的順序", () => {
    expect(parseAllowHeader("OPTIONS, GET, HEAD")).toEqual(["OPTIONS", "GET", "HEAD"]);
  });
});

describe("analyzeMethods：TRACE", () => {
  it("TRACE 回 200 但沒有回吐＝medium", () => {
    const findings = analyzeMethods(observe({ traceStatus: 200 }), apiCtx);
    expect(findings.find((f) => f.id === "methods.trace.enabled")?.severity).toBe("medium");
  });

  it("204 一樣算 2xx（可用）", () => {
    expect(ids(analyzeMethods(observe({ traceStatus: 204 }), apiCtx))).toContain("methods.trace.enabled");
  });

  it("回吐請求時只報 echo（high），不再重複報一筆 enabled", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, traceEchoesRequest: true, traceBodySnippet: "TRACE / HTTP/1.1" }),
      apiCtx,
    );
    expect(findings.find((f) => f.id === "methods.trace.echo")?.severity).toBe("high");
    expect(ids(findings)).not.toContain("methods.trace.enabled");
  });

  it("TRACE 被站台擋掉（405）是正確行為，不產生任何發現", () => {
    expect(analyzeMethods(observe({ traceStatus: 405 }), apiCtx)).toEqual([]);
  });

  it("站台明說不支援（501）同樣不產生任何發現", () => {
    expect(analyzeMethods(observe({ traceStatus: 501 }), apiCtx)).toEqual([]);
  });

  // 「沒測到」與「沒問題」必須分開：未判定要留下一筆 info 紀錄，
  // 而不是安靜地變成一份看起來全綠的報告。
  it("traceStatus 為 null＝未判定，留下 info 紀錄", () => {
    const findings = analyzeMethods(observe(), apiCtx);
    expect(findings.find((f) => f.id === "methods.trace.unknown")?.severity).toBe("info");
  });

  // 回吐是唯一一條靠內文成立的判定：看得到探針值就代表請求真的被寫了回來，
  // 那不可能是「沒測到」。把它讓給 unknown 等於把已經測到的 high 降級成 info。
  it("看到回吐就報 echo，即使沒有拿到狀態碼也不會被降級成未判定", () => {
    const findings = analyzeMethods(observe({ traceEchoesRequest: true, traceBodySnippet: ECHO_BODY }), apiCtx);
    expect(ids(findings)).toEqual(["methods.trace.echo"]);
  });

  it("沒有內文也沒有狀態碼時，證據欄留空而不是印出「HTTP null」", () => {
    const findings = analyzeMethods(observe({ traceEchoesRequest: true }), apiCtx);
    expect(findings[0]?.evidence).toBeUndefined();
    expect(JSON.stringify(findings)).not.toContain("HTTP null");
  });

  it("未判定時把可補驗的指令寫進修法（線索不能斷在這裡）", () => {
    const hit = analyzeMethods(observe(), apiCtx).find((f) => f.id === "methods.trace.unknown");
    expect(hit?.remediation).toContain("curl -X TRACE");
    expect(hit?.remediation).toContain(TRACE_PROBE_TOKEN);
  });
});

describe("analyzeMethods：Allow", () => {
  it("Allow 含 PUT／DELETE／PATCH 報 medium 並列出實際命中的方法", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT, DELETE" }), apiCtx);
    const hit = findings.find((f) => f.id === "methods.dangerous-allowed");
    expect(hit?.severity).toBe("medium");
    expect(hit?.title).toContain("PUT");
    expect(hit?.title).toContain("DELETE");
    expect(hit?.title).not.toContain("GET");
  });

  it("小寫寫法一樣抓得到（正規化後才比對）", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "get, patch" }), apiCtx);
    expect(ids(findings)).toContain("methods.dangerous-allowed");
  });

  it("只有讀取類方法時不報", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET, HEAD, POST, OPTIONS" }), apiCtx);
    expect(ids(findings)).not.toContain("methods.dangerous-allowed");
  });

  // 這條是紅線：我們從來沒有真的送出 PUT／DELETE 去驗證，所以文案不可以把
  // Allow 的自述講成已經證實的漏洞，否則讀者會照著一個不存在的結論去排優先序。
  it("文案把 Allow 講成自述而非已證實可用，並要求人工確認認證保護", () => {
    const detail =
      analyzeMethods(observe({ traceStatus: 405, allow: "GET, DELETE" }), apiCtx).find(
        (f) => f.id === "methods.dangerous-allowed",
      )?.detail ?? "";
    expect(detail).toContain("自述");
    expect(detail).toContain("不代表未授權");
    expect(detail).toContain("認證");
  });

  it("API 路徑與一般路徑給出不同的說明（嚴重度看用途）", () => {
    const onApi = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT" }), apiCtx).find(
      (f) => f.id === "methods.dangerous-allowed",
    );
    const onSite = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT", path: "/" }), siteCtx).find(
      (f) => f.id === "methods.dangerous-allowed",
    );
    expect(onApi?.detail).not.toBe(onSite?.detail);
    expect(onSite?.detail).toContain("預設值");
  });

  it("方法數超過 6 個報 low（框架預設全開的徵兆）", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 405, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(findings.find((f) => f.id === "methods.allow-verbose")?.severity).toBe("low");
  });

  it("剛好 6 個不算異常多（門檻邊界）", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET,HEAD,POST,PUT,DELETE,OPTIONS" }), apiCtx);
    expect(ids(findings)).not.toContain("methods.allow-verbose");
  });

  it("重複值不會把方法數灌到超過門檻", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 405, allow: "GET,GET,GET,HEAD,HEAD,POST,POST,OPTIONS" }),
      apiCtx,
    );
    expect(ids(findings)).not.toContain("methods.allow-verbose");
  });

  it("沒有 Allow 標頭時不產生任何 Allow 相關發現", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: null }), apiCtx);
    expect(findings).toEqual([]);
  });

  it("Allow 只有空白或逗號時視同沒有自述，不臆測", () => {
    expect(analyzeMethods(observe({ traceStatus: 405, allow: " , " }), apiCtx)).toEqual([]);
  });

  it("證據原樣附上 Allow 標頭值，方便直接重現", () => {
    const hit = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT" }), apiCtx).find(
      (f) => f.id === "methods.dangerous-allowed",
    );
    expect(hit?.evidence).toBe("Allow: GET, PUT");
  });
});

// 這一組是規格裡兩條降噪要求的本體。它們決定了報告上多數的假警報會不會發生，
// 所以必須離線可測——把判定留在 IO 層裡，等於這兩條規則永遠沒有人驗過。
describe("classifyTraceProbe：哪些回應不算站台的答覆", () => {
  it("送不出去（Node 的 fetch 依規範禁用 TRACE）算未問到站台，原文照抄不替它下結論", () => {
    const state = classifyTraceProbe({ error: "'TRACE' HTTP method is unsupported" });
    expect(state.state).toBe("unreachable");
    expect(state.state === "unreachable" && state.reason).toContain("unsupported");
  });

  // 代理對 TRACE 回 405 是很常見的預設。把它讀成「站台拒絕了 TRACE」，
  // 等於把中介層的設定寫成站台的體質——中介層一換掉，這份結論就整個作廢。
  it("中介層的裸 405 不算站台答覆", () => {
    const state = classifyTraceProbe({
      status: 405,
      body: "<html><head><title>405 Not Allowed</title></head><body>nginx</body></html>",
      contentType: "text/html",
    });
    expect(state.state).toBe("unreachable");
  });

  // catch-all 路由對任何方法都回 index.html 200。照 200 判成「TRACE 可用」，
  // 每一條路徑都會生出一筆假的 medium。
  it("SPA 兜底頁的 200 歸為 shadowed，不會被當成 TRACE 可用", () => {
    const state = classifyTraceProbe({ status: 200, body: SPA_FALLBACK, contentType: "text/html; charset=utf-8" });
    expect(state.state).toBe("shadowed");
  });

  it("shadowed 仍代表應用活著——它只是遮住了 TRACE 的處理方式", () => {
    const state = classifyTraceProbe({ status: 200, body: SPA_FALLBACK, contentType: "text/html" });
    expect(state.state === "shadowed" && state.reason).toContain("catch-all");
  });

  it("站台自己回的 405（帶應用的 JSON 錯誤格式）算答覆，狀態碼要留下來", () => {
    const state = classifyTraceProbe({
      status: 405,
      body: '{"error":"Method Not Allowed"}',
      contentType: "application/json",
    });
    expect(state).toMatchObject({ state: "answered", status: 405, echoed: false });
  });

  it("真的回吐時認得出來（TRACE 的標準回應是 message/http）", () => {
    const state = classifyTraceProbe({ status: 200, body: ECHO_BODY, contentType: "message/http" });
    expect(state).toMatchObject({ state: "answered", status: 200, echoed: true });
  });

  it("中介層把探針值改成大寫也一樣認得出來", () => {
    const state = classifyTraceProbe({
      status: 200,
      body: `TRACE / HTTP/1.1\r\nX-SENTINEL-PROBE: ${TRACE_PROBE_TOKEN.toUpperCase()}\r\n`,
      contentType: "message/http",
    });
    expect(state.state === "answered" && state.echoed).toBe(true);
  });

  // 回吐要排在所有排除規則之前：兜底的 index.html 是建置產物、代理錯誤頁是罐頭字串，
  // 兩者都不可能含有我們幾毫秒前才送出去的探針值。先排除就會把 high 講成「未判定」。
  it("回吐夾在看起來像兜底頁的回應裡，仍然判為回吐", () => {
    const state = classifyTraceProbe({
      status: 200,
      body: `${SPA_FALLBACK}<!-- ${TRACE_PROBE_TOKEN} -->`,
      contentType: "text/html",
    });
    expect(state.state === "answered" && state.echoed).toBe(true);
  });

  it("回吐夾在中介層的錯誤頁裡，同樣不會被排除規則吃掉", () => {
    const state = classifyTraceProbe({
      status: 400,
      body: `Bad Request: ${TRACE_PROBE_TOKEN}`,
      contentType: "text/plain",
    });
    expect(state.state === "answered" && state.echoed).toBe(true);
  });

  it("回應片段只留開頭一段，不把整份回應搬進報告", () => {
    const state = classifyTraceProbe({ status: 200, body: "x".repeat(5_000), contentType: "text/plain" });
    expect(state.snippet?.length).toBe(200);
  });

  it("空內文的 snippet 是 null，不是空字串（報告上要看得出「沒有內容」）", () => {
    const state = classifyTraceProbe({ status: 200, body: "", contentType: "text/plain" });
    expect(state.snippet).toBeNull();
  });
});

describe("classifyAllowProbe：哪些 Allow 可以拿來判定", () => {
  it("正常的 OPTIONS 回應原樣交出 Allow", () => {
    const state = classifyAllowProbe({ status: 204, body: "", contentType: "", allow: "GET,HEAD,POST" });
    expect(state).toMatchObject({ state: "answered", allow: "GET,HEAD,POST" });
  });

  it("探針失敗＝沒觀測到，不能寫成「站台沒有宣告任何方法」", () => {
    const state = classifyAllowProbe({ error: "fetch failed" });
    expect(state.state).toBe("unverified");
    expect(state.state === "unverified" && state.reason).toContain("fetch failed");
  });

  it("中介層的裸 403 不拿來判定", () => {
    const state = classifyAllowProbe({
      status: 403,
      body: "Forbidden",
      contentType: "text/plain",
      allow: null,
    });
    expect(state.state).toBe("unverified");
  });

  // RFC 9110 規定回 405 必須附上 Allow，而中介層的罐頭錯誤頁不知道這條路由收哪些方法，
  // 也就寫不出這個標頭。先套中介層排除規則會把整份檢查最可靠的一次自述丟掉。
  it("405 但帶了 Allow 時採信——那是路由自己說的", () => {
    const state = classifyAllowProbe({
      status: 405,
      body: "Method Not Allowed",
      contentType: "text/plain",
      allow: "GET, HEAD, DELETE",
    });
    expect(state).toMatchObject({ state: "answered", allow: "GET, HEAD, DELETE" });
  });

  it("有回應但沒有 Allow 時，說明要分得出「觀測到沒有」而不是「沒觀測到」", () => {
    const state = classifyAllowProbe({ status: 200, body: SPA_FALLBACK, contentType: "text/html", allow: null });
    expect(state).toMatchObject({ state: "answered", allow: null });
    expect(state.state === "answered" && state.note).toContain("沒有可解析的 Allow");
  });

  it("空的 Allow 標頭等同沒有自述，不會被當成一份空的方法清單", () => {
    const state = classifyAllowProbe({ status: 200, body: "", contentType: "", allow: "  " });
    expect(state).toMatchObject({ state: "answered", allow: null });
  });
});

describe("analyzeMethods：發現本身的品質", () => {
  it("每一筆都帶得動手的修法與觸發位置", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, traceEchoesRequest: true, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(findings.length).toBe(3);
    for (const f of findings) {
      expect(f.remediation ?? "").not.toBe("");
      expect(f.where).toBe(apiCtx.where);
      expect(f.check).toBe("methods");
      expect(f.category).toBe("security");
    }
  });

  // id 是跨次執行比對與抑制清單的鍵，混進路徑或時間戳就會讓同一個問題每次都算「新增」。
  it("id 穩定：不含路徑、時間戳或隨機值", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(ids(findings).sort()).toEqual([
      "methods.allow-verbose",
      "methods.dangerous-allowed",
      "methods.trace.enabled",
    ]);
  });

  it("同一筆觀測跑兩次結果完全相同（判定不帶任何隨機或時間成分）", () => {
    const obs = observe({ traceStatus: 200, traceEchoesRequest: true, allow: "GET,PUT" });
    expect(analyzeMethods(obs, apiCtx)).toEqual(analyzeMethods(obs, apiCtx));
  });
});

/**
 * 逐路徑的「TRACE 未判定」要收攏成一筆。
 *
 * 三條路徑都判不出來時，原因幾乎總是同一個（執行環境擋下 TRACE、或站台前面有代理），
 * 所以那是同一件事被講了三次。這件事本身不嚴重，但一份 18 筆發現的報告裡有 3 筆是
 * 重複的雜訊，讀者對「這份清單值得逐條看」的信任就少一分。降噪是正經工作，info 也一樣。
 */
describe("checkMethods — 未判定的收攏", () => {
  const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("多條路徑都判不出 TRACE 時只報一筆，並列出受影響的路徑", async () => {
    // OPTIONS 拿得到應用回應（所以整項不會被標記跳過），TRACE 一律送不出去。
    vi.stubGlobal("fetch", async (input: string | URL, init?: { method?: string }) => {
      if ((init?.method ?? "GET") === "TRACE") throw new TypeError("TRACE is a forbidden method");
      return new Response(null, { status: 204, headers: { allow: "GET, HEAD, OPTIONS" } });
    });

    const result = await checkMethods(web, 1000);
    const unknowns = result.findings.filter((f) => f.id === "methods.trace.unknown");

    expect(result.completed).toBe(true);
    expect(unknowns).toHaveLength(1);
    expect(unknowns[0]?.title).toContain("3 條路徑");
    // 「沒測到」要留在報告上，只是講一次就夠——路徑仍逐條列在證據裡。
    expect(unknowns[0]?.evidence).toContain("/api/health");
    expect(unknowns[0]?.evidence).toContain("/api/v1/databases");
    // 每條路徑的確切原因照舊留在 facts。
    expect(Object.keys(result.facts?.observed as object)).toHaveLength(3);
  });

  it("只有一條路徑未判定時維持原樣，不會多出「N 條路徑」的字樣", async () => {
    // 其餘兩條由**應用自己**乾脆地拒絕 TRACE（帶應用的 JSON 錯誤格式，
    // 才不會被當成中介層攔截），所以它們是「判定為關閉」而不是「未判定」。
    vi.stubGlobal("fetch", async (input: string | URL, init?: { method?: string }) => {
      const url = String(input);
      if ((init?.method ?? "GET") === "TRACE") {
        if (url.endsWith("/api/health")) throw new TypeError("TRACE is a forbidden method");
        return new Response('{"error":"method not allowed"}', {
          status: 405,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(null, { status: 204, headers: { allow: "GET, HEAD, OPTIONS" } });
    });

    const result = await checkMethods(web, 1000);
    const unknowns = result.findings.filter((f) => f.id === "methods.trace.unknown");
    expect(unknowns).toHaveLength(1);
    expect(unknowns[0]?.title).not.toContain("條路徑）");
  });
});
