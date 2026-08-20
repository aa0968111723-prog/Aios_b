/**
 * 認證閘門檢測的測試。
 *
 * 這是整套系統裡最有價值、也最容易假警報的一組檢查：未認證回 200 是「現在就在外洩資料」，
 * 所以它的發現一律是 critical／high。也正因為如此，它誤判一次的代價特別高——
 * 一份把「這條路徑根本不存在」報成 critical 外洩的報告，會直接毀掉整個工具的可信度。
 *
 * 所以這裡用假的 fetch 把三種回應餵給 `checkAuthGate`：SPA 兜底、正確擋下、真的漏了。
 * 測試不發出任何真實網路請求。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { GUARDED_ENDPOINTS, checkAuthGate, looksLikeData, trpcBlocked } from "../src/detectors/authGate.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;

/** Vite 建置的站台對所有未匹配路徑回傳的東西。 */
const SPA_HTML =
  '<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head>' +
  '<body><div id="root"></div></body></html>';

type Responder = (url: string) => { status: number; body: string; contentType: string };

function stubFetch(responder: Responder): void {
  vi.stubGlobal("fetch", async (input: string | URL) =>
    (({ status, body, contentType }) => new Response(body, { status, headers: { "content-type": contentType } }))(
      responder(String(input)),
    ),
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("checkAuthGate — SPA 兜底頁", () => {
  it("每個端點都回 SPA 兜底時，不產生任何發現", async () => {
    stubFetch(() => ({ status: 200, body: SPA_HTML, contentType: "text/html; charset=utf-8" }));
    const result = await checkAuthGate(web, 1000);
    expect(result.findings).toEqual([]);
  });

  it("而且不是回報「通過」，是標記為沒驗到——這兩件事差很多", async () => {
    stubFetch(() => ({ status: 200, body: SPA_HTML, contentType: "text/html; charset=utf-8" }));
    const result = await checkAuthGate(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("SPA 兜底頁");
    expect(result.skippedReason).toContain("未實際驗到任何認證閘門");
  });

  it("兜底頁的路徑會如實記在 facts，讓人看得出當時發生什麼", async () => {
    stubFetch(() => ({ status: 200, body: SPA_HTML, contentType: "text/html; charset=utf-8" }));
    const result = await checkAuthGate(web, 1000);
    const observed = result.facts?.observed as Record<string, string>;
    expect(Object.values(observed).every((v) => v.includes("SPA 兜底頁"))).toBe(true);
    expect(result.facts?.probedByApi).toBe(0);
  });

  it("tRPC 端點回兜底頁也不會被誤判成「未授權卻回了結果」", async () => {
    const trpc = GUARDED_ENDPOINTS.find((e) => e.path.startsWith("/api/trpc/"));
    expect(trpc).toBeDefined();
    stubFetch((url) =>
      url.includes("/api/trpc/")
        ? { status: 200, body: SPA_HTML, contentType: "text/html" }
        : { status: 401, body: '{"error":"unauthorized"}', contentType: "application/json" },
    );
    const result = await checkAuthGate(web, 1000);
    expect(result.findings.filter((f) => f.id.startsWith("auth-gate.trpc"))).toEqual([]);
  });
});

describe("checkAuthGate — 正常擋下與真的漏了", () => {
  it("全部乾脆地回 401 時完成且零發現", async () => {
    stubFetch(() => ({ status: 401, body: '{"error":"unauthorized"}', contentType: "application/json" }));
    const result = await checkAuthGate(web, 1000);
    expect(result.completed).toBe(true);
    expect(result.findings).toEqual([]);
  });

  it("受保護的 REST 端點回 200 且有內容＝critical", async () => {
    stubFetch((url) =>
      url.endsWith("/api/v1/databases")
        ? { status: 200, body: '[{"id":"1","name":"客戶名單"}]', contentType: "application/json" }
        : { status: 401, body: '{"error":"unauthorized"}', contentType: "application/json" },
    );
    const result = await checkAuthGate(web, 1000);
    const leak = result.findings.find((f) => f.id === "auth-gate.open./api/v1/databases");
    expect(leak?.severity).toBe("critical");
    expect(result.completed).toBe(true);
  });

  it("部分端點是兜底頁時，其餘照常判定（不會整組被跳過）", async () => {
    stubFetch((url) =>
      url.endsWith("/api/me/export")
        ? { status: 200, body: '{"projects":[{"id":"1"}]}', contentType: "application/json" }
        : { status: 200, body: SPA_HTML, contentType: "text/html" },
    );
    const result = await checkAuthGate(web, 1000);
    expect(result.completed).toBe(true);
    expect(result.findings.map((f) => f.id)).toContain("auth-gate.open./api/me/export");
  });

  it("導向登入頁算有正確擋下", async () => {
    vi.stubGlobal("fetch", async () => new Response("", { status: 302, headers: { location: "/login" } }));
    const result = await checkAuthGate(web, 1000);
    expect(result.findings).toEqual([]);
  });

  it("連線失敗記進 facts 而不是變成發現——連不到不等於有漏洞", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    const result = await checkAuthGate(web, 1000);
    expect(result.findings).toEqual([]);
    const observed = result.facts?.observed as Record<string, string>;
    expect(Object.values(observed).every((v) => v.startsWith("連線失敗"))).toBe(true);
  });
});

describe("looksLikeData", () => {
  it("空 JSON 物件與陣列不算有資料", () => {
    expect(looksLikeData("{}", "application/json")).toBe(false);
    expect(looksLikeData("[]", "application/json")).toBe(false);
  });

  it("帶 error 欄位的 JSON 不算有資料", () => {
    expect(looksLikeData('{"error":"unauthorized"}', "application/json")).toBe(false);
  });

  it("有內容的 JSON 算有資料", () => {
    expect(looksLikeData('[{"id":1}]', "application/json")).toBe(true);
  });

  it("二進位下載只要有內容就算", () => {
    expect(looksLikeData("PK", "application/octet-stream")).toBe(true);
  });
});

describe("trpcBlocked", () => {
  it("認得單一回應與批次陣列兩種形狀", () => {
    expect(trpcBlocked('{"error":{"data":{"code":"UNAUTHORIZED"}}}')).toBe(true);
    expect(trpcBlocked('[{"error":{"data":{"code":"FORBIDDEN"}}}]')).toBe(true);
  });

  it("回了結果就是沒擋", () => {
    expect(trpcBlocked('{"result":{"data":{"items":[1]}}}')).toBe(false);
  });

  it("不是 JSON 時回 false（由呼叫端先排除兜底頁，這裡不猜）", () => {
    expect(trpcBlocked("<!doctype html>")).toBe(false);
  });

  // ai_os 用 superjson 當 transformer，於是錯誤內容被包在 error.json 底下。
  // 認不得這層外殼，會把一個「正確擋下了」的回應判成「未授權卻回了結果」——一筆假的 critical。
  it("認得 superjson transformer 的外殼", () => {
    const single = '{"error":{"json":{"message":"UNAUTHORIZED","code":-32001,"data":{"code":"UNAUTHORIZED","httpStatus":401}}}}';
    expect(trpcBlocked(single)).toBe(true);
    expect(trpcBlocked(`[${single}]`)).toBe(true);
  });

  it("只靠 httpStatus 或 JSON-RPC 錯誤碼也判得出來", () => {
    expect(trpcBlocked('{"error":{"data":{"httpStatus":403}}}')).toBe(true);
    expect(trpcBlocked('{"error":{"code":-32003}}')).toBe(true);
  });

  it("英文訊息也算——放寬的代價遠低於把正確防護報成 critical 外洩", () => {
    expect(trpcBlocked('{"error":{"message":"Unauthorized"}}')).toBe(true);
    expect(trpcBlocked('{"error":{"message":"Forbidden"}}')).toBe(true);
  });

  it("真的回了資料就不算擋下（放寬不能寬到把外洩也吃掉）", () => {
    expect(trpcBlocked('{"error":{"json":{"message":"Something failed","data":{"code":"INTERNAL_SERVER_ERROR"}}}}')).toBe(false);
  });
});
