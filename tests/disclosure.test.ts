import { describe, expect, it } from "vitest";
import { findStackTrace, looksLikeSpaFallback, SENSITIVE_PATHS } from "../src/detectors/disclosure.js";
import { findMetaCsp, findMixedContent } from "../src/detectors/transport.js";
import { looksLikeData, trpcBlocked } from "../src/detectors/authGate.js";

describe("looksLikeSpaFallback", () => {
  // 這是整個洩漏偵測最關鍵的一條：SPA 對任何未知路徑都回 index.html 200，
  // 沒有這個判定，每一條敏感路徑都會變成假警報。
  it("認得 Vite 產出的 index.html", () => {
    const html = `<!doctype html><html><body><div id="root"></div><script type="module" src="/assets/index.js"></script></body></html>`;
    expect(looksLikeSpaFallback(html, "text/html; charset=utf-8")).toBe(true);
  });

  it("真的洩漏出來的 .env 不會被當成 SPA 兜底", () => {
    expect(looksLikeSpaFallback("DATABASE_URL=postgres://u:p@h/db\n", "text/plain")).toBe(false);
  });

  it("非 HTML 型別一律不是兜底", () => {
    expect(looksLikeSpaFallback('{"a":1}', "application/json")).toBe(false);
  });
});

describe("SENSITIVE_PATHS 特徵", () => {
  it(".env 的特徵比對得到真實內容", () => {
    const env = SENSITIVE_PATHS.find((p) => p.path === "/.env")!;
    expect(env.signature.test("DATABASE_URL=postgres://x\nFAL_KEY=abc")).toBe(true);
    expect(env.signature.test("<!doctype html><div id=root>")).toBe(false);
  });

  it(".git/HEAD 的特徵比對得到 ref 行", () => {
    const git = SENSITIVE_PATHS.find((p) => p.path === "/.git/HEAD")!;
    expect(git.signature.test("ref: refs/heads/main\n")).toBe(true);
  });

  it("每一條敏感路徑都有嚴重度與修法", () => {
    for (const p of SENSITIVE_PATHS) {
      expect(p.severity).toBeTruthy();
      expect(p.remediation.length).toBeGreaterThan(0);
    }
  });
});

describe("findStackTrace", () => {
  it("抓得到 V8 堆疊", () => {
    const body = `Error: boom\n    at handler (/app/server/index.ts:120:15)\n    at next (/app/node_modules/express/lib/router/index.js:1:1)`;
    expect(findStackTrace(body)).toBeTruthy();
  });

  it("一般錯誤訊息不誤判", () => {
    expect(findStackTrace('{"error":"請先登入"}')).toBeNull();
  });
});

describe("findMixedContent", () => {
  it("抓出 http 子資源", () => {
    const html = `<img src="http://cdn.test/a.png"><script src="https://ok.test/b.js"></script>`;
    expect(findMixedContent(html)).toEqual(["http://cdn.test/a.png"]);
  });

  it("本機 http 引用不算混合內容（本機測試常態）", () => {
    expect(findMixedContent(`<img src="http://localhost:3000/a.png">`)).toEqual([]);
  });
});

describe("findMetaCsp", () => {
  it("抓得到 meta 版 CSP", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'">`;
    expect(findMetaCsp(html)).toBe("default-src 'self'");
  });

  it("沒有時回 null", () => {
    expect(findMetaCsp("<meta charset=utf-8>")).toBeNull();
  });
});

describe("trpcBlocked", () => {
  // tRPC 未授權也回 HTTP 200，只看狀態碼會把「有正確擋下」誤判成「外洩」。
  it("UNAUTHORIZED 視為有擋下來", () => {
    const body = JSON.stringify({ error: { data: { code: "UNAUTHORIZED" }, message: "請先登入" } });
    expect(trpcBlocked(body)).toBe(true);
  });

  it("批次回應中任一筆未授權即算擋下", () => {
    const body = JSON.stringify([{ result: { data: 1 } }, { error: { data: { code: "FORBIDDEN" } } }]);
    expect(trpcBlocked(body)).toBe(true);
  });

  it("成功回傳資料不算擋下", () => {
    expect(trpcBlocked(JSON.stringify({ result: { data: { persistence: "ok" } } }))).toBe(false);
  });

  it("非 JSON 不算擋下（無法證明有防護就不能當通過）", () => {
    expect(trpcBlocked("<html>")).toBe(false);
  });
});

describe("looksLikeData", () => {
  it("空陣列不算有資料", () => {
    expect(looksLikeData("[]", "application/json")).toBe(false);
  });

  it("含錯誤欄位的 JSON 不算有資料", () => {
    expect(looksLikeData('{"error":"nope"}', "application/json")).toBe(false);
  });

  it("有內容的 JSON 算有資料", () => {
    expect(looksLikeData('[{"id":1}]', "application/json")).toBe(true);
  });

  it("二進位下載只要有位元組就算有資料", () => {
    expect(looksLikeData("PK", "application/zip")).toBe(true);
  });
});
