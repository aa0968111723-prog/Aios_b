/**
 * 傳輸層檢測的測試。
 *
 * 兩個焦點，各對應一種失效方向：
 *
 * - `findMixedContent` 說錯話（假警報）：把頁尾一條指向合作夥伴的 `<a href="http://…">`
 *   報成「瀏覽器會封鎖這些資源」。瀏覽器對一般連結什麼都不會做，這種說錯話的告警
 *   讀者只要抓到一次，就不會再相信整份報告。
 * - http 目標靜默跳過（假綠燈）：`--target http://…` 時 HSTS、Cookie Secure、
 *   http→https 導向、混合內容四項全部不執行，而檢查仍回報完成。
 *   一個完全沒有 TLS 的站台會拿到一份幾乎全綠的資安報告。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkTransport, findMetaCsp, findMixedContent, isLocalHost } from "../src/detectors/transport.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const ids = (findings: Array<{ id: string }>) => findings.map((f) => f.id);

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("findMixedContent", () => {
  it("抓得到真正的 http 子資源", () => {
    const hits = findMixedContent(
      '<img src="http://cdn.example/a.png"><script src="http://cdn.example/b.js"></script>' +
        '<link rel="stylesheet" href="http://cdn.example/c.css">',
    );
    expect(hits).toHaveLength(3);
  });

  it("一般的 http 外部連結不算子資源", () => {
    expect(findMixedContent('<a href="http://example.org/partner">夥伴</a>')).toEqual([]);
    expect(findMixedContent('<area href="http://example.org/x">')).toEqual([]);
  });

  it("不會載入資源的 link rel 不算", () => {
    expect(findMixedContent('<link rel="alternate" href="http://example.org/feed">')).toEqual([]);
    expect(findMixedContent('<link rel="canonical" href="http://example.org/">')).toEqual([]);
  });

  it("表單送到 http 端點算——送出去的是使用者輸入", () => {
    expect(findMixedContent('<form action="http://example.org/submit">')).toEqual(["http://example.org/submit"]);
  });

  it("本機的 http 引用在本機測試是正常的", () => {
    expect(findMixedContent('<img src="http://localhost:5173/a.png">')).toEqual([]);
  });

  it("同一個網址重複出現只算一次", () => {
    const html = '<img src="http://cdn.example/a.png"><img src="http://cdn.example/a.png">';
    expect(findMixedContent(html)).toHaveLength(1);
  });
});

describe("isLocalHost", () => {
  it.each(["localhost", "127.0.0.1", "::1", "0.0.0.0", "mac.local"])("%s 是本機", (host) => {
    expect(isLocalHost(host)).toBe(true);
  });

  it.each(["ai-os-app.zeabur.app", "staging.example.com"])("%s 不是本機", (host) => {
    expect(isLocalHost(host)).toBe(false);
  });
});

describe("findMetaCsp", () => {
  it("CSP 內容本身充滿單引號，取值要用同種引號回頭配對", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">`;
    expect(findMetaCsp(html)).toBe("default-src 'self'; script-src 'self'");
  });

  it("沒有 meta CSP 時回 null", () => {
    expect(findMetaCsp("<html></html>")).toBeNull();
  });
});

describe("checkTransport — 明文目標", () => {
  const HARDENED = {
    "content-type": "text/html",
    "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
  };

  it("非本機的 http 目標會被明白指出來，而不是靜靜地少跑四項判定", async () => {
    vi.stubGlobal("fetch", async () => new Response('<div id="root"></div>', { status: 200, headers: HARDENED }));
    const surface = buildSurfaces("http://staging.example.com")[0]!;
    const result = await checkTransport(surface, 1000);
    const plaintext = result.findings.find((f) => f.id === "transport.plaintext");
    expect(plaintext?.severity).toBe("high");
    expect(plaintext?.detail).toContain("在本輪都失去意義而未執行");
  });

  it("本機 http 測試不報明文（那是正常的開發情境）", async () => {
    vi.stubGlobal("fetch", async () => new Response('<div id="root"></div>', { status: 200, headers: HARDENED }));
    const surface = buildSurfaces("http://localhost:5173")[0]!;
    expect(ids((await checkTransport(surface, 1000)).findings)).not.toContain("transport.plaintext");
  });

  it("https 目標不報明文", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response('<div id="root"></div>', {
        status: 200,
        headers: { ...HARDENED, "strict-transport-security": "max-age=31536000; includeSubDomains" },
      }),
    );
    const surface = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;
    const result = await checkTransport(surface, 1000);
    expect(ids(result.findings)).not.toContain("transport.plaintext");
    expect(ids(result.findings)).not.toContain("headers.hsts.missing");
  });
});
