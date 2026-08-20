/**
 * HTTP 探針的測試。
 *
 * 這一層的錯誤特別難察覺，因為它不會產生錯誤的發現——它會讓**呼叫端整項放棄**。
 * 例如把一份完整的回應誤標成「被截斷」，supply-chain 就會回「首頁 HTML 超過讀取上限」
 * 並跳過整份子資源盤點：一個 byte 都沒少的回應，換來一項沒做的檢查。
 *
 * 測試以本機伺服器驅動，不碰外部網路。
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createServer, type Server } from "node:http";
import { probe } from "../src/core/http.js";

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const size = Number(url.searchParams.get("size") ?? "10");

    if (url.pathname === "/redirect-chain") {
      // 第一跳就種下 cookie——express-session 的預設行為正是如此。
      res.writeHead(302, { location: "/landing", "set-cookie": "connect.sid=s%3Aabc; Path=/; HttpOnly" });
      res.end();
      return;
    }
    if (url.pathname === "/landing") {
      res.writeHead(200, { "content-type": "text/html", "set-cookie": "theme=dark; Path=/" });
      res.end("<html></html>");
      return;
    }

    res.writeHead(200, { "content-type": "text/plain" });
    res.end("x".repeat(size));
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("測試伺服器沒有拿到埠號");
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("probe — 讀取上限與截斷", () => {
  it("內容小於上限：完整讀到，不標截斷", async () => {
    const res = await probe(`${origin}/?size=1000`, { maxBodyBytes: 4096 });
    expect(res.body.length).toBe(1000);
    expect(res.truncated).toBe(false);
  });

  // 這是本次修掉的缺陷：判準應該是「串流還沒結束」，不是「size 達到上限」。
  it("內容**剛好等於**上限：一個 byte 都沒少，不該標成截斷", async () => {
    const res = await probe(`${origin}/?size=4096`, { maxBodyBytes: 4096 });
    expect(res.body.length).toBe(4096);
    expect(res.truncated).toBe(false);
  });

  it("內容超過上限：確實標成截斷", async () => {
    // 大檔會分成多個 chunk 送達，所以要夠大才保證讀不完。
    const res = await probe(`${origin}/?size=${1024 * 1024}`, { maxBodyBytes: 4096 });
    expect(res.truncated).toBe(true);
    expect(res.body.length).toBeLessThan(1024 * 1024);
  });

  it("剛好一個 chunk 就送完整包內容時也不算截斷", async () => {
    const res = await probe(`${origin}/?size=4000`, { maxBodyBytes: 4000 });
    expect(res.body.length).toBe(4000);
    expect(res.truncated).toBe(false);
  });
});

describe("probe — 重導向鏈上的 Cookie", () => {
  it("整條鏈的 Set-Cookie 都收得到", async () => {
    const res = await probe(`${origin}/redirect-chain`, { followRedirects: 3 });
    // 會話 Cookie 種在 302 上，只取最終回應的話它完全不會被稽核。
    expect(res.setCookies.some((c) => c.startsWith("connect.sid="))).toBe(true);
    expect(res.setCookies.some((c) => c.startsWith("theme="))).toBe(true);
    expect(res.redirects).toHaveLength(1);
  });

  it("不跟隨時只回第一跳，並保留 3xx 供判定", async () => {
    const res = await probe(`${origin}/redirect-chain`, { followRedirects: 0 });
    expect(res.status).toBe(302);
    expect(res.setCookies.some((c) => c.startsWith("connect.sid="))).toBe(true);
  });
});
