import { describe, expect, it } from "vitest";
import { looksLikeGatewayInterception } from "../src/core/http.js";

/**
 * 這組測試守的是掃描器最嚴重的失準方式：把「沒測到」報成「測到很糟」。
 *
 * 實際踩過：在有出口代理的環境跑掃描，代理對所有請求回 403，
 * 報告於是列出「缺 HSTS／缺 CSP／缺 nosniff／未導向 https」一整排 high 與 medium——
 * 全部無效，因為請求根本沒到達站台。
 */
describe("looksLikeGatewayInterception", () => {
  it("代理的裸 403 判定為攔截", () => {
    expect(
      looksLikeGatewayInterception({ status: 403, body: "Forbidden by proxy policy", contentType: "text/plain" }),
    ).toBe(true);
  });

  it("平台的 502 閘道頁判定為攔截", () => {
    expect(
      looksLikeGatewayInterception({
        status: 502,
        body: "<html><head><title>502 Bad Gateway</title></head><body><h1>502</h1></body></html>",
        contentType: "text/html",
      }),
    ).toBe(true);
  });

  it("代理驗證要求（407）判定為攔截", () => {
    expect(looksLikeGatewayInterception({ status: 407, body: "", contentType: "" })).toBe(true);
  });

  it("應用自己的 JSON 錯誤不算攔截——那是真實觀測，必須照常分析", () => {
    expect(
      looksLikeGatewayInterception({
        status: 401,
        body: '{"error":"請先登入"}',
        contentType: "application/json; charset=utf-8",
      }),
    ).toBe(false);
  });

  it("應用回的 SPA 錯誤頁不算攔截", () => {
    expect(
      looksLikeGatewayInterception({
        status: 404,
        body: '<!doctype html><html><body><div id="root"></div></body></html>',
        contentType: "text/html",
      }),
    ).toBe(false);
  });

  it("正常回應一律不是攔截", () => {
    expect(looksLikeGatewayInterception({ status: 200, body: "anything", contentType: "text/html" })).toBe(false);
    expect(looksLikeGatewayInterception({ status: 302, body: "", contentType: "" })).toBe(false);
  });
});
