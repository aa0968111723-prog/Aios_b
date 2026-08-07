import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders } from "../src/detectors/headers.js";

const httpsCtx = { surface: "web" as const, where: "https://example.test/", https: true };
const httpCtx = { surface: "web" as const, where: "http://localhost:3000/", https: false };
const ids = (findings: ReturnType<typeof analyzeSecurityHeaders>) => findings.map((f) => f.id);

/** helmet 預設 + ai_os 的 CSP，作為「應該全綠」的基準。 */
const HARDENED: Record<string, string> = {
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "cross-origin-opener-policy": "same-origin",
  "content-security-policy":
    "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
};

describe("analyzeSecurityHeaders", () => {
  it("完整加固的回應沒有 low 以上的問題", () => {
    const findings = analyzeSecurityHeaders(HARDENED, httpsCtx);
    const notable = findings.filter((f) => f.severity !== "info");
    expect(notable).toEqual([]);
  });

  it("https 下缺 HSTS 報 high", () => {
    const { "strict-transport-security": _, ...rest } = HARDENED;
    const findings = analyzeSecurityHeaders(rest, httpsCtx);
    expect(findings.find((f) => f.id === "headers.hsts.missing")?.severity).toBe("high");
  });

  it("本機 http 測試不誤報 HSTS", () => {
    const findings = analyzeSecurityHeaders({ ...HARDENED, "strict-transport-security": "" }, httpCtx);
    expect(ids(findings)).not.toContain("headers.hsts.missing");
  });

  it("HSTS max-age 太短報 medium", () => {
    const findings = analyzeSecurityHeaders(
      { ...HARDENED, "strict-transport-security": "max-age=86400" },
      httpsCtx,
    );
    expect(findings.find((f) => f.id === "headers.hsts.short")?.severity).toBe("medium");
    expect(ids(findings)).toContain("headers.hsts.no-subdomains");
  });

  it("缺 nosniff 報 medium（素材上傳站的儲存型 XSS 風險）", () => {
    const { "x-content-type-options": _, ...rest } = HARDENED;
    expect(ids(analyzeSecurityHeaders(rest, httpsCtx))).toContain("headers.nosniff");
  });

  it("只要 CSP 有 frame-ancestors，缺 X-Frame-Options 不算沒防點擊劫持", () => {
    const { "x-frame-options": _, ...rest } = HARDENED;
    expect(ids(analyzeSecurityHeaders(rest, httpsCtx))).not.toContain("headers.clickjacking");
  });

  it("兩者都缺才報點擊劫持", () => {
    const { "x-frame-options": _, ...rest } = HARDENED;
    const findings = analyzeSecurityHeaders(
      { ...rest, "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'" },
      httpsCtx,
    );
    expect(ids(findings)).toContain("headers.clickjacking");
  });

  it("X-Frame-Options 用已失效的 ALLOW-FROM 會被指出", () => {
    const findings = analyzeSecurityHeaders({ ...HARDENED, "x-frame-options": "ALLOW-FROM https://a.test" }, httpsCtx);
    expect(ids(findings)).toContain("headers.xfo.invalid");
  });

  it("Referrer-Policy 為 unsafe-url 比缺少更嚴重", () => {
    const missing = analyzeSecurityHeaders(
      Object.fromEntries(Object.entries(HARDENED).filter(([k]) => k !== "referrer-policy")),
      httpsCtx,
    );
    const unsafe = analyzeSecurityHeaders({ ...HARDENED, "referrer-policy": "unsafe-url" }, httpsCtx);
    expect(missing.find((f) => f.id === "headers.referrer-policy")?.severity).toBe("low");
    expect(unsafe.find((f) => f.id === "headers.referrer-policy.unsafe")?.severity).toBe("medium");
  });

  it("洩漏技術棧與版本會被抓出來", () => {
    const findings = analyzeSecurityHeaders(
      { ...HARDENED, "x-powered-by": "Express", server: "nginx/1.25.3" },
      httpsCtx,
    );
    expect(ids(findings)).toContain("headers.x-powered-by");
    expect(ids(findings)).toContain("headers.server-version");
  });

  it("CSP 的指令級判定會一併帶進來", () => {
    const findings = analyzeSecurityHeaders(
      { ...HARDENED, "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-eval'" },
      httpsCtx,
    );
    expect(ids(findings)).toContain("csp.script-src.unsafe-eval");
  });
});
