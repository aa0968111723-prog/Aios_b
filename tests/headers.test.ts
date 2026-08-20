import { describe, expect, it } from "vitest";
import { analyzeSecurityHeaders } from "../src/detectors/headers.js";
import { analyzeCsp } from "../src/detectors/csp.js";

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

/**
 * CSP 只寫在 meta 標籤時的判定。
 *
 * 舊版一律報「缺少 Content-Security-Policy」（high），detail 還寫著「任何被注入的腳本都能
 * 直接執行」——但瀏覽器確實在執行那份 meta 政策，敘述根本不成立。說錯話的告警只要被抓到
 * 一次，讀者就不會再相信整份報告。
 */
describe("analyzeCsp — meta 版本的政策", () => {
  const ctx = { surface: "web" as const, where: "https://example.test/" };
  const ids = (f: ReturnType<typeof analyzeCsp>) => f.map((x) => x.id);

  it("標頭沒有但 meta 有時，不報「缺少 CSP」", () => {
    const findings = analyzeCsp(null, { ...ctx, metaCsp: "default-src 'self'; script-src 'self'" });
    expect(ids(findings)).not.toContain("csp.missing");
    expect(findings.find((f) => f.id === "csp.header-missing-meta-only")?.severity).toBe("medium");
  });

  it("meta 的政策仍會做指令級分析", () => {
    const findings = analyzeCsp(null, { ...ctx, metaCsp: "default-src 'self'; script-src 'self' 'unsafe-eval'" });
    expect(ids(findings)).toContain("csp.script-src.unsafe-eval");
  });

  it("meta 裡的 frame-ancestors 會被瀏覽器忽略，所以照樣算沒有防護", () => {
    const findings = analyzeCsp(null, { ...ctx, metaCsp: "default-src 'self'; frame-ancestors 'none'" });
    expect(ids(findings)).toContain("csp.frame-ancestors");
  });

  it("兩邊都沒有才是真的缺少 CSP", () => {
    expect(ids(analyzeCsp(null, { ...ctx, metaCsp: null }))).toEqual(["csp.missing"]);
  });

  it("有標頭時以標頭為準，不受 meta 影響", () => {
    const findings = analyzeCsp("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'", {
      ...ctx,
      metaCsp: "script-src 'unsafe-eval'",
    });
    expect(ids(findings)).not.toContain("csp.script-src.unsafe-eval");
    expect(ids(findings)).not.toContain("csp.header-missing-meta-only");
  });
});

/**
 * `'strict-dynamic'`：業界建議的嚴格 CSP 寫法，卻最容易被掃描器誤報。
 *
 * 依 CSP3 規格，來源清單一旦含 'strict-dynamic'，所有 host-source 與 scheme-source
 * （含 https:）與 'unsafe-inline' 都會被瀏覽器忽略——那些 https: 是刻意留給舊瀏覽器的回退值。
 */
describe("analyzeCsp — strict-dynamic", () => {
  const ctx = { surface: "web" as const, where: "https://example.test/" };
  const ids = (f: ReturnType<typeof analyzeCsp>) => f.map((x) => x.id);

  it("有 nonce 的 strict-dynamic 不報過寬來源", () => {
    const findings = analyzeCsp("script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'; default-src 'self'", ctx);
    expect(ids(findings)).not.toContain("csp.script-src.wildcard");
    expect(ids(findings)).not.toContain("csp.script-src.unsafe-inline");
  });

  it("但沒有 nonce 的 strict-dynamic 是真的有問題——兩種結局都不是本意", () => {
    const findings = analyzeCsp("script-src 'strict-dynamic' https:; default-src 'self'", ctx);
    expect(findings.find((f) => f.id === "csp.script-src.strict-dynamic-without-nonce")?.severity).toBe("high");
  });

  it("沒有 strict-dynamic 時 https: 照樣算過寬", () => {
    expect(ids(analyzeCsp("script-src 'self' https:; default-src 'self'", ctx))).toContain("csp.script-src.wildcard");
  });
});
