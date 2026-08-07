import { describe, expect, it } from "vitest";
import { analyzeCsp, parseCsp } from "../src/detectors/csp.js";

const ctx = { surface: "web" as const, where: "https://example.test/" };
const ids = (findings: ReturnType<typeof analyzeCsp>) => findings.map((f) => f.id);

describe("parseCsp", () => {
  it("解析指令與來源", () => {
    const parsed = parseCsp("default-src 'self'; script-src 'self' https://cdn.test; object-src 'none'");
    expect(parsed.get("default-src")).toEqual(["'self'"]);
    expect(parsed.get("script-src")).toEqual(["'self'", "https://cdn.test"]);
    expect(parsed.get("object-src")).toEqual(["'none'"]);
  });

  it("重複指令以第一次出現為準（比照瀏覽器行為）", () => {
    const parsed = parseCsp("script-src 'self'; script-src *");
    expect(parsed.get("script-src")).toEqual(["'self'"]);
  });

  it("容忍多餘空白與結尾分號", () => {
    const parsed = parseCsp("  default-src   'self' ;  ");
    expect(parsed.get("default-src")).toEqual(["'self'"]);
  });
});

describe("analyzeCsp", () => {
  it("完全沒有 CSP 時只報缺失，不連帶噴出一堆指令級告警", () => {
    const findings = analyzeCsp(null, ctx);
    expect(ids(findings)).toEqual(["csp.missing"]);
    expect(findings[0]?.severity).toBe("high");
  });

  it("空字串視同沒有 CSP", () => {
    expect(ids(analyzeCsp("   ", ctx))).toEqual(["csp.missing"]);
  });

  it("抓出 unsafe-eval 與 unsafe-inline", () => {
    const findings = analyzeCsp("script-src 'self' 'unsafe-inline' 'unsafe-eval'", ctx);
    expect(ids(findings)).toContain("csp.script-src.unsafe-eval");
    expect(ids(findings)).toContain("csp.script-src.unsafe-inline");
  });

  it("有 nonce 時不把 unsafe-inline 報成問題（現代瀏覽器會忽略它）", () => {
    const findings = analyzeCsp("script-src 'self' 'unsafe-inline' 'nonce-abc123'", ctx);
    expect(ids(findings)).not.toContain("csp.script-src.unsafe-inline");
  });

  it("script-src 用 * 比用 https: 更嚴重", () => {
    const star = analyzeCsp("script-src *", ctx).find((f) => f.id === "csp.script-src.wildcard");
    const scheme = analyzeCsp("script-src https:", ctx).find((f) => f.id === "csp.script-src.wildcard");
    expect(star?.severity).toBe("high");
    expect(scheme?.severity).toBe("medium");
  });

  it("script-src 缺席時沿用 default-src，並標記為繼承", () => {
    const findings = analyzeCsp("default-src 'self'", ctx);
    expect(ids(findings)).toContain("csp.script-src.inherited");
    expect(ids(findings)).not.toContain("csp.script-src.unrestricted");
  });

  it("既無 script-src 也無 default-src 時報未限制", () => {
    const findings = analyzeCsp("img-src 'self'", ctx);
    expect(ids(findings)).toContain("csp.script-src.unrestricted");
  });

  it("frame-ancestors 不吃 default-src 的兜底", () => {
    // 有 default-src 'none' 也不能算擋住點擊劫持——這是 CSP 規格的特例，最容易寫錯的一條
    const findings = analyzeCsp("default-src 'none'", ctx);
    expect(ids(findings)).toContain("csp.frame-ancestors");
  });

  it("ai_os 現況的 style-src unsafe-inline 只報 low", () => {
    const findings = analyzeCsp("default-src 'self'; style-src 'self' 'unsafe-inline'", ctx);
    const styleFinding = findings.find((f) => f.id === "csp.style-src.unsafe-inline");
    expect(styleFinding?.severity).toBe("low");
  });

  it("設定良好的政策只剩參考級的回報項", () => {
    const good =
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; report-to csp-endpoint";
    const findings = analyzeCsp(good, ctx);
    expect(findings.every((f) => f.severity === "info")).toBe(true);
  });

  it("每筆發現都帶得走的修法", () => {
    const findings = analyzeCsp("script-src * 'unsafe-eval'", ctx);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect((f.remediation ?? "").length).toBeGreaterThan(0);
  });
});
