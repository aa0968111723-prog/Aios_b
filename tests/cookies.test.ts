import { describe, expect, it } from "vitest";
import { analyzeCookies, looksLikeSessionCookie, parseSetCookie } from "../src/detectors/cookies.js";

const ctx = { surface: "web" as const, where: "https://example.test/", https: true };

describe("parseSetCookie", () => {
  it("拆出名稱、值與屬性", () => {
    const cookie = parseSetCookie("sid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax");
    expect(cookie?.name).toBe("sid");
    expect(cookie?.value).toBe("abc123");
    expect(cookie?.attributes.has("httponly")).toBe(true);
    expect(cookie?.attributes.get("samesite")).toBe("Lax");
  });

  it("值含 = 時不會被截斷（base64 憑證常見）", () => {
    expect(parseSetCookie("token=aGVsbG8=; HttpOnly")?.value).toBe("aGVsbG8=");
  });

  it("格式不對回 null 而不是丟例外", () => {
    expect(parseSetCookie("garbage")).toBeNull();
  });
});

describe("looksLikeSessionCookie", () => {
  it.each(["sid", "session", "connect.sid", "auth_token", "refresh-token", "csrf"])("%s 判為會話類", (name) => {
    expect(looksLikeSessionCookie(name)).toBe(true);
  });

  it.each(["theme", "locale", "density"])("%s 不是會話類", (name) => {
    expect(looksLikeSessionCookie(name)).toBe(false);
  });
});

describe("analyzeCookies", () => {
  it("設定正確的會話 Cookie 不產生任何發現", () => {
    const findings = analyzeCookies(["sid=abc; Path=/; HttpOnly; Secure; SameSite=Lax"], ctx);
    expect(findings).toEqual([]);
  });

  it("會話 Cookie 缺 HttpOnly 是 critical", () => {
    const findings = analyzeCookies(["sid=abc; Secure; SameSite=Lax"], ctx);
    expect(findings.find((f) => f.id === "cookies.httponly.sid")?.severity).toBe("critical");
  });

  it("同一個缺陷在非會話 Cookie 上只是 low——嚴重度必須看用途", () => {
    const findings = analyzeCookies(["theme=dark; Secure; SameSite=Lax"], ctx);
    expect(findings.find((f) => f.id === "cookies.httponly.theme")?.severity).toBe("low");
  });

  it("SameSite=None 沒配 Secure 會被瀏覽器拒收，報 high", () => {
    const findings = analyzeCookies(["sid=abc; HttpOnly; SameSite=None"], ctx);
    expect(findings.find((f) => f.id === "cookies.samesite-none-insecure.sid")?.severity).toBe("high");
  });

  it("會話 Cookie 的 Domain 開到父網域會被指出", () => {
    const findings = analyzeCookies(["sid=abc; HttpOnly; Secure; SameSite=Lax; Domain=example.test"], ctx);
    expect(findings.find((f) => f.id === "cookies.domain-scope.sid")?.severity).toBe("medium");
  });

  it("Domain 指到完整子網域則不報", () => {
    const findings = analyzeCookies(["sid=abc; HttpOnly; Secure; SameSite=Lax; Domain=app.example.test"], ctx);
    expect(findings.map((f) => f.id)).not.toContain("cookies.domain-scope.sid");
  });

  it("本機 http 測試不因缺 Secure 誤報", () => {
    const findings = analyzeCookies(["sid=abc; HttpOnly; SameSite=Lax"], { ...ctx, https: false });
    expect(findings.map((f) => f.id)).not.toContain("cookies.secure.sid");
  });

  it("證據欄位不含 Cookie 值（避免報告本身變成外洩管道）", () => {
    const findings = analyzeCookies(["sid=super-secret-token-value; SameSite=Lax"], ctx);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.evidence ?? "").not.toContain("super-secret-token-value");
  });
});
