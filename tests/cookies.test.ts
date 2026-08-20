import { describe, expect, it } from "vitest";
import { analyzeCookies, looksLikeCredentialValue, looksLikeSessionCookie, parseSetCookie } from "../src/detectors/cookies.js";

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

  // 駝峰命名是 JS 生態最常見的寫法。漏掉它等於把最該抓的那類 Cookie 整批放掉，
  // 而且症狀是「報告上有一筆 low」——沒有人會去看。
  it.each(["authToken", "sessionToken", "refreshToken", "accessToken", "XSRF-TOKEN", "idToken"])(
    "%s（駝峰／全大寫）也判為會話類",
    (name) => {
      expect(looksLikeSessionCookie(name)).toBe(true);
    },
  );

  // 各框架的預設名沒有分隔符也拆不開，只能單獨列出。
  it.each(["csrftoken", "JSESSIONID", "PHPSESSID", "sessionid"])("%s（框架預設名）判為會話類", (name) => {
    expect(looksLikeSessionCookie(name)).toBe(true);
  });

  it.each(["__Host-sid", "__Secure-authToken"])("%s 的瀏覽器安全前綴不影響判定", (name) => {
    expect(looksLikeSessionCookie(name)).toBe(true);
  });

  it.each(["theme", "locale", "density", "_ga", "authorship", "tokenizer", "lastPage"])("%s 不是會話類", (name) => {
    expect(looksLikeSessionCookie(name)).toBe(false);
  });
});

describe("looksLikeCredentialValue", () => {
  it("JWT 值本身就是憑證的證據——名字可以任意取", () => {
    expect(looksLikeCredentialValue("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123")).toBe(true);
  });

  it("express cookie-parser 的簽章前綴（含 URL 編碼）", () => {
    expect(looksLikeCredentialValue("s:abc.def")).toBe(true);
    expect(looksLikeCredentialValue("s%3Aabc.def")).toBe(true);
  });

  it("又長又亂但不是憑證格式的值不算——分析 Cookie 本來就必須讓 JS 讀得到", () => {
    expect(looksLikeCredentialValue("GA1.1.1234567890.1234567890")).toBe(false);
    expect(looksLikeCredentialValue("dark")).toBe(false);
    expect(looksLikeCredentialValue("")).toBe(false);
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

  it("名字看不出來但值是 JWT 時，仍照會話憑證的等級處理", () => {
    const findings = analyzeCookies(["_aios_k=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig; Secure; SameSite=Lax"], ctx);
    expect(findings.find((f) => f.id === "cookies.httponly._aios_k")?.severity).toBe("critical");
  });

  it("駝峰命名的憑證 Cookie 缺 HttpOnly 一樣是 critical（過去會被降成 low）", () => {
    const findings = analyzeCookies(["authToken=abc123; Secure; SameSite=Lax"], ctx);
    expect(findings.find((f) => f.id === "cookies.httponly.authToken")?.severity).toBe("critical");
  });

  it("證據欄位不含 Cookie 值（避免報告本身變成外洩管道）", () => {
    const findings = analyzeCookies(["sid=super-secret-token-value; SameSite=Lax"], ctx);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.evidence ?? "").not.toContain("super-secret-token-value");
  });
});
