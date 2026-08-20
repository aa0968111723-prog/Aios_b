/**
 * CORS 判定的測試。
 *
 * 這個偵測器要抓的是整套系統裡危害最直接的一種設定：反射任意 Origin ＋ allow-credentials，
 * 等於任何網站都能用受害者的登入 Cookie 呼叫 Aios API 並讀走回應。
 *
 * 而它最容易的失效方式是**比對太嚴**：伺服器把 Origin 正規化後回填（多一個尾端斜線、
 * 大小寫不同），字串 `===` 就不成立，於是一個 critical 漏洞得到零發現。
 */
import { describe, expect, it } from "vitest";
import { analyzeCors, normalizeOrigin, type CorsObservation } from "../src/detectors/cors.js";

const SENT = "https://sentinel-cors-probe.invalid";
const ctx = { surface: "web" as const, where: "https://example.test/api/health", sentOrigin: SENT };

const obs = (over: Partial<CorsObservation>): CorsObservation => ({
  allowOrigin: null,
  allowCredentials: null,
  allowMethods: null,
  allowHeaders: null,
  ...over,
});

const ids = (findings: ReturnType<typeof analyzeCors>) => findings.map((f) => f.id);

describe("normalizeOrigin", () => {
  it("尾端斜線與大小寫不影響同一性", () => {
    expect(normalizeOrigin("https://A.Test/")).toBe(normalizeOrigin("https://a.test"));
    expect(normalizeOrigin("https://a.test:443")).toBe(normalizeOrigin("https://a.test"));
  });

  it("不是合法網址時退回字串正規化，不丟例外", () => {
    expect(normalizeOrigin("*")).toBe("*");
    expect(normalizeOrigin("null")).toBe("null");
  });
});

describe("analyzeCors", () => {
  it("原樣反射 ＋ credentials ＝ critical", () => {
    const findings = analyzeCors(obs({ allowOrigin: SENT, allowCredentials: "true" }), ctx);
    expect(findings.find((f) => f.id === "cors.reflects-origin")?.severity).toBe("critical");
  });

  it("反射但沒放行 credentials 是 high", () => {
    expect(analyzeCors(obs({ allowOrigin: SENT }), ctx).find((f) => f.id === "cors.reflects-origin")?.severity).toBe("high");
  });

  // 這一組是本次修掉的缺陷：伺服器把 Origin 正規化後回填是最常見的寫法
  // （`new URL(req.headers.origin).href` 會多出尾端斜線），舊版的 === 完全比不到。
  it("回填值多一個尾端斜線仍算反射", () => {
    const findings = analyzeCors(obs({ allowOrigin: `${SENT}/`, allowCredentials: "true" }), ctx);
    expect(findings.find((f) => f.id === "cors.reflects-origin")?.severity).toBe("critical");
  });

  it("回填值大小寫不同仍算反射", () => {
    const findings = analyzeCors(obs({ allowOrigin: SENT.toUpperCase(), allowCredentials: "true" }), ctx);
    expect(ids(findings)).toContain("cors.reflects-origin");
  });

  it("白名單回填自家網域不是反射，不報", () => {
    expect(analyzeCors(obs({ allowOrigin: "https://ai-os-app.zeabur.app", allowCredentials: "true" }), ctx)).toEqual([]);
  });

  it("* 搭配 credentials 是 critical，單獨的 * 只是 low", () => {
    expect(analyzeCors(obs({ allowOrigin: "*", allowCredentials: "true" }), ctx).find((f) => f.id === "cors.wildcard")?.severity).toBe(
      "critical",
    );
    expect(analyzeCors(obs({ allowOrigin: "*" }), ctx).find((f) => f.id === "cors.wildcard")?.severity).toBe("low");
  });

  it("允許 null 來源報 high", () => {
    expect(ids(analyzeCors(obs({ allowOrigin: "null" }), ctx))).toContain("cors.null-origin");
  });

  it("證據欄位同時附上兩個標頭，方便重現", () => {
    const evidence = analyzeCors(obs({ allowOrigin: SENT, allowCredentials: "true" }), ctx)[0]?.evidence ?? "";
    expect(evidence).toContain("Access-Control-Allow-Origin");
    expect(evidence).toContain("Access-Control-Allow-Credentials");
  });
});
