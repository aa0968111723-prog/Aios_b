import { describe, expect, it } from "vitest";
import { analyzeMethods, parseAllowHeader, type MethodObservation } from "../src/detectors/methods.js";

const apiCtx = { surface: "web" as const, where: "https://example.test/api/v1/databases", isApi: true };
const siteCtx = { surface: "web" as const, where: "https://example.test/", isApi: false };

/** 一筆「什麼都沒觀測到」的基準，各測試只覆寫自己關心的欄位。 */
function observe(patch: Partial<MethodObservation> = {}): MethodObservation {
  return {
    path: "/api/v1/databases",
    allow: null,
    traceStatus: null,
    traceEchoesRequest: false,
    traceBodySnippet: null,
    ...patch,
  };
}

const ids = (findings: ReturnType<typeof analyzeMethods>) => findings.map((f) => f.id);

describe("parseAllowHeader", () => {
  it("拆開逗號分隔並統一成大寫", () => {
    expect(parseAllowHeader("get, post, options")).toEqual(["GET", "POST", "OPTIONS"]);
  });

  it("去掉方法之間的多餘空白與換行（代理折行時常見）", () => {
    expect(parseAllowHeader("GET ,\tHEAD,\r\n POST")).toEqual(["GET", "HEAD", "POST"]);
  });

  // 多層代理各自補一次 Allow 時同一個方法會出現兩遍，那不代表它比較危險，
  // 不去重會讓「方法數異常多」的判定被重複值灌爆。
  it("重複的方法只留一次", () => {
    expect(parseAllowHeader("GET, get, GET, PUT")).toEqual(["GET", "PUT"]);
  });

  it("連續逗號不會變成空字串方法", () => {
    expect(parseAllowHeader("GET,,POST,")).toEqual(["GET", "POST"]);
  });

  it("沒有 Allow 標頭（null／空字串）回空陣列，而不是丟例外", () => {
    expect(parseAllowHeader(null)).toEqual([]);
    expect(parseAllowHeader("")).toEqual([]);
    expect(parseAllowHeader("   ")).toEqual([]);
  });
});

describe("analyzeMethods：TRACE", () => {
  it("TRACE 回 200 但沒有回吐＝medium", () => {
    const findings = analyzeMethods(observe({ traceStatus: 200 }), apiCtx);
    expect(findings.find((f) => f.id === "methods.trace.enabled")?.severity).toBe("medium");
  });

  it("204 一樣算 2xx（可用）", () => {
    expect(ids(analyzeMethods(observe({ traceStatus: 204 }), apiCtx))).toContain("methods.trace.enabled");
  });

  it("回吐請求時只報 echo（high），不再重複報一筆 enabled", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, traceEchoesRequest: true, traceBodySnippet: "TRACE / HTTP/1.1" }),
      apiCtx,
    );
    expect(findings.find((f) => f.id === "methods.trace.echo")?.severity).toBe("high");
    expect(ids(findings)).not.toContain("methods.trace.enabled");
  });

  it("TRACE 被站台擋掉（405）是正確行為，不產生任何發現", () => {
    expect(analyzeMethods(observe({ traceStatus: 405 }), apiCtx)).toEqual([]);
  });

  // 「沒測到」與「沒問題」必須分開：未判定要留下一筆 info 紀錄，
  // 而不是安靜地變成一份看起來全綠的報告。
  it("traceStatus 為 null＝未判定，留下 info 紀錄", () => {
    const findings = analyzeMethods(observe(), apiCtx);
    expect(findings.find((f) => f.id === "methods.trace.unknown")?.severity).toBe("info");
  });

  it("未判定不會退化成 enabled 或 echo", () => {
    const findings = analyzeMethods(observe({ traceEchoesRequest: true }), apiCtx);
    expect(ids(findings)).toEqual(["methods.trace.unknown"]);
  });
});

describe("analyzeMethods：Allow", () => {
  it("Allow 含 PUT／DELETE／PATCH 報 medium 並列出實際命中的方法", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT, DELETE" }), apiCtx);
    const hit = findings.find((f) => f.id === "methods.dangerous-allowed");
    expect(hit?.severity).toBe("medium");
    expect(hit?.title).toContain("PUT");
    expect(hit?.title).toContain("DELETE");
    expect(hit?.title).not.toContain("GET");
  });

  it("小寫寫法一樣抓得到（正規化後才比對）", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "get, patch" }), apiCtx);
    expect(ids(findings)).toContain("methods.dangerous-allowed");
  });

  it("只有讀取類方法時不報", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET, HEAD, POST, OPTIONS" }), apiCtx);
    expect(ids(findings)).not.toContain("methods.dangerous-allowed");
  });

  // 這條是紅線：我們從來沒有真的送出 PUT／DELETE 去驗證，所以文案不可以把
  // Allow 的自述講成已經證實的漏洞，否則讀者會照著一個不存在的結論去排優先序。
  it("文案把 Allow 講成自述而非已證實可用，並要求人工確認認證保護", () => {
    const detail = analyzeMethods(observe({ traceStatus: 405, allow: "GET, DELETE" }), apiCtx)
      .find((f) => f.id === "methods.dangerous-allowed")?.detail ?? "";
    expect(detail).toContain("自述");
    expect(detail).toContain("不代表未授權");
    expect(detail).toContain("認證");
  });

  it("API 路徑與一般路徑給出不同的說明（嚴重度看用途）", () => {
    const onApi = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT" }), apiCtx)
      .find((f) => f.id === "methods.dangerous-allowed");
    const onSite = analyzeMethods(observe({ traceStatus: 405, allow: "GET, PUT", path: "/" }), siteCtx)
      .find((f) => f.id === "methods.dangerous-allowed");
    expect(onApi?.detail).not.toBe(onSite?.detail);
    expect(onSite?.detail).toContain("預設值");
  });

  it("方法數超過 6 個報 low（框架預設全開的徵兆）", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 405, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(findings.find((f) => f.id === "methods.allow-verbose")?.severity).toBe("low");
  });

  it("剛好 6 個不算異常多（門檻邊界）", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET,HEAD,POST,PUT,DELETE,OPTIONS" }), apiCtx);
    expect(ids(findings)).not.toContain("methods.allow-verbose");
  });

  it("重複值不會把方法數灌到超過門檻", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: "GET,GET,GET,HEAD,HEAD,POST,POST,OPTIONS" }), apiCtx);
    expect(ids(findings)).not.toContain("methods.allow-verbose");
  });

  it("沒有 Allow 標頭時不產生任何 Allow 相關發現", () => {
    const findings = analyzeMethods(observe({ traceStatus: 405, allow: null }), apiCtx);
    expect(findings).toEqual([]);
  });
});

describe("analyzeMethods：發現本身的品質", () => {
  it("每一筆都帶得動手的修法與觸發位置", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, traceEchoesRequest: true, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(findings.length).toBe(3);
    for (const f of findings) {
      expect(f.remediation ?? "").not.toBe("");
      expect(f.where).toBe(apiCtx.where);
      expect(f.check).toBe("methods");
      expect(f.category).toBe("security");
    }
  });

  // id 是跨次執行比對與抑制清單的鍵，混進路徑或時間戳就會讓同一個問題每次都算「新增」。
  it("id 穩定：不含路徑、時間戳或隨機值", () => {
    const findings = analyzeMethods(
      observe({ traceStatus: 200, allow: "GET,HEAD,POST,PUT,DELETE,PATCH,OPTIONS" }),
      apiCtx,
    );
    expect(ids(findings).sort()).toEqual([
      "methods.allow-verbose",
      "methods.dangerous-allowed",
      "methods.trace.enabled",
    ]);
  });
});
