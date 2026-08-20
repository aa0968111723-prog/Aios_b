import { describe, expect, it } from "vitest";
import { analyzeZeabur, analyzeZeaburDeployments, classifyPlatformError } from "../src/detectors/zeabur.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;
const ids = (f: Array<{ id: string }>) => f.map((x) => x.id);

describe("classifyPlatformError", () => {
  it("2xx＝ok", () => {
    expect(classifyPlatformError({ status: 200, body: "<html></html>", contentType: "text/html", server: "zeabur" })).toBe("ok");
  });

  it("帶 SPA 外殼的 5xx＝應用錯誤（該查應用碼）", () => {
    expect(
      classifyPlatformError({ status: 500, body: `<div id="root"></div>`, contentType: "text/html", server: null }),
    ).toBe("app-error");
  });

  it("應用 JSON 錯誤＝應用錯誤", () => {
    expect(
      classifyPlatformError({ status: 500, body: `{"error":"boom","code":500}`, contentType: "application/json", server: null }),
    ).toBe("app-error");
  });

  it("裸 502／504＝邊緣錯誤（該查平台）", () => {
    expect(classifyPlatformError({ status: 502, body: "Bad Gateway", contentType: "text/plain", server: "nginx" })).toBe("edge-5xx");
    expect(classifyPlatformError({ status: 504, body: "Gateway Timeout", contentType: "text/plain", server: null })).toBe("edge-5xx");
  });

  it("非 5xx 的裸錯誤（403）＝閘道攔截", () => {
    expect(classifyPlatformError({ status: 403, body: "Forbidden", contentType: "text/plain", server: "proxy" })).toBe("gateway");
  });
});

describe("analyzeZeabur", () => {
  it("邊緣 502＝high", () => {
    const findings = analyzeZeabur(
      { root: { status: 502, body: "Bad Gateway", contentType: "text/plain", server: "nginx" } },
      web,
    );
    expect(ids(findings)).toContain("zeabur.edge-5xx");
    expect(findings.find((f) => f.id === "zeabur.edge-5xx")?.severity).toBe("high");
  });

  it("storage 分項未通過且 note 指向非持久磁碟＝high", () => {
    const findings = analyzeZeabur(
      {
        root: { status: 200, body: `<div id="root"></div>`, contentType: "text/html", server: "zeabur" },
        storageOk: false,
        storageNote: "素材存在容器本地磁碟非持久——重新部署會遺失",
      },
      web,
    );
    expect(ids(findings)).toContain("zeabur.ephemeral-storage");
  });

  // note 是自然語言，純子字串比對讀不出否定語意。舊版只看 note，於是
  // 「Volume 已掛載，重新部署不會遺失素材」同時命中「Volume」與「遺失」兩組樣式——
  // 把設定講清楚的健康站台，反而比含糊的更容易被誤報成 high。
  it("storage 分項通過時，note 寫得再詳細也不誤報", () => {
    const findings = analyzeZeabur(
      {
        root: { status: 200, body: `<div id="root"></div>`, contentType: "text/html", server: "zeabur" },
        storageOk: true,
        storageNote: "ASSET_DIR=/data；Volume 已掛載，重新部署不會遺失素材",
      },
      web,
    );
    expect(ids(findings)).not.toContain("zeabur.ephemeral-storage");
  });

  it("拿不到 storage 分項狀態時不猜——沒有前提就不下判定", () => {
    const findings = analyzeZeabur(
      {
        root: { status: 200, body: `<div id="root"></div>`, contentType: "text/html", server: "zeabur" },
        storageNote: "Volume 遺失",
      },
      web,
    );
    expect(ids(findings)).not.toContain("zeabur.ephemeral-storage");
  });

  it("健康的站台不報平台錯誤", () => {
    const findings = analyzeZeabur(
      { root: { status: 200, body: `<div id="root"></div>`, contentType: "text/html", server: "zeabur" }, storageNote: "ok" },
      web,
    );
    expect(findings).toEqual([]);
  });
});

describe("analyzeZeaburDeployments", () => {
  it("最近一次部署失敗＝high", () => {
    const findings = analyzeZeaburDeployments([{ status: "FAILED", createdAt: "2026-08-18" }]);
    expect(ids(findings)).toEqual(["zeabur.deploy-failed"]);
  });

  it("最近一次部署成功＝無發現", () => {
    expect(analyzeZeaburDeployments([{ status: "SUCCEEDED" }])).toEqual([]);
  });
});
