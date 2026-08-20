import { describe, expect, it } from "vitest";
import {
  analyzeDbExposure,
  analyzeDbTraffic,
  detectPublicStudioRoute,
  summarizeSamples,
  type ReadySample,
} from "../src/detectors/dbTraffic.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;
const ids = (f: Array<{ id: string }>) => f.map((x) => x.id);

const sample = (over: Partial<ReadySample>): ReadySample => ({
  status: 200,
  latencyMs: 120,
  ok: true,
  dbOk: true,
  unreachable: false,
  ...over,
});

describe("summarizeSamples", () => {
  it("彙整可達數、逾時數與延遲", () => {
    const stats = summarizeSamples([
      sample({ latencyMs: 100 }),
      sample({ latencyMs: 300 }),
      sample({ unreachable: true, latencyMs: 0, ok: null, dbOk: null }),
    ]);
    expect(stats.samples).toBe(3);
    expect(stats.reachable).toBe(2);
    expect(stats.timeouts).toBe(1);
    expect(stats.avgLatencyMs).toBe(200);
    expect(stats.maxLatencyMs).toBe(300);
  });
});

describe("analyzeDbTraffic", () => {
  it("db 分項失敗＝critical（讀寫進出中斷）", () => {
    const { findings } = analyzeDbTraffic([sample({ dbOk: false, dbNote: "connection refused" })], web);
    expect(ids(findings)).toContain("db.unreachable");
    expect(findings.find((f) => f.id === "db.unreachable")?.severity).toBe("critical");
  });

  it("全數逾時＝high（連線池疑似耗盡）", () => {
    const s = sample({ unreachable: true, latencyMs: 0, ok: null, dbOk: null });
    const { findings } = analyzeDbTraffic([s, s, s], web);
    expect(ids(findings)).toEqual(["db.ready-timeout"]);
  });

  it("往返偏慢＝medium", () => {
    const { findings } = analyzeDbTraffic([sample({ latencyMs: 2000 }), sample({ latencyMs: 1800 })], web);
    expect(ids(findings)).toContain("db.slow-roundtrip");
  });

  it("健康且快速＝無發現", () => {
    const { findings } = analyzeDbTraffic([sample({ latencyMs: 120 }), sample({ latencyMs: 90 })], web);
    expect(findings).toEqual([]);
  });
});

describe("detectPublicStudioRoute", () => {
  it("start 腳本綁 drizzle-kit studio＝公開介面", () => {
    const pkg = JSON.stringify({
      scripts: { start: "node server.js & drizzle-kit studio --host 0.0.0.0", "db:studio": "drizzle-kit studio" },
    });
    expect(detectPublicStudioRoute([{ where: "package.json", content: pkg }])).toMatch(/scripts\.start/);
  });

  it("僅本機 db:studio 腳本＝不報（開發者自開）", () => {
    const pkg = JSON.stringify({ scripts: { start: "node dist/index.js", "db:studio": "drizzle-kit studio" } });
    expect(detectPublicStudioRoute([{ where: "package.json", content: pkg }])).toBeNull();
  });

  it("伺服器掛 /studio 路由＝公開介面", () => {
    const src = `app.use("/studio", drizzleStudioHandler);\napp.get("/api/health", ok);`;
    expect(detectPublicStudioRoute([{ where: "server/index.ts", content: src }])).toBe("server/index.ts: /studio");
  });

  it("無關伺服器碼＝不報", () => {
    expect(
      detectPublicStudioRoute([{ where: "server/index.ts", content: `app.get("/api/ready", ready);` }]),
    ).toBeNull();
  });
});

describe("analyzeDbExposure", () => {
  it("連線字串出現在前端＝critical", () => {
    const findings = analyzeDbExposure({ clientReferencesDbUrl: true, publicStudioRoute: null });
    expect(ids(findings)).toContain("db.url-in-client");
  });

  it("有公開的資料庫管理介面＝high", () => {
    const findings = analyzeDbExposure({ clientReferencesDbUrl: false, publicStudioRoute: "/studio" });
    expect(ids(findings)).toContain("db.public-studio");
  });

  it("兩者都無＝無發現", () => {
    expect(analyzeDbExposure({ clientReferencesDbUrl: false, publicStudioRoute: null })).toEqual([]);
  });
});

/**
 * 間歇逾時：這個模組的檔頭一開始就宣稱要抓「連線池耗盡的典型症狀」，
 * 但舊版只判「全數逾時」。3 次取樣有 2 次連不上時，報告是「檢查完成、零發現」——
 * 而間歇比全數更難查，因為健康檢查與人工重試常常剛好落在成功的那幾次。
 */
describe("analyzeDbTraffic — 間歇逾時", () => {
  it("有些成功、有些逾時＝high，不是零發現", () => {
    const { findings } = analyzeDbTraffic(
      [sample({ unreachable: true, ok: null, dbOk: null, latencyMs: 0 }), sample({ latencyMs: 120 }), sample({ unreachable: true, ok: null, dbOk: null, latencyMs: 0 })],
      web,
    );
    const hit = findings.find((f) => f.id === "db.ready-intermittent");
    expect(hit?.severity).toBe("high");
    expect(hit?.evidence).toContain("2/3");
  });

  it("全部逾時仍走 db.ready-timeout，不會變成間歇", () => {
    const { findings } = analyzeDbTraffic(
      [sample({ unreachable: true, ok: null, dbOk: null, latencyMs: 0 }), sample({ unreachable: true, ok: null, dbOk: null, latencyMs: 0 })],
      web,
    );
    expect(ids(findings)).toContain("db.ready-timeout");
    expect(ids(findings)).not.toContain("db.ready-intermittent");
  });

  it("全部成功且不慢時零發現", () => {
    const { findings } = analyzeDbTraffic([sample({ latencyMs: 80 }), sample({ latencyMs: 90 })], web);
    expect(findings).toEqual([]);
  });

  it("間歇逾時與偏慢可以同時成立——兩件事都值得說", () => {
    const { findings } = analyzeDbTraffic(
      [sample({ unreachable: true, ok: null, dbOk: null, latencyMs: 0 }), sample({ latencyMs: 4000 })],
      web,
    );
    expect(ids(findings)).toContain("db.ready-intermittent");
    expect(ids(findings)).toContain("db.slow-roundtrip");
  });
});
