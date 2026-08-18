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
