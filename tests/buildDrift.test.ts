import { describe, expect, it } from "vitest";
import { analyzeBuildDrift, type SurfaceBuild } from "../src/detectors/buildDrift.js";

const build = (over: Partial<SurfaceBuild> & Pick<SurfaceBuild, "surface">): SurfaceBuild => ({
  origin: "https://ai-os-app.zeabur.app",
  sha: "abc123",
  branch: "main",
  builtAt: "2026-01-01T00:00:00Z",
  reachable: true,
  ...over,
});

const ids = (findings: ReturnType<typeof analyzeBuildDrift>) => findings.map((f) => f.id);

describe("analyzeBuildDrift", () => {
  it("三端同源同版時沒有發現", () => {
    expect(analyzeBuildDrift([build({ surface: "web" }), build({ surface: "app" }), build({ surface: "desktop" })])).toEqual([]);
  });

  it("只有一端可連時不做漂移判定（沒有比較基準）", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web" }),
      build({ surface: "app", reachable: false, sha: null }),
      build({ surface: "desktop", reachable: false, sha: null }),
    ]);
    expect(findings).toEqual([]);
  });

  it("同一個站對不同端回不同版本＝high（快取或部署沒同步）", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa" }),
      build({ surface: "app", sha: "bbb" }),
    ]);
    const hit = findings.find((f) => f.id === "build-drift.sha-mismatch");
    expect(hit?.severity).toBe("high");
    expect(hit?.evidence).toContain("aaa");
    expect(hit?.evidence).toContain("bbb");
  });

  it("刻意指向不同部署時降為 info，不是故障", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa", origin: "https://prod.test" }),
      build({ surface: "desktop", sha: "bbb", origin: "https://staging.test" }),
    ]);
    expect(findings.find((f) => f.id === "build-drift.sha-mismatch")?.severity).toBe("info");
  });

  it("缺 SHA 的端會被列為比對盲區", () => {
    const findings = analyzeBuildDrift([build({ surface: "web" }), build({ surface: "app", sha: null })]);
    const hit = findings.find((f) => f.id === "build-drift.sha-missing");
    expect(hit?.severity).toBe("low");
    expect(hit?.title).toContain("app");
  });

  it("分支不一致單獨報 medium", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa", branch: "main" }),
      build({ surface: "app", sha: "bbb", branch: "hotfix" }),
    ]);
    expect(ids(findings)).toContain("build-drift.branch-mismatch");
  });

  it("全部端都缺 SHA 時只報盲區，不誤報漂移", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: null }),
      build({ surface: "app", sha: null }),
    ]);
    expect(ids(findings)).toEqual(["build-drift.sha-missing"]);
  });
});
