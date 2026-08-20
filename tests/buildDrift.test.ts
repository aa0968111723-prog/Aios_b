import { describe, expect, it } from "vitest";
import { analyzeBuildDrift, originKey, type SurfaceBuild } from "../src/detectors/buildDrift.js";

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
    expect(findings.find((f) => f.id === "build-drift.cross-origin")?.severity).toBe("info");
    expect(ids(findings)).not.toContain("build-drift.sha-mismatch");
  });

  // 這一組全部針對同一個缺陷：判準是「以 origin 分組」，不是「全體是否同源」。
  // 舊版只要有一端指向別處，就把整組判為異源，於是另外兩端之間真正的同源漂移
  // 被降成 info 並附上一句「這是預期結果」——那正是這項檢查存在的唯一理由。
  it("有一端指向 staging 時，另外兩端之間的同源漂移仍然是 high", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa", origin: "https://prod.test" }),
      build({ surface: "app", sha: "bbb", origin: "https://prod.test" }),
      build({ surface: "desktop", sha: "ccc", origin: "https://staging.test" }),
    ]);
    const drift = findings.find((f) => f.id === "build-drift.sha-mismatch");
    expect(drift?.severity).toBe("high");
    expect(drift?.evidence).toContain("aaa");
    expect(drift?.evidence).toContain("bbb");
    expect(drift?.evidence).not.toContain("ccc"); // 證據只列該 origin 底下的那幾端
    expect(ids(findings)).toContain("build-drift.cross-origin");
  });

  it("主機名大小寫與顯式預設埠不算異源", () => {
    expect(originKey("https://Prod.test")).toBe(originKey("https://prod.test"));
    expect(originKey("https://prod.test:443")).toBe(originKey("https://prod.test"));
    expect(originKey("https://prod.test/")).toBe(originKey("https://prod.test"));
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa", origin: "https://Prod.test" }),
      build({ surface: "app", sha: "bbb", origin: "https://prod.test" }),
    ]);
    expect(findings.find((f) => f.id === "build-drift.sha-mismatch")?.severity).toBe("high");
  });

  it("跨部署的分支差異是設定意圖，不再單獨報 medium", () => {
    const findings = analyzeBuildDrift([
      build({ surface: "web", sha: "aaa", branch: "main", origin: "https://prod.test" }),
      build({ surface: "desktop", sha: "bbb", branch: "develop", origin: "https://staging.test" }),
    ]);
    expect(ids(findings)).not.toContain("build-drift.branch-mismatch");
  });

  it("缺 SHA 的端會被列為比對盲區", () => {
    const findings = analyzeBuildDrift([build({ surface: "web" }), build({ surface: "app", sha: null })]);
    const hit = findings.find((f) => f.id === "build-drift.sha-missing");
    expect(hit?.severity).toBe("low");
    expect(hit?.title).toContain("app");
  });

  it("同一個站台吐出兩個分支時單獨報 medium", () => {
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
