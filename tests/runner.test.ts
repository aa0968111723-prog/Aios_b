import { describe, expect, it } from "vitest";
import { exitCodeFor, runChecks } from "../src/core/runner.js";
import { finding } from "../src/core/findings.js";
import { buildSurfaces } from "../src/core/surfaces.js";
import type { CheckResult, RunReport, SentinelConfig, Severity } from "../src/core/types.js";

const config: SentinelConfig = {
  target: "https://example.test",
  surfaces: buildSurfaces("https://example.test"),
  routes: [],
  outDir: "./reports",
  failOn: "high",
  timeoutMs: 1000,
  screenshots: false,
};

const result = (over: Partial<CheckResult> = {}): CheckResult => ({
  check: "t",
  category: "security",
  surface: "web",
  completed: true,
  durationMs: 1,
  findings: [],
  ...over,
});

const report = (over: Partial<RunReport["summary"]> = {}): RunReport => ({
  startedAt: "",
  finishedAt: "",
  durationMs: 0,
  target: "t",
  surfaces: ["web"],
  results: [],
  summary: {
    total: 1,
    completed: 1,
    skipped: 0,
    errored: 0,
    findings: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    worst: null,
    ...over,
  },
});

describe("runChecks", () => {
  it("單一檢查丟例外不會拖垮整輪，其餘照跑", async () => {
    const run = await runChecks(config, [
      {
        name: "explodes",
        category: "security",
        surface: "web",
        run: async () => {
          throw new Error("boom");
        },
      },
      {
        name: "fine",
        category: "security",
        surface: "web",
        run: async () =>
          result({
            check: "fine",
            findings: [
              finding({
                id: "x",
                check: "fine",
                category: "security",
                severity: "high",
                surface: "web",
                title: "t",
                detail: "d",
                remediation: "r",
              }),
            ],
          }),
      },
    ]);

    expect(run.results).toHaveLength(2);
    expect(run.results[0]?.error).toContain("boom");
    expect(run.results[0]?.completed).toBe(false);
    expect(run.results[1]?.findings).toHaveLength(1);
    expect(run.summary.errored).toBe(1);
    expect(run.summary.worst).toBe("high");
  });

  it("跳過與執行錯誤分開統計", async () => {
    const run = await runChecks(config, [
      { name: "a", category: "page", surface: "web", run: async () => result({ completed: false, skippedReason: "缺瀏覽器" }) },
      {
        name: "b",
        category: "page",
        surface: "web",
        run: async () => {
          throw new Error("nope");
        },
      },
    ]);
    expect(run.summary.skipped).toBe(1);
    expect(run.summary.errored).toBe(1);
    expect(run.summary.completed).toBe(0);
  });
});

describe("exitCodeFor", () => {
  it("一切通過回 0", () => {
    expect(exitCodeFor(report(), "high")).toBe(0);
  });

  it("達門檻的發現回 1", () => {
    expect(exitCodeFor(report({ worst: "high" as Severity }), "high")).toBe(1);
  });

  it("低於門檻回 0", () => {
    expect(exitCodeFor(report({ worst: "low" as Severity }), "high")).toBe(0);
  });

  it("檢查器自身出錯且沒有任何發現回 2", () => {
    expect(exitCodeFor(report({ errored: 1 }), "high")).toBe(2);
  });

  it("什麼都沒實際跑到回 3——不能讓 CI 顯示綠燈", () => {
    expect(exitCodeFor(report({ completed: 0, skipped: 5, total: 5 }), "high")).toBe(3);
  });

  it("全部跳過時，即使門檻很寬也不回 0", () => {
    expect(exitCodeFor(report({ completed: 0, skipped: 3, total: 3 }), "info")).toBe(3);
  });
});
