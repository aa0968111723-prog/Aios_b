import { describe, expect, it } from "vitest";
import { exitCodeFor, perOrigin, perSurface, runChecks } from "../src/core/runner.js";
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
    suppressed: 0,
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

/**
 * `--fail-on-new` 的語意測試。
 *
 * 這個模式最容易寫出的錯誤是「有基準就一律放行」——那會讓存量的 critical 永遠沒人處理，
 * 也會讓一筆 low 悄悄變成 critical 而不被擋下。所以這裡逐條把語意釘死。
 */
describe("exitCodeFor — --fail-on-new", () => {
  const f = (id: string, severity: Severity) =>
    finding({ id, check: "t", category: "security", surface: "web", severity, title: id, detail: "d", remediation: "r" });

  const withDiff = (diff: Partial<NonNullable<RunReport["diff"]>>, worst: Severity | null): RunReport => ({
    ...report({ worst }),
    diff: { baselineTarget: null, baselineStartedAt: null, added: [], fixed: [], unchanged: [], changed: [], ...diff },
  });

  it("只有存量問題時放行——既有專案才導得進來", () => {
    expect(exitCodeFor(withDiff({ unchanged: [f("a", "critical")] }, "critical"), "high", { onlyNew: true })).toBe(0);
  });

  it("新增達門檻就擋下", () => {
    expect(exitCodeFor(withDiff({ added: [f("b", "high")] }, "high"), "high", { onlyNew: true })).toBe(1);
  });

  it("新增但未達門檻不擋", () => {
    expect(exitCodeFor(withDiff({ added: [f("c", "low")] }, "low"), "high", { onlyNew: true })).toBe(0);
  });

  it("嚴重度惡化等同新增——危害不會因為它上次就在而減少", () => {
    const changed = [{ key: "d::", before: f("d", "low"), after: f("d", "critical") }];
    expect(exitCodeFor(withDiff({ changed }, "critical"), "high", { onlyNew: true })).toBe(1);
  });

  it("嚴重度減輕不算惡化", () => {
    const changed = [{ key: "e::", before: f("e", "critical"), after: f("e", "low") }];
    expect(exitCodeFor(withDiff({ changed }, "low"), "high", { onlyNew: true })).toBe(0);
  });

  it("沒有基準可比時退回一般判準——不能因為拿不到基準就放行", () => {
    expect(exitCodeFor(report({ worst: "critical" as Severity }), "high", { onlyNew: true })).toBe(1);
  });

  it("什麼都沒跑到仍然回 3，優先於新增判定", () => {
    const nothing = { ...withDiff({ added: [f("g", "critical")] }, "critical"), summary: { ...report().summary, completed: 0, total: 3, skipped: 3 } };
    expect(exitCodeFor(nothing, "high", { onlyNew: true })).toBe(3);
  });
});

/**
 * `perOrigin` 的語意測試。
 *
 * 這個輔助函式存在的理由是「憑證不會因為 UA 而不同」。寫錯的兩種方式都有代價：
 * 退化成 perSurface 會讓同一份判定重複三次並讓請求量變成三倍；
 * 寫死成「只跑 web」則會在三端各指不同部署時漏驗另外兩個站。
 */
describe("perOrigin", () => {
  const task = async () => result();

  it("三端同源時只展開一項，且標為 all（那筆發現不屬於任何單一載體）", () => {
    const planned = perOrigin(buildSurfaces("https://example.test"), "tls", "security", () => task);
    expect(planned).toHaveLength(1);
    expect(planned[0]?.surface).toBe("all");
  });

  it("三端各指不同部署時每個 origin 都要驗——不能只驗 web", () => {
    const surfaces = buildSurfaces("https://example.test", {
      app: "https://app.example.test",
      desktop: "https://desktop.example.test",
    });
    const planned = perOrigin(surfaces, "tls", "security", () => task);
    expect(planned).toHaveLength(3);
    expect(planned.map((p) => p.surface).sort()).toEqual(["app", "desktop", "web"]);
  });

  it("兩端同源、一端另指時，同源那組標 all，獨立那端標自己", () => {
    const surfaces = buildSurfaces("https://example.test", { desktop: "https://desktop.example.test" });
    const planned = perOrigin(surfaces, "tls", "security", () => task);
    expect(planned).toHaveLength(2);
    expect(planned[0]?.surface).toBe("all");
    expect(planned[1]?.surface).toBe("desktop");
  });

  it("與 perSurface 的差別：同源時 perSurface 仍展開三項", () => {
    const surfaces = buildSurfaces("https://example.test");
    expect(perSurface(surfaces, "transport", "security", () => task)).toHaveLength(3);
    expect(perOrigin(surfaces, "tls", "security", () => task)).toHaveLength(1);
  });

  it("沒有可連的端時回空陣列，不會憑空產生一項", () => {
    expect(perOrigin([], "tls", "security", () => task)).toEqual([]);
  });
});
