/**
 * 報告後製的測試。
 *
 * 後製這一層有一個很容易寫錯、而且寫錯之後不會報錯的性質：它只該改變**呈現**，
 * 不該改變**事實**。被抑制的發現必須還在報告裡（只是換一區）、計數必須對得起來、
 * 後製自己出錯時必須變成一筆看得到的發現而不是一行 stderr。
 * 這裡驗的就是這幾件事。
 */
import { describe, expect, it } from "vitest";
import { annotateReport } from "../src/core/annotate.js";
import { parseSuppressions } from "../src/core/suppress.js";
import { parseBaseline } from "../src/core/baseline.js";
import type { CheckResult, Finding, RunReport, Severity } from "../src/core/types.js";

const NOW = new Date("2026-08-20T00:00:00.000Z");

function makeFinding(id: string, severity: Severity = "high", where?: string): Finding {
  const f: Finding = {
    id,
    check: id.split(".")[0] ?? id,
    category: "security",
    severity,
    surface: "web",
    title: `問題 ${id}`,
    detail: "說明。",
    remediation: "修法。",
  };
  if (where) f.where = where;
  return f;
}

function makeReport(findings: Finding[], extra: CheckResult[] = []): RunReport {
  const results: CheckResult[] = [
    { check: "transport", category: "security", surface: "web", completed: true, durationMs: 1, findings },
    ...extra,
  ];
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return {
    startedAt: "2026-08-20T00:00:00.000Z",
    finishedAt: "2026-08-20T00:01:00.000Z",
    durationMs: 60_000,
    target: "https://ai-os-app.zeabur.app",
    surfaces: ["web"],
    results,
    summary: {
      total: results.length,
      completed: results.length,
      skipped: 0,
      errored: 0,
      suppressed: 0,
      findings: counts,
      worst: findings[0]?.severity ?? null,
    },
  };
}

const allFindings = (r: RunReport) => r.results.flatMap((x) => x.findings);
const ids = (r: RunReport) => allFindings(r).map((f) => f.id);

describe("annotateReport — 抑制", () => {
  const rules = parseSuppressions(
    JSON.stringify([{ id: "csp.style-src.unsafe-inline", reason: "React inline style 的已知取捨", expires: "2026-12-31" }]),
  );

  it("命中的發現被移出主清單，但連同理由留在 report.suppressed", () => {
    const report = annotateReport(
      makeReport([makeFinding("csp.style-src.unsafe-inline", "low"), makeFinding("headers.nosniff", "medium")]),
      { suppressions: rules, now: NOW },
    );
    expect(ids(report)).not.toContain("csp.style-src.unsafe-inline");
    expect(report.suppressed?.[0]?.finding.id).toBe("csp.style-src.unsafe-inline");
    expect(report.suppressed?.[0]?.reason).toBe("React inline style 的已知取捨");
    expect(report.suppressed?.[0]?.expires).toBe("2026-12-31");
  });

  it("summary.suppressed 與 report.suppressed 的筆數一致——計數不能自己說一套", () => {
    const report = annotateReport(makeReport([makeFinding("csp.style-src.unsafe-inline", "low")]), {
      suppressions: rules,
      now: NOW,
    });
    expect(report.summary.suppressed).toBe(1);
    expect(report.suppressed).toHaveLength(1);
  });

  it("嚴重度計數會重算，被抑制的那筆不再計入主清單", () => {
    const report = annotateReport(
      makeReport([makeFinding("csp.style-src.unsafe-inline", "low"), makeFinding("headers.nosniff", "medium")]),
      { suppressions: rules, now: NOW },
    );
    expect(report.summary.findings.low).toBe(0);
    expect(report.summary.findings.medium).toBe(1);
    expect(report.summary.worst).toBe("medium");
  });

  it("抑制規則沒命中任何發現時，會產生一筆提醒（死規則會在問題復發時把它靜默吃掉）", () => {
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium")]), {
      suppressions: rules,
      now: NOW,
    });
    expect(ids(report).some((id) => id.startsWith("suppress.stale"))).toBe(true);
  });

  it("過期的規則不生效，發現照常出現，並附上一筆說明", () => {
    const expired = parseSuppressions(
      JSON.stringify([{ id: "headers.nosniff", reason: "等後端排程", expires: "2026-01-01" }]),
    );
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium")]), {
      suppressions: expired,
      now: NOW,
    });
    expect(ids(report)).toContain("headers.nosniff");
    expect(report.summary.suppressed).toBe(0);
    expect(ids(report).some((id) => id.startsWith("suppress.expired"))).toBe(true);
  });

  it("壞掉的規則會變成 medium 發現——沒生效的規則比沒有規則更危險", () => {
    const broken = parseSuppressions(JSON.stringify([{ id: "headers.nosniff" }]));
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium")]), {
      suppressions: broken,
      now: NOW,
    });
    const invalid = allFindings(report).find((f) => f.id.startsWith("suppress.invalid-rule"));
    expect(invalid?.severity).toBe("medium");
    expect(ids(report)).toContain("headers.nosniff");
  });

  it("沒有給抑制清單時，報告完全不變（不憑空長出 suppressed 欄位）", () => {
    const base = makeReport([makeFinding("headers.nosniff", "medium")]);
    const report = annotateReport(base, {});
    expect(report.suppressed).toBeUndefined();
    expect(report.summary.suppressed).toBe(0);
    expect(ids(report)).toEqual(["headers.nosniff"]);
  });

  it("不會改動傳進來的報告物件", () => {
    const base = makeReport([makeFinding("csp.style-src.unsafe-inline", "low")]);
    annotateReport(base, { suppressions: rules, now: NOW });
    expect(base.results[0]?.findings).toHaveLength(1);
    expect(base.summary.suppressed).toBe(0);
  });
});

describe("annotateReport — 跨次比對", () => {
  const baselineJson = JSON.stringify({
    target: "https://ai-os-app.zeabur.app",
    startedAt: "2026-08-19T00:00:00.000Z",
    results: [{ findings: [makeFinding("headers.nosniff", "medium"), makeFinding("cors.wildcard", "low")] }],
  });

  it("新增、已修復、持續三種關係都被算出來", () => {
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium"), makeFinding("csp.missing", "high")]), {
      baseline: parseBaseline(baselineJson),
    });
    expect(report.diff?.added.map((f) => f.id)).toEqual(["csp.missing"]);
    expect(report.diff?.fixed.map((f) => f.id)).toEqual(["cors.wildcard"]);
    expect(report.diff?.unchanged.map((f) => f.id)).toEqual(["headers.nosniff"]);
  });

  it("基準檔的目標與時間會被帶進報告，讓讀者知道在跟什麼比", () => {
    const report = annotateReport(makeReport([]), { baseline: parseBaseline(baselineJson) });
    expect(report.diff?.baselineTarget).toBe("https://ai-os-app.zeabur.app");
    expect(report.diff?.baselineStartedAt).toBe("2026-08-19T00:00:00.000Z");
  });

  it("基準檔讀不出來時產生一筆 medium 發現，而不是安靜地當作沒有變化", () => {
    const report = annotateReport(makeReport([]), { baseline: parseBaseline("{ 這不是 JSON") });
    const err = allFindings(report).find((f) => f.id === "baseline.unreadable");
    expect(err?.severity).toBe("medium");
    expect(report.diff).toBeUndefined();
  });

  it("比對的對象是抑制之後的清單——讀者實際看到的那一份", () => {
    const rules = parseSuppressions(JSON.stringify([{ id: "headers.nosniff", reason: "已排程", expires: "2026-12-31" }]));
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium")]), {
      suppressions: rules,
      baseline: parseBaseline(baselineJson),
      now: NOW,
    });
    // 被抑制的那筆不在這次的清單上，所以相對基準是「消失了」，不會被算成持續存在。
    expect(report.diff?.unchanged.map((f) => f.id)).not.toContain("headers.nosniff");
    expect(report.diff?.fixed.map((f) => f.id)).toContain("headers.nosniff");
  });

  it("空基準代表上次全綠，這次每一筆都是新增（與『沒有基準』不同）", () => {
    const report = annotateReport(makeReport([makeFinding("csp.missing", "high")]), {
      baseline: parseBaseline(JSON.stringify({ findings: [] })),
    });
    expect(report.diff?.added).toHaveLength(1);

    const noBaseline = annotateReport(makeReport([makeFinding("csp.missing", "high")]), {});
    expect(noBaseline.diff).toBeUndefined();
  });
});

/**
 * 後製只能改變呈現，不能改變事實——這條規則有一個很容易被忽略的角落：
 * 後製自己產生的 meta 結果，絕不能被算成「跑過的檢查」。
 */
describe("annotateReport — meta 結果不算跑過的檢查", () => {
  const rules = parseSuppressions(JSON.stringify([{ id: "never.matches", reason: "留著以防復發", expires: "2026-12-31" }]));

  it("什麼都沒跑到的那一輪，不會因為多了抑制提醒而變成跑過了", () => {
    const skippedOnly: RunReport = {
      ...makeReport([]),
      results: [
        {
          check: "transport",
          category: "security",
          surface: "web",
          completed: false,
          skippedReason: "連不到站台。",
          durationMs: 0,
          findings: [],
        },
      ],
    };
    const report = annotateReport(skippedOnly, { suppressions: rules, now: NOW });

    // 抑制提醒確實產生了（死規則要被點名）……
    expect(ids(report).some((id) => id.startsWith("suppress.stale"))).toBe(true);
    // ……但它不能讓 completed 從 0 變成 1，否則結束碼會從 3（什麼都沒驗）變成 0（綠燈）。
    expect(report.summary.completed).toBe(0);
    expect(report.summary.total).toBe(1);
  });

  it("meta 結果仍然留在 results 裡，讀者看得到", () => {
    const report = annotateReport(makeReport([makeFinding("headers.nosniff", "medium")]), { suppressions: rules, now: NOW });
    expect(report.results.some((r) => r.check === "suppress" && r.meta === true)).toBe(true);
  });
});

describe("annotateReport — 涵蓋範圍", () => {
  it("有過濾時寫進 report.filter", () => {
    const report = annotateReport(makeReport([]), { filter: { only: ["csp"], skip: [] } });
    expect(report.filter).toEqual({ only: ["csp"], skip: [] });
  });

  it("空的過濾條件不會留下欄位——沒縮小範圍就不該有告示", () => {
    const report = annotateReport(makeReport([]), { filter: { only: [], skip: [] } });
    expect(report.filter).toBeUndefined();
  });
});
