/**
 * SARIF 匯出的測試。
 *
 * 這一層值得測的不是「有沒有吐出檔案」，而是**轉檔過程有沒有把資訊弄丟或弄反**：
 * 跳過被洗成通過、同一件事每輪都變成新告警、修法在 code scanning 上看不到——
 * 這三種失誤都不會讓程式壞掉，只會讓報告安靜地失去可信度，所以只能靠測試守住。
 */
import { describe, expect, it } from "vitest";
import { renderSarif, sarifRuleFor, severityToSarifLevel, toArtifactUri } from "../src/report/sarif.js";
import type { SarifLog, SarifRun } from "../src/report/sarif.js";
import type { CheckResult, Finding, RunReport, Severity } from "../src/core/types.js";

function makeFinding(over: Partial<Finding> & { id: string }): Finding {
  return {
    check: "transport",
    category: "security",
    severity: "high",
    surface: "web",
    title: `問題 ${over.id}`,
    detail: "說明。",
    remediation: "修法。",
    ...over,
  };
}

function makeResult(over: Partial<CheckResult> & { check: string }): CheckResult {
  return {
    category: "security",
    surface: "web",
    completed: true,
    durationMs: 120,
    findings: [],
    ...over,
  };
}

function makeReport(over: Partial<RunReport> = {}): RunReport {
  const results = over.results ?? [makeResult({ check: "transport" })];
  const findings = results.flatMap((r) => r.findings);
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return {
    startedAt: "2026-08-20T00:00:00.000Z",
    finishedAt: "2026-08-20T00:01:00.000Z",
    durationMs: 60_000,
    target: "https://ai-os-app.zeabur.app",
    surfaces: ["web", "app", "desktop"],
    results,
    summary: {
      total: results.length,
      completed: results.filter((r) => r.completed).length,
      skipped: results.filter((r) => !r.completed && r.skippedReason).length,
      errored: results.filter((r) => r.error).length,
      suppressed: over.suppressed?.length ?? 0,
      findings: counts,
      worst: findings.length > 0 ? findings[0]!.severity : null,
    },
    ...over,
  };
}

/** 只有這裡做 JSON.parse——其餘測試都在斷言結構，不該各自重複解析。 */
function firstRun(report: RunReport): SarifRun {
  return (JSON.parse(renderSarif(report)) as SarifLog).runs[0]!;
}

describe("renderSarif 的骨架", () => {
  it("輸出是合法 JSON，且帶齊 SARIF 2.1.0 的頂層欄位", () => {
    const raw = renderSarif(makeReport());
    expect(() => JSON.parse(raw)).not.toThrow();
    const log = JSON.parse(raw) as SarifLog;
    expect(log.version).toBe("2.1.0");
    expect(log.$schema).toContain("sarif-2.1.0");
    expect(log.runs).toHaveLength(1);
  });

  it("driver 帶工具名與說明網址，讀者才知道這批告警是誰產的", () => {
    const { tool } = firstRun(makeReport());
    expect(tool.driver.name).toBe("Aios Sentinel");
    expect(() => new URL(tool.driver.informationUri)).not.toThrow();
    expect(Array.isArray(tool.driver.rules)).toBe(true);
  });

  it("零發現時仍輸出合法且完整的 SARIF，不是空字串", () => {
    const run = firstRun(makeReport());
    expect(run.results).toEqual([]);
    expect(run.tool.driver.rules).toEqual([]);
    expect(run.invocations[0]!.executionSuccessful).toBe(true);
    expect(run.invocations[0]!.startTimeUtc).toBe("2026-08-20T00:00:00.000Z");
    expect(run.invocations[0]!.endTimeUtc).toBe("2026-08-20T00:01:00.000Z");
  });
});

describe("severityToSarifLevel", () => {
  it.each([
    ["critical", "error"],
    ["high", "error"],
    ["medium", "warning"],
    ["low", "note"],
    ["info", "note"],
  ] as Array<[Severity, string]>)("%s 對應到 %s", (severity, level) => {
    expect(severityToSarifLevel(severity)).toBe(level);
  });

  it("五級嚴重度壓成三級後，靠 security-severity 保住排序資訊", () => {
    const findings: Finding[] = [
      makeFinding({ id: "a.critical", severity: "critical" }),
      makeFinding({ id: "a.high", severity: "high" }),
      makeFinding({ id: "a.medium", severity: "medium" }),
      makeFinding({ id: "a.low", severity: "low" }),
      makeFinding({ id: "a.info", severity: "info" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings })] }));
    const byId = new Map(run.tool.driver.rules.map((r) => [r.id, r.properties["security-severity"]]));
    expect(byId.get("a.critical")).toBe("9.5");
    expect(byId.get("a.high")).toBe("7.5");
    expect(byId.get("a.medium")).toBe("5.0");
    expect(byId.get("a.low")).toBe("3.0");
    expect(byId.get("a.info")).toBe("0.0");
  });
});

describe("sarifRuleFor", () => {
  it("單一規則帶齊 code scanning 會用到的欄位", () => {
    const rule = sarifRuleFor(
      makeFinding({ id: "csp.missing", severity: "high", title: "沒有 CSP", detail: "為什麼危險。", remediation: "加上 CSP。" }),
    );
    expect(rule.id).toBe("csp.missing");
    expect(rule.name).toBe("沒有 CSP");
    expect(rule.shortDescription.text).toBe("沒有 CSP");
    expect(rule.fullDescription.text).toBe("為什麼危險。");
    expect(rule.defaultConfiguration.level).toBe("error");
    expect(rule.properties.tags).toEqual(["security", "web"]);
  });

  it("修法放在 help.text——那是 code scanning 上唯一會顯示修法的位置", () => {
    const rule = sarifRuleFor(makeFinding({ id: "cookies.httponly.sid", remediation: "會話 Cookie 加上 HttpOnly。" }));
    expect(rule.help.text).toBe("會話 Cookie 加上 HttpOnly。");
  });
});

describe("規則去重", () => {
  it("同一個 id 出現多次只登錄一筆規則，但每一處都留成獨立的 result", () => {
    const findings = [
      makeFinding({ id: "headers.nosniff", where: "https://a.test/" }),
      makeFinding({ id: "headers.nosniff", where: "https://a.test/app" }),
      makeFinding({ id: "csp.missing", where: "https://a.test/" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings })] }));
    expect(run.tool.driver.rules.map((r) => r.id).sort()).toEqual(["csp.missing", "headers.nosniff"]);
    expect(run.results).toHaveLength(3);
  });

  it("同 id 不同嚴重度時規則取最嚴重的那一筆——security-severity 沒有逐筆覆寫的餘地，低估比高估危險", () => {
    const findings = [
      makeFinding({ id: "cookies.httponly.x", severity: "low", where: "https://a.test/" }),
      makeFinding({ id: "cookies.httponly.x", severity: "critical", where: "https://a.test/api" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "cookies", findings })] }));
    const rule = run.tool.driver.rules[0]!;
    expect(rule.defaultConfiguration.level).toBe("error");
    expect(rule.properties["security-severity"]).toBe("9.5");
    // 但個別 result 仍保留自己的等級，讀者看得到哪一處比較輕。
    expect(run.results.map((r) => r.level).sort()).toEqual(["error", "note"]);
  });

  it("同一種問題跨端出現時，規則的 tags 併入所有端，不會讓人以為只有一端有事", () => {
    const findings = [
      makeFinding({ id: "headers.nosniff", surface: "web" }),
      makeFinding({ id: "headers.nosniff", surface: "app" }),
      makeFinding({ id: "headers.nosniff", surface: "desktop" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings })] }));
    expect(run.tool.driver.rules[0]!.properties.tags).toEqual(["security", "app", "desktop", "web"]);
  });

  it("每筆 result 的 ruleIndex 指得到自己的規則", () => {
    const findings = [
      makeFinding({ id: "csp.missing", severity: "high" }),
      makeFinding({ id: "headers.nosniff", severity: "medium" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings })] }));
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex]!.id).toBe(result.ruleId);
    }
  });
});

describe("result 內容", () => {
  it("訊息同時帶標題與說明——只有標題的告警看不出為什麼要處理", () => {
    const f = makeFinding({ id: "cors.reflects-origin", title: "CORS 反射任意 Origin", detail: "任何網站都能讀走回應。" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "cors", findings: [f] })] }));
    expect(run.results[0]!.message.text).toContain("CORS 反射任意 Origin");
    expect(run.results[0]!.message.text).toContain("任何網站都能讀走回應。");
  });

  it("指紋是 id::where，同一件事跨次執行才不會每輪都變成新告警", () => {
    const f = makeFinding({ id: "csp.missing", where: "https://a.test/" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] }));
    expect(run.results[0]!.partialFingerprints.aiosSentinelId).toBe("csp.missing::https://a.test/");
    // 同樣的報告轉兩次必須一模一樣：指紋含時間或亂數就等於沒有指紋。
    expect(renderSarif(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] }))).toBe(
      renderSarif(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] })),
    );
  });

  it("同一種問題在不同位置有不同指紋，不會被 GitHub 折成一筆", () => {
    const findings = [
      makeFinding({ id: "headers.nosniff", where: "https://a.test/" }),
      makeFinding({ id: "headers.nosniff", where: "https://a.test/app" }),
    ];
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings })] }));
    const prints = run.results.map((r) => r.partialFingerprints.aiosSentinelId);
    expect(new Set(prints).size).toBe(2);
  });

  it("properties 保留嚴重度、端與檢查名，五級嚴重度不會在轉檔時消失", () => {
    const f = makeFinding({ id: "csp.missing", severity: "medium", surface: "desktop", check: "transport" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", surface: "desktop", findings: [f] })] }));
    expect(run.results[0]!.properties).toEqual({ severity: "medium", surface: "desktop", check: "transport" });
  });
});

describe("位置（artifactLocation.uri）", () => {
  it("殼層稽核的相對檔案路徑維持相對且合法——GitHub 只有這樣才標得到檔案", () => {
    const f = makeFinding({ id: "shell.tauri.csp.missing", where: "ai_os/src-tauri/tauri.conf.json", surface: "desktop" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "shells", findings: [f] })] }));
    const uri = run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri;
    expect(uri).toBe("ai_os/src-tauri/tauri.conf.json");
    expect(() => new URL(uri, "https://example.test/repo/")).not.toThrow();
  });

  it("絕對檔案路徑轉成 file:// 並逐段編碼，空白不會產生非法 URI", () => {
    expect(toArtifactUri("/home/ci/ai os/capacitor.config.ts", "https://a.test")).toBe(
      "file:///home/ci/ai%20os/capacitor.config.ts",
    );
    expect(toArtifactUri("C:\\repo\\ai_os\\tauri.conf.json", "https://a.test")).toBe(
      "file:///C:/repo/ai_os/tauri.conf.json",
    );
    expect(toArtifactUri("./ai_os/capacitor.config.ts", "https://a.test")).toBe("ai_os/capacitor.config.ts");
  });

  it("where 缺席時退回受測目標，不會輸出空的 uri", () => {
    const f = makeFinding({ id: "health.unreachable" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "health", findings: [f] })] }));
    expect(run.results[0]!.locations[0]!.physicalLocation.artifactLocation.uri).toBe("https://ai-os-app.zeabur.app/");
    expect(toArtifactUri(undefined, "")).toBe("urn:aios-sentinel:unlocated");
  });
});

describe("沒測到的部分（toolExecutionNotifications）", () => {
  it("跳過的檢查寫成 warning 通知，並明說跳過不等於通過", () => {
    const run = firstRun(
      makeReport({
        results: [makeResult({ check: "page-test", completed: false, skippedReason: "缺少 playwright 瀏覽器。" })],
      }),
    );
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.descriptor.id).toBe("check.skipped");
    expect(notes[0]!.level).toBe("warning");
    expect(notes[0]!.message.text).toContain("page-test");
    expect(notes[0]!.message.text).toContain("缺少 playwright 瀏覽器。");
    expect(notes[0]!.message.text).toContain("跳過不等於通過");
  });

  it("全部跳過時 results 為空，但 SARIF 上仍看得到「什麼都沒驗」", () => {
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport", completed: false, skippedReason: "連不到站台。" }),
          makeResult({ check: "cors", completed: false, skippedReason: "連不到站台。" }),
        ],
      }),
    );
    expect(run.results).toEqual([]);
    expect(run.invocations[0]!.toolExecutionNotifications).toHaveLength(2);
    // 跳過是有意識的略過，不是檢測器故障——executionSuccessful 不該因此變 false。
    expect(run.invocations[0]!.executionSuccessful).toBe(true);
  });

  it("檢查自己爆掉是 error 通知，且 executionSuccessful 為 false", () => {
    const run = firstRun(
      makeReport({
        results: [makeResult({ check: "dbTraffic", completed: false, error: "TypeError: x is not a function" })],
      }),
    );
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1); // 爆掉的檢查不會同時再報一次「跳過」
    expect(notes[0]!.descriptor.id).toBe("check.errored");
    expect(notes[0]!.level).toBe("error");
    expect(notes[0]!.message.text).toContain("TypeError: x is not a function");
    expect(run.invocations[0]!.executionSuccessful).toBe(false);
  });

  it("範圍被 --only 縮小時會多一筆通知——一份只跑了 CSP 的 SARIF 看起來跟全站乾淨一樣", () => {
    const run = firstRun(makeReport({ filter: { only: ["csp"], skip: [] } }));
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes[0]!.descriptor.id).toBe("run.filtered");
    expect(notes[0]!.message.text).toContain("csp");
    expect(notes[0]!.message.text).toContain("不代表通過");
  });

  it("沒有過濾也沒有未完成的檢查時不會生出多餘通知", () => {
    expect(firstRun(makeReport()).invocations[0]!.toolExecutionNotifications).toEqual([]);
  });
});

describe("被抑制的發現", () => {
  it("以 suppressions 形式留在 SARIF，理由與到期日一起帶著，而不是靜靜消失", () => {
    const f = makeFinding({ id: "csp.style-src.unsafe-inline", severity: "low", title: "style-src 允許 inline" });
    const run = firstRun(
      makeReport({ suppressed: [{ finding: f, reason: "React inline style 的已知取捨", expires: "2026-12-31", owner: "平台組" }] }),
    );
    expect(run.results).toHaveLength(1);
    const suppression = run.results[0]!.suppressions![0]!;
    expect(suppression.kind).toBe("external");
    expect(suppression.justification).toContain("React inline style 的已知取捨");
    expect(suppression.justification).toContain("2026-12-31");
    expect(suppression.justification).toContain("平台組");
    // 抑制掉的發現同樣要有規則，否則 GitHub 收到一筆指不到規則的 result。
    expect(run.tool.driver.rules.map((r) => r.id)).toContain("csp.style-src.unsafe-inline");
  });

  it("沒被抑制的發現不會帶 suppressions（別讓 GitHub 誤以為它已經關掉）", () => {
    const f = makeFinding({ id: "csp.missing" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] }));
    expect(run.results[0]!.suppressions).toBeUndefined();
  });
});
