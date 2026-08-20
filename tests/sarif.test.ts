/**
 * SARIF 匯出的測試。
 *
 * 這一層值得測的不是「有沒有吐出檔案」，而是**轉檔過程有沒有把資訊弄丟或弄反**：
 * 一輪什麼都沒跑到卻輸出一份看起來很乾淨的空 SARIF、跳過被洗成通過、
 * 同一件事每輪都變成新告警、修法在 code scanning 上看不到——
 * 這四種失誤都不會讓程式壞掉，只會讓報告安靜地失去可信度，所以只能靠測試守住。
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

  it("發現漏填修法時 help.text 仍要說話——空白的說明欄在介面上等於這條規則沒有交代", () => {
    const rule = sarifRuleFor(makeFinding({ id: "x.y", remediation: undefined }));
    expect(rule.help.text).toContain("沒有附修法");
    expect(rule.helpUri).toContain("CHECKS.md");
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

  it("證據跟著 result 一起帶走，維運者不必為了看實際觀測值再去翻另一份報告", () => {
    const f = makeFinding({ id: "headers.hsts.missing", evidence: "strict-transport-security：（沒有這個標頭）" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "security-headers", findings: [f] })] }));
    expect(run.results[0]!.properties.evidence).toBe("strict-transport-security：（沒有這個標頭）");
  });

  it("過長的證據會截斷——一份把整份回應塞進去的 SARIF 會大到上傳不了", () => {
    const f = makeFinding({ id: "disclosure.stacktrace", evidence: "壹".repeat(5000) });
    const run = firstRun(makeReport({ results: [makeResult({ check: "disclosure", findings: [f] })] }));
    const evidence = run.results[0]!.properties.evidence ?? "";
    expect(evidence.length).toBeLessThan(1300);
    expect(evidence).toContain("已截斷");
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

  it("--repo 指到上層目錄時的 ../ 路徑保持相對，硬轉 file:// 會讓 PR 標註失效", () => {
    expect(toArtifactUri("../ai_os/src-tauri/capabilities/remote.json", "https://a.test")).toBe(
      "../ai_os/src-tauri/capabilities/remote.json",
    );
  });

  it("只是「看起來像」scheme 的字串不會被當成絕對 URI 原樣輸出", () => {
    // 這兩個在 URL 解析器眼中都是合法的絕對 URI（scheme 分別被解讀成 x.ts 與整串主機名），
    // 原樣輸出的話 code scanning 會收到一個指不到任何檔案、也點不開的位置。
    expect(toArtifactUri("x.ts:42", "https://a.test")).toBe("x.ts%3A42");
    expect(toArtifactUri("ai-os-app.zeabur.app:443", "https://a.test")).toBe("ai-os-app.zeabur.app%3A443");
  });

  it("受測頁面提供的 javascript:／data: 不會原封不動變成位置", () => {
    // 供應鏈檢查會把頁面上的 <script src> 當作位置，而那是受測站台給的內容。
    expect(toArtifactUri("javascript:alert(1)", "https://a.test").startsWith("javascript:")).toBe(false);
    expect(toArtifactUri("data:text/javascript,alert(1)", "https://a.test").startsWith("data:")).toBe(false);
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
        results: [
          makeResult({ check: "transport" }),
          makeResult({ check: "page-test", completed: false, skippedReason: "缺少 playwright 瀏覽器。" }),
        ],
      }),
    );
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.descriptor.id).toBe("check.skipped");
    expect(notes[0]!.level).toBe("warning");
    expect(notes[0]!.message.text).toContain("page-test");
    expect(notes[0]!.message.text).toContain("缺少 playwright 瀏覽器。");
    expect(notes[0]!.message.text).toContain("跳過不等於通過");
    // 二十項裡跳過一項是常態，不該讓整輪被標成失敗——真正要警覺的是「一項都沒跑完」。
    expect(run.invocations[0]!.executionSuccessful).toBe(true);
  });

  it("跳過原因沒有句尾標點時不會跟後面的提醒黏成一句", () => {
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport" }),
          // 偵測器實際寫出來的原因常常沒有句號，例如 `首頁無法連線：fetch failed`。
          makeResult({ check: "transport", completed: false, skippedReason: "首頁無法連線：fetch failed" }),
        ],
      }),
    );
    const text = run.invocations[0]!.toolExecutionNotifications[0]!.message.text;
    expect(text).toContain("首頁無法連線：fetch failed。跳過不等於通過");
  });

  it("後製的 meta 結果不會被講成「某項檢查沒跑到」——讀者會去找一項根本不存在的檢查", () => {
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport" }),
          makeResult({ check: "suppress", category: "integrity", surface: "all", meta: true, completed: false }),
        ],
      }),
    );
    expect(run.invocations[0]!.toolExecutionNotifications).toEqual([]);
  });

  it("跳過卻沒記錄原因時照樣出聲，不會因為少一段文字就被當成通過", () => {
    const run = firstRun(
      makeReport({ results: [makeResult({ check: "transport" }), makeResult({ check: "a11y", completed: false })] }),
    );
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.descriptor.id).toBe("check.skipped");
    expect(notes[0]!.message.text).toContain("a11y");
  });

  it("全部跳過時 results 為空，SARIF 必須自己講出「什麼都沒驗」而不是留一片綠", () => {
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport", completed: false, skippedReason: "連不到站台。" }),
          makeResult({ check: "cors", completed: false, skippedReason: "連不到站台。" }),
        ],
      }),
    );
    expect(run.results).toEqual([]);
    const notes = run.invocations[0]!.toolExecutionNotifications;
    // 整輪的結論排在逐項細節前面：讀者先知道這份結果不能當一回事，再看是哪幾項沒跑。
    expect(notes.map((n) => n.descriptor.id)).toEqual(["run.nothing-executed", "check.skipped", "check.skipped"]);
    expect(notes[0]!.level).toBe("error");
    expect(notes[0]!.message.text).toContain("完成 0 項");
    // 空的 results 配上 executionSuccessful=true，在 code scanning 上與「全站掃過、很乾淨」
    // 完全無法區分。這種假綠燈比紅燈危險，所以一項都沒跑完的執行一律不算成功。
    expect(run.invocations[0]!.executionSuccessful).toBe(false);
  });

  it("連一項檢查都沒排到時，同樣不准看起來像全部通過", () => {
    const run = firstRun(makeReport({ results: [] }));
    expect(run.results).toEqual([]);
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1);
    expect(notes[0]!.descriptor.id).toBe("run.nothing-executed");
    expect(run.invocations[0]!.executionSuccessful).toBe(false);
  });

  it("後製產生的 meta 結果不算跑過檢查——帶了 --suppress 不該讓空轉的一輪變成綠燈", () => {
    const note = makeFinding({
      id: "suppress.unused-rule.old",
      check: "suppress",
      category: "integrity",
      surface: "all",
      severity: "info",
    });
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport", completed: false, skippedReason: "連不到站台。" }),
          makeResult({ check: "suppress", category: "integrity", surface: "all", meta: true, findings: [note] }),
        ],
      }),
    );
    // meta 的發現照樣要看得見，但它不能把「什麼都沒驗」洗成「有跑」。
    expect(run.results).toHaveLength(1);
    expect(run.invocations[0]!.toolExecutionNotifications[0]!.descriptor.id).toBe("run.nothing-executed");
    expect(run.invocations[0]!.executionSuccessful).toBe(false);
  });

  it("檢查自己爆掉是 error 通知，且 executionSuccessful 為 false", () => {
    const run = firstRun(
      makeReport({
        results: [
          makeResult({ check: "transport" }),
          makeResult({ check: "db-traffic", completed: false, error: "TypeError: x is not a function" }),
        ],
      }),
    );
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes).toHaveLength(1); // 爆掉的檢查不會同時再報一次「跳過」
    expect(notes[0]!.descriptor.id).toBe("check.errored");
    expect(notes[0]!.level).toBe("error");
    expect(notes[0]!.message.text).toContain("TypeError: x is not a function");
    // 別的項目照常跑完，但檢測器故障本身就足以讓這一輪不算成功。
    expect(run.invocations[0]!.executionSuccessful).toBe(false);
  });

  it("範圍被 --only 縮小時會多一筆通知——一份只跑了 CSP 的 SARIF 看起來跟全站乾淨一樣", () => {
    const run = firstRun(makeReport({ filter: { only: ["csp"], skip: [] } }));
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes[0]!.descriptor.id).toBe("run.filtered");
    expect(notes[0]!.message.text).toContain("csp");
    expect(notes[0]!.message.text).toContain("不代表通過");
  });

  it("--skip 也要留下痕跡，不能只有 --only 才出聲", () => {
    const run = firstRun(makeReport({ filter: { only: [], skip: ["rate-limit"] } }));
    const notes = run.invocations[0]!.toolExecutionNotifications;
    expect(notes[0]!.descriptor.id).toBe("run.filtered");
    expect(notes[0]!.message.text).toContain("rate-limit");
  });

  it("沒有過濾也沒有未完成的檢查時不會生出多餘通知", () => {
    expect(firstRun(makeReport()).invocations[0]!.toolExecutionNotifications).toEqual([]);
  });

  it("driver 宣告了所有通知描述子——只丟一個 id 給消費端，等於沒有說明", () => {
    const declared = firstRun(makeReport()).tool.driver.notifications;
    expect(declared.map((d) => d.id).sort()).toEqual([
      "check.errored",
      "check.skipped",
      "run.filtered",
      "run.nothing-executed",
    ]);
    for (const d of declared) expect(d.fullDescription.text.length).toBeGreaterThan(0);
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

  it("沒有到期日的抑制在理由裡寫成「永久」，讓無限期的忽略無所遁形", () => {
    const f = makeFinding({ id: "csp.style-src.unsafe-inline", severity: "low" });
    const run = firstRun(makeReport({ suppressed: [{ finding: f, reason: "已知取捨", expires: null, owner: null }] }));
    const justification = run.results[0]!.suppressions![0]!.justification;
    expect(justification).toContain("永久");
    // 沒有負責人時不要硬生出一個空欄位，讀者會以為那是有人認領過的。
    expect(justification).not.toContain("負責人");
  });

  it("同一個 id 一處被抑制、一處沒有時，規則仍取最嚴重的那一筆，兩筆 result 也各自指得到它", () => {
    const kept = makeFinding({ id: "cookies.secure.sid", severity: "high", where: "https://a.test/" });
    const hidden = makeFinding({ id: "cookies.secure.sid", severity: "low", where: "https://a.test/x" });
    const run = firstRun(
      makeReport({
        results: [makeResult({ check: "cookies", findings: [kept] })],
        suppressed: [{ finding: hidden, reason: "另一條路徑上是靜態資源", expires: "2026-12-31", owner: null }],
      }),
    );
    expect(run.tool.driver.rules).toHaveLength(1);
    expect(run.tool.driver.rules[0]!.properties["security-severity"]).toBe("7.5");
    expect(run.results).toHaveLength(2);
    for (const result of run.results) {
      expect(run.tool.driver.rules[result.ruleIndex]!.id).toBe(result.ruleId);
    }
  });

  it("沒被抑制的發現不會帶 suppressions（別讓 GitHub 誤以為它已經關掉）", () => {
    const f = makeFinding({ id: "csp.missing" });
    const run = firstRun(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] }));
    expect(run.results[0]!.suppressions).toBeUndefined();
  });
});
