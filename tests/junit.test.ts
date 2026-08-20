/**
 * JUnit 匯出的測試。
 *
 * 這裡驗的不是排版，是**面板上的顏色有沒有說實話**：跳過必須是 skipped、檢查器自己爆掉必須是
 * error、門檻以下的發現不能算 failure。JUnit 的預設語意是「沒有 failure 就是綠的」，
 * 一個照著直覺寫的匯出器會把「什麼都沒測到」畫成一排綠勾——那是這套系統最不能接受的失效，
 * 所以這幾條斷言就是這個模組存在的理由。
 *
 * 另一半驗的是 XML 本身合法：控制字元或沒跳脫的角括號漏出去，解析器不是忽略那一段，
 * 是拒收整份檔案，CI 面板連一筆結果都讀不到——比報告難看嚴重得多。
 */
import { describe, expect, it } from "vitest";
import { escapeXml, renderJunit } from "../src/report/junit.js";
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

/**
 * 極簡的 XML 結構檢查，回傳問題清單（空陣列＝結構沒問題）。
 *
 * 刻意不引入解析器套件（專案規定不加相依），但這個掃描已經擋得住實際會犯的錯：
 * 標籤沒關、巢狀交錯、屬性值裡有沒跳脫的引號或角括號、文字節點有裸露的 `&`。
 * 它靠的假設正是匯出器該保證的事——所有角括號與引號都只出現在標籤語法裡。
 */
function xmlProblems(xml: string): string[] {
  const problems: string[] = [];
  const body = xml.replace(/^<\?xml[^>]*\?>\n?/, "");
  const stack: string[] = [];
  let i = 0;

  while (i < body.length) {
    const lt = body.indexOf("<", i);
    const text = lt === -1 ? body.slice(i) : body.slice(i, lt);
    if (/&(?!(amp|lt|gt|quot|apos|#\d+);)/.test(text)) {
      problems.push(`文字節點有未跳脫的 &：${text.slice(0, 40)}`);
    }
    if (lt === -1) break;

    const gt = body.indexOf(">", lt);
    if (gt === -1) {
      problems.push("有標籤沒有結束");
      break;
    }
    const raw = body.slice(lt + 1, gt);
    // 屬性值裡若混進沒跳脫的引號，這一段的雙引號數量就會是奇數。
    if ((raw.match(/"/g) ?? []).length % 2 !== 0) problems.push(`屬性引號不成對：${raw.slice(0, 40)}`);
    i = gt + 1;

    if (raw.startsWith("/")) {
      const name = raw.slice(1).trim();
      if (stack.pop() !== name) problems.push(`結束標籤不配對：${name}`);
    } else if (!raw.endsWith("/")) {
      stack.push(raw.split(/\s/)[0] ?? "");
    }
  }

  if (stack.length > 0) problems.push(`未關閉的標籤：${stack.join("、")}`);
  return problems;
}

/** 出現次數。用來驗「每個 testcase 都是 skipped」這類整體性質。 */
function occurrences(text: string, needle: string): number {
  return text.split(needle).length - 1;
}

/**
 * 落單的代理對（半個字元）。
 *
 * 刻意不加 `u` 旗標：要找的正是「單獨出現的一個 UTF-16 單位」，而 `u` 模式會把字串當成
 * 完整的碼位序列來看，反而看不到那半個字元。它寫進檔案後會變成一個問號方塊，
 * 而讀者會把它當成站台真的回了亂碼——一個由報告自己製造出來的假觀測值。
 */
function hasLoneSurrogate(text: string): boolean {
  return /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(text);
}

/** 抓出所有 testcase 的身分（name + classname）。面板就是用這組值當測試主鍵。 */
function testcaseIdentities(xml: string): string[] {
  return [...xml.matchAll(/<testcase name="([^"]*)" classname="([^"]*)"/g)].map((m) => `${m[2]}::${m[1]}`);
}

describe("escapeXml", () => {
  it("五個 XML 特殊字元都被跳脫", () => {
    expect(escapeXml(`&<>"'`)).toBe("&amp;&lt;&gt;&quot;&apos;");
  });

  it("控制字元被移除而不是保留——留著會讓解析器拒收整份報告", () => {
    expect(escapeXml("前\u0000中\u0008後\u001F")).toBe("前中後");
    expect(escapeXml("\uFFFE\uFFFF")).toBe("");
  });

  it("tab、換行、歸位是合法字元，不可以一起被清掉（否則多行說明會擠成一團）", () => {
    expect(escapeXml("一\t二\n三\r四")).toBe("一\t二\n三\r四");
  });

  it("一般文字原樣通過", () => {
    expect(escapeXml("憑證將於 30 天內到期")).toBe("憑證將於 30 天內到期");
  });
});

describe("renderJunit", () => {
  it("開頭是 XML 宣告，且整份輸出標籤配對完整", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({ check: "transport", findings: [makeFinding({ id: "tls.cert.expiring" })] }),
          makeResult({ check: "page-test", completed: false, skippedReason: "缺少 playwright 瀏覽器。" }),
        ],
      }),
      "high",
    );
    expect(xml.startsWith('<?xml version="1.0" encoding="UTF-8"?>\n')).toBe(true);
    expect(xml.split("\n")[1]).toContain('<testsuites name="Aios Sentinel"');
    expect(xmlProblems(xml)).toEqual([]);
  });

  it("被跳過的檢查輸出 skipped，不是通過的 testcase", () => {
    const xml = renderJunit(
      makeReport({
        results: [makeResult({ check: "page-test", completed: false, skippedReason: "缺少 playwright 瀏覽器。" })],
      }),
      "high",
    );
    expect(xml).toContain('<skipped message="缺少 playwright 瀏覽器。" />');
    expect(xml).not.toContain("無發現");
    expect(xml.split("\n")[1]).toContain('skipped="1"');
  });

  it("整輪都沒測到時不會出現任何綠勾——這正是直接映射 JUnit 會犯的錯", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({ check: "page-test", completed: false, skippedReason: "缺少瀏覽器。" }),
          makeResult({ check: "shell-audit", completed: false, skippedReason: "沒有提供 repoPath。" }),
        ],
      }),
      "high",
    );
    // 每一個 testcase 都必須帶 skipped：沒有任何一項可以被讀成通過。
    expect(occurrences(xml, "<testcase ")).toBe(2);
    expect(occurrences(xml, "<skipped ")).toBe(2);
    expect(xml).not.toContain("<failure");
  });

  it("沒有記錄跳過原因的未完成檢查也算 skipped，不會退回通過", () => {
    const xml = renderJunit(makeReport({ results: [makeResult({ check: "health", completed: false })] }), "high");
    expect(xml).toContain("<skipped ");
    expect(xml).toContain("沒有記錄原因");
  });

  it("檢查器自己爆掉輸出 error 而不是 failure——探針壞掉跟站台壞掉要分開看", () => {
    const xml = renderJunit(
      makeReport({
        results: [makeResult({ check: "cors", completed: false, error: "fetch failed: ECONNREFUSED" })],
      }),
      "high",
    );
    expect(xml).toContain('<error message="fetch failed: ECONNREFUSED">');
    expect(xml).not.toContain("<failure");
    expect(xml.split("\n")[1]).toContain('errors="1"');
  });

  it("達到門檻的發現是 failure，type 帶嚴重度、message 帶標題", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({
            check: "transport",
            findings: [makeFinding({ id: "tls.cert.expiring", severity: "critical", title: "憑證即將到期" })],
          }),
        ],
      }),
      "high",
    );
    expect(xml).toContain('<testcase name="tls.cert.expiring" classname="aios-sentinel.security"');
    expect(xml).toContain('<failure type="critical" message="憑證即將到期">');
  });

  it("門檻以下的發現不算 failure，改用 system-out——面板上是通過但看得到說明", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({
            check: "headers",
            findings: [makeFinding({ id: "headers.referrer-policy", severity: "low", title: "缺 Referrer-Policy" })],
          }),
        ],
      }),
      "high",
    );
    expect(xml).not.toContain("<failure");
    expect(xml).toContain("<system-out>");
    expect(xml).toContain("缺 Referrer-Policy");
    expect(xml.split("\n")[1]).toContain('failures="0"');
  });

  it("門檻放寬到 low 時，同一筆 low 發現就變成 failure（紅線由 failOn 決定）", () => {
    const report = makeReport({
      results: [makeResult({ check: "headers", findings: [makeFinding({ id: "headers.referrer-policy", severity: "low" })] })],
    });
    expect(renderJunit(report, "low")).toContain('<failure type="low"');
  });

  it("failure 內文帶說明、修法與證據——只有紅叉的告警沒有人修得動", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({
            check: "cookies",
            findings: [
              makeFinding({
                id: "cookies.httponly.sid",
                severity: "critical",
                detail: "會話 Cookie 沒有 HttpOnly，任何 XSS 都能直接讀走它。",
                remediation: "在 Set-Cookie 補上 HttpOnly。",
                evidence: "sid=<redacted>; Secure",
                where: "https://ai-os-app.zeabur.app/",
              }),
            ],
          }),
        ],
      }),
      "high",
    );
    expect(xml).toContain("任何 XSS 都能直接讀走它。");
    expect(xml).toContain("修法：在 Set-Cookie 補上 HttpOnly。");
    expect(xml).toContain("證據：sid=&lt;redacted&gt;; Secure");
    expect(xml).toContain("位置：https://ai-os-app.zeabur.app/");
  });

  it("完成且零發現的檢查有一個通過的 testcase", () => {
    const xml = renderJunit(makeReport({ results: [makeResult({ check: "cors" })] }), "high");
    expect(xml).toContain('<testcase name="cors 無發現" classname="aios-sentinel.security"');
    expect(xml).not.toContain("<failure");
    expect(xml).not.toContain("<skipped");
    expect(xml.split("\n")[1]).toContain('tests="1"');
  });

  it("每個 CheckResult 一個 testsuite，classname 用 aios-sentinel.<category>", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({ check: "health", category: "availability", surface: "app" }),
          makeResult({ check: "a11y", category: "a11y", completed: false, skippedReason: "沒有瀏覽器。" }),
        ],
      }),
      "high",
    );
    expect(xml).toContain('<testsuite name="health" classname="aios-sentinel.availability"');
    expect(xml).toContain('<testsuite name="a11y" classname="aios-sentinel.a11y"');
    // 三端會跑出同名 testsuite，surface 只能靠 property 區分。
    expect(xml).toContain('<property name="surface" value="app" />');
  });

  it("計數屬性反映實際輸出的 testcase，而不是 summary 的複述", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({
            check: "headers",
            findings: [
              makeFinding({ id: "headers.hsts.missing", severity: "high" }),
              makeFinding({ id: "headers.referrer-policy", severity: "info" }),
            ],
          }),
          makeResult({ check: "page-test", completed: false, skippedReason: "沒有瀏覽器。" }),
          makeResult({ check: "cors", completed: false, error: "boom" }),
          makeResult({ check: "csp" }),
        ],
      }),
      "high",
    );
    const root = xml.split("\n")[1] ?? "";
    expect(root).toContain('tests="5"');
    expect(root).toContain('failures="1"');
    expect(root).toContain('errors="1"');
    expect(root).toContain('skipped="1"');
    expect(occurrences(xml, "<testsuite ")).toBe(4);
  });

  it("time 用秒（durationMs / 1000），檢查耗時平均攤到自己的 testcase 上", () => {
    const xml = renderJunit(
      makeReport({
        durationMs: 60_000,
        results: [
          makeResult({
            check: "headers",
            durationMs: 400,
            findings: [makeFinding({ id: "headers.hsts.missing" }), makeFinding({ id: "headers.nosniff" })],
          }),
        ],
      }),
      "high",
    );
    expect(xml.split("\n")[1]).toContain('time="60.000"');
    expect(xml).toContain('<testsuite name="headers" classname="aios-sentinel.security" tests="2"');
    expect(xml).toContain('time="0.400"');
    expect(occurrences(xml, 'time="0.200"')).toBe(2);
  });

  it("特殊字元與控制字元不會破壞整份 XML（證據常常直接抄回應內容）", () => {
    const xml = renderJunit(
      makeReport({
        results: [
          makeResult({
            check: "disclosure",
            findings: [
              makeFinding({
                id: "disclosure.stacktrace",
                severity: "high",
                title: `錯誤頁回傳 <script> & "堆疊" 'trace'`,
                detail: "頁面把內部堆疊直接印給使用者。",
                evidence: "at <anonymous>\u0000 (app.js:1)\u0007",
              }),
            ],
          }),
        ],
      }),
      "high",
    );
    expect(xmlProblems(xml)).toEqual([]);
    expect(xml).toContain("&lt;script&gt; &amp; &quot;堆疊&quot; &apos;trace&apos;");
    // 控制字元被刪掉，周圍文字保留——不是整段被丟棄。
    expect(xml).toContain("at &lt;anonymous&gt; (app.js:1)");
    expect(xml).not.toContain("\u0000");
  });

  it("被抑制的發現仍然出現在報告裡，而且是 skipped 不是通過", () => {
    const xml = renderJunit(
      makeReport({
        results: [makeResult({ check: "cors" })],
        suppressed: [
          {
            finding: makeFinding({ id: "cors.wildcard", severity: "high" }),
            reason: "後端改版前暫時接受。",
            expires: "2026-12-31",
            owner: "platform",
          },
        ],
      }),
      "high",
    );
    expect(xml).toContain('<testsuite name="已抑制的發現"');
    expect(xml).toContain('<testcase name="cors.wildcard"');
    expect(xml).toContain("後端改版前暫時接受。");
    expect(xml).toContain("問題本身仍然存在。");
    expect(xml).not.toContain("<failure");
  });

  it("範圍被縮小時輸出涵蓋範圍告示，避免局部檢測在面板上看起來像全綠", () => {
    const narrowed = renderJunit(makeReport({ filter: { only: ["csp"], skip: [] } }), "high");
    expect(narrowed).toContain('<testsuite name="檢測涵蓋範圍"');
    expect(narrowed).toContain("不代表通過");
    // 沒有過濾就不該多出這一段雜訊。
    expect(renderJunit(makeReport({ filter: { only: [], skip: [] } }), "high")).not.toContain("檢測涵蓋範圍");
    expect(renderJunit(makeReport(), "high")).not.toContain("檢測涵蓋範圍");
  });
});
