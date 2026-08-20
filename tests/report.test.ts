/**
 * 報告層的測試。
 *
 * 為什麼報告值得測：報告是整套系統唯一會被人讀到的產物。判定再準，只要渲染時把
 * 「跳過」畫成綠勾、或把被抑制的發現整批吃掉，讀者拿到的結論就是錯的——而且錯得無聲無息。
 * 所以這裡驗的不是排版好不好看，是**幾個絕不能消失的資訊**有沒有真的出現在輸出裡。
 */
import { describe, expect, it } from "vitest";
import { renderMarkdown } from "../src/report/markdown.js";
import { renderHtml } from "../src/report/html.js";
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

describe("renderMarkdown", () => {
  it("跳過的檢查會被放進顯眼的『未完成』一節，而不是混在通過裡", () => {
    const md = renderMarkdown(
      makeReport({
        results: [makeResult({ check: "page-test", completed: false, skippedReason: "缺少 playwright 瀏覽器。" })],
      }),
    );
    expect(md).toContain("未完成的檢查（不等於通過）");
    expect(md).toContain("缺少 playwright 瀏覽器。");
  });

  it("有過濾時會在最前面標明涵蓋範圍被縮小", () => {
    const md = renderMarkdown(makeReport({ filter: { only: ["csp"], skip: [] } }));
    expect(md).toContain("本次檢測範圍被縮小");
    expect(md).toContain("不代表通過");
  });

  it("沒有過濾時不會多出範圍告示（避免無意義的雜訊）", () => {
    expect(renderMarkdown(makeReport())).not.toContain("本次檢測範圍被縮小");
    expect(renderMarkdown(makeReport({ filter: { only: [], skip: [] } }))).not.toContain("本次檢測範圍被縮小");
  });

  it("比對區塊會分開列出新增、已修復與惡化", () => {
    const added = makeFinding({ id: "csp.missing", severity: "high", title: "沒有 CSP" });
    const fixed = makeFinding({ id: "headers.nosniff", severity: "medium", title: "缺 nosniff" });
    const before = makeFinding({ id: "cors.wildcard", severity: "low", title: "CORS 開放" });
    const after = makeFinding({ id: "cors.wildcard", severity: "critical", title: "CORS 開放" });
    const md = renderMarkdown(
      makeReport({
        results: [makeResult({ check: "transport", findings: [added, after] })],
        diff: {
          baselineTarget: "https://ai-os-app.zeabur.app",
          baselineStartedAt: "2026-08-19T00:00:00.000Z",
          added: [added],
          fixed: [fixed],
          unchanged: [],
          changed: [{ key: "cors.wildcard::", before, after }],
        },
      }),
    );
    expect(md).toContain("與基準比對");
    expect(md).toContain("沒有 CSP");
    expect(md).toContain("已修復");
    expect(md).toContain("缺 nosniff");
    expect(md).toContain("嚴重度惡化");
  });

  it("基準檔的目標與本次不同時會明確警告，不讓人把兩個站的結果混著看", () => {
    const md = renderMarkdown(
      makeReport({
        diff: {
          baselineTarget: "https://staging.example.test",
          baselineStartedAt: null,
          added: [],
          fixed: [],
          unchanged: [],
          changed: [],
        },
      }),
    );
    expect(md).toContain("staging.example.test");
    expect(md).toContain("只能參考");
  });

  it("新增的發現在主清單上有標記——讀者要先處理這次才冒出來的那幾筆", () => {
    const f = makeFinding({ id: "csp.missing", title: "沒有 CSP" });
    const md = renderMarkdown(
      makeReport({
        results: [makeResult({ check: "transport", findings: [f] })],
        diff: { baselineTarget: null, baselineStartedAt: null, added: [f], fixed: [], unchanged: [], changed: [] },
      }),
    );
    expect(md).toContain("### 🆕 沒有 CSP");
  });

  it("被抑制的發現連同理由與到期日留在報告上，不會消失", () => {
    const f = makeFinding({ id: "csp.style-src.unsafe-inline", severity: "low", title: "style-src 允許 inline" });
    const md = renderMarkdown(
      makeReport({
        suppressed: [{ finding: f, reason: "React inline style 的已知取捨", expires: "2026-12-31", owner: "平台組" }],
      }),
    );
    expect(md).toContain("已抑制");
    expect(md).toContain("React inline style 的已知取捨");
    expect(md).toContain("2026-12-31");
    expect(md).toContain("平台組");
    expect(md).toContain("依然存在");
  });

  it("永久抑制會被特別標出來（永久抑制應該極少）", () => {
    const f = makeFinding({ id: "headers.coop", severity: "low", title: "缺 COOP" });
    const md = renderMarkdown(makeReport({ suppressed: [{ finding: f, reason: "第三方無法修", expires: null, owner: null }] }));
    expect(md).toContain("**永久**");
  });

  it("表格欄位裡的管線符號會被跳脫，不會把 Markdown 表格打壞", () => {
    const f = makeFinding({ id: "x.y", title: "含 | 管線 | 的標題" });
    const md = renderMarkdown(
      makeReport({
        suppressed: [{ finding: f, reason: "理由 | 含管線", expires: null, owner: null }],
      }),
    );
    expect(md).toContain("含 \\| 管線 \\| 的標題");
    expect(md).toContain("理由 \\| 含管線");
  });
});

describe("renderHtml", () => {
  it("是一份自足的 HTML（沒有任何外部資源引用，才能直接寄出）", () => {
    const html = renderHtml(makeReport());
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toMatch(/<script[^>]+src=/i);
    expect(html).not.toMatch(/<link[^>]+href=["']https?:/i);
  });

  it("跳過的檢查在儀表板上是警示橫幅，不是綠燈", () => {
    const html = renderHtml(
      makeReport({ results: [makeResult({ check: "health", completed: false, skippedReason: "連不到站台。" })] }),
    );
    expect(html).toContain("未完成不等於通過");
    expect(html).toContain("連不到站台。");
  });

  it("HTML 特殊字元會被跳脫，惡意標題不會變成注入", () => {
    const f = makeFinding({ id: "x.y", title: '<img src=x onerror="alert(1)">' });
    const html = renderHtml(makeReport({ results: [makeResult({ check: "transport", findings: [f] })] }));
    expect(html).not.toContain('<img src=x onerror="alert(1)">');
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
  });

  it("有比對時會出現『只看新增』的篩選，且新增的發現被標記", () => {
    const f = makeFinding({ id: "csp.missing", title: "沒有 CSP" });
    const html = renderHtml(
      makeReport({
        results: [makeResult({ check: "transport", findings: [f] })],
        diff: { baselineTarget: null, baselineStartedAt: null, added: [f], fixed: [], unchanged: [], changed: [] },
      }),
    );
    expect(html).toContain('data-filter="new"');
    expect(html).toContain('data-new="true"');
  });

  it("沒有比對時不會出現比對區塊（不要憑空生出沒有依據的欄位）", () => {
    const html = renderHtml(makeReport());
    expect(html).not.toContain("與基準比對");
    expect(html).not.toContain('data-filter="new"');
  });

  it("被抑制的發現有自己的表格，並寫明抑制不等於修好", () => {
    const f = makeFinding({ id: "csp.style-src.unsafe-inline", severity: "low", title: "style-src 允許 inline" });
    const html = renderHtml(
      makeReport({ suppressed: [{ finding: f, reason: "已知取捨", expires: "2026-12-31", owner: "平台組" }] }),
    );
    expect(html).toContain("已抑制（1）");
    expect(html).toContain("抑制不等於修好");
    expect(html).toContain("已知取捨");
  });

  it("零發現時仍然輸出完整頁面，而不是一片空白", () => {
    const html = renderHtml(makeReport());
    expect(html).toContain("本次檢測沒有發現任何問題");
    expect(html).toContain("</html>");
  });
});
