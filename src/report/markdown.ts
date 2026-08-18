/**
 * Markdown 報告。用途是貼進 PR 留言或 issue，所以要在沒有樣式的環境下依然好讀。
 */
import { sortFindings } from "../core/severity.js";
import { allFindings } from "../core/runner.js";
import type { Finding, RunReport, Severity } from "../core/types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "🔴 極嚴重",
  high: "🟠 高",
  medium: "🟡 中",
  low: "🔵 低",
  info: "⚪ 參考",
};

const CATEGORY_LABEL: Record<string, string> = {
  security: "資訊安全",
  availability: "可用性",
  page: "頁面",
  a11y: "無障礙",
  integrity: "一致性",
  monitoring: "監測",
};

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

export function renderMarkdown(report: RunReport): string {
  const findings = sortFindings(allFindings(report));
  const lines: string[] = [];
  const { summary } = report;

  lines.push("# Aios Sentinel 檢測報告", "");
  lines.push(`- 受測目標：\`${report.target}\``);
  lines.push(`- 檢測端：${report.surfaces.join("、")}`);
  lines.push(`- 執行時間：${report.startedAt}（耗時 ${(report.durationMs / 1000).toFixed(1)} 秒）`);
  lines.push(`- 檢查項：${summary.completed}/${summary.total} 完成，${summary.skipped} 跳過，${summary.errored} 執行錯誤`);
  lines.push("");

  lines.push("## 總覽", "");
  lines.push("| 嚴重度 | 數量 |", "| --- | ---: |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${summary.findings[severity]} |`);
  }
  lines.push("");

  if (findings.length === 0) {
    lines.push("> 本次檢測沒有發現任何問題。", "");
  }

  // 跳過與錯誤要放在最前面顯眼處：沒跑到的檢查最容易被誤讀成通過。
  const skipped = report.results.filter((r) => !r.completed && r.skippedReason);
  const errored = report.results.filter((r) => r.error);
  if (skipped.length > 0 || errored.length > 0) {
    lines.push("## ⚠️ 未完成的檢查（不等於通過）", "");
    for (const r of skipped) lines.push(`- **${r.check}**（${r.surface}）已跳過：${r.skippedReason}`);
    for (const r of errored) lines.push(`- **${r.check}**（${r.surface}）執行錯誤：${r.error}`);
    lines.push("");
  }

  const bySeverity = new Map<Severity, Finding[]>();
  for (const f of findings) {
    const list = bySeverity.get(f.severity) ?? [];
    list.push(f);
    bySeverity.set(f.severity, list);
  }

  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const list = bySeverity.get(severity);
    if (!list || list.length === 0) continue;
    lines.push(`## ${SEVERITY_LABEL[severity]}（${list.length}）`, "");
    for (const f of list) {
      lines.push(`### ${f.title}`, "");
      lines.push(`- 分類：${CATEGORY_LABEL[f.category] ?? f.category} ｜ 端：${f.surface} ｜ 檢查：\`${f.check}\``);
      if (f.where) lines.push(`- 位置：\`${f.where}\``);
      lines.push("");
      lines.push(f.detail, "");
      if (f.evidence) {
        lines.push("<details><summary>觀測證據</summary>", "", "```", f.evidence.slice(0, 1200), "```", "", "</details>", "");
      }
      lines.push(`**建議修法**：${f.remediation ?? "（未提供）"}`, "");
    }
  }

  lines.push("## 檢查明細", "");
  lines.push("| 檢查 | 端 | 狀態 | 發現 | 耗時 |", "| --- | --- | --- | ---: | ---: |");
  for (const r of report.results) {
    const status = r.error ? "執行錯誤" : r.completed ? "完成" : "跳過";
    lines.push(
      `| ${escapeCell(r.check)} | ${r.surface} | ${status} | ${r.findings.length} | ${(r.durationMs / 1000).toFixed(1)}s |`,
    );
  }
  lines.push("");

  return lines.join("\n");
}
