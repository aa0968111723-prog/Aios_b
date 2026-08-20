/**
 * 終端輸出。CI 日誌與本機執行都看這個，所以要能在沒有顏色的環境下依然可讀
 * （顏色只是加分，資訊不靠顏色承載）。
 */
import { sortFindings, severityRank } from "../core/severity.js";
import { findingKey } from "../core/findings.js";
import { allFindings } from "../core/runner.js";
import type { RunReport, Severity } from "../core/types.js";

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const c = (code: string, text: string): string => (useColor ? `[${code}m${text}[0m` : text);

const SEVERITY_STYLE: Record<Severity, { label: string; code: string }> = {
  critical: { label: "極嚴重", code: "1;31" },
  high: { label: "高    ", code: "31" },
  medium: { label: "中    ", code: "33" },
  low: { label: "低    ", code: "36" },
  info: { label: "參考  ", code: "90" },
};

export function printSummary(report: RunReport): void {
  const findings = sortFindings(allFindings(report));
  const { summary } = report;

  process.stdout.write("\n");
  process.stdout.write(`${c("1", "Aios Sentinel 檢測結果")}\n`);
  process.stdout.write(`目標：${report.target}\n`);
  process.stdout.write(`端點：${report.surfaces.join("、")}　耗時：${(report.durationMs / 1000).toFixed(1)}s\n`);
  process.stdout.write(
    `檢查：${summary.completed}/${summary.total} 完成` +
      (summary.skipped ? `，${c("33", `${summary.skipped} 跳過`)}` : "") +
      (summary.errored ? `，${c("31", `${summary.errored} 執行錯誤`)}` : "") +
      (summary.suppressed ? `，${c("90", `${summary.suppressed} 已抑制`)}` : "") +
      "\n",
  );

  // 過濾過的報告不是完整檢測。這行要在最前面，否則讀者會把局部結果當成全貌。
  if (report.filter && (report.filter.only.length > 0 || report.filter.skip.length > 0)) {
    const parts: string[] = [];
    if (report.filter.only.length > 0) parts.push(`只執行 ${report.filter.only.join("、")}`);
    if (report.filter.skip.length > 0) parts.push(`略過 ${report.filter.skip.join("、")}`);
    process.stdout.write(`${c("33", `範圍：${parts.join("；")}——未執行的項目沒有結論，不代表通過。`)}\n`);
  }

  if (report.diff) {
    const escalated = report.diff.changed.filter((x) => severityRank(x.after.severity) < severityRank(x.before.severity)).length;
    process.stdout.write(
      `比對基準：${c("31", `新增 ${report.diff.added.length}`)}　${c("32", `已修復 ${report.diff.fixed.length}`)}` +
        `　${escalated ? c("31", `惡化 ${escalated}`) : `惡化 ${escalated}`}　持續 ${report.diff.unchanged.length}\n`,
    );
  }
  process.stdout.write("\n");

  // 未完成的檢查放最前面：這是最容易被誤讀成「通過」的東西。
  for (const r of report.results) {
    if (r.completed) continue;
    const reason = r.error ?? r.skippedReason ?? "未說明";
    const tag = r.error ? c("31", "執行錯誤") : c("33", "跳過");
    process.stdout.write(`  ${tag} ${r.check}（${r.surface}）：${reason}\n`);
  }
  if (report.results.some((r) => !r.completed)) process.stdout.write("\n");

  if (findings.length === 0) {
    // 「沒有發現」與「什麼都沒測到」必須講清楚。全部跳過卻印綠勾，
    // 是這類工具最容易誤導人的一瞬間——讀者只會記得那個勾。
    if (summary.completed === 0) {
      process.stdout.write(`${c("33", "！ 沒有任何檢查實際執行——本次結果不代表系統健康。請先排除上列跳過原因。")}\n\n`);
    } else if (summary.skipped > 0 || summary.errored > 0) {
      process.stdout.write(
        `${c("32", `✓ 已完成的 ${summary.completed} 項檢查沒有發現問題`)}${c("33", `，但有 ${summary.skipped + summary.errored} 項未完成（見上）。`)}\n\n`,
      );
    } else {
      process.stdout.write(`${c("32", "✓ 沒有發現問題。")}\n\n`);
    }
    return;
  }

  const newKeys = new Set((report.diff?.added ?? []).map(findingKey));

  for (const f of findings) {
    const style = SEVERITY_STYLE[f.severity];
    const isNew = newKeys.has(findingKey(f)) ? c("1;31", " 新") : "";
    process.stdout.write(`${c(style.code, `[${style.label}]`)}${isNew} ${f.title}\n`);
    process.stdout.write(`${c("90", `           ${f.detail.split("\n")[0]}`)}\n`);
    if (f.where) process.stdout.write(`${c("90", `           位置：${f.where}`)}\n`);
    if (f.remediation) process.stdout.write(`${c("90", `           修法：${f.remediation}`)}\n`);
    process.stdout.write("\n");
  }

  const parts = (["critical", "high", "medium", "low", "info"] as Severity[])
    .filter((s) => summary.findings[s] > 0)
    .map((s) => c(SEVERITY_STYLE[s].code, `${SEVERITY_STYLE[s].label.trim()} ${summary.findings[s]}`));
  process.stdout.write(`合計：${parts.join("　")}\n`);

  // 被抑制的發現只印摘要與提醒，明細留在報告檔——但絕不能完全不印，
  // 否則抑制清單就變成「讓問題從終端消失」的開關。
  if (summary.suppressed > 0) {
    process.stdout.write(
      `${c("90", `另有 ${summary.suppressed} 筆依抑制清單移出主清單（問題仍存在，明細見報告的「已抑制」一節）。`)}\n`,
    );
  }
  process.stdout.write("\n");
}
