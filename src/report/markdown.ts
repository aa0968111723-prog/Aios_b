/**
 * Markdown 報告。用途是貼進 PR 留言或 issue，所以要在沒有樣式的環境下依然好讀。
 */
import { sortFindings } from "../core/severity.js";
import { findingKey } from "../core/findings.js";
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

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function escapeCell(text: string): string {
  return text.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

/**
 * 涵蓋範圍告示。
 *
 * 有過濾就代表這份報告**不是完整檢測**。不寫在最前面，讀者會把一份只跑了 CSP 的報告
 * 當成「全部都查過了」——那是這套系統最不能接受的誤讀。
 */
function coverageNotice(report: RunReport): string[] {
  if (!report.filter) return [];
  const { only, skip } = report.filter;
  if (only.length === 0 && skip.length === 0) return [];
  const parts: string[] = [];
  if (only.length > 0) parts.push(`只執行 \`${only.join("、")}\``);
  if (skip.length > 0) parts.push(`略過 \`${skip.join("、")}\``);
  return [
    `> ⚠️ **本次檢測範圍被縮小**：${parts.join("；")}。未執行的項目在這份報告裡沒有任何結論——不代表通過。`,
    "",
  ];
}

/** 與基準的比對。存量與新增分開看，報告才不會變成沒人讀的噪音牆。 */
function diffSection(report: RunReport): string[] {
  const diff = report.diff;
  if (!diff) return [];
  const lines: string[] = ["## 與基準比對", ""];

  if (diff.baselineTarget && diff.baselineTarget !== report.target) {
    lines.push(
      `> ⚠️ 基準檔測的是 \`${diff.baselineTarget}\`，與本次的 \`${report.target}\` 不同。` +
        "跨站台比對只能參考，兩邊的差異可能來自部署本身而非變更。",
      "",
    );
  }
  if (diff.baselineStartedAt) lines.push(`- 基準時間：${diff.baselineStartedAt}`);

  const escalated = diff.changed.filter((c) => SEVERITY_RANK[c.after.severity] < SEVERITY_RANK[c.before.severity]);
  const improved = diff.changed.filter((c) => SEVERITY_RANK[c.after.severity] > SEVERITY_RANK[c.before.severity]);
  lines.push(
    `- 🆕 新增 **${diff.added.length}**　✅ 已修復 **${diff.fixed.length}**　` +
      `⬆️ 惡化 **${escalated.length}**　⬇️ 減輕 **${improved.length}**　➖ 持續 ${diff.unchanged.length}`,
    "",
  );

  if (diff.added.length > 0) {
    lines.push("### 🆕 新增", "", "| 嚴重度 | 問題 | id |", "| --- | --- | --- |");
    for (const f of sortFindings(diff.added)) {
      lines.push(`| ${SEVERITY_LABEL[f.severity]} | ${escapeCell(f.title)} | \`${f.id}\` |`);
    }
    lines.push("");
  }
  if (escalated.length > 0) {
    lines.push("### ⬆️ 嚴重度惡化", "", "| 變化 | 問題 | id |", "| --- | --- | --- |");
    for (const c of escalated) {
      lines.push(
        `| ${SEVERITY_LABEL[c.before.severity]} → ${SEVERITY_LABEL[c.after.severity]} | ${escapeCell(c.after.title)} | \`${c.after.id}\` |`,
      );
    }
    lines.push("");
  }
  if (diff.fixed.length > 0) {
    // 修好的東西要被看見。只列壞消息的報告，會讓人覺得修了也沒差。
    lines.push("### ✅ 已修復（本次不再出現）", "");
    for (const f of sortFindings(diff.fixed)) lines.push(`- ${SEVERITY_LABEL[f.severity]} ${escapeCell(f.title)}（\`${f.id}\`）`);
    lines.push("");
  }
  return lines;
}

/** 被抑制的發現。抑制是一種決定，不是讓問題消失的開關——所以它留在報告上。 */
function suppressedSection(report: RunReport): string[] {
  const suppressed = report.suppressed ?? [];
  if (suppressed.length === 0) return [];
  const lines: string[] = [`## 🔇 已抑制（${suppressed.length}）`, ""];
  lines.push("這些發現**依然存在**，只是依抑制清單移出主清單。每一筆都記著理由與到期日。", "");
  lines.push("| 嚴重度 | 問題 | 理由 | 到期 | 負責人 |", "| --- | --- | --- | --- | --- |");
  for (const s of suppressed) {
    lines.push(
      `| ${SEVERITY_LABEL[s.finding.severity]} | ${escapeCell(s.finding.title)} | ${escapeCell(s.reason)} | ` +
        `${s.expires ?? "**永久**"} | ${s.owner ?? "—"} |`,
    );
  }
  lines.push("");
  return lines;
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
  if (summary.suppressed > 0) lines.push(`- 已抑制：${summary.suppressed} 筆（見下方「已抑制」一節）`);
  lines.push("");
  lines.push(...coverageNotice(report));

  lines.push("## 總覽", "");
  lines.push("| 嚴重度 | 數量 |", "| --- | ---: |");
  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    lines.push(`| ${SEVERITY_LABEL[severity]} | ${summary.findings[severity]} |`);
  }
  lines.push("");

  lines.push(...diffSection(report));

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

  // 新增的發現要一眼看得出來：一份 40 筆的報告裡，讀者真正該先處理的是這次才冒出來的那幾筆。
  const newKeys = new Set((report.diff?.added ?? []).map(findingKey));

  for (const severity of ["critical", "high", "medium", "low", "info"] as Severity[]) {
    const list = bySeverity.get(severity);
    if (!list || list.length === 0) continue;
    lines.push(`## ${SEVERITY_LABEL[severity]}（${list.length}）`, "");
    for (const f of list) {
      lines.push(`### ${newKeys.has(findingKey(f)) ? "🆕 " : ""}${f.title}`, "");
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

  lines.push(...suppressedSection(report));

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
