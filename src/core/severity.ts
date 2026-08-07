import type { Finding, Severity } from "./types.js";

/** 由高到低。索引即權重，`compareSeverity` 與 `worstSeverity` 都靠這個順序。 */
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

const RANK = new Map<Severity, number>(SEVERITY_ORDER.map((s, i) => [s, i]));

export function severityRank(severity: Severity): number {
  return RANK.get(severity) ?? SEVERITY_ORDER.length;
}

/** 排序用：回傳負數代表 a 比較嚴重。 */
export function compareSeverity(a: Severity, b: Severity): number {
  return severityRank(a) - severityRank(b);
}

/** 一組發現裡最嚴重的一筆；空陣列回 null（「沒發現」不是一種嚴重度）。 */
export function worstSeverity(findings: Finding[]): Severity | null {
  let worst: Severity | null = null;
  for (const f of findings) {
    if (worst === null || severityRank(f.severity) < severityRank(worst)) worst = f.severity;
  }
  return worst;
}

/**
 * 是否該讓 CI 失敗。
 *
 * 語意是「達到或超過門檻」：`failOn: "high"` 會被 critical 與 high 觸發，medium 不會。
 * 沒有任何發現時一律回 false——包含 `failOn: "info"`，否則門檻設最寬反而永遠紅燈。
 */
export function shouldFail(findings: Finding[], failOn: Severity): boolean {
  const worst = worstSeverity(findings);
  if (worst === null) return false;
  return severityRank(worst) <= severityRank(failOn);
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } satisfies Record<Severity, number>;
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** 依嚴重度排序（穩定：同嚴重度維持原順序，讓報告的閱讀順序可預期）。 */
export function sortFindings(findings: Finding[]): Finding[] {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => compareSeverity(a.f.severity, b.f.severity) || a.i - b.i)
    .map(({ f }) => f);
}
