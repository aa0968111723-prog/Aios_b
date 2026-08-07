import type { Category, Finding, Severity, SurfaceId } from "./types.js";

/**
 * 建立 Finding 的小工廠。
 *
 * 存在的理由不是省字，是**強制每筆發現都帶 remediation**。
 * 沒有修法的告警會被無視，被無視的告警等於沒有檢測——這是這類系統最常見的死法。
 */
export function finding(input: {
  id: string;
  check: string;
  category: Category;
  severity: Severity;
  surface: SurfaceId | "all";
  title: string;
  detail: string;
  remediation: string;
  evidence?: string;
  where?: string;
}): Finding {
  return { ...input };
}

/** 檢查耗時計量：把 `Date.now()` 的樣板集中，順便確保每個結果都有 durationMs。 */
export function stopwatch(): () => number {
  const startedAt = Date.now();
  return () => Date.now() - startedAt;
}

/** 同 id 只留第一筆。三端掃同一個站時，同源問題會重複三次——報告只需要一次。 */
export function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = `${f.id}::${f.where ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
