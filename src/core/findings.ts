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

/**
 * 一筆發現的穩定識別鍵。
 *
 * `id` 標明「是哪一種問題」，`where` 標明「在哪一處」——兩者合起來才是「同一件事」。
 * 只用 id 會讓五條路徑上的同一種問題被折成一筆；只用 where 則會讓同一個網址上的
 * 不同問題互相蓋掉。這個鍵同時服務三個地方：去重、抑制清單比對、跨次執行比對，
 * 三者必須用同一把鍵，否則「上次抑制掉的」與「這次新增的」會對不起來。
 */
export function findingKey(f: Pick<Finding, "id" | "where">): string {
  return `${f.id}::${f.where ?? ""}`;
}

/** 同 id 只留第一筆。三端掃同一個站時，同源問題會重複三次——報告只需要一次。 */
export function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of findings) {
    const key = findingKey(f);
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
