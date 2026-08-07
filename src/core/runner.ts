/**
 * 執行編排。
 *
 * 一個規則貫穿全檔：**檢查器自己爆掉，不能讓整輪掛掉**。
 * 檢測系統最沒有價值的失敗模式，就是因為某一項的邊界情況拋例外，
 * 導致其他 20 項本來會抓到的問題全都沒跑到。所以每一項都包在 `safely` 裡，
 * 例外被轉成 `error` 欄位（與「發現問題」分開統計），其餘照跑。
 */
import { countBySeverity, worstSeverity } from "./severity.js";
import type { CheckResult, RunReport, SentinelConfig, Severity, Surface } from "./types.js";

export type CheckTask = () => Promise<CheckResult>;

async function safely(name: string, meta: Pick<CheckResult, "category" | "surface">, task: CheckTask): Promise<CheckResult> {
  const startedAt = Date.now();
  try {
    return await task();
  } catch (err) {
    return {
      check: name,
      category: meta.category,
      surface: meta.surface,
      completed: false,
      durationMs: Date.now() - startedAt,
      findings: [],
      error: err instanceof Error ? `${err.name}: ${err.message}` : String(err),
    };
  }
}

export interface RunnerHooks {
  onCheckStart?: (name: string, surface: string) => void;
  onCheckDone?: (result: CheckResult) => void;
}

export interface PlannedCheck {
  name: string;
  category: CheckResult["category"];
  surface: CheckResult["surface"];
  run: CheckTask;
}

/**
 * 依序執行所有檢查。
 *
 * 刻意序列而非並行：並行掃描會對目標站產生突發負載，在小型部署上可能自己造成 5xx，
 * 然後把自己造成的錯誤報成「站台有問題」。檢測系統不該污染它要測量的東西。
 */
export async function runChecks(
  config: SentinelConfig,
  planned: PlannedCheck[],
  hooks: RunnerHooks = {},
): Promise<RunReport> {
  const startedAt = new Date();
  const results: CheckResult[] = [];

  for (const item of planned) {
    hooks.onCheckStart?.(item.name, String(item.surface));
    const result = await safely(item.name, { category: item.category, surface: item.surface }, item.run);
    results.push(result);
    hooks.onCheckDone?.(result);
  }

  const finishedAt = new Date();
  const allFindings = results.flatMap((r) => r.findings);

  return {
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    target: config.target,
    surfaces: config.surfaces.map((s) => s.id),
    results,
    summary: {
      total: results.length,
      completed: results.filter((r) => r.completed).length,
      skipped: results.filter((r) => !r.completed && r.skippedReason).length,
      errored: results.filter((r) => r.error).length,
      findings: countBySeverity(allFindings),
      worst: worstSeverity(allFindings),
    },
  };
}

export function allFindings(report: RunReport) {
  return report.results.flatMap((r) => r.findings);
}

/** 每個 surface 都跑一次的檢查，展開成 planned 清單。 */
export function perSurface(
  surfaces: Surface[],
  name: string,
  category: CheckResult["category"],
  build: (surface: Surface) => CheckTask,
): PlannedCheck[] {
  return surfaces.map((surface) => ({ name, category, surface: surface.id, run: build(surface) }));
}

/**
 * 結束碼。
 *   0 通過　1 發現達門檻的問題　2 檢查器自身出錯　3 什麼都沒實際執行
 *
 * 3 是刻意分出來的：全部被跳過（連不到站、缺瀏覽器）時若回 0，CI 會顯示綠燈，
 * 而那個綠燈的意思其實是「我們什麼都沒驗」。這種假綠燈比紅燈危險得多。
 */
export function exitCodeFor(report: RunReport, failOn: Severity): number {
  const { worst, completed, errored } = report.summary;
  if (completed === 0) return 3;
  if (errored > 0 && worst === null) return 2;
  if (!worst) return 0;
  const order: Severity[] = ["critical", "high", "medium", "low", "info"];
  return order.indexOf(worst) <= order.indexOf(failOn) ? 1 : 0;
}
