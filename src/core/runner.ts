/**
 * 執行編排。
 *
 * 一個規則貫穿全檔：**檢查器自己爆掉，不能讓整輪掛掉**。
 * 檢測系統最沒有價值的失敗模式，就是因為某一項的邊界情況拋例外，
 * 導致其他 20 項本來會抓到的問題全都沒跑到。所以每一項都包在 `safely` 裡，
 * 例外被轉成 `error` 欄位（與「發現問題」分開統計），其餘照跑。
 */
import { countBySeverity, severityRank, worstSeverity } from "./severity.js";
import { hasNewFindings } from "./baseline.js";
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
      // 這一輪還沒套用抑制清單（那是 annotate 的事），所以恆為 0；
      // 欄位在這裡就給值，是為了讓 summary 的形狀在整條流程上始終一致。
      suppressed: 0,
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
 * 每個**不同的 origin** 只跑一次的檢查。
 *
 * 有一類判定與載體完全無關：TLS 憑證、robots.txt、開放重導向、方法稽核——
 * 伺服器不會因為請求帶著 App 的 UA 就換一張憑證。這些檢查若照 surface 展開，
 * 三端同源時只會得到三份一模一樣的發現，並讓請求量無謂地變成三倍；
 * 而這套系統的原則之一正是「檢測系統不該污染它要測量的東西」。
 *
 * 但也不能寫死成「只跑 web」：三端可以各自指到不同部署（`AIOS_APP_TARGET` 等），
 * 那時候每個 origin 都必須各驗一次。所以判準是 origin 而不是 surface。
 */
export function perOrigin(
  surfaces: Surface[],
  name: string,
  category: CheckResult["category"],
  build: (surface: Surface) => CheckTask,
): PlannedCheck[] {
  const byOrigin = new Map<string, Surface[]>();
  for (const surface of surfaces) {
    const group = byOrigin.get(surface.origin) ?? [];
    group.push(surface);
    byOrigin.set(surface.origin, group);
  }

  return [...byOrigin.values()].map((group) => {
    const representative = group[0] as Surface;
    // 一個 origin 底下有多個 surface 時，這筆發現不屬於任何單一載體——標 all 才誠實。
    const surface: CheckResult["surface"] = group.length > 1 ? "all" : representative.id;
    return { name, category, surface, run: build(representative) };
  });
}

/**
 * 結束碼。
 *   0 通過　1 發現達門檻的問題　2 檢查器自身出錯　3 什麼都沒實際執行
 *
 * 3 是刻意分出來的：全部被跳過（連不到站、缺瀏覽器）時若回 0，CI 會顯示綠燈，
 * 而那個綠燈的意思其實是「我們什麼都沒驗」。這種假綠燈比紅燈危險得多。
 *
 * `onlyNew` 是導入既有專案時的務實選項：存量問題不擋 CI，但**新增與惡化要擋**。
 * 沒有這個模式，第一次跑完就是滿江紅，接著整個檢查會被關掉——那等於沒有檢測。
 * 但它有代價：存量的 critical 會安靜地留在那裡，所以無論如何都要求有基準可比，
 * 沒有基準時退回一般判準，絕不因為「拿不到基準」就放行。
 */
export function exitCodeFor(report: RunReport, failOn: Severity, options: { onlyNew?: boolean } = {}): number {
  const { worst, completed, errored } = report.summary;
  if (completed === 0) return 3;
  if (errored > 0 && worst === null) return 2;

  // 判準委派給 baseline.ts，不在這裡另寫一份「什麼算惡化」。
  // 兩份門檻邏輯遲早會走偏，而走偏的那天不會有人發現——只會發現某天 CI 突然不擋了。
  if (options.onlyNew && report.diff) return hasNewFindings(report.diff, failOn) ? 1 : 0;

  if (!worst) return 0;
  return severityRank(worst) <= severityRank(failOn) ? 1 : 0;
}
