/**
 * 報告後製：把抑制清單、跨次比對與過濾範圍套進一份已經跑完的報告。
 *
 * 為什麼獨立成一層，而不是塞進 runner：runner 的職責是「把檢查跑完並如實記錄」，
 * 它不該知道有抑制清單這種東西存在。把後製抽出來之後，這三件事有一個共同的性質可以被
 * 一致地保證——**它們只能改變呈現，不能改變事實**：
 *
 * - 抑制：發現被移出主清單，但連同理由與到期日留在 `report.suppressed`，計數留在 summary。
 * - 比對：只是替既有的發現貼上「新增／持續」的標籤，不會讓任何一筆消失。
 * - 過濾：範圍寫進 `report.filter`，報告會在最前面告訴讀者涵蓋範圍被縮小過。
 *
 * 還有一條同樣重要的規則：**後製自己出錯時要出聲**。抑制清單有壞規則、基準檔讀不出來，
 * 都會產生正式的發現進入報告，而不是印一行 stderr 就算了。一個沒生效的抑制規則會讓人
 * 以為某件事已經被處理掉，而一份讀不出來的基準會讓「新增」這一欄整個失去意義——
 * 兩者都是靜默的錯誤結論，正是這套系統最要避免的東西。
 */
import { finding } from "./findings.js";
import { countBySeverity, worstSeverity } from "./severity.js";
import { diffFindings, type BaselineSnapshot } from "./baseline.js";
import { applySuppressions, type SuppressionProblem, type SuppressionRule } from "./suppress.js";
import type { CheckResult, Finding, RunReport, SuppressedFindingRecord } from "./types.js";

export interface AnnotateInput {
  /** 抑制清單的解析結果。壞掉的規則（problems）也會被寫進報告。 */
  suppressions?: { rules: SuppressionRule[]; problems: SuppressionProblem[] };
  /** 基準檔的解析結果。`snapshot` 為 null 且 `error` 有值時代表讀失敗，要出聲。 */
  baseline?: { snapshot: BaselineSnapshot | null; error: string | null };
  filter?: { only: string[]; skip: string[] };
  now?: Date;
}

const META: Pick<CheckResult, "category" | "surface"> = { category: "integrity", surface: "all" };

/**
 * 把一組 meta 發現包成一筆結果，讓它們走一般的報告管線。
 *
 * `meta: true` 不是裝飾：summary 的 completed／skipped／errored 會排除它。
 * 後製不可以把任何東西變成「跑過的檢查」——那會讓「什麼都沒驗」的那一輪從 exit 3 變成 exit 0。
 */
function metaResult(check: string, findings: Finding[]): CheckResult {
  return { check, ...META, completed: true, durationMs: 0, findings, meta: true };
}

/**
 * 壞掉的抑制規則要變成發現。
 *
 * 一條寫錯的規則不會報錯，它只是安靜地沒有生效。而寫規則的人此刻正相信那件事已經被
 * 處理掉了——這比沒有抑制清單更危險，所以嚴重度給 medium 而不是 info。
 */
function problemFindings(problems: SuppressionProblem[]): Finding[] {
  return problems.map((p, i) =>
    finding({
      ...META,
      check: "suppress",
      id: `suppress.invalid-rule.${p.rule?.id ?? `第${i + 1}筆`}`,
      severity: "medium",
      title: `抑制清單有一條規則無法使用：${p.rule?.id ?? `第 ${i + 1} 筆`}`,
      detail:
        `${p.message}。這條規則沒有生效——寫下它的人此刻可能以為那個問題已經被處理掉了，` +
        "而實際上它要嘛照常出現在報告裡（還好），要嘛因為別的規則而被蓋住（不好）。",
      remediation: "修正抑制清單裡的這條規則；每條規則都需要合法的 id 與不可空白的 reason。",
      evidence: p.raw === undefined ? undefined : JSON.stringify(p.raw).slice(0, 400),
    }),
  );
}

/** 基準檔讀不出來時，把它變成一筆發現——否則「新增」那一欄會安靜地變成空的。 */
function baselineErrorFinding(error: string): Finding {
  return finding({
    ...META,
    check: "baseline",
    id: "baseline.unreadable",
    severity: "medium",
    title: "基準檔無法解讀，本次沒有跨次比對",
    detail:
      `${error}。報告裡的「新增」與「已修復」因此沒有結果——不是沒有變化，是沒有比較過。` +
      "若把讀不出來的基準當成空基準，所有存量問題會被報成新增而淹沒 CI；" +
      "反過來當成「沒有變化」，則真正新增的問題會被吃掉。兩種都是錯的結論，所以這裡直接說沒比。",
    remediation: "確認 --baseline 指向的是上一次執行輸出的 report.json（或一份只含 findings 陣列的精簡基準）。",
  });
}

/**
 * 重算 summary。
 *
 * 發現數要含 meta 結果（抑制提醒與基準錯誤都是讀者該看到的發現），
 * 但**檢查計數一律排除 meta**——那些不是跑過的檢查，把它們算進 completed
 * 會直接破壞 exitCodeFor 的「什麼都沒實際執行回 3」那條防線。
 */
function recomputeSummary(results: CheckResult[], suppressedCount: number): RunReport["summary"] {
  const all = results.flatMap((r) => r.findings);
  const real = results.filter((r) => !r.meta);
  return {
    total: real.length,
    completed: real.filter((r) => r.completed).length,
    skipped: real.filter((r) => !r.completed && r.skippedReason).length,
    errored: real.filter((r) => r.error).length,
    suppressed: suppressedCount,
    findings: countBySeverity(all),
    worst: worstSeverity(all),
  };
}

/**
 * 套用後製，回傳一份新的報告（不改動輸入）。
 *
 * 順序是刻意的：先抑制、再比對。反過來的話，被抑制的發現會先進入比對而被算成「持續」，
 * 隔天有人把抑制規則刪掉，同一筆問題又會被算成「新增」——比對結果會隨著抑制清單的
 * 編輯而跳動，而不是隨著站台的實際狀態。比對要比的是**讀者實際會看到的那份清單**。
 */
export function annotateReport(report: RunReport, input: AnnotateInput): RunReport {
  const now = input.now ?? new Date();
  let results = report.results;
  let suppressedRecords: SuppressedFindingRecord[] | undefined;

  // ── 抑制 ────────────────────────────────────────────────────────────────
  if (input.suppressions) {
    const { rules, problems } = input.suppressions;
    const outcome = applySuppressions(
      results.flatMap((r) => r.findings),
      rules,
      now,
    );
    const kept = new Set(outcome.kept);
    results = results.map((r) => ({ ...r, findings: r.findings.filter((f) => kept.has(f)) }));

    suppressedRecords = outcome.suppressed.map((s) => ({
      finding: s.finding,
      reason: s.rule.reason,
      expires: s.rule.expires ?? null,
      owner: s.rule.owner ?? null,
    }));

    const meta = [...outcome.notes, ...problemFindings(problems)];
    if (meta.length > 0) results = [...results, metaResult("suppress", meta)];
  }

  // ── 跨次比對 ────────────────────────────────────────────────────────────
  let diff: RunReport["diff"];
  if (input.baseline) {
    if (input.baseline.error) {
      results = [...results, metaResult("baseline", [baselineErrorFinding(input.baseline.error)])];
    } else if (input.baseline.snapshot) {
      const snapshot = input.baseline.snapshot;
      // 比對的對象是抑制之後的清單——讀者實際會看到的那一份。
      const current = results.flatMap((r) => r.findings);
      diff = {
        baselineTarget: snapshot.target,
        baselineStartedAt: snapshot.startedAt,
        ...diffFindings(snapshot.findings, current),
      };
    }
  }

  const annotated: RunReport = {
    ...report,
    results,
    summary: recomputeSummary(results, suppressedRecords?.length ?? 0),
  };
  if (diff) annotated.diff = diff;
  if (suppressedRecords && suppressedRecords.length > 0) annotated.suppressed = suppressedRecords;
  if (input.filter && (input.filter.only.length > 0 || input.filter.skip.length > 0)) annotated.filter = input.filter;

  return annotated;
}
