/**
 * 跨次執行比對。
 *
 * docs/CHECKS.md 開宗明義寫著「每一筆發現都有穩定的 id，可用於抑制清單、跨次執行比對」，
 * 但比對本身一直沒有實作。少了它，每次執行都只是一張互不相干的快照：沒有人看得出
 * 「這次多了什麼」，也沒有人知道「上次那件到底修好了沒」。於是報告變成一面每次都長得
 * 差不多的噪音牆，讀的人越來越少，最後連真的新增的 critical 都沒人注意到——
 * 檢測系統就是這樣死掉的，不是因為漏抓，而是因為沒人再讀它的輸出。
 *
 * 這個模組只做一件事：把兩次執行的發現依穩定鍵配對，然後說出四種關係
 * （新增／已修復／持續／嚴重度變動）。它不碰網路也不碰檔案系統——讀基準檔是呼叫端的事，
 * 這裡只收字串——所以整套比對規則都能離線測試。
 *
 * 一條原則貫穿全檔：**沉默是最糟的結果**。基準檔壞掉不該讓整輪檢測掛掉，但也絕不可以
 * 被當成「沒有基準」——那會讓所有存量問題一夕之間變成「新增」而淹沒 CI，或反過來讓真正
 * 新增的問題被吃掉。所以 `parseBaseline` 只有兩種回答：一份可信的快照，或一句說得出
 * 原因的錯誤。
 */
import { findingKey } from "./findings.js";
import { severityRank, shouldFail } from "./severity.js";
import type { Category, Finding, Severity, SurfaceId } from "./types.js";

/**
 * 穩定鍵沿用 `findings.ts` 的同一支函式，不在這裡重寫一份。
 *
 * 去重、抑制清單、跨次比對三者只要有一處算法走偏，「上次抑制掉的」與「這次新增的」
 * 就會對不起來——那種錯誤不會報錯，只會安靜地給出錯誤的比對結果。
 */
export { findingKey };

/** 同一筆問題在兩次執行之間的嚴重度變動。`key` 是兩邊配對用的穩定鍵。 */
export interface FindingChange {
  key: string;
  before: Finding;
  after: Finding;
}

/**
 * 兩次執行的比對結果。
 *
 * 欄位刻意與 `types.ts` 的 `ReportDiff` 對齊：呼叫端把基準檔的 target／時間補上去
 * （`{ baselineTarget, baselineStartedAt, ...diff }`）就能直接塞進報告，不必再轉換一次。
 */
export interface FindingDiff {
  /** 這次才出現的。 */
  added: Finding[];
  /** 上次有、這次沒有的——注意這是「這次沒測到」，不必然等於「已經修好」，見下方註解。 */
  fixed: Finding[];
  /** 兩次都在且嚴重度相同的存量問題。存的是這次的觀測（證據較新）。 */
  unchanged: Finding[];
  /** 兩次都在但嚴重度不同的。用 `isEscalation` 分辨惡化與減輕。 */
  changed: FindingChange[];
}

/** 基準檔還原出來的內容。 */
export interface BaselineSnapshot {
  findings: Finding[];
  /** 基準檔的執行時間；精簡格式沒有這個欄位時為 null。 */
  startedAt: string | null;
  /**
   * 基準檔測的是哪個站。
   *
   * 與本次 target 不同時**照樣比對**（拿 staging 比 production 有時正是想看的事），
   * 但呼叫端必須把它顯示出來——不然讀者會把兩個站之間的差異當成「這次改壞了」。
   */
  target: string | null;
}

const SEVERITIES = new Set<string>(["critical", "high", "medium", "low", "info"]);

/**
 * 依鍵建索引，重複鍵一律以第一筆為準。
 *
 * 與 `dedupe()` 同一套規則：三端掃同一個站時同源問題會重複三次，若這裡改成「後者覆蓋」，
 * 比對結果會隨著檢查的執行順序而變——同樣的站、同樣的問題，換個順序就多一筆「惡化」。
 * Map 保留插入順序，因此輸出順序即為原始出現順序。
 */
function indexByKey(findings: Finding[]): Map<string, Finding> {
  const index = new Map<string, Finding>();
  for (const f of findings) {
    const key = findingKey(f);
    if (index.has(key)) continue;
    index.set(key, f);
  }
  return index;
}

/**
 * 比對兩次執行。
 *
 * 只用嚴重度區分「持續」與「變動」，不比 detail／evidence：證據字串每次都可能不同
 * （時間戳、回應片段、隨機 nonce），拿它當變動判準會讓整份報告每次都宣稱「全部都變了」。
 *
 * `fixed` 的語意要克制：它的真正意思是「上次有、這次沒有」。檢查被跳過、路由改名、
 * 目標換站都會讓一筆發現從清單上消失，那些都不是修好。所以這裡只給事實，
 * 是否慶祝由讀者搭配 `CheckResult.completed` 自行判斷。
 */
export function diffFindings(previous: Finding[], current: Finding[]): FindingDiff {
  const before = indexByKey(previous);
  const after = indexByKey(current);

  const added: Finding[] = [];
  const unchanged: Finding[] = [];
  const changed: FindingChange[] = [];

  for (const [key, now] of after) {
    const then = before.get(key);
    if (!then) {
      added.push(now);
      continue;
    }
    if (then.severity === now.severity) {
      unchanged.push(now);
      continue;
    }
    changed.push({ key, before: then, after: now });
  }

  const fixed: Finding[] = [];
  for (const [key, then] of before) {
    if (!after.has(key)) fixed.push(then);
  }

  return { added, fixed, unchanged, changed };
}

/**
 * 這筆變動是惡化嗎？
 *
 * `severityRank` 的數字越小越嚴重，所以 after 的名次比 before 前面就是惡化。
 * 惡化與新增要一起擋 CI：一筆 low 悄悄變成 critical，危害不會因為「它上次就在了」而減少。
 */
export function isEscalation(change: FindingChange): boolean {
  return severityRank(change.after.severity) < severityRank(change.before.severity);
}

/** 給報告抬頭用的計數。`changed` 只含嚴重度不同的筆數，故非惡化即減輕。 */
export function summarizeDiff(diff: FindingDiff): {
  added: number;
  fixed: number;
  unchanged: number;
  escalated: number;
  improved: number;
} {
  const escalated = diff.changed.filter(isEscalation).length;
  return {
    added: diff.added.length,
    fixed: diff.fixed.length,
    unchanged: diff.unchanged.length,
    escalated,
    improved: diff.changed.length - escalated,
  };
}

/**
 * `--fail-on-new` 的判準：新增或惡化之中有達到門檻者即為 true。
 *
 * 存量問題不擋 CI，是為了讓既有專案導得進來——第一次跑完滿江紅，接著整個檢查會被關掉，
 * 那等於沒有檢測。但今天新長出來的、以及今天變嚴重的，一定要當場擋下，否則這個模式
 * 就只是把門檻無限期往後延。
 *
 * 門檻語意（達到或超過）直接沿用 `shouldFail`，不在這裡另寫一份比較——兩份門檻邏輯
 * 遲早會走偏，而走偏的那天沒有人會發現。
 */
export function hasNewFindings(diff: FindingDiff, failOn: Severity): boolean {
  const escalated = diff.changed.filter(isEscalation).map((c) => c.after);
  return shouldFail([...diff.added, ...escalated], failOn);
}

type Collected = { items: unknown[] } | { error: string };

/**
 * 認出這份 JSON 是哪一種報告，並取出其中的發現。
 *
 * 接受三種形狀：完整的 RunReport（`results[].findings[]`）、只有 `findings` 陣列的精簡格式，
 * 以及裸的發現陣列（手工整理的基準常長這樣）。認不出來就明講認不出來——
 * 把不認識的檔案當成空基準，等於宣告「上次全綠」，會讓所有存量問題被報成新增。
 */
function collectFindings(raw: object): Collected {
  if (Array.isArray(raw)) return { items: raw };

  const record = raw as Record<string, unknown>;
  if (Array.isArray(record.findings)) return { items: record.findings };

  if (Array.isArray(record.results)) {
    const items: unknown[] = [];
    for (const [i, result] of record.results.entries()) {
      if (result === null || typeof result !== "object" || Array.isArray(result)) {
        return { error: `results[${i}] 不是檢查結果物件` };
      }
      const findings = (result as Record<string, unknown>).findings;
      // 沒有 findings 欄位的結果一律當成沒有發現：被跳過的檢查本來就可能只留下 skippedReason。
      if (findings === undefined || findings === null) continue;
      if (!Array.isArray(findings)) return { error: `results[${i}].findings 不是陣列` };
      items.push(...findings);
    }
    return { items };
  }

  return { error: "既沒有 results[].findings[]，也沒有 findings 陣列" };
}

/**
 * 把一筆基準紀錄還原成 Finding。
 *
 * 這裡刻意不走 `finding()` 工廠：工廠是為「產生新發現」而設，強制填 remediation；
 * 而基準檔是還原歷史資料，欄位由當時的版本決定，為了一個顯示用欄位把整份基準判定作廢，
 * 傷害遠大於少一句修法。
 *
 * 但兩個欄位不容妥協——`id` 與 `severity` 是比對本身的依據：
 * 沒有 id 就沒有鍵，這筆會被靜默丟掉，然後這次的同一個問題被報成「新增」；
 * 沒有合法 severity 就分不出惡化與減輕。這兩者缺一，整份基準都不可信，所以回報錯誤。
 *
 * 回傳字串代表無法解讀，內容是給人看的原因。
 */
function normalizeFinding(entry: unknown): Finding | string {
  if (entry === null || typeof entry !== "object" || Array.isArray(entry)) return "不是物件";
  const record = entry as Record<string, unknown>;

  const id = record.id;
  if (typeof id !== "string" || id.trim() === "") return "缺少 id（沒有穩定鍵就無從比對）";

  const severity = record.severity;
  if (typeof severity !== "string" || !SEVERITIES.has(severity)) {
    return `\`${id}\` 的 severity 不是合法等級：${JSON.stringify(severity ?? null)}`;
  }

  const where = record.where;
  if (where !== undefined && where !== null && typeof where !== "string") {
    return `\`${id}\` 的 where 不是字串（鍵會算錯）`;
  }

  const text = (value: unknown, fallback: string): string => (typeof value === "string" ? value : fallback);

  const restored: Finding = {
    id,
    severity: severity as Severity,
    // check／category／surface 只影響報告怎麼分節與顯示，不參與任何判定。
    // 缺漏時補上不會誤導的預設值：check 退回 id 的第一段（id 的第一段本來就是檢查名），
    // category 退回 security（比對區塊不依 category 分節，這個值只是型別上的佔位）。
    check: text(record.check, id.split(".")[0] ?? id),
    category: typeof record.category === "string" ? (record.category as Category) : "security",
    surface: typeof record.surface === "string" ? (record.surface as SurfaceId | "all") : "all",
    title: text(record.title, id),
    detail: text(record.detail, ""),
  };
  if (typeof where === "string") restored.where = where;
  if (typeof record.evidence === "string") restored.evidence = record.evidence;
  if (typeof record.remediation === "string") restored.remediation = record.remediation;

  return restored;
}

/**
 * 容忍地解析既有的報告當作基準。
 *
 * 「容忍」指的是形狀：完整報告、精簡格式、裸陣列都收，缺的顯示欄位補預設。
 * 但**不容忍靜默**：任何無法解讀的情形都回一句 error 而不是 `snapshot: null` 加空陣列，
 * 也不是丟例外。呼叫端拿到 error 應該把它印在報告上並退回「無基準」模式，
 * 而不是假裝上次全綠。
 *
 * 空基準（`findings: []`）與沒有基準是兩件事：前者代表上次確實全綠，這次的每一筆都是新增；
 * 後者是 `snapshot: null`，代表根本無從比較。這個區別必須留給呼叫端，不能在這裡壓平。
 */
export function parseBaseline(json: string): { snapshot: BaselineSnapshot | null; error: string | null } {
  let raw: unknown;
  try {
    raw = JSON.parse(json);
  } catch (err) {
    return { snapshot: null, error: `基準檔不是合法 JSON：${err instanceof Error ? err.message : String(err)}` };
  }

  if (raw === null || typeof raw !== "object") {
    return { snapshot: null, error: "基準檔的最外層不是物件或陣列，看不出是報告" };
  }

  const collected = collectFindings(raw);
  if ("error" in collected) {
    return { snapshot: null, error: `基準檔的結構認不出來：${collected.error}` };
  }

  const findings: Finding[] = [];
  for (const [i, entry] of collected.items.entries()) {
    const restored = normalizeFinding(entry);
    if (typeof restored === "string") {
      return { snapshot: null, error: `基準檔第 ${i + 1} 筆發現無法解讀：${restored}` };
    }
    findings.push(restored);
  }

  const record = Array.isArray(raw) ? {} : (raw as Record<string, unknown>);
  return {
    snapshot: {
      findings,
      startedAt: typeof record.startedAt === "string" ? record.startedAt : null,
      target: typeof record.target === "string" ? record.target : null,
    },
    error: null,
  };
}
