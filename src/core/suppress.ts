/**
 * 抑制清單。
 *
 * 任何檢測系統活過三個月都會需要抑制清單——已知取捨、待排程的問題、第三方無法修的東西。
 * 但抑制清單本身是這類系統最常見的死法：有人為了讓 CI 變綠，一次把整批告警關掉；
 * 半年後沒人記得為什麼關、也沒人重新檢視。報告從此永遠是綠的，而系統早就不安全了。
 *
 * 所以這份實作的立場是：**抑制是一種有期限、要具名、且永遠留在報告上的決定，
 * 不是讓問題消失的開關。** 具體表現在五件事：
 * 1. 沒有 reason 的規則不收——沒有理由的抑制就是隱藏。
 * 2. 過期的規則自動失效，被它蓋住的發現會自己浮回報告，不需要有人記得回來看。
 * 3. 要蓋掉 critical 級發現必須明示 `acknowledgeCritical`，逼這個決定留下名字。
 * 4. 沒命中的規則、沒有到期日的規則，都會被反過來報出來——抑制清單自己也是受檢對象。
 * 5. 純 `*` 一律拒收：那不是抑制，那是停用檢測系統。
 *
 * 被抑制的發現不會被丟掉，而是原樣放在 `suppressed` 裡交給報告層另闢一區列出：
 * 讀者永遠看得到「有什麼被蓋住、被哪條規則蓋、為什麼蓋、蓋到哪天」。
 *
 * 本檔不碰網路也不碰檔案系統（讀檔是 CLI 的事），因此所有判定都能離線測試。
 */
import { finding, findingKey } from "./findings.js";
import type { Finding, SuppressedFindingRecord } from "./types.js";

/** 一條抑制規則。欄位刻意少，但每一個都有存在的理由。 */
export interface SuppressionRule {
  /** 要抑制的發現 id；支援**結尾**萬用字元（`cookies.*`、`csp.script-src.*`）。純 `*` 不接受。 */
  id: string;
  /** 選填。給了就必須與 `finding.where` 完全相同才命中——用來只放行「某一個端點上的」那筆。 */
  where?: string;
  /** 必填且不可空白。寫給半年後的自己看：當初為什麼決定不修。 */
  reason: string;
  /** ISO 日期（`2026-12-31`）或帶時區的完整時間。缺少即為永久抑制——允許，但會被報出來。 */
  expires?: string;
  /** 誰做的決定。過期時報告要知道該找誰。 */
  owner?: string;
  /** 明示承認要蓋掉 critical 級發現。沒有這個旗標，critical 一律照常回報。 */
  acknowledgeCritical?: boolean;
}

/** 清單裡壞掉的一筆。壞的進這裡、好的照收——一筆寫錯不該讓整份清單失效。 */
export interface SuppressionProblem {
  /** 已能辨識出是哪條規則時附上；連物件形狀都不對時為 null。 */
  rule: SuppressionRule | null;
  /** 原始資料，讓報告能原樣附上方便對照。 */
  raw?: unknown;
  message: string;
}

export interface SuppressedFinding {
  finding: Finding;
  rule: SuppressionRule;
}

export interface SuppressionOutcome {
  /** 照常回報的發現。 */
  kept: Finding[];
  /** 被蓋住的發現（連同蓋住它的規則）。報告仍應另闢一區列出，不可靜默丟棄。 */
  suppressed: SuppressedFinding[];
  /** 針對抑制清單本身的發現：過期、缺 ack、沒命中、永久抑制。 */
  notes: Finding[];
}

/** 規則物件允許的欄位。多一個都不行，理由見 `validateRule`。 */
const RULE_KEYS = ["id", "where", "reason", "expires", "owner", "acknowledgeCritical"] as const;

/** 只有日期（`2026-12-31`）。 */
const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
/** 完整時間，且**必須**帶時區（`Z` 或 `+08:00`）。 */
const ISO_WITH_ZONE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;

/** 這個檢查自己產出的發現，前綴保留不給抑制——理由見 `ruleMatches`。 */
const SELF_PREFIX = "suppress.";

const NOTE_BASE = { check: "suppress", category: "integrity" as const, surface: "all" as const };

const isBlank = (value: string): boolean => value.trim().length === 0;

/**
 * id 樣式比對。
 *
 * 只支援結尾萬用字元，因為 finding id 是由粗到細的階層（`cookies.httponly.sid`），
 * 「整個家族」正好等於「同一段前綴」。支援任意位置的萬用字元只會讓人寫出自己也看不懂
 * 命中範圍的規則，而抑制清單最不需要的就是「我以為它只蓋住那一筆」。
 */
export function matchesId(pattern: string, id: string): boolean {
  if (!pattern.endsWith("*")) return pattern === id;
  const prefix = pattern.slice(0, -1);
  return prefix.length > 0 && id.startsWith(prefix);
}

/**
 * 規則是否命中這筆發現。
 *
 * `where` 有給就必須完全相同：抑制清單常見的誤用是「本來只想放行測試站的那一筆，
 * 結果連正式站的同一筆一起蓋掉」。要精確就精確到底，不做前綴或包含比對。
 *
 * `suppress.*` 系列永遠不命中：讓抑制清單能蓋掉「關於抑制清單的提醒」，
 * 等於給了一個把所有煞車一次拆掉的開關。
 */
export function ruleMatches(rule: SuppressionRule, item: Finding): boolean {
  if (item.id.startsWith(SELF_PREFIX)) return false;
  if (!matchesId(rule.id, item.id)) return false;
  if (rule.where === undefined) return true;
  return item.where === rule.where;
}

/**
 * `YYYY-MM-DD` 是不是真實存在的日期。
 *
 * 不能只靠 `Date.parse`：它會把 `2026-02-30` 悄悄捲成 3 月 2 日，寫下那個日期的人
 * 不會知道自己多拿了兩天有效期。抑制清單的期限是一個承諾，多一天都不該是筆誤換來的。
 */
function isRealDate(datePart: string): boolean {
  const parts = datePart.split("-");
  const year = Number(parts[0]);
  const month = Number(parts[1]);
  const day = Number(parts[2]);
  const probe = new Date(Date.UTC(year, month - 1, day));
  return (
    probe.getUTCFullYear() === year && probe.getUTCMonth() === month - 1 && probe.getUTCDate() === day
  );
}

/**
 * 到期時刻（毫秒）。無法解析回 null。
 *
 * 只寫日期時判定為**那一天結束**（UTC 23:59:59.999）：寫下 `2026-12-31` 的人意思是
 * 「到那天為止都算數」，而不是「那天凌晨零點就失效」。在到期日當天突然噴出一整排告警，
 * 只會讓人以為工具壞了。一律以 UTC 判定，讓同一份清單在任何機器上得到相同結果。
 */
export function expiryInstant(expires: string): number | null {
  const value = expires.trim();
  const dateOnly = DATE_ONLY.test(value);
  if (!dateOnly && !ISO_WITH_ZONE.test(value)) return null;
  if (!isRealDate(value.slice(0, 10))) return null;
  const at = Date.parse(dateOnly ? `${value}T23:59:59.999Z` : value);
  return Number.isNaN(at) ? null : at;
}

/**
 * 規則是否已失效。
 *
 * 沒有 `expires` 是永久抑制（回 false，另外用 `suppress.no-expiry` 提醒）；
 * 有 `expires` 卻解析不出日期時視同已過期——看不懂的日期不可以變成永久抑制。
 *
 * 判斷「有沒有寫」用 `undefined` 而不是真假值：`expires: ""` 是**寫了但寫壞了**，
 * 落到永久抑制那一側等於讓一個空字串換到無限期的靜音，正好是這份實作最想避免的事。
 * 解析走 `expiryInstant`，所以空字串會照「看不懂的日期」處理——視同已過期。
 */
export function isExpired(rule: SuppressionRule, now: Date): boolean {
  if (rule.expires === undefined) return false;
  const at = expiryInstant(rule.expires);
  return at === null || at < now.getTime();
}

function validateIdPattern(id: string): string | null {
  if (id === "*") {
    return "不可以是純萬用字元：那不是抑制某個已知取捨，而是把整個檢測系統關掉。";
  }
  const stars = id.split("*").length - 1;
  if (stars > 1 || (stars === 1 && !id.endsWith("*"))) {
    return "的萬用字元只支援結尾（例如 cookies.*）；開頭或中間的 * 不支援，因為那種樣式沒人看得出實際會蓋住什麼。";
  }
  if (id.startsWith(SELF_PREFIX)) {
    return `不可以指向 ${SELF_PREFIX}* ——那是「關於抑制清單本身」的提醒，蓋掉它等於讓這份清單永遠不會被檢討。`;
  }
  return null;
}

function validateExpires(value: string): string | null {
  if (!DATE_ONLY.test(value) && !ISO_WITH_ZONE.test(value)) {
    return "不是合法的 ISO 日期。請寫 2026-12-31，或帶時區的完整時間（2026-12-31T23:59:59Z）——沒有時區的時間在不同機器上會在不同時刻到期。";
  }
  if (expiryInstant(value) === null) return "不是真實存在的日期。";
  return null;
}

/**
 * 退件時附上的「規則回音」——只求讓讀者認得出是哪一條，不是一條可以套用的規則。
 *
 * 為什麼值得做：呼叫端（`annotate.ts`）用 `problem.rule?.id` 組出 `suppress.invalid-rule.*`
 * 的發現 id，認不出來時只能退回「第 N 筆」。而 N 是這筆在清單裡的位置——在清單最前面
 * 插一條新規則，同一個錯誤就換了一個 id，跨次執行比對會把它報成「舊的修好了、又多一個新的」。
 * id 必須跟著規則走，不能跟著行號走。
 *
 * `reason` 缺漏時填「（未填寫）」而不是空字串：這個物件可能被原樣印進報告，
 * 空白一格會被讀成「沒事」，而事實是這條規則根本沒生效。
 */
function echoRule(entry: Record<string, unknown>): SuppressionRule | null {
  const id = typeof entry.id === "string" ? entry.id.trim() : "";
  if (id.length === 0) return null;
  const hasReason = typeof entry.reason === "string" && !isBlank(entry.reason);
  return { id, reason: hasReason ? (entry.reason as string).trim() : "（未填寫）" };
}

/** 單筆驗證的結果。壞的那筆也要帶回規則回音，理由見 `echoRule`。 */
type RuleCheck =
  | { ok: true; rule: SuppressionRule }
  | { ok: false; rule: SuppressionRule | null; message: string };

/**
 * 逐筆驗證一則規則。
 *
 * 未知欄位一律拒收，看起來嚴苛，但這裡的拼字錯誤會直接改變判定：把 `expires` 打成
 * `expiry`，規則會安靜地變成永久抑制，而且沒有任何跡象。寧可當場退件。
 */
function validateRule(raw: unknown, index: number): RuleCheck {
  const at = `第 ${index + 1} 筆規則`;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, rule: null, message: `${at}不是物件。` };
  }
  const entry = raw as Record<string, unknown>;
  const reject = (message: string): RuleCheck => ({ ok: false, rule: echoRule(entry), message });

  for (const key of Object.keys(entry)) {
    if (!RULE_KEYS.includes(key as (typeof RULE_KEYS)[number])) {
      return reject(`${at}含未知欄位「${key}」。可用欄位只有 ${RULE_KEYS.join("、")}；欄位打錯不能當成沒寫（expires 打成 expiry 會靜靜變成永久抑制）。`);
    }
  }

  if (typeof entry.id !== "string" || isBlank(entry.id)) {
    return reject(`${at}缺少 id。`);
  }
  const id = entry.id.trim();
  const idProblem = validateIdPattern(id);
  if (idProblem) return reject(`${at}的 id「${id}」${idProblem}`);

  if (typeof entry.reason !== "string" || isBlank(entry.reason)) {
    return reject(
      `${at}（${id}）缺少 reason。沒有理由的抑制就是隱藏——半年後沒人知道當初為什麼關掉，也沒人敢打開。`,
    );
  }

  const rule: SuppressionRule = { id, reason: entry.reason.trim() };

  if (entry.where !== undefined) {
    if (typeof entry.where !== "string" || isBlank(entry.where)) {
      return reject(`${at}（${id}）的 where 必須是非空字串。`);
    }
    rule.where = entry.where.trim();
  }

  if (entry.expires !== undefined) {
    if (typeof entry.expires !== "string" || isBlank(entry.expires)) {
      return reject(`${at}（${id}）的 expires 必須是非空字串。`);
    }
    const expires = entry.expires.trim();
    const expiresProblem = validateExpires(expires);
    if (expiresProblem) return reject(`${at}（${id}）的 expires「${expires}」${expiresProblem}`);
    rule.expires = expires;
  }

  if (entry.owner !== undefined) {
    if (typeof entry.owner !== "string" || isBlank(entry.owner)) {
      return reject(`${at}（${id}）的 owner 必須是非空字串。`);
    }
    rule.owner = entry.owner.trim();
  }

  if (entry.acknowledgeCritical !== undefined) {
    if (typeof entry.acknowledgeCritical !== "boolean") {
      return reject(`${at}（${id}）的 acknowledgeCritical 必須是布林值 true／false。`);
    }
    if (entry.acknowledgeCritical) rule.acknowledgeCritical = true;
  }

  return { ok: true, rule };
}

/**
 * 取出頂層的規則陣列。
 *
 * 頂層額外欄位刻意放行（`EXAMPLE_SUPPRESSION_FILE` 就是靠 `_說明` 夾帶中文說明；
 * JSON 沒有註解語法，總得有地方寫給人看）。規則物件本身則嚴格，因為那裡的拼字錯誤
 * 會改變判定結果，而頂層的多餘欄位不會。
 */
function extractEntries(parsed: unknown): unknown[] | null {
  if (Array.isArray(parsed)) return parsed;
  if (typeof parsed === "object" && parsed !== null) {
    const list = (parsed as Record<string, unknown>).suppressions;
    if (Array.isArray(list)) return list;
  }
  return null;
}

/**
 * 解析抑制清單。
 *
 * 逐筆驗證，壞的那筆進 problems、好的照收：一份清單裡有十條規則，其中一條打錯字，
 * 不該讓另外九條連帶失效——那會在使用者最沒預期的時候把一整批已知取捨變回噪音。
 * 反過來說 problems 也絕不能被吞掉，呼叫端有義務把它印出來。
 */
export function parseSuppressions(json: string): { rules: SuppressionRule[]; problems: SuppressionProblem[] } {
  const rules: SuppressionRule[] = [];
  const problems: SuppressionProblem[] = [];

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    return {
      rules,
      problems: [
        {
          rule: null,
          message:
            `抑制清單不是合法的 JSON：${err instanceof Error ? err.message : String(err)}。` +
            "整份清單未套用——注意這代表原本被抑制的發現會全部回到報告，而不是全部被靜音。",
        },
      ],
    };
  }

  const entries = extractEntries(parsed);
  if (!entries) {
    return {
      rules,
      problems: [
        {
          rule: null,
          raw: parsed,
          message: "抑制清單的頂層必須是陣列，或是含 suppressions 陣列的物件。",
        },
      ],
    };
  }

  entries.forEach((raw, index) => {
    const result = validateRule(raw, index);
    if (result.ok) rules.push(result.rule);
    else problems.push({ rule: result.rule, raw, message: result.message });
  });

  return { rules, problems };
}

/** 規則在報告裡的「位置」：這類發現的位置就是抑制清單裡的那一條。 */
function ruleLocation(rule: SuppressionRule): string {
  return rule.where ? `${rule.id} @ ${rule.where}` : rule.id;
}

function describeRule(rule: SuppressionRule): string {
  const lines = [`id: ${rule.id}`];
  if (rule.where) lines.push(`where: ${rule.where}`);
  lines.push(`reason: ${rule.reason}`);
  lines.push(`expires: ${rule.expires ?? "（無，永久抑制）"}`);
  lines.push(`owner: ${rule.owner ?? "（未具名）"}`);
  if (rule.acknowledgeCritical) lines.push("acknowledgeCritical: true");
  return lines.join("\n");
}

const listIds = (findings: Finding[]): string => [...new Set(findings.map((f) => f.id))].join("、");

const ownerOf = (rule: SuppressionRule): string => rule.owner ?? "未具名（規則沒有 owner）";

function expiredNote(rule: SuppressionRule, matched: Finding[]): Finding {
  const unparseable = rule.expires !== undefined && expiryInstant(rule.expires) === null;
  return finding({
    ...NOTE_BASE,
    id: "suppress.expired",
    severity: "low",
    where: ruleLocation(rule),
    title: `抑制規則已到期，被它蓋住的 ${matched.length} 筆發現重新浮現`,
    detail: unparseable
      ? `規則 ${rule.id} 的 expires「${rule.expires}」無法解析為日期，一律視同已過期：看不懂的日期不可以變成永久抑制。` +
        `本次不再套用，${listIds(matched)} 已重新列入報告。原註記理由：${rule.reason}（決定人：${ownerOf(rule)}）`
      : `規則 ${rule.id} 已於 ${rule.expires} 到期，本次不再套用，${listIds(matched)} 已重新列入報告。` +
        `當初的理由是「${rule.reason}」（決定人：${ownerOf(rule)}），期限到了代表這個取捨該重新做一次決定。`,
    remediation:
      "問題已修好就刪掉這條規則；還要繼續放著就延長 expires 並更新 reason 與 owner。" +
      "延期必須是一個有人簽名的決定，不能靠沒人注意而自動延續。",
    evidence: describeRule(rule),
  });
}

function criticalAckNote(rule: SuppressionRule, blocked: Finding[]): Finding {
  return finding({
    ...NOTE_BASE,
    id: "suppress.critical-requires-ack",
    severity: "medium",
    where: ruleLocation(rule),
    title: `抑制規則想蓋掉 ${blocked.length} 筆 critical 發現，但沒有明示承認`,
    detail:
      `規則 ${rule.id} 命中了 critical 等級的發現（${listIds(blocked)}）。critical 的定義是「現在就在外洩資料或可被接管」，` +
      "這種等級不接受順手加一條規則就靜音——因此這幾筆不套用，仍然照常出現在主清單上。",
    remediation:
      '確定要承擔風險就在規則加上 "acknowledgeCritical": true，並補上 owner 與 expires，讓這個決定留下名字與期限；否則請直接修掉問題。',
    evidence: describeRule(rule),
  });
}

function staleNote(rule: SuppressionRule): Finding {
  return finding({
    ...NOTE_BASE,
    id: "suppress.stale",
    severity: "info",
    where: ruleLocation(rule),
    title: "抑制規則本輪沒有命中任何發現",
    detail:
      `規則 ${rule.id} 這次沒有蓋住任何東西，最常見的原因是問題已經修好了。` +
      "留著不刪的風險是：同一個問題日後復發時會被它靜默吃掉，報告依然全綠。" +
      "但「沒命中」不等於「已修好」——本輪用 --only／--skip 縮小過範圍，或對應的檢查被跳過（缺原始碼、缺瀏覽器）時，" +
      "那些發現根本沒有機會產生，規則自然也命中不到。刪之前請先確認這次真的測到了那一項。",
    remediation:
      "先看報告裡對應的檢查是不是「已完成」：完成了才代表問題確實不見了，這時請刪掉這條規則；" +
      "若是被跳過或被過濾掉，請保留規則，改在有跑到那項檢查的那一輪再判斷。",
    evidence: describeRule(rule),
  });
}

function noExpiryNote(rule: SuppressionRule, matched: Finding[]): Finding {
  return finding({
    ...NOTE_BASE,
    id: "suppress.no-expiry",
    severity: "info",
    where: ruleLocation(rule),
    title: "抑制規則沒有到期日（永久抑制）",
    detail:
      `規則 ${rule.id} 沒有 expires，命中的 ${listIds(matched)}（本次 ${matched.length} 筆）只要規則還在就會一直被蓋下去。` +
      "永久抑制等於對這個問題永久失明——沒有到期日就不會有人回來重新評估，永久抑制應該極少。",
    remediation: "補上 expires（建議不超過 90 天）；到期時規則自動失效，強迫重新做一次決定。",
    evidence: describeRule(rule),
  });
}

/** 一條規則在本輪的處置。先全部判完再產生提醒，理由見 `applySuppressions`。 */
type RuleDecision =
  | { kind: "stale"; rule: SuppressionRule }
  | { kind: "expired"; rule: SuppressionRule; matched: Finding[] }
  | { kind: "applied"; rule: SuppressionRule; matched: Finding[]; blocked: Finding[] };

/**
 * 套用抑制清單。
 *
 * 判定順序刻意如此：先看規則有沒有命中（沒命中就只是死規則），再看有沒有過期
 * （過期的規則連 ack 都不必討論），最後才逐筆決定能不能蓋。
 *
 * critical 的攔截是**逐筆**的：同一條萬用字元規則命中一筆 critical 與三筆 low 時，
 * 只有那筆 critical 退回 kept，其餘照常抑制。整條規則作廢會讓三筆已知取捨一起復活，
 * 讀者反而更難看出重點是那筆 critical。
 *
 * `now` 由呼叫端傳入而非在函式內取現在時間——到期判定必須能在測試裡固定住。
 *
 * 「哪一筆是同一筆」一律用 `findingKey`（id + where），與去重、跨次執行比對同一把鍵：
 * 三者用不同的鍵時，「上次抑制掉的」與「這次新增的」會對不起來。**攔截與認領必須用同一把鍵**：
 * 三端掃同一個站時，同一筆問題會由不同 surface 各回報一次（id 與 where 相同、物件不同），
 * 若攔截認物件、認領認鍵，那筆被擋下的 critical 會從另一個孿生物件的鍵溜進 suppressed——
 * 一個沒有人會發現的假綠燈。
 *
 * 提醒統一等到認領定案後才產生：`suppress.critical-requires-ack` 說的是「這筆仍然照常回報」，
 * 而同一筆 critical 可能被另一條有 ack 的規則合法蓋掉（廣泛規則 + 個別具名規則是常見寫法）。
 * 邊判邊寫提醒的話，報告會出現一句與事實相反的話——比不寫還糟。
 *
 * 回傳的 `kept`／`suppressed` 一律是**原本那些物件**，不做任何複製：呼叫端
 * （`annotate.ts`）靠物件同一性把發現放回各自的 CheckResult，複製一份會讓整份報告清空。
 */
export function applySuppressions(
  findings: Finding[],
  rules: SuppressionRule[],
  now: Date,
): SuppressionOutcome {
  const claimed = new Map<string, SuppressionRule>();
  const decisions: RuleDecision[] = [];

  for (const rule of rules) {
    const matched = findings.filter((f) => ruleMatches(rule, f));
    if (matched.length === 0) {
      decisions.push({ kind: "stale", rule });
      continue;
    }

    if (isExpired(rule, now)) {
      decisions.push({ kind: "expired", rule, matched });
      continue;
    }

    const blocked = rule.acknowledgeCritical ? [] : matched.filter((f) => f.severity === "critical");
    const blockedKeys = new Set(blocked.map(findingKey));
    for (const f of matched) {
      const key = findingKey(f);
      if (blockedKeys.has(key)) continue;
      // 先命中的規則負責這筆：兩條規則蓋同一筆時，報告只需要說明其中一條。
      if (!claimed.has(key)) claimed.set(key, rule);
    }
    decisions.push({ kind: "applied", rule, matched, blocked });
  }

  const kept: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const rule = claimed.get(findingKey(f));
    if (rule) suppressed.push({ finding: f, rule });
    else kept.push(f);
  }

  const notes: Finding[] = [];
  for (const decision of decisions) {
    if (decision.kind === "stale") {
      notes.push(staleNote(decision.rule));
      continue;
    }
    if (decision.kind === "expired") {
      notes.push(expiredNote(decision.rule, decision.matched));
      continue;
    }
    const stillReported = decision.blocked.filter((f) => !claimed.has(findingKey(f)));
    if (stillReported.length > 0) notes.push(criticalAckNote(decision.rule, stillReported));
    if (decision.rule.expires === undefined) notes.push(noExpiryNote(decision.rule, decision.matched));
  }

  return { kept, suppressed, notes };
}

/**
 * 攤平成報告層的紀錄格式。
 *
 * 判定過程需要整條規則（萬用字元樣式、ack 旗標都影響判定），報告只需要讀者該看的四件事：
 * 是什麼問題、為什麼被蓋、蓋到哪天、誰決定的。缺 expires／owner 一律轉成 null 而不是留空，
 * 報告才有辦法把「永久抑制」與「未具名」明確標示出來，而不是印成一格空白讓人以為沒事。
 */
export function toSuppressedRecords(suppressed: SuppressedFinding[]): SuppressedFindingRecord[] {
  return suppressed.map(({ finding: item, rule }) => ({
    finding: item,
    reason: rule.reason,
    expires: rule.expires ?? null,
    owner: rule.owner ?? null,
  }));
}

/**
 * 一行摘要，給終端列印。
 *
 * 就算一筆都沒抑制也要印：讀者必須隨時知道自己看的是「全部的發現」還是「被篩過的發現」，
 * 這個差別不能靠有沒有印訊息來暗示。
 */
export function describeSuppression(outcome: SuppressionOutcome): string {
  const ruleCount = new Set(outcome.suppressed.map((s) => ruleLocation(s.rule))).size;
  const head =
    outcome.suppressed.length === 0
      ? `抑制清單：本次沒有任何發現被抑制，${outcome.kept.length} 筆照常回報`
      : `抑制清單：${outcome.suppressed.length} 筆發現被 ${ruleCount} 條規則暫時蓋住（仍列在報告的抑制區），${outcome.kept.length} 筆照常回報`;
  const tail = outcome.notes.length > 0 ? `；另有 ${outcome.notes.length} 筆關於抑制清單本身的提醒` : "";
  return `${head}${tail}。`;
}

/**
 * 範例抑制清單。CLI 在使用者指定的檔案不存在時印出來當範本。
 *
 * JSON 沒有註解語法，說明改放在頂層的 `_說明` 欄位——所以這份範例貼上去就能用，
 * 直接餵給 `parseSuppressions` 也是零問題的合法清單。
 */
export const EXAMPLE_SUPPRESSION_FILE = `{
  "_說明": [
    "抑制清單：列出「已知、已決定暫時不處理」的發現。",
    "被抑制的發現不會消失——報告會另闢一區列出，並附上這裡寫的理由、負責人與到期日。",
    "id 支援結尾萬用字元（cookies.*、csp.script-src.*）；純 * 會被拒絕，那等於關掉整個檢測。",
    "reason 必填：寫給半年後的自己看，為什麼當初決定不修。",
    "expires 建議一律填（ISO 日期，到期日當天仍然有效）；沒填就是永久抑制，會被反過來報出來。",
    "where 選填；填了就必須與發現的 where 完全相同才命中，用來只放行某一個端點上的那一筆。",
    "要蓋掉 critical 等級的發現，必須明寫 acknowledgeCritical: true 並留下 owner。"
  ],
  "suppressions": [
    {
      "id": "csp.style-src.unsafe-inline",
      "reason": "React inline style 的已知取捨；元件層改用 CSS 變數後即可移除。",
      "expires": "2026-12-31",
      "owner": "frontend@aios"
    },
    {
      "id": "headers.server-version",
      "where": "https://aios.example/",
      "reason": "版本標頭由平台閘道加上，我們無權關閉，已向供應商回報（工單 #1234）。",
      "expires": "2026-10-31",
      "owner": "ops@aios"
    }
  ]
}
`;
