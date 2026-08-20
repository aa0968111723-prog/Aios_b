/**
 * SARIF 2.1.0 匯出。
 *
 * 存在的理由：SARIF 能上傳到 GitHub code scanning，發現會直接標在 PR 的檔案上與安全性頁籤裡，
 * 而不是躺在 artifact 的 HTML 檔中等人下載——沒有人會為了看檢測結果去解壓縮一份附件。
 *
 * 轉檔時最容易掉的東西是「沒測到」：SARIF 的資料模型天生只描述「找到了什麼」，
 * 沒有任何欄位在講「什麼沒跑到」。照字面轉的話，一輪「連不到站台、全部跳過」的執行
 * 會變成一份漂亮的空 SARIF，在 GitHub 上跟「全部通過」長得一模一樣——那正是本專案
 * 最不能接受的失效方式。所以這裡把跳過、執行錯誤與被縮小的範圍逐筆寫進
 * `invocations[].toolExecutionNotifications`，並讓 `invocations[].executionSuccessful`
 * 如實反映兩件事：有沒有檢查自己爆掉，以及**這一輪到底有沒有檢查真的跑完**。
 * 後者是這個模組唯一會「主動判斷」的事——一份 result 為空、executionSuccessful 為 true 的
 * SARIF，在 code scanning 上就是一面綠燈，而它可能只代表站台連不上、一項都沒驗到。
 * 轉檔不負責把結論變好看，只負責不把「未執行」洗成「通過」。
 */
import { severityRank, sortFindings } from "../core/severity.js";
import { findingKey } from "../core/findings.js";
import { allFindings } from "../core/runner.js";
import type { Finding, RunReport, Severity, SuppressedFindingRecord } from "../core/types.js";

/** SARIF 的告警等級。規格另有 `none`，本工具不會產生——沒問題就不會有 result。 */
export type SarifLevel = "error" | "warning" | "note";

const SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
const TOOL_NAME = "Aios Sentinel";
const TOOL_INFORMATION_URI = "https://github.com/aa0968111723-prog/Aios_b";
/** 每個 id 的判定依據都登錄在這份對照表，讓 code scanning 上的讀者查得到「為什麼這樣判」。 */
const CHECKS_DOC_URI = `${TOOL_INFORMATION_URI}/blob/main/docs/CHECKS.md`;
/** 連受測目標都拿不到時的最後退路：SARIF 的 uri 不接受空字串，但也不該憑空編一個檔案路徑。 */
const UNLOCATED_URI = "urn:aios-sentinel:unlocated";

/**
 * 可以原樣當成位置用的 scheme。
 *
 * 為什麼是白名單，而不是「只要 `new URL()` 解析得過就放行」：URL 解析器眼中，
 * `x.ts:42`（帶行號的檔案路徑）與 `ai-os-app.zeabur.app:443`（主機加埠）都是合法的絕對 URI，
 * scheme 分別是 `x.ts` 與 `ai-os-app.zeabur.app`。原樣輸出的話，code scanning 會收到一個
 * 指不到任何檔案的位置，而讀者只看得到一條點不開的連結。
 *
 * 還有一層考量：`where` 不全是我們自己組出來的字串——供應鏈檢查會把頁面上的
 * `<script src>` 當作位置，而那是受測頁面提供的內容。`data:` 與 `javascript:` 這類 scheme
 * 沒有理由被原封不動放進一個會被 UI 當連結呈現的欄位。認得的 scheme 才走 URL 正規化，
 * 其餘一律退回路徑處理（順帶解決 Windows 的 `C:\repo`——單字母磁碟機代號本來就不在名單內）。
 */
const URI_SCHEMES = new Set(["http", "https", "file", "urn"]);

const LEVEL_BY_SEVERITY: Record<Severity, SarifLevel> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};

/**
 * GitHub 用 `security-severity`（CVSS 風格的 0–10）決定告警的排序與 Critical／High 標籤，
 * 而不是看 SARIF 的 level——level 只有三級，撐不起本系統的五級嚴重度。
 * 值用字串是 GitHub 文件的用法（它自己再 parse 成浮點數）。
 */
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "7.5",
  medium: "5.0",
  low: "3.0",
  info: "0.0",
};

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  help: { text: string };
  helpUri: string;
  defaultConfiguration: { level: SarifLevel };
  properties: { tags: string[]; "security-severity": string };
}

export interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{ physicalLocation: { artifactLocation: { uri: string } } }>;
  partialFingerprints: { aiosSentinelId: string };
  /** `evidence` 是實際觀測到的字串，只在該筆發現有留證據時出現。 */
  properties: { severity: Severity; surface: string; check: string; evidence?: string };
  /** 有值代表這筆被抑制清單移出主清單；GitHub 會顯示成「已關閉（附理由）」。 */
  suppressions?: Array<{ kind: "external"; justification: string }>;
}

export interface SarifNotification {
  descriptor: { id: string };
  level: SarifLevel;
  message: { text: string };
  properties?: Record<string, unknown>;
}

/**
 * 通知的描述子。
 *
 * SARIF 規定 `notification.descriptor` 指向的是 driver 宣告過的描述子；不宣告的話，
 * 消費端拿到的只是一個沒有定義的字串 id。宣告出來還有一個實際好處：讀者在 SARIF 檔案裡
 * 就能看懂 `check.skipped` 是什麼意思，不必回頭翻這份原始碼。
 */
export interface SarifNotificationDescriptor {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
}

export interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  toolExecutionNotifications: SarifNotification[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      rules: SarifRule[];
      notifications: SarifNotificationDescriptor[];
    };
  };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

/**
 * 四種「這一輪有事情沒跑到」的通知。
 *
 * 一律宣告，即使這一輪一筆都沒用到：一份完整的描述子清單本身就是在告訴讀者
 * 「這個工具會回報哪些未執行狀況」，而讀者要判斷一份乾淨的報告可不可信，
 * 靠的正是知道它在什麼情況下會出聲。
 */
const NOTIFICATION_DESCRIPTORS: SarifNotificationDescriptor[] = [
  {
    id: "run.nothing-executed",
    shortDescription: { text: "本輪沒有任何檢查真正執行完成" },
    fullDescription: {
      text:
        "所有檢查都被跳過、被過濾或自己爆掉。此時 results 是空的，而一份沒有 result 的 SARIF " +
        "在 code scanning 上與「全部通過」長得一模一樣，所以同一輪也會把 executionSuccessful 標成 false。",
    },
  },
  {
    id: "run.filtered",
    shortDescription: { text: "本輪的檢測範圍被刻意縮小" },
    fullDescription: {
      text: "使用了 --only／--skip。被排除的項目在這份結果裡沒有任何結論，不代表它們通過。",
    },
  },
  {
    id: "check.skipped",
    shortDescription: { text: "某一項檢查被跳過" },
    fullDescription: {
      text: "缺少必要條件（憑證、瀏覽器、原始碼路徑）或目標沒有該功能。跳過不等於通過。",
    },
  },
  {
    id: "check.errored",
    shortDescription: { text: "某一項檢查自己執行失敗" },
    fullDescription: {
      text: "是檢測器故障，不是受測目標的問題；該項在本輪沒有任何結論，必須與「發現問題」分開看。",
    },
  },
];

export function severityToSarifLevel(severity: Severity): SarifLevel {
  return LEVEL_BY_SEVERITY[severity];
}

/**
 * 把 `finding.where` 轉成合法的 SARIF `artifactLocation.uri`。
 *
 * `where` 有三種真實形態：線上檢查給的絕對網址、殼層稽核給的版本庫相對檔案路徑
 * （`ai_os/capacitor.config.ts`）、以及跑在本機時的絕對檔案路徑。三者都要輸出成合法 URI，
 * 但**相對路徑必須保持相對**：GitHub code scanning 只有在 uri 相對於版本庫根目錄時，
 * 才能把發現標到 PR 的那一行上；硬轉成 `file://` 會讓標註能力整個消失。
 */
export function toArtifactUri(where: string | null | undefined, fallback: string): string {
  return normalizeUri(where) ?? normalizeUri(fallback) ?? UNLOCATED_URI;
}

function normalizeUri(value: string | null | undefined): string | null {
  const raw = (value ?? "").trim();
  if (raw === "") return null;

  // 認得的 scheme 交給 URL 正規化，順便驗證它真的合法；其餘一律往下當路徑處理。
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(raw)?.[1]?.toLowerCase();
  if (scheme !== undefined && URI_SCHEMES.has(scheme)) {
    try {
      return new URL(raw).toString();
    } catch {
      // 有 scheme 但組不成 URL（例如少了主機的 `https://`）：當成路徑，不輸出半成品。
    }
  }

  const slashed = raw.replace(/\\/g, "/");
  const drive = /^([A-Za-z]):\/(.*)$/.exec(slashed);
  if (drive) return `file:///${drive[1] ?? ""}:/${encodePath(drive[2] ?? "")}`;
  if (slashed.startsWith("/")) return `file://${encodePath(slashed)}`;
  return encodePath(slashed.replace(/^\.\//, ""));
}

/** 逐段百分比編碼：空白與中文檔名不編碼就不是合法 URI，但 `/` 要留著當路徑分隔。 */
function encodePath(path: string): string {
  return path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}

export function sarifRuleFor(finding: Finding): SarifRule {
  return {
    id: finding.id,
    name: finding.title,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.detail },
    // help.text 是 code scanning 介面上唯一會顯示修法的位置。修法沒放進來，
    // 讀者在 GitHub 上就只看得到「你有問題」，看不到「怎麼修」——那種告警最後都會被關掉。
    help: { text: finding.remediation ?? "（這筆發現沒有附修法；判定依據見 helpUri 的檢查項目對照表）" },
    helpUri: CHECKS_DOC_URI,
    defaultConfiguration: { level: severityToSarifLevel(finding.severity) },
    properties: {
      tags: [finding.category, finding.surface],
      "security-severity": SECURITY_SEVERITY[finding.severity],
    },
  };
}

/**
 * 把所有發現收斂成規則清單（每個 id 一筆）。
 *
 * 兩個收斂決定：
 * 1. 同 id 出現多次且嚴重度不同時，規則取**最嚴重**的那一筆。`security-severity` 只能掛在
 *    規則上，沒有逐筆覆寫的餘地，取輕的會讓 GitHub 把最嚴重的那一處標成低風險。
 * 2. tags 併入所有出現過的端。只留最嚴重那筆的端，讀者會以為另外兩端沒事。
 */
function buildRules(findings: Finding[]): { rules: SarifRule[]; indexById: Map<string, number> } {
  const order: string[] = [];
  const worst = new Map<string, Finding>();
  const surfaces = new Map<string, Set<string>>();

  for (const f of findings) {
    const seen = worst.get(f.id);
    if (!seen) {
      order.push(f.id);
      worst.set(f.id, f);
    } else if (severityRank(f.severity) < severityRank(seen.severity)) {
      worst.set(f.id, f);
    }
    const set = surfaces.get(f.id) ?? new Set<string>();
    set.add(f.surface);
    surfaces.set(f.id, set);
  }

  const rules: SarifRule[] = [];
  const indexById = new Map<string, number>();
  for (const id of order) {
    const representative = worst.get(id)!;
    const rule = sarifRuleFor(representative);
    rule.properties.tags = [representative.category, ...[...(surfaces.get(id) ?? [])].sort()];
    indexById.set(id, rules.length);
    rules.push(rule);
  }
  return { rules, indexById };
}

const EVIDENCE_LIMIT = 1200;

/** 證據可能是一整份回應標頭。SARIF 會整份上傳，過長的原文只會讓檔案膨脹，先截斷再帶走。 */
function clipEvidence(evidence: string): string {
  return evidence.length > EVIDENCE_LIMIT ? `${evidence.slice(0, EVIDENCE_LIMIT)}…（證據已截斷）` : evidence;
}

function toResult(finding: Finding, ctx: { ruleIndex: number; fallbackUri: string }): SarifResult {
  // message.text 刻意只放標題與說明——那是告警列表上直接顯示的內容，塞進整份標頭會沒人看得下去。
  // 觀測到的原文改放 properties：SARIF 檢視器與後續程式拿得到，重現問題時不必回頭翻別的報告。
  const properties: SarifResult["properties"] = {
    severity: finding.severity,
    surface: finding.surface,
    check: finding.check,
  };
  if (finding.evidence) properties.evidence = clipEvidence(finding.evidence);

  return {
    ruleId: finding.id,
    ruleIndex: ctx.ruleIndex,
    level: severityToSarifLevel(finding.severity),
    message: { text: `${finding.title}\n\n${finding.detail}` },
    locations: [
      { physicalLocation: { artifactLocation: { uri: toArtifactUri(finding.where, ctx.fallbackUri) } } },
    ],
    // 指紋用的是全系統共用的那把鍵（去重、抑制清單、基準比對都用它），跨次執行才對得起來。
    // 沒有指紋，GitHub 每輪掃描都會把同一件事當成一批「新的」告警，幾輪之後就沒有人再看那頁了。
    partialFingerprints: { aiosSentinelId: findingKey(finding) },
    properties,
  };
}

/** 抑制理由連同到期日一起寫進 SARIF：沒有期限的忽略，半年後沒有人會記得當初為什麼忽略。 */
function justificationFor(record: SuppressedFindingRecord): string {
  const parts = [record.reason, `到期：${record.expires ?? "永久"}`];
  if (record.owner) parts.push(`負責人：${record.owner}`);
  return parts.join("；");
}

/**
 * 這一輪真正跑完的檢查數。
 *
 * `meta` 結果（抑制清單的提醒、基準檔讀取錯誤）雖然標著 completed，但它們不是檢查——
 * 把它們算進來，一輪「連站台都連不到、每一項都跳過」卻剛好帶了 `--suppress` 的執行，
 * 就會憑空多出一項「完成」的檢查，於是 SARIF 上不再有人說「什麼都沒驗到」。
 * 判準與 summary、`exitCodeFor` 的 exit 3 完全一致——三處各算各的，遲早會有一處先說謊。
 */
function completedCheckCount(report: RunReport): number {
  return report.results.filter((r) => !r.meta && r.completed).length;
}

/**
 * 「這一輪有哪些事沒跑到」——SARIF 裡唯一能承載這個資訊的地方。
 *
 * 四種都算沒跑到：一項都沒跑完、檢查自己爆掉、檢查被跳過、以及本輪範圍被
 * `--only`／`--skip` 縮小過。第三、四種在別的報告層是最上方的告示，在這裡同樣不能省：
 * 一份只跑了 CSP 的 SARIF 上傳到 code scanning 後，看起來就跟「全站都查過而且很乾淨」一樣。
 */
function buildNotifications(report: RunReport): SarifNotification[] {
  const out: SarifNotification[] = [];

  // 這一條要排在最前面：其餘通知是逐項的細節，而它講的是整份結果能不能當一回事。
  const planned = report.results.filter((r) => !r.meta).length;
  if (completedCheckCount(report) === 0) {
    // 措辭刻意不寫成「下面沒有任何發現」：後製的提醒（抑制清單、基準檔）也會產生發現，
    // 一輪什麼都沒驗到的執行仍可能帶著幾筆 result。要講的是「這些發現不代表目標的狀態」。
    const scope =
      planned === 0
        ? "本輪沒有排定任何檢查"
        : `本輪排定 ${planned} 項檢查，完成 0 項（全部被跳過、被過濾或執行失敗）`;
    out.push({
      descriptor: { id: "run.nothing-executed" },
      level: "error",
      message: {
        text:
          `${scope}。這份結果不論有沒有列出發現，都不代表受測目標的狀態——` +
          "這一輪沒有任何一項檢查真的量到東西。請先確認執行環境（站台是否可達、認證、瀏覽器、" +
          "原始碼路徑）再重跑，不要把這份結果當成一次檢測。",
      },
      properties: { plannedChecks: planned, completedChecks: 0 },
    });
  }

  const filter = report.filter;
  if (filter && (filter.only.length > 0 || filter.skip.length > 0)) {
    const parts: string[] = [];
    if (filter.only.length > 0) parts.push(`只執行 ${filter.only.join("、")}`);
    if (filter.skip.length > 0) parts.push(`略過 ${filter.skip.join("、")}`);
    out.push({
      descriptor: { id: "run.filtered" },
      level: "warning",
      message: {
        text: `本次檢測範圍被縮小（${parts.join("；")}）。未執行的項目在這份結果裡沒有任何結論——不代表通過。`,
      },
      properties: { only: filter.only, skip: filter.skip },
    });
  }

  for (const result of report.results) {
    // 執行錯誤與跳過是兩件事，但同一項只該被講一次：爆掉的檢查不必再說它「沒完成」。
    if (result.error) {
      out.push({
        descriptor: { id: "check.errored" },
        level: "error",
        message: {
          text:
            `檢查「${result.check}」（${result.surface}）執行錯誤：${result.error}。` +
            "這是檢測器自己失敗，不是目標通過——這一項在本次沒有任何結論。",
        },
        properties: { check: result.check, surface: result.surface, category: result.category },
      });
      continue;
    }
    if (!result.completed) {
      out.push({
        descriptor: { id: "check.skipped" },
        level: "warning",
        message: {
          text:
            `檢查「${result.check}」（${result.surface}）已跳過：${result.skippedReason ?? "未提供原因。"}` +
            "跳過不等於通過，這一項在本次沒有任何結論。",
        },
        properties: { check: result.check, surface: result.surface, category: result.category },
      });
    }
  }

  return out;
}

/**
 * SARIF 的時間必須是可解析的 ISO-8601。
 * 解析不了就整個欄位不寫——寧可少一個欄位，也不要讓一份不合規格的檔案被 code scanning 整份退回。
 */
function utcOrUndefined(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const at = new Date(value);
  return Number.isNaN(at.getTime()) ? undefined : at.toISOString();
}

export function renderSarif(report: RunReport): string {
  const primary = sortFindings(allFindings(report));
  const suppressed = report.suppressed ?? [];
  const { rules, indexById } = buildRules([...primary, ...suppressed.map((s) => s.finding)]);
  const fallbackUri = report.target;

  const results: SarifResult[] = primary.map((f) =>
    toResult(f, { ruleIndex: indexById.get(f.id) ?? 0, fallbackUri }),
  );

  // 被抑制的發現照樣輸出，只是掛上 SARIF 的 suppressions。直接不輸出也能讓告警消失，
  // 但那會把「有人決定忽略它」這個決定一起刪掉——抑制不等於修好，報告要看得到這件事。
  for (const record of suppressed) {
    results.push({
      ...toResult(record.finding, { ruleIndex: indexById.get(record.finding.id) ?? 0, fallbackUri }),
      suppressions: [{ kind: "external", justification: justificationFor(record) }],
    });
  }

  const log: SarifLog = {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            informationUri: TOOL_INFORMATION_URI,
            rules,
            notifications: NOTIFICATION_DESCRIPTORS,
          },
        },
        results,
        invocations: [
          {
            // 兩種情況才算「這次執行不成功」：有檢查自己爆掉，或者一項都沒跑完。
            //
            // 少數幾項被跳過不算失敗——那是有意識的略過，已經逐筆寫進 notifications。
            // 但**一項都沒跑完**是另一回事：那時 results 恆為空，而空的 SARIF 在 code scanning 上
            // 就是一片綠。這是本專案最反對的假綠燈，與 `exitCodeFor` 特地保留 exit 3 同一個理由，
            // 所以這裡不靠讀者自己去翻 notifications，直接讓這一輪表態它不成立。
            executionSuccessful: completedCheckCount(report) > 0 && report.results.every((r) => !r.error),
            startTimeUtc: utcOrUndefined(report.startedAt),
            endTimeUtc: utcOrUndefined(report.finishedAt),
            toolExecutionNotifications: buildNotifications(report),
          },
        ],
      },
    ],
  };

  return JSON.stringify(log, null, 2);
}
