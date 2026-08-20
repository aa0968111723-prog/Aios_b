/**
 * SARIF 2.1.0 匯出。
 *
 * 存在的理由：SARIF 能上傳到 GitHub code scanning，發現會直接標在 PR 的檔案上與安全性頁籤裡，
 * 而不是躺在 artifact 的 HTML 檔中等人下載——沒有人會為了看檢測結果去解壓縮一份附件。
 *
 * 轉檔時最容易掉的東西是「沒測到」：SARIF 的資料模型天生只描述「找到了什麼」，
 * 沒有任何欄位在講「什麼沒跑到」。照字面轉的話，一輪「連不到站台、全部跳過」的執行
 * 會變成一份漂亮的空 SARIF，在 GitHub 上跟「全部通過」長得一模一樣——那正是本專案
 * 最不能接受的失效方式。所以這裡把跳過與執行錯誤逐筆寫進
 * `invocations[].toolExecutionNotifications`，並讓 `invocations[].executionSuccessful`
 * 如實反映有沒有檢查自己爆掉。轉檔不負責把結論變好看，只負責不把「未執行」洗成「通過」。
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
  properties: { severity: Severity; surface: string; check: string };
  /** 有值代表這筆被抑制清單移出主清單；GitHub 會顯示成「已關閉（附理由）」。 */
  suppressions?: Array<{ kind: "external"; justification: string }>;
}

export interface SarifNotification {
  descriptor: { id: string };
  level: SarifLevel;
  message: { text: string };
  properties?: Record<string, unknown>;
}

export interface SarifInvocation {
  executionSuccessful: boolean;
  startTimeUtc?: string;
  endTimeUtc?: string;
  toolExecutionNotifications: SarifNotification[];
}

export interface SarifRun {
  tool: { driver: { name: string; informationUri: string; rules: SarifRule[] } };
  results: SarifResult[];
  invocations: SarifInvocation[];
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

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

  // 已經帶 scheme 的絕對 URI（http／https／file…）交給 URL 正規化，順便驗證它真的合法。
  // 例外是 Windows 的磁碟機代號：`C:\repo` 在正則上看起來也像 scheme，要先排除。
  const looksLikeDrive = /^[A-Za-z]:[\\/]/.test(raw);
  if (!looksLikeDrive && /^[A-Za-z][A-Za-z0-9+.-]*:/.test(raw)) {
    try {
      return new URL(raw).toString();
    } catch {
      // 不是合法 URI（例如 `weird:thing`），往下當成路徑處理。
    }
  }

  const slashed = raw.replace(/\\/g, "/");
  const drive = /^([A-Za-z]):\/(.*)$/.exec(slashed);
  if (drive) return `file:///${drive[1]}:/${encodePath(drive[2] ?? "")}`;
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
    help: { text: finding.remediation ?? "（未提供修法）" },
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

function toResult(finding: Finding, ctx: { ruleIndex: number; fallbackUri: string }): SarifResult {
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
    properties: { severity: finding.severity, surface: finding.surface, check: finding.check },
  };
}

/** 抑制理由連同到期日一起寫進 SARIF：沒有期限的忽略，半年後沒有人會記得當初為什麼忽略。 */
function justificationFor(record: SuppressedFindingRecord): string {
  const parts = [record.reason, `到期：${record.expires ?? "永久"}`];
  if (record.owner) parts.push(`負責人：${record.owner}`);
  return parts.join("；");
}

/**
 * 「這一輪有哪些事沒跑到」——SARIF 裡唯一能承載這個資訊的地方。
 *
 * 三種都算沒跑到：檢查自己爆掉、檢查被跳過、以及本輪範圍被 `--only`／`--skip` 縮小過。
 * 第三種在別的報告層是最上方的告示，在這裡同樣不能省：一份只跑了 CSP 的 SARIF
 * 上傳到 code scanning 後，看起來就跟「全站都查過而且很乾淨」一樣。
 */
function buildNotifications(report: RunReport): SarifNotification[] {
  const out: SarifNotification[] = [];

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
        tool: { driver: { name: TOOL_NAME, informationUri: TOOL_INFORMATION_URI, rules } },
        results,
        invocations: [
          {
            // 只要有檢查自己爆掉，這一輪就不是一次成功的執行。跳過不算失敗（那是有意識的略過，
            // 已經逐筆寫進 notifications），但檢測器故障必須讓消費端一眼看得出來。
            executionSuccessful: report.results.every((r) => !r.error),
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
