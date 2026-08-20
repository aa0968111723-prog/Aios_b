#!/usr/bin/env -S npx tsx
/**
 * Aios Sentinel CLI。
 *
 * 指令：
 *   scan     資安 + 可用性掃描（純 HTTP，不需要瀏覽器）
 *   pages    頁面測試（需要 playwright）
 *   shells   App／桌面殼層靜態設定稽核（讀 ai_os 原始碼，不需要網路）
 *   monitor  深度監測：PostHog 使用者行為、Zeabur 平台錯誤、資料庫進出、裝置紀錄
 *   all      以上全部
 *
 * 設計取捨：預設**不需要任何參數**就能對正式站跑完整掃描。
 * 需要 12 個旗標才跑得起來的工具，最後不會有人跑。
 *
 * 另一條貫穿全檔的規則：**任何讓檢測範圍變小的選項，都必須在輸出裡留下痕跡**。
 * 過濾掉的檢查會以「跳過＋原因」進報告、抑制掉的發現會留在專屬區塊、
 * 讀不到的基準檔會變成一筆發現。一個安靜地少做事的旗標，會製造出這套系統
 * 最反對的東西：看起來全綠、實際上沒驗到的報告。
 */
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { buildSurfaces, isSurfaceId, pickSurfaces } from "./core/surfaces.js";
import { discoverAiosRepo } from "./core/aiosRepo.js";
import { preflight } from "./core/preflight.js";
import { exitCodeFor, perOrigin, perSurface, runChecks, type PlannedCheck } from "./core/runner.js";
import { annotateReport } from "./core/annotate.js";
import { parseBaseline } from "./core/baseline.js";
import { EXAMPLE_SUPPRESSION_FILE, parseSuppressions, type SuppressionProblem, type SuppressionRule } from "./core/suppress.js";
import { describeFilter, matchesFilter, parseFilter, partitionChecks, unknownTokens, type CheckFilter } from "./core/filter.js";
import { checkHealth } from "./detectors/health.js";
import { checkTransport } from "./detectors/transport.js";
import { checkAuthGate } from "./detectors/authGate.js";
import { checkDisclosure } from "./detectors/disclosure.js";
import { checkCors } from "./detectors/cors.js";
import { checkBuildDrift } from "./detectors/buildDrift.js";
import { checkShells } from "./detectors/shellAudit.js";
import { checkAnalytics } from "./detectors/analytics.js";
import { checkZeabur } from "./detectors/zeabur.js";
import { checkDbTraffic } from "./detectors/dbTraffic.js";
import { checkDevice } from "./detectors/device.js";
import { checkTls } from "./detectors/tls.js";
import { checkMethods } from "./detectors/methods.js";
import { checkRedirect } from "./detectors/redirect.js";
import { checkSupplyChain } from "./detectors/supplyChain.js";
import { checkWellKnown } from "./detectors/wellknown.js";
import { checkRateLimit } from "./detectors/rateLimit.js";
import { checkPages } from "./pages/pageTest.js";
import { checkA11y } from "./pages/a11y.js";
import { launchBrowser } from "./pages/browser.js";
import { DEFAULT_ROUTES, parseRoutes } from "./pages/routes.js";
import { renderHtml } from "./report/html.js";
import { renderMarkdown } from "./report/markdown.js";
import { renderSarif } from "./report/sarif.js";
import { renderJunit } from "./report/junit.js";
import { printSummary } from "./report/console.js";
import { SEVERITY_ORDER } from "./core/severity.js";
import type { RunReport, SentinelConfig, Severity, SurfaceId } from "./core/types.js";

/** 預設受測站台：ai_os 的 capacitor.config.ts 與 tauri.conf.json 都寫死這個網址。 */
const DEFAULT_TARGET = "https://ai-os-app.zeabur.app";

/** 輸出格式。json／md／html 是給人與程式看的三種面貌，sarif／junit 是給 CI 介面看的。 */
const FORMATS = ["json", "md", "html", "sarif", "junit"] as const;
type Format = (typeof FORMATS)[number];
const DEFAULT_FORMATS: Format[] = ["json", "md", "html"];

/**
 * 布林旗標清單。
 *
 * 沒有這份清單時，`--json scan` 會把 `scan` 當成 `--json` 的值吃掉，指令就消失了。
 * 這種錯誤的症狀是「說明畫面莫名其妙跳出來」，非常難從症狀反推原因。
 */
const BOOLEAN_FLAGS = new Set(["json", "help", "h", "no-screenshots", "fail-on-new", "probe-rate-limit", "init-suppress"]);

const USAGE = `
Aios Sentinel — aios 網站／App／桌面三端的錯誤、資訊安全與頁面檢測系統

用法：
  npm run sentinel -- <指令> [選項]

指令：
  scan        資安與可用性掃描（HTTP 層，不需瀏覽器）
  pages       頁面測試與無障礙掃描（需要 playwright）
  shells      App／桌面殼層設定稽核（讀原始碼，不需網路）
  monitor     深度監測：使用者行為（PostHog）、平台錯誤（Zeabur）、資料庫進出、裝置紀錄
  all         以上全部

選項：
  --target <url>        受測站台（預設 ${DEFAULT_TARGET}）
  --surfaces <list>     要檢測的端：web,app,desktop（預設全部）
  --repo <path>         ai_os 原始碼路徑（殼層稽核用）
  --routes <list>       自訂受測路由，逗號分隔（預設用內建路由表）
  --out <dir>           報告輸出目錄（預設 ./reports）
  --formats <list>      輸出格式：${FORMATS.join(",")}（預設 ${DEFAULT_FORMATS.join(",")}）
  --only <list>         只執行這些檢查或分類（例：--only security 或 --only csp,cors）
  --skip <list>         略過這些檢查或分類
  --baseline <path>     以既有的 report.json 為基準，比對出新增與已修復
  --suppress <path>     抑制清單 JSON（用 --init-suppress 產生範本）
  --fail-on <severity>  達到此嚴重度即以非 0 結束（預設 high）
  --fail-on-new         只有新增與惡化才以非 0 結束（需搭配 --baseline）
  --probe-rate-limit    授權對登入端點做速率限制探測（會送出數次失敗嘗試）
  --timeout <ms>        單一請求逾時（預設 15000）
  --no-screenshots      頁面測試不存截圖
  --json                只輸出 JSON 到 stdout（給程式消費）
  --init-suppress       印出抑制清單範本後結束
  -h, --help            顯示說明

環境變數：
  AIOS_TARGET / AIOS_REPO           同 --target / --repo
  AIOS_WEB_TARGET / AIOS_APP_TARGET / AIOS_DESKTOP_TARGET
                                    個別覆寫某一端的站台（用於偵測版本漂移）
  TEST_EMAIL / TEST_PW              頁面測試的登入帳密；不提供則只測公開路由
  POSTHOG_API_KEY / POSTHOG_PROJECT_ID / POSTHOG_HOST
                                    monitor 深度拉取近期使用者行為與前端例外（不提供則略過該段）
  ZEABUR_API_TOKEN / ZEABUR_SERVICE_ID
                                    monitor 深度拉取 Zeabur 部署狀態（不提供則略過該段）

範例：
  npm run sentinel -- all --repo ../ai_os
  npm run sentinel -- scan --surfaces app,desktop --fail-on medium
  npm run sentinel -- scan --only security --formats json,sarif
  npm run sentinel -- all --baseline reports/report.json --fail-on-new
`.trim();

interface Args {
  command: string;
  flags: Map<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const flags = new Map<string, string | boolean>();
  let command = "";
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i] as string;
    if (!arg.startsWith("-")) {
      if (!command) command = arg;
      continue;
    }
    const name = arg.replace(/^--?/, "");
    const next = argv[i + 1];
    if (!BOOLEAN_FLAGS.has(name) && next && !next.startsWith("-")) {
      flags.set(name, next);
      i += 1;
    } else {
      flags.set(name, true);
    }
  }
  return { command, flags };
}

function asSeverity(value: string | undefined, fallback: Severity): Severity {
  if (!value) return fallback;
  return (SEVERITY_ORDER as string[]).includes(value) ? (value as Severity) : fallback;
}

/** 解析 --formats。認不得的格式要出聲，不能安靜地少寫一份檔案。 */
function parseFormats(value: string | undefined): { formats: Format[]; unknown: string[] } {
  if (!value) return { formats: DEFAULT_FORMATS, unknown: [] };
  const tokens = value
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
  const formats = tokens.filter((t): t is Format => (FORMATS as readonly string[]).includes(t));
  const unknown = tokens.filter((t) => !(FORMATS as readonly string[]).includes(t));
  return { formats: formats.length > 0 ? [...new Set(formats)] : DEFAULT_FORMATS, unknown };
}

interface RepoResolution {
  path: string | undefined;
  source: "flag" | "env" | "auto" | "none";
}

/**
 * 決定 ai_os 原始碼路徑。
 * 優先序：`--repo` 明示 ＞ `AIOS_REPO` 環境變數 ＞ 就地自動探測。
 * 都沒有時回傳 undefined（殼層稽核會據此標記跳過，而非假裝通過）。
 */
function resolveRepoPath(flag: (name: string) => string | undefined): RepoResolution {
  const explicit = flag("repo");
  if (explicit) return { path: explicit, source: "flag" };
  if (process.env.AIOS_REPO) return { path: process.env.AIOS_REPO, source: "env" };
  const discovered = discoverAiosRepo();
  if (discovered) return { path: discovered, source: "auto" };
  return { path: undefined, source: "none" };
}

function buildConfig(args: Args): SentinelConfig {
  const flag = (name: string): string | undefined => {
    const value = args.flags.get(name);
    return typeof value === "string" ? value : undefined;
  };

  const target = (flag("target") ?? process.env.AIOS_TARGET ?? DEFAULT_TARGET).replace(/\/$/, "");
  const surfaceIds = flag("surfaces")
    ?.split(",")
    .map((s) => s.trim())
    .filter(isSurfaceId) as SurfaceId[] | undefined;

  const surfaces = pickSurfaces(
    buildSurfaces(target, {
      web: process.env.AIOS_WEB_TARGET,
      app: process.env.AIOS_APP_TARGET,
      desktop: process.env.AIOS_DESKTOP_TARGET,
    }),
    surfaceIds ?? null,
  );

  const email = process.env.TEST_EMAIL;
  const password = process.env.TEST_PW;

  return {
    target,
    surfaces,
    repoPath: resolveRepoPath(flag).path,
    routes: [],
    outDir: flag("out") ?? "./reports",
    failOn: asSeverity(flag("fail-on"), "high"),
    timeoutMs: Number(flag("timeout") ?? 15_000),
    credentials: email && password ? { email, password } : undefined,
    screenshots: args.flags.get("no-screenshots") !== true,
  };
}

/** 一筆「沒有實際執行」的結果。跳過的理由必須寫進報告，不能只留在終端。 */
function skipped(name: string, category: PlannedCheck["category"], surface: PlannedCheck["surface"], reason: string): PlannedCheck {
  return {
    name,
    category,
    surface,
    run: async () => ({ check: name, category, surface, completed: false, skippedReason: reason, durationMs: 0, findings: [] }),
  };
}

/** `scan` 會排入的所有檢查（名稱與分類）。過濾與「連不到就整組跳過」都以這份為準。 */
const SCAN_CHECKS: Array<[string, "availability" | "security" | "integrity"]> = [
  ["health", "availability"],
  ["transport", "security"],
  ["auth-gate", "security"],
  ["disclosure", "security"],
  ["cors", "security"],
  ["tls", "security"],
  ["methods", "security"],
  ["redirect", "security"],
  ["supply-chain", "security"],
  ["wellknown", "security"],
  ["rate-limit", "security"],
  ["build-drift", "integrity"],
];

const MONITOR_CHECKS: Array<[string, "monitoring"]> = [
  ["analytics", "monitoring"],
  ["zeabur", "monitoring"],
  ["db-traffic", "monitoring"],
  ["device", "monitoring"],
];

/**
 * 這組檢查裡還有任何一項會被保留嗎？
 *
 * 全部被篩掉時就不該為它們做連通性前置檢查——`--only shell-audit` 是純離線的稽核，
 * 卻要先對正式站送三個請求並等它們回來，既沒有意義也違反「不要對站台製造無謂流量」。
 */
function anyKept(names: Array<[string, PlannedCheck["category"]]>, filter: CheckFilter): boolean {
  return names.some(([name, category]) => matchesFilter({ name, category }, filter));
}

/** 某一端連不到時，把它的每一項網路檢查都寫成「跳過＋原因」，而不是讓它們各自回報零發現。 */
function unreachableScanChecks(surfaceId: SurfaceId, reason: string): PlannedCheck[] {
  return SCAN_CHECKS.filter(([name]) => name !== "build-drift").map(([name, category]) =>
    skipped(name, category, surfaceId, reason),
  );
}

interface ScanOptions {
  probeRateLimit: boolean;
  filter: CheckFilter;
}

async function planScan(config: SentinelConfig, options: ScanOptions): Promise<PlannedCheck[]> {
  const { surfaces, timeoutMs } = config;
  const checks: PlannedCheck[] = [];

  // 這一輪的 scan 檢查全被 --only／--skip 篩掉時，連前置檢查都不必做。
  // 交還一份完整的「未執行」清單，讓過濾層照常把原因寫進報告。
  if (!anyKept(SCAN_CHECKS, options.filter)) {
    return SCAN_CHECKS.map(([name, category]) => skipped(name, category, "all", "本輪未排入執行。"));
  }

  // 先確認每一端連得到。連不到就整組標記跳過——沉默的零發現比誤報更危險。
  const reachable: typeof surfaces = [];
  for (const surface of surfaces) {
    const state = await preflight(surface, timeoutMs);
    if (state.ok) reachable.push(surface);
    else checks.push(...unreachableScanChecks(surface.id, state.reason));
  }

  // 與載體有關的檢查：伺服器可能對不同 UA 給不同分支，破口常藏在那裡，所以三端各掃一次。
  checks.push(
    ...perSurface(reachable, "health", "availability", (s) => () => checkHealth(s, timeoutMs)),
    ...perSurface(reachable, "transport", "security", (s) => () => checkTransport(s, timeoutMs)),
    ...perSurface(reachable, "auth-gate", "security", (s) => () => checkAuthGate(s, timeoutMs)),
    ...perSurface(reachable, "disclosure", "security", (s) => () => checkDisclosure(s, timeoutMs)),
    ...perSurface(reachable, "cors", "security", (s) => () => checkCors(s, timeoutMs)),
  );

  // 與載體無關的檢查：憑證、robots.txt、開放重導向不會因為 UA 而不同。
  // 每個不同的 origin 只跑一次——三端同源時就是一次，請求量不會白白變成三倍。
  checks.push(
    ...perOrigin(reachable, "tls", "security", (s) => () => checkTls(s, timeoutMs)),
    ...perOrigin(reachable, "methods", "security", (s) => () => checkMethods(s, timeoutMs)),
    ...perOrigin(reachable, "redirect", "security", (s) => () => checkRedirect(s, timeoutMs)),
    ...perOrigin(reachable, "supply-chain", "security", (s) => () => checkSupplyChain(s, timeoutMs)),
    ...perOrigin(reachable, "wellknown", "security", (s) => () => checkWellKnown(s, timeoutMs)),
    ...perOrigin(
      reachable,
      "rate-limit",
      "security",
      (s) => () => checkRateLimit(s, timeoutMs, { enabled: options.probeRateLimit }),
    ),
  );

  // 一端都連不到時 build-drift 也要留一筆「跳過」。整項從報告上消失的話，
  // 讀者掃過檢查清單只會覺得少了一項，而不會知道版本一致性這一輪根本沒驗。
  checks.push(
    reachable.length > 0
      ? {
          name: "build-drift",
          category: "integrity",
          surface: "all",
          run: () => checkBuildDrift(reachable, timeoutMs),
        }
      : skipped("build-drift", "integrity", "all", "沒有任何一端可連，無從比對版本。"),
  );

  return checks;
}

/** 監測：使用者行為（PostHog）、平台錯誤（Zeabur）、資料庫進出、裝置紀錄。 */
async function planMonitor(config: SentinelConfig, filter: CheckFilter): Promise<PlannedCheck[]> {
  const { surfaces, timeoutMs, repoPath } = config;
  const checks: PlannedCheck[] = [];

  if (!anyKept(MONITOR_CHECKS, filter)) {
    return MONITOR_CHECKS.map(([name, category]) => skipped(name, category, "all", "本輪未排入執行。"));
  }

  const reachable: typeof surfaces = [];
  for (const surface of surfaces) {
    const state = await preflight(surface, timeoutMs);
    if (state.ok) reachable.push(surface);
    else for (const name of ["analytics", "zeabur", "db-traffic"]) checks.push(skipped(name, "monitoring", surface.id, state.reason));
  }

  checks.push(
    ...perSurface(reachable, "analytics", "monitoring", (s) => () => checkAnalytics(s, repoPath, timeoutMs)),
    ...perSurface(reachable, "zeabur", "monitoring", (s) => () => checkZeabur(s, timeoutMs)),
    ...perSurface(reachable, "db-traffic", "monitoring", (s) => () => checkDbTraffic(s, repoPath, timeoutMs)),
  );

  checks.push(
    reachable.length > 0
      ? {
          name: "device",
          category: "monitoring",
          surface: "all",
          run: () => checkDevice(reachable, timeoutMs),
        }
      : skipped("device", "monitoring", "all", "沒有任何一端可連，無法建立裝置紀錄。"),
  );

  return checks;
}

function planShells(config: SentinelConfig): PlannedCheck[] {
  return [
    {
      name: "shell-audit",
      category: "security",
      surface: "all",
      run: () => checkShells(config.repoPath, config.target),
    },
  ];
}

async function planPages(config: SentinelConfig, args: Args): Promise<{ checks: PlannedCheck[]; cleanup: () => Promise<void> }> {
  const routes = parseRoutes(typeof args.flags.get("routes") === "string" ? (args.flags.get("routes") as string) : undefined) ?? DEFAULT_ROUTES;
  const launch = await launchBrowser();

  if (!launch.ok) {
    // 瀏覽器起不來時，把「為什麼跳過」變成正式的檢查結果，而不是一行 stderr 就算了。
    const reason = launch.reason;
    return {
      checks: config.surfaces.map((surface) => skipped("page-test", "page", surface.id, reason)),
      cleanup: async () => {},
    };
  }

  const session = launch.session;
  const checks: PlannedCheck[] = [];
  for (const surface of config.surfaces) {
    checks.push({
      name: "page-test",
      category: "page",
      surface: surface.id,
      run: () =>
        checkPages(session, surface, routes, {
          credentials: config.credentials,
          screenshots: config.screenshots,
          outDir: config.outDir,
        }),
    });
  }
  // 無障礙只在網頁端跑一次：三端載的是同一份 DOM，重複掃只會產生三份一模一樣的違規清單。
  const webSurface = config.surfaces.find((s) => s.id === "web") ?? config.surfaces[0];
  if (webSurface) {
    checks.push({
      name: "a11y",
      category: "a11y",
      surface: webSurface.id,
      run: () => checkA11y(session, webSurface, routes, { credentials: config.credentials }),
    });
  }

  return { checks, cleanup: () => session.close() };
}

/**
 * 套用 --only／--skip。
 *
 * 被篩掉的檢查**不會從報告上消失**，而是變成「跳過＋原因」——這是整個過濾功能的重點。
 * 直接把它們拿掉的話，一份 `--only csp` 的報告看起來會跟一份跑完全部後全綠的報告一模一樣。
 */
function applyFilter(checks: PlannedCheck[], filter: CheckFilter): PlannedCheck[] {
  if (filter.only.length === 0 && filter.skip.length === 0) return checks;
  const { kept, excluded } = partitionChecks(
    checks.map((c) => ({ name: c.name, category: c.category, planned: c })),
    filter,
  );
  const reason = `依 ${describeFilter(filter)} 排除，本輪未執行——未執行不等於通過。`;
  return [
    ...kept.map((c) => c.planned),
    ...excluded.map((c) => skipped(c.planned.name, c.planned.category, c.planned.surface, reason)),
  ];
}

/** 讀取選用檔案。讀不到時回 null 與原因——明確要求了卻靜默失效，是最糟的結果。 */
async function readOptional(filePath: string): Promise<{ text: string; error: null } | { text: null; error: string }> {
  try {
    return { text: await readFile(filePath, "utf8"), error: null };
  } catch (err) {
    return { text: null, error: `讀取 ${filePath} 失敗：${err instanceof Error ? err.message : String(err)}` };
  }
}

async function writeReports(config: SentinelConfig, report: RunReport, formats: Format[]): Promise<string[]> {
  await mkdir(config.outDir, { recursive: true });
  const files: Array<{ file: string; content: string }> = [];
  const at = (name: string) => path.join(config.outDir, name);

  if (formats.includes("json")) files.push({ file: at("report.json"), content: JSON.stringify(report, null, 2) });
  if (formats.includes("md")) files.push({ file: at("report.md"), content: renderMarkdown(report) });
  if (formats.includes("html")) files.push({ file: at("report.html"), content: renderHtml(report) });
  if (formats.includes("sarif")) files.push({ file: at("report.sarif"), content: renderSarif(report) });
  if (formats.includes("junit")) files.push({ file: at("report.junit.xml"), content: renderJunit(report, config.failOn) });

  for (const { file, content } of files) await writeFile(file, content, "utf8");
  return files.map((f) => f.file);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);
  const flag = (name: string): string | undefined => {
    const value = args.flags.get(name);
    return typeof value === "string" ? value : undefined;
  };

  if (args.flags.get("init-suppress") === true) {
    process.stdout.write(`${EXAMPLE_SUPPRESSION_FILE}\n`);
    process.exit(0);
  }

  if (args.flags.has("help") || args.flags.has("h") || !args.command) {
    process.stdout.write(`${USAGE}\n`);
    process.exit(args.command ? 0 : 1);
  }

  const config = buildConfig(args);
  const jsonOnly = args.flags.get("json") === true;
  const command = args.command;
  const note = (text: string) => {
    if (!jsonOnly) process.stdout.write(`${text}\n`);
  };

  const { formats, unknown: unknownFormats } = parseFormats(flag("formats"));
  if (unknownFormats.length > 0) note(`！ 認不得的輸出格式：${unknownFormats.join("、")}（可用：${FORMATS.join("、")}）`);

  const filter = parseFilter(flag("only"), flag("skip"));

  const repo = resolveRepoPath(flag);
  const wantsRepo = command === "shells" || command === "monitor" || command === "all";
  if (wantsRepo) {
    if (repo.path) {
      const how = repo.source === "auto" ? "自動探測" : repo.source === "env" ? "AIOS_REPO" : "--repo";
      note(`連結 ai_os 原始碼（${how}）：${repo.path}`);
    } else {
      note("未連結 ai_os 原始碼——殼層稽核將標記跳過（設 AIOS_REPO、帶 --repo，或把 ai_os 併排檢出）。");
    }
  }

  const checks: PlannedCheck[] = [];
  let cleanup: () => Promise<void> = async () => {};

  if (command === "scan" || command === "all") {
    checks.push(...(await planScan(config, { probeRateLimit: args.flags.get("probe-rate-limit") === true, filter })));
  }
  if (command === "shells" || command === "all") checks.push(...planShells(config));
  if (command === "monitor" || command === "all") checks.push(...(await planMonitor(config, filter)));
  if (command === "pages" || command === "all") {
    const planned = await planPages(config, args);
    checks.push(...planned.checks);
    cleanup = planned.cleanup;
  }

  if (checks.length === 0) {
    process.stderr.write(`未知指令：${command}\n\n${USAGE}\n`);
    process.exit(1);
  }

  // 打錯字的過濾條件會篩掉全部然後產出一份空報告——那是最惡劣的假綠燈，一定要出聲。
  const strays = unknownTokens(filter, checks.map((c) => ({ name: c.name, category: c.category })));
  if (strays.length > 0) note(`！ 這些 --only／--skip 的值沒有對應到任何檢查：${strays.join("、")}`);

  const planned = applyFilter(checks, filter);
  const filterNote = describeFilter(filter);
  // 範圍縮小的告示要在開跑前就講，而且要把「未執行不等於通過」講出來——
  // describeFilter 只負責描述篩了什麼，這句提醒是呼叫端的責任。
  if (filterNote) note(`檢查範圍：${filterNote}——未執行的項目沒有結論，不代表通過。`);

  if (!jsonOnly) {
    process.stdout.write(`\n開始檢測 ${config.target}（${config.surfaces.map((s) => s.id).join("、")}）——共 ${planned.length} 項\n`);
  }

  let report: RunReport;
  try {
    report = await runChecks(config, planned, {
      onCheckStart: (name, surface) => {
        if (!jsonOnly) process.stdout.write(`  · ${name}（${surface}）…`);
      },
      onCheckDone: (result) => {
        if (jsonOnly) return;
        const mark = result.error ? "！" : result.completed ? "✓" : "－";
        process.stdout.write(` ${mark} ${result.findings.length ? `${result.findings.length} 項發現` : ""}\n`);
      },
    });
  } finally {
    await cleanup();
  }

  // ── 後製：抑制、比對、範圍 ─────────────────────────────────────────────
  let suppressions: { rules: SuppressionRule[]; problems: SuppressionProblem[] } | undefined;
  const suppressPath = flag("suppress");
  if (suppressPath) {
    const read = await readOptional(suppressPath);
    suppressions = read.text === null
      ? { rules: [], problems: [{ rule: null, message: read.error }] }
      : parseSuppressions(read.text);
  }

  let baseline: { snapshot: ReturnType<typeof parseBaseline>["snapshot"]; error: string | null } | undefined;
  const baselinePath = flag("baseline");
  if (baselinePath) {
    const read = await readOptional(baselinePath);
    baseline = read.text === null ? { snapshot: null, error: read.error } : parseBaseline(read.text);
  }

  const failOnNew = args.flags.get("fail-on-new") === true;
  if (failOnNew && !baselinePath) {
    note("！ --fail-on-new 需要 --baseline 才有意義；沒有基準可比，本輪退回一般門檻判定。");
  }

  const annotated = annotateReport(report, { suppressions, baseline, filter });

  if (jsonOnly) {
    process.stdout.write(`${JSON.stringify(annotated, null, 2)}\n`);
  } else {
    printSummary(annotated);
    const files = await writeReports(config, annotated, formats);
    process.stdout.write(`報告已輸出：\n${files.map((f) => `  ${f}`).join("\n")}\n\n`);
  }

  process.exit(exitCodeFor(annotated, config.failOn, { onlyNew: failOnNew }));
}

main().catch((err: unknown) => {
  process.stderr.write(`Sentinel 執行失敗：${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
