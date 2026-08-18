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
 */
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { buildSurfaces, isSurfaceId, pickSurfaces } from "./core/surfaces.js";
import { discoverAiosRepo } from "./core/aiosRepo.js";
import { preflight } from "./core/preflight.js";
import { exitCodeFor, perSurface, runChecks, type PlannedCheck } from "./core/runner.js";
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
import { checkPages } from "./pages/pageTest.js";
import { checkA11y } from "./pages/a11y.js";
import { launchBrowser } from "./pages/browser.js";
import { DEFAULT_ROUTES, parseRoutes } from "./pages/routes.js";
import { renderHtml } from "./report/html.js";
import { renderMarkdown } from "./report/markdown.js";
import { printSummary } from "./report/console.js";
import { SEVERITY_ORDER } from "./core/severity.js";
import type { SentinelConfig, Severity, SurfaceId } from "./core/types.js";

/** 預設受測站台：ai_os 的 capacitor.config.ts 與 tauri.conf.json 都寫死這個網址。 */
const DEFAULT_TARGET = "https://ai-os-app.zeabur.app";

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
  --fail-on <severity>  達到此嚴重度即以非 0 結束（預設 high）
  --timeout <ms>        單一請求逾時（預設 15000）
  --no-screenshots      頁面測試不存截圖
  --json                只輸出 JSON 到 stdout（給程式消費）
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
  npm run sentinel -- pages --routes /,/login --no-screenshots
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
    if (next && !next.startsWith("-")) {
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

/** 某一端連不到時，把它的每一項網路檢查都寫成「跳過＋原因」，而不是讓它們各自回報零發現。 */
function skippedChecks(surfaceId: SurfaceId, reason: string): PlannedCheck[] {
  const names: Array<[string, "availability" | "security"]> = [
    ["health", "availability"],
    ["transport", "security"],
    ["auth-gate", "security"],
    ["disclosure", "security"],
    ["cors", "security"],
  ];
  return names.map(([name, category]) => ({
    name,
    category,
    surface: surfaceId,
    run: async () => ({
      check: name,
      category,
      surface: surfaceId,
      completed: false,
      skippedReason: reason,
      durationMs: 0,
      findings: [],
    }),
  }));
}

async function planScan(config: SentinelConfig): Promise<PlannedCheck[]> {
  const { surfaces, timeoutMs } = config;
  const checks: PlannedCheck[] = [];

  // 先確認每一端連得到。連不到就整組標記跳過——沉默的零發現比誤報更危險。
  const reachable: typeof surfaces = [];
  for (const surface of surfaces) {
    const state = await preflight(surface, timeoutMs);
    if (state.ok) reachable.push(surface);
    else checks.push(...skippedChecks(surface.id, state.reason));
  }

  checks.push(
    ...perSurface(reachable, "health", "availability", (s) => () => checkHealth(s, timeoutMs)),
    ...perSurface(reachable, "transport", "security", (s) => () => checkTransport(s, timeoutMs)),
    ...perSurface(reachable, "auth-gate", "security", (s) => () => checkAuthGate(s, timeoutMs)),
    ...perSurface(reachable, "disclosure", "security", (s) => () => checkDisclosure(s, timeoutMs)),
    ...perSurface(reachable, "cors", "security", (s) => () => checkCors(s, timeoutMs)),
  );

  if (reachable.length > 0) {
    checks.push({
      name: "build-drift",
      category: "integrity",
      surface: "all",
      run: () => checkBuildDrift(reachable, timeoutMs),
    });
  }

  return checks;
}

/** 監測：使用者行為（PostHog）、平台錯誤（Zeabur）、資料庫進出、裝置紀錄。 */
async function planMonitor(config: SentinelConfig): Promise<PlannedCheck[]> {
  const { surfaces, timeoutMs, repoPath } = config;
  const checks: PlannedCheck[] = [];

  const reachable: typeof surfaces = [];
  for (const surface of surfaces) {
    const state = await preflight(surface, timeoutMs);
    if (state.ok) reachable.push(surface);
    else {
      for (const name of ["analytics", "zeabur", "db-traffic"]) {
        checks.push({
          name,
          category: "monitoring",
          surface: surface.id,
          run: async () => ({
            check: name,
            category: "monitoring",
            surface: surface.id,
            completed: false,
            skippedReason: state.reason,
            durationMs: 0,
            findings: [],
          }),
        });
      }
    }
  }

  checks.push(
    ...perSurface(reachable, "analytics", "monitoring", (s) => () => checkAnalytics(s, repoPath, timeoutMs)),
    ...perSurface(reachable, "zeabur", "monitoring", (s) => () => checkZeabur(s, timeoutMs)),
    ...perSurface(reachable, "db-traffic", "monitoring", (s) => () => checkDbTraffic(s, repoPath, timeoutMs)),
  );

  if (reachable.length > 0) {
    checks.push({
      name: "device",
      category: "monitoring",
      surface: "all",
      run: () => checkDevice(reachable, timeoutMs),
    });
  }

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
      checks: config.surfaces.flatMap((surface) => [
        {
          name: "page-test",
          category: "page" as const,
          surface: surface.id,
          run: async () => ({
            check: "page-test",
            category: "page" as const,
            surface: surface.id,
            completed: false,
            skippedReason: reason,
            durationMs: 0,
            findings: [],
          }),
        },
      ]),
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

async function writeReports(config: SentinelConfig, report: Awaited<ReturnType<typeof runChecks>>): Promise<string[]> {
  await mkdir(config.outDir, { recursive: true });
  const files = [
    { file: path.join(config.outDir, "report.json"), content: JSON.stringify(report, null, 2) },
    { file: path.join(config.outDir, "report.md"), content: renderMarkdown(report) },
    { file: path.join(config.outDir, "report.html"), content: renderHtml(report) },
  ];
  for (const { file, content } of files) await writeFile(file, content, "utf8");
  return files.map((f) => f.file);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const args = parseArgs(argv);

  if (args.flags.has("help") || args.flags.has("h") || !args.command) {
    process.stdout.write(`${USAGE}\n`);
    process.exit(args.command ? 0 : 1);
  }

  const config = buildConfig(args);
  const jsonOnly = args.flags.get("json") === true;
  const command = args.command;

  const repo = resolveRepoPath((name) => {
    const value = args.flags.get(name);
    return typeof value === "string" ? value : undefined;
  });
  const wantsRepo = command === "shells" || command === "monitor" || command === "all";
  if (!jsonOnly && wantsRepo) {
    if (repo.path) {
      const how = repo.source === "auto" ? "自動探測" : repo.source === "env" ? "AIOS_REPO" : "--repo";
      process.stdout.write(`連結 ai_os 原始碼（${how}）：${repo.path}\n`);
    } else {
      process.stdout.write("未連結 ai_os 原始碼——殼層稽核將標記跳過（設 AIOS_REPO、帶 --repo，或把 ai_os 併排檢出）。\n");
    }
  }

  const checks: PlannedCheck[] = [];
  let cleanup: () => Promise<void> = async () => {};

  if (command === "scan" || command === "all") checks.push(...(await planScan(config)));
  if (command === "shells" || command === "all") checks.push(...planShells(config));
  if (command === "monitor" || command === "all") checks.push(...(await planMonitor(config)));
  if (command === "pages" || command === "all") {
    const planned = await planPages(config, args);
    checks.push(...planned.checks);
    cleanup = planned.cleanup;
  }

  if (checks.length === 0) {
    process.stderr.write(`未知指令：${command}\n\n${USAGE}\n`);
    process.exit(1);
  }

  if (!jsonOnly) {
    process.stdout.write(`\n開始檢測 ${config.target}（${config.surfaces.map((s) => s.id).join("、")}）——共 ${checks.length} 項\n`);
  }

  let report: Awaited<ReturnType<typeof runChecks>>;
  try {
    report = await runChecks(config, checks, {
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

  if (jsonOnly) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    printSummary(report);
    const files = await writeReports(config, report);
    process.stdout.write(`報告已輸出：\n${files.map((f) => `  ${f}`).join("\n")}\n\n`);
  }

  process.exit(exitCodeFor(report, config.failOn));
}

main().catch((err: unknown) => {
  process.stderr.write(`Sentinel 執行失敗：${err instanceof Error ? err.stack : String(err)}\n`);
  process.exit(2);
});
