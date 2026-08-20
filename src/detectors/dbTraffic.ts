/**
 * 資料庫進出監測。
 *
 * 我們沒有資料庫的直接連線，但 ai_os 的 `/api/ready` 會**實際探測 DB**（不像 `/api/health`
 * 只回行程狀態）。所以連續打幾次就緒端點，就能觀測到「資料庫進出」的三件事：
 *
 * - **連得到嗎**：db 分項 ok/note；
 * - **一趟往返多久**：就緒延遲是 DB roundtrip 的下界，偏高＝連線池競用或查詢變慢；
 * - **穩不穩**：多次取樣裡有沒有間歇逾時（連線池耗盡的典型症狀）。
 *
 * 另外從原始碼稽核 DB 是否被不當暴露（連線字串進了前端、公開的 Studio 路由）。
 * 取樣刻意序列、間隔進行，不對小型部署造成突發負載。
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, parseJson, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

const base = { check: "db-traffic", category: "monitoring" as const };

export interface ReadySample {
  status: number;
  latencyMs: number;
  /** 整體 ok。 */
  ok: boolean | null;
  /** db 分項 ok。 */
  dbOk: boolean | null;
  dbNote?: string | null;
  /** 連不上／逾時。 */
  unreachable: boolean;
}

export interface DbTrafficStats {
  samples: number;
  reachable: number;
  timeouts: number;
  dbOkCount: number;
  avgLatencyMs: number | null;
  maxLatencyMs: number | null;
}

export function summarizeSamples(samples: ReadySample[]): DbTrafficStats {
  const reachable = samples.filter((s) => !s.unreachable);
  const latencies = reachable.map((s) => s.latencyMs);
  return {
    samples: samples.length,
    reachable: reachable.length,
    timeouts: samples.filter((s) => s.unreachable).length,
    dbOkCount: samples.filter((s) => s.dbOk === true).length,
    avgLatencyMs: latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : null,
    maxLatencyMs: latencies.length ? Math.max(...latencies) : null,
  };
}

/** 就緒延遲多慢算「DB 往返偏慢」。就緒會實打 DB，>1.5s 通常是連線池競用或查詢退化。 */
const SLOW_ROUNDTRIP_MS = 1500;

export function analyzeDbTraffic(samples: ReadySample[], surface: Surface): { findings: Finding[]; stats: DbTrafficStats } {
  const stats = summarizeSamples(samples);
  const findings: Finding[] = [];

  const dbDown = samples.find((s) => s.dbOk === false);
  if (dbDown) {
    findings.push(
      finding({
        ...base,
        surface: surface.id,
        id: "db.unreachable",
        severity: "critical",
        title: `${surface.label}：資料庫連線失敗（讀寫進出中斷）`,
        detail:
          "就緒檢查回報 db 分項未通過。此刻所有需要讀寫資料庫的操作——登入、載入專案、儲存——都會失敗，站台等同全滅。",
        remediation: "檢查 Zeabur Variables 的 DATABASE_URL 與 PostgreSQL 服務狀態；確認資料庫沒被打滿連線或停用。",
        evidence: dbDown.dbNote?.slice(0, 300) ?? undefined,
        where: join(surface.origin, "/api/ready"),
      }),
    );
  }

  // 全部取樣都逾時／連不上：就緒會實打 DB，反覆逾時是連線池耗盡的典型症狀。
  if (stats.samples > 0 && stats.reachable === 0) {
    findings.push(
      finding({
        ...base,
        surface: surface.id,
        id: "db.ready-timeout",
        severity: "high",
        title: `${surface.label}：就緒端點連續逾時（${stats.timeouts}/${stats.samples} 次）`,
        detail:
          "就緒檢查會實際探測資料庫；連續逾時通常代表連線池被耗盡或 DB 卡住，新的請求全在排隊等連線。使用者體感是操作按下去轉圈很久然後失敗。",
        remediation: "檢查資料庫連線池上限與是否有長交易佔用連線；必要時提高 pool size 或重啟服務釋放連線。",
        where: join(surface.origin, "/api/ready"),
      }),
    );
  } else if (stats.timeouts > 0) {
    // 間歇逾時：有些取樣成功、有些連不上。
    //
    // 這正是連線池耗盡最典型的症狀（也是這個模組檔頭宣稱要抓的東西），但舊版只判「全數逾時」，
    // 於是 3 次取樣有 2 次連不上時，報告是「檢查完成、零發現」——最糟的那種輸出。
    // 間歇比全數更難查，因為健康檢查與人工重試常常剛好落在成功的那幾次。
    findings.push(
      finding({
        ...base,
        surface: surface.id,
        id: "db.ready-intermittent",
        severity: "high",
        title: `${surface.label}：就緒端點間歇逾時（${stats.timeouts}/${stats.samples} 次）`,
        detail:
          "同一輪取樣裡有些成功、有些連不上。就緒檢查會實打資料庫，這種時好時壞通常代表連線池在尖峰被占滿——" +
          "使用者遇到的是「有時候好好的，有時候轉圈很久然後失敗」，而人工重試常常剛好落在成功的那幾次，因此極難查。",
        remediation: "檢查資料庫連線池上限與長交易；把就緒端點的逾時與重試設定拉出來看，確認不是探測本身太緊。",
        evidence: `timeouts=${stats.timeouts}/${stats.samples} avg=${stats.avgLatencyMs ?? "?"}ms max=${stats.maxLatencyMs ?? "?"}ms`,
        where: join(surface.origin, "/api/ready"),
      }),
    );
  }

  // 延遲判定與逾時判定並存：間歇逾時的那幾次成功樣本也可能同時偏慢，兩件事都值得說。
  if (stats.reachable > 0 && stats.avgLatencyMs !== null && stats.avgLatencyMs > SLOW_ROUNDTRIP_MS) {
    findings.push(
      finding({
        ...base,
        surface: surface.id,
        id: "db.slow-roundtrip",
        severity: "medium",
        title: `${surface.label}：資料庫往返偏慢（平均 ${stats.avgLatencyMs}ms）`,
        detail:
          "就緒端點會實打資料庫，平均延遲偏高代表 DB 往返變慢——連線池競用、缺索引、或資料庫實例資源吃緊。使用者端會表現為列表與儲存操作普遍變鈍。",
        remediation: "看資料庫的慢查詢與連線數；確認熱路徑有索引，必要時擴充資料庫資源或連線池。",
        evidence: `avg=${stats.avgLatencyMs}ms max=${stats.maxLatencyMs}ms n=${stats.reachable}`,
        where: join(surface.origin, "/api/ready"),
      }),
    );
  }

  return { findings, stats };
}

// ── 原始碼稽核：DB 是否被不當暴露 ──────────────────────────────────────────────

export interface DbExposureInput {
  /** 前端原始碼是否引用了 DATABASE_URL／連線字串。 */
  clientReferencesDbUrl: boolean;
  /** 是否有把 drizzle studio／pgweb 之類掛成公開路由。 */
  publicStudioRoute: string | null;
}

export function analyzeDbExposure(input: DbExposureInput): Finding[] {
  const out: Finding[] = [];
  if (input.clientReferencesDbUrl) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "db.url-in-client",
        severity: "critical",
        title: "資料庫連線字串疑似出現在前端程式碼",
        detail:
          "DATABASE_URL 一旦被打包進前端 bundle，任何使用者都能從瀏覽器讀到帳密與主機位址，等同資料庫直接對外開放。",
        remediation: "連線字串只能存在於伺服器端環境變數；前端絕不引用。若已外洩，立即輪替資料庫憑證。",
      }),
    );
  }
  if (input.publicStudioRoute) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "db.public-studio",
        severity: "high",
        title: "疑似有公開的資料庫管理介面",
        detail: "Drizzle Studio／pgweb 之類的管理介面若掛在公開路由，任何人都能瀏覽甚至改動資料。",
        remediation: "移除公開路由，或鎖在僅限內網／需驗證的入口後面。",
        evidence: input.publicStudioRoute,
      }),
    );
  }
  return out;
}

/**
 * 從 package.json scripts 與伺服器原始碼找出「公開的」DB 管理介面線索。
 *
 * 本機專用腳本（如 `db:studio`）不報——那是開發者自己開的。
 * 只抓會跟著正式服務一起起來的東西：start／serve／prod 腳本，或 HTTP 路由掛載。
 */
export function detectPublicStudioRoute(sources: Array<{ where: string; content: string }>): string | null {
  for (const { where, content } of sources) {
    if (where === "package.json" || where.endsWith("/package.json")) {
      try {
        const pkg = JSON.parse(content) as { scripts?: Record<string, string> };
        for (const [name, cmd] of Object.entries(pkg.scripts ?? {})) {
          if (!/^(start|serve|prod|production|server)(:|$)/i.test(name)) continue;
          if (/drizzle-kit\s+studio|\bpgweb\b|\badminer\b/i.test(cmd)) {
            return `package.json scripts.${name}: ${cmd}`;
          }
        }
      } catch {
        /* 壞掉的 package.json 不當成發現 */
      }
      continue;
    }

    const route =
      /(?:\.(?:get|use|all|post)\s*\(\s*|path\s*:\s*|route\s*\(\s*)["'`](\/(?:studio|pgweb|adminer)[^"'`]*)["'`]/i.exec(
        content,
      )?.[1] ??
      /["'`](\/(?:studio|pgweb|adminer)(?:\/[^"'`]*)?)["'`]\s*,\s*(?:async\s*)?(?:\(|function)/i.exec(content)?.[1];
    if (route) return `${where}: ${route}`;

    if (/drizzle-kit\s+studio/i.test(content) && /0\.0\.0\.0|\.listen\s*\(/i.test(content)) {
      return `${where}: drizzle-kit studio`;
    }
  }
  return null;
}

/** 蒐集可能掛公開 Studio 的原始碼片段（package.json + server 進入點／含關鍵字的檔）。 */
async function collectStudioSources(repoPath: string): Promise<Array<{ where: string; content: string }>> {
  const out: Array<{ where: string; content: string }> = [];
  for (const rel of ["package.json", "server/index.ts"]) {
    const content = await readIfExists(path.join(repoPath, rel));
    if (content) out.push({ where: rel, content });
  }
  try {
    const entries = await readdir(path.join(repoPath, "server"));
    for (const name of entries) {
      if (!name.endsWith(".ts") || name === "index.ts") continue;
      const rel = `server/${name}`;
      const content = await readIfExists(path.join(repoPath, rel));
      if (content && /studio|pgweb|adminer/i.test(content)) out.push({ where: rel, content });
    }
  } catch {
    /* 沒有 server/ 就略過 */
  }
  return out;
}

// ── 執行 ──────────────────────────────────────────────────────────────────────

async function sampleReady(surface: Surface, timeoutMs: number): Promise<ReadySample> {
  const startedAt = Date.now();
  const res = await tryProbe(join(surface.origin, "/api/ready"), { surface, timeoutMs, followRedirects: 2 });
  if (isProbeFailure(res)) {
    return { status: 0, latencyMs: Date.now() - startedAt, ok: null, dbOk: null, unreachable: true };
  }
  const body = parseJson<{ ok?: boolean; components?: Record<string, { ok?: boolean; note?: string }> }>(res.body);
  const db = body?.components?.db;
  return {
    status: res.status,
    latencyMs: res.durationMs,
    ok: body?.ok ?? null,
    dbOk: db?.ok ?? null,
    dbNote: db?.note ?? null,
    unreachable: false,
  };
}

async function readIfExists(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

const SAMPLE_COUNT = 3;

export async function checkDbTraffic(
  surface: Surface,
  repoPath: string | undefined,
  timeoutMs: number,
): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const meta = { ...base, surface: surface.id };

  // 序列取樣，每次之間留一點間隔——不對小型部署造成突發負載。
  const samples: ReadySample[] = [];
  for (let i = 0; i < SAMPLE_COUNT; i += 1) {
    samples.push(await sampleReady(surface, timeoutMs));
    if (i < SAMPLE_COUNT - 1) await new Promise((r) => setTimeout(r, 300));
  }
  facts.samples = samples;

  const { findings: trafficFindings, stats } = analyzeDbTraffic(samples, surface);
  facts.stats = stats;
  findings.push(...trafficFindings);

  // 原始碼稽核（有 repo 才跑；只在 web 端跑一次，避免三端重複同一份原始碼判定）。
  if (repoPath && surface.id === "web") {
    const clientDir = path.join(repoPath, "client/src");
    const [main, viteEnv, studioSources] = await Promise.all([
      readIfExists(path.join(clientDir, "main.tsx")),
      readIfExists(path.join(repoPath, "client/src/vite-env.d.ts")),
      collectStudioSources(repoPath),
    ]);
    const clientBlob = `${main ?? ""}\n${viteEnv ?? ""}`;
    const publicStudioRoute = detectPublicStudioRoute(studioSources);
    facts.publicStudioRoute = publicStudioRoute;
    findings.push(
      ...analyzeDbExposure({
        clientReferencesDbUrl: /DATABASE_URL|postgres:\/\//.test(clientBlob),
        publicStudioRoute,
      }),
    );
  }

  return { ...meta, completed: true, durationMs: elapsed(), findings, facts };
}
