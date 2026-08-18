/**
 * 使用者行為監測稽核（PostHog）。
 *
 * ai_os 用 PostHog 監測前端行為與例外（`client/src/posthog.ts`，延後載入的代理）。
 * 這組檢查回答三個問題：
 *
 * 1. **靜態**：分析的設定本身有沒有監測盲區或隱私問題？（讀原始碼）
 * 2. **線上**：正式站真的有把分析載進去嗎？CSP 有沒有放行 PostHog？
 *    ——最危險的失效是「金鑰沒注入到 build，事件靜默全掉」，ai_os 自己的註解就寫了這點。
 * 3. **深度**（需 PostHog API 金鑰）：實際使用者行為長什麼樣？近期有沒有事件、
 *    有沒有前端例外、裝置分布如何？沒金鑰時誠實標記跳過，不假裝有在監測。
 *
 * 判定邏輯全寫成純函式，網路與檔案 I/O 集中在 `checkAnalytics`。
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, tryProbe } from "../core/http.js";
import { parseCsp } from "./csp.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

/** 從回應標頭與 HTML meta 取出 CSP 的 script-src（含 default-src 兜底）。 */
function cspScriptSrcOf(header: string | null, html: string): string[] | null {
  const metaCsp = /<meta[^>]+http-equiv=["']content-security-policy["'][^>]+content=["']([^"']+)["']/i.exec(html)?.[1];
  const raw = header ?? metaCsp ?? null;
  if (!raw) return null;
  const directives = parseCsp(raw);
  return directives.get("script-src") ?? directives.get("default-src") ?? [];
}

const base = { check: "analytics", category: "monitoring" as const };

// ─────────────────────────────────────────────────────────────────────────────
// 靜態：PostHog 用戶端設定
// ─────────────────────────────────────────────────────────────────────────────

export interface PosthogSourceFacts {
  /** 是否確實接上 PostHog（有 import/init）。 */
  wired: boolean;
  usesEnvKey: boolean;
  captureUnhandledErrors: boolean;
  captureConsoleErrors: boolean;
  /** 用戶端原始碼裡是否出現個人 API 金鑰（phx_/phs_）——那是絕不該進 bundle 的東西。 */
  personalKeyLeak: string | null;
}

export function parsePosthogSource(source: string): PosthogSourceFacts {
  return {
    wired: /posthog/i.test(source),
    usesEnvKey: /VITE_POSTHOG_KEY|import\.meta\.env\.\w*POSTHOG/i.test(source),
    captureUnhandledErrors: /capture_unhandled_errors\s*:\s*true/.test(source),
    captureConsoleErrors: /capture_console_errors\s*:\s*true/.test(source),
    // 公開的專案金鑰是 phc_（設計上可公開）；phx_/phs_ 是個人/伺服器金鑰，外洩即可讀寫整個專案。
    personalKeyLeak: /\b(phx_[A-Za-z0-9]{16,}|phs_[A-Za-z0-9]{16,})\b/.exec(source)?.[1] ?? null,
  };
}

export function analyzePosthogSource(facts: PosthogSourceFacts, where: string): Finding[] {
  const out: Finding[] = [];

  if (facts.personalKeyLeak) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "analytics.posthog.personal-key-leak",
        severity: "critical",
        title: "PostHog 個人／伺服器金鑰疑似寫死在用戶端",
        detail:
          "phx_／phs_ 開頭的金鑰能讀寫整個 PostHog 專案；一旦被打包進前端 bundle，任何使用者都能從瀏覽器取得並竄改分析資料、匯出個資。",
        remediation: "改用 phc_ 開頭的公開專案金鑰於前端；個人金鑰只留在伺服器環境變數。立即在 PostHog 後台輪替外洩的金鑰。",
        evidence: facts.personalKeyLeak,
        where,
      }),
    );
  }

  if (facts.wired && !facts.captureUnhandledErrors) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "analytics.posthog.no-exception-capture",
        severity: "medium",
        title: "PostHog 未開啟前端例外擷取",
        detail:
          "沒有 capture_unhandled_errors，使用者端崩潰的 JavaScript 例外不會回報到分析後台。線上壞掉時你只能等使用者客訴，而不是主動看到錯誤曲線上升。",
        remediation: "在 posthog.init 設定 capture_exceptions.capture_unhandled_errors 與 capture_unhandled_rejections 為 true。",
        where,
      }),
    );
  }

  if (facts.wired && facts.captureUnhandledErrors && !facts.captureConsoleErrors) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "analytics.posthog.no-console-capture",
        severity: "low",
        title: "PostHog 未擷取 console 錯誤",
        detail:
          "未擷取 console.error 代表非致命但重要的錯誤（失敗的請求、被吞掉的例外）不會進入監測，這類問題往往是體驗劣化的先兆。",
        remediation: "評估開啟 capture_exceptions.capture_console_errors；若因雜訊過多而關閉，請記錄為已知取捨。",
        where,
      }),
    );
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 線上：正式站是否真的載入並放行 PostHog
// ─────────────────────────────────────────────────────────────────────────────

export interface RuntimeAnalyticsInput {
  /** 進入點 JS（posthog 代理是被 main.tsx 靜態 import 的，所以會在 entry chunk）。 */
  entryJs: string;
  /** transport 檢查解析到的 CSP script-src 指令（可能為 null＝沒設 CSP）。 */
  cspScriptSrc: string[] | null;
}

/** entry chunk 裡有沒有 PostHog 的痕跡，以及注入的 ingestion host。 */
export function detectPosthogInBundle(entryJs: string): { present: boolean; host: string | null } {
  const present = /posthog/i.test(entryJs);
  const host = /https?:\/\/[a-z0-9.-]*posthog\.com/i.exec(entryJs)?.[0]
    ?? /api_host\s*[:=]\s*["'`](https?:\/\/[^"'`]+)["'`]/i.exec(entryJs)?.[1]
    ?? null;
  return { present, host };
}

/** CSP 的 script-src 是否放行了某個來源（含萬用與 default-src 不在此兜底——這裡只看 script-src）。 */
function scriptSrcAllows(scriptSrc: string[], host: string): boolean {
  let hostname: string;
  try {
    hostname = new URL(host).hostname;
  } catch {
    return false;
  }
  return scriptSrc.some((src) => {
    const s = src.replace(/^https?:\/\//, "").replace(/\/$/, "");
    if (s === "*" ) return true;
    if (s === hostname) return true;
    if (s.startsWith("*.")) return hostname === s.slice(2) || hostname.endsWith(s.slice(1));
    return false;
  });
}

export function analyzePosthogRuntime(input: RuntimeAnalyticsInput, surface: Surface, where: string): Finding[] {
  const out: Finding[] = [];
  const { present, host } = detectPosthogInBundle(input.entryJs);

  if (!present) {
    out.push(
      finding({
        ...base,
        surface: surface.id,
        id: "analytics.posthog.not-loaded",
        severity: "high",
        title: `${surface.label}：正式站似乎未載入 PostHog 分析`,
        detail:
          "進入點程式碼裡找不到 PostHog 的痕跡。若金鑰沒被注入到 build，分析與前端例外會被靜默丟棄——監測看起來在跑，實際上一筆都沒收到。",
        remediation: "確認部署平台已設定 VITE_POSTHOG_KEY／VITE_POSTHOG_HOST，且 build 有把它們編譯進前端。",
        where,
      }),
    );
    return out;
  }

  // 有載 PostHog，但 CSP 的 script-src 沒放行它的來源——瀏覽器會直接擋掉分析腳本／請求。
  if (host && input.cspScriptSrc && !scriptSrcAllows(input.cspScriptSrc, host)) {
    out.push(
      finding({
        ...base,
        surface: surface.id,
        id: "analytics.posthog.csp-blocked",
        severity: "high",
        title: `${surface.label}：CSP 未放行 PostHog 來源（${host}）`,
        detail:
          "頁面載入 PostHog，但 Content-Security-Policy 的 script-src 沒放行它的網域，瀏覽器會攔下分析請求。結果是監測靜默失效，而報告若只看「有沒有接分析」會誤判為正常。",
        remediation: `把 ${new URL(host).hostname}（或 https://*.posthog.com）加進 CSP 的 script-src 與 connect-src。`,
        evidence: input.cspScriptSrc.join(" "),
        where,
      }),
    );
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 深度：PostHog API 拉近期使用者行為（需金鑰）
// ─────────────────────────────────────────────────────────────────────────────

export interface PosthogInsight {
  totalEvents: number;
  exceptionEvents: number;
  topEvents: Array<{ event: string; count: number }>;
  devices: Array<{ type: string; count: number }>;
}

/** 把 PostHog HogQL 查詢結果（`{ results: [[event, count, isException?], ...] }`）整理成監測摘要。 */
export function summarizePosthogEvents(
  rows: Array<{ event: string; count: number; deviceType?: string | null }>,
): PosthogInsight {
  const byDevice = new Map<string, number>();
  let total = 0;
  let exceptions = 0;
  const byEvent = new Map<string, number>();
  for (const row of rows) {
    const count = Number(row.count) || 0;
    total += count;
    byEvent.set(row.event, (byEvent.get(row.event) ?? 0) + count);
    if (row.event === "$exception") exceptions += count;
    const device = row.deviceType?.trim() || "unknown";
    byDevice.set(device, (byDevice.get(device) ?? 0) + count);
  }
  const topEvents = [...byEvent.entries()]
    .map(([event, count]) => ({ event, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);
  const devices = [...byDevice.entries()]
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
  return { totalEvents: total, exceptionEvents: exceptions, topEvents, devices };
}

export function analyzePosthogInsight(insight: PosthogInsight, windowHours: number): Finding[] {
  const out: Finding[] = [];
  if (insight.totalEvents === 0) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "analytics.posthog.no-recent-events",
        severity: "high",
        title: `PostHog 近 ${windowHours} 小時沒有任何事件`,
        detail:
          "分析後台在觀測窗內收到 0 筆事件。要嘛真的沒人用（值得知道），要嘛更常見的是——分析在正式站靜默失效（金鑰漏設、被 CSP／攔截器擋掉），監測形同虛設。",
        remediation: "先確認站台確有流量；若有流量卻沒事件，檢查 VITE_POSTHOG_KEY／CSP／ingestion host 是否正確。",
      }),
    );
  }
  if (insight.exceptionEvents > 0) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "analytics.posthog.exceptions-observed",
        severity: "medium",
        title: `PostHog 觀測到 ${insight.exceptionEvents} 筆前端例外`,
        detail: "使用者端正在丟出未捕捉的例外。這是真實使用者踩到的錯誤，通常對應到白畫面或功能失效。",
        remediation: "到 PostHog 的 Error tracking 看堆疊與受影響路由，依發生量排修復順序。",
        evidence: insight.topEvents.map((e) => `${e.event}: ${e.count}`).join("\n"),
      }),
    );
  }
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 執行
// ─────────────────────────────────────────────────────────────────────────────

async function readIfExists(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

/** 從首頁 HTML 抽出第一個 module 進入點腳本的絕對網址。 */
function entryScriptUrl(html: string, origin: string): string | null {
  const match = /<script[^>]+type=["']module["'][^>]+src=["']([^"']+)["']/i.exec(html)
    ?? /<script[^>]+src=["']([^"']+\.js)["'][^>]*type=["']module["']/i.exec(html);
  if (!match?.[1]) return null;
  try {
    return join(origin, match[1]);
  } catch {
    return null;
  }
}

export async function checkAnalytics(
  surface: Surface,
  repoPath: string | undefined,
  timeoutMs: number,
): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const meta = { ...base, surface: surface.id };

  // ── 靜態：用戶端設定（有原始碼才跑；只在 web 端跑一次，避免三端重複同一份原始碼判定）──
  if (repoPath && surface.id === "web") {
    const posthogPath = path.join(repoPath, "client/src/posthog.ts");
    const src = await readIfExists(posthogPath);
    if (src) {
      const sf = parsePosthogSource(src);
      facts.source = sf;
      findings.push(...analyzePosthogSource(sf, posthogPath));
    }
  }

  // ── 線上：正式站是否載入並放行 PostHog ─────────────────────────────
  const home = await tryProbe(surface.origin, { surface, timeoutMs, followRedirects: 2 });
  if (!isProbeFailure(home)) {
    const cspScriptSrc = cspScriptSrcOf(home.headers.get("content-security-policy"), home.body);
    const entryUrl = entryScriptUrl(home.body, surface.origin);
    facts.entryScript = entryUrl;
    if (entryUrl) {
      const entry = await tryProbe(entryUrl, { surface, timeoutMs, followRedirects: 2 });
      if (!isProbeFailure(entry)) {
        const detected = detectPosthogInBundle(entry.body);
        facts.posthog = detected;
        findings.push(...analyzePosthogRuntime({ entryJs: entry.body, cspScriptSrc }, surface, entryUrl));
      }
    }
  }

  // ── 深度：PostHog API（需金鑰，否則誠實標記本段跳過）────────────────
  const apiKey = process.env.POSTHOG_API_KEY;
  const projectId = process.env.POSTHOG_PROJECT_ID;
  const apiHost = process.env.POSTHOG_HOST ?? process.env.POSTHOG_API_HOST;
  if (apiKey && projectId && apiHost) {
    const windowHours = 24;
    const query = {
      query: {
        kind: "HogQLQuery",
        query:
          `select event, count() as count, properties.$device_type as deviceType ` +
          `from events where timestamp > now() - interval ${windowHours} hour group by event, deviceType order by count desc limit 100`,
      },
    };
    const res = await tryProbe(join(apiHost, `/api/projects/${projectId}/query/`), {
      method: "POST",
      headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
      body: JSON.stringify(query),
      timeoutMs,
    });
    if (!isProbeFailure(res) && res.status === 200) {
      try {
        const parsed = JSON.parse(res.body) as { results?: Array<[string, number, string | null]> };
        const rows = (parsed.results ?? []).map(([event, count, deviceType]) => ({ event, count, deviceType }));
        const insight = summarizePosthogEvents(rows);
        facts.insight = insight;
        findings.push(...analyzePosthogInsight(insight, windowHours));
      } catch {
        /* 回應形狀變了不該讓整項爆掉——當作深度段沒拿到資料 */
      }
    }
  } else {
    facts.insightSkipped = "未設定 POSTHOG_API_KEY／POSTHOG_PROJECT_ID／POSTHOG_HOST，略過使用者行為深度拉取。";
  }

  return { ...meta, completed: true, durationMs: elapsed(), findings, facts };
}
