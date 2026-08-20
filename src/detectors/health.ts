/**
 * 健康與就緒檢測。
 *
 * 對接 ai_os 的兩個公開端點（server/index.ts）：
 * - `/api/health`：純 HTTP、不碰 DB，回 `{ ok, time, build:{sha,branch,builtAt} }`
 * - `/api/ready`：分項就緒，回 `{ ok, processRole, components:{db,boot,storage,runner,provider}, runners, resources }`
 *   任一必要分項失敗即 503。
 *
 * 這裡的價值不是「再呼叫一次 health」，而是**把 503 的分項翻成人看得懂的故障判定**，
 * 並把 runner 心跳、資源用量這些「不參與 503 但會預告故障」的訊號拉出來報。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, parseJson, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

interface HealthPayload {
  ok?: boolean;
  time?: string;
  build?: { sha?: string | null; branch?: string | null; builtAt?: string | null };
}

interface ReadyComponent {
  ok?: boolean;
  note?: string;
}

/**
 * 一個就緒分項的狀態。
 *
 * 「無法判定」必須與「通過」和「故障」並列成第三種答案。舊版把
 * 「形狀不是 `{ok: true}`」一律當成故障，於是一個回 `{"db":"ok"}`（分項用字串狀態，
 * 同一份型別宣告自己就允許這種寫法）的健康站台，會被報成 db／boot／storage 全部掛掉——
 * 一次五筆 critical／high，全部是假的。
 */
export type ComponentState = "ok" | "failed" | "unknown";

/** 這些字串在各家健康檢查慣例裡都代表通過。`skipped`／`disabled` 也算——ai_os 的 web 角色不跑 runner。 */
const PASS_WORDS = /^(ok|up|pass(ed)?|healthy|ready|skipped|disabled|not[-_ ]?applicable|n\/a)$/i;
const FAIL_WORDS = /^(fail(ed|ing)?|down|error|unhealthy|degraded|unavailable)$/i;

/**
 * 判讀分項狀態。
 *
 * 認得三種寫法：布林、狀態字串、以及 `{ ok: boolean }` 物件。認不得的一律回 `unknown`——
 * 猜錯的方向無論哪一邊都有代價，所以不猜。
 */
export function componentState(value: unknown): ComponentState {
  if (value === true) return "ok";
  if (value === false) return "failed";
  if (typeof value === "string") {
    const text = value.trim();
    if (PASS_WORDS.test(text)) return "ok";
    if (FAIL_WORDS.test(text)) return "failed";
    return "unknown";
  }
  if (value !== null && typeof value === "object") {
    const ok = (value as { ok?: unknown }).ok;
    return ok === undefined ? "unknown" : componentState(ok);
  }
  return "unknown";
}

interface ReadyPayload {
  ok?: boolean;
  processRole?: string;
  db?: string;
  boot?: string;
  components?: Record<string, ReadyComponent>;
  runners?: Array<{ name?: string; started?: boolean; lastTickAgeMs?: number | null; queueDepth?: number; inflight?: number }>;
  resources?: Record<string, unknown>;
}

/** 各分項失敗時的嚴重度。DB 掛掉是站台全滅，provider 缺金鑰只是生成會失敗。 */
const COMPONENT_SEVERITY: Record<string, "critical" | "high" | "medium"> = {
  db: "critical",
  boot: "high",
  storage: "high",
  runner: "medium",
  provider: "medium",
};

/** runner 心跳超過這個秒數就當它停了（ai_os 端的期望是 60 秒內有 tick）。 */
const RUNNER_STALE_MS = 120_000;

export async function checkHealth(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "health", category: "availability" as const, surface: surface.id };

  // ── /api/health ─────────────────────────────────────────────────────────
  const healthUrl = join(surface.origin, "/api/health");
  const health = await tryProbe(healthUrl, { surface, timeoutMs, followRedirects: 2 });

  if (isProbeFailure(health)) {
    findings.push(
      finding({
        ...base,
        id: "health.unreachable",
        severity: "critical",
        title: `${surface.label}：站台無法連線`,
        detail: `健康檢查端點連不上。這一端的使用者現在看到的是白畫面或連線錯誤。原因：${health.error}`,
        remediation: "檢查部署平台的服務狀態與網域解析；若是部署中，等部署完成後重跑。",
        where: healthUrl,
      }),
    );
    // 連不上就沒有後續判定的基礎，直接收工——繼續跑只會產生一串誤導性的次生告警。
    return { ...base, completed: true, durationMs: elapsed(), findings, facts };
  }

  const healthBody = parseJson<HealthPayload>(health.body);
  facts.healthStatus = health.status;
  facts.healthLatencyMs = health.durationMs;
  facts.build = healthBody?.build ?? null;

  // 被中介層攔截時，這一輪根本沒碰到應用。誠實回報「沒測到」，
  // 而不是把代理的 403 說成「行程崩潰重啟中」——後者會讓人去查完全不存在的故障。
  if (
    looksLikeGatewayInterception({
      status: health.status,
      body: health.body,
      contentType: health.headers.get("content-type") ?? "",
    })
  ) {
    return {
      ...base,
      completed: false,
      skippedReason:
        `${surface.label}：健康檢查回應 HTTP ${health.status}，且內容不是應用的 JSON——` +
        "判定為中介層（代理／WAF／平台閘道）攔截，本輪未實際觸及站台。請從能直連目標的網路環境重跑。",
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  if (health.status !== 200 || healthBody?.ok !== true) {
    findings.push(
      finding({
        ...base,
        id: "health.not-ok",
        severity: "critical",
        title: `${surface.label}：健康檢查未通過（HTTP ${health.status}）`,
        detail: "健康檢查不碰資料庫，它失敗代表行程本身有問題（崩潰重啟中、記憶體不足、或路由沒掛上）。",
        remediation: "查部署平台的容器日誌，確認行程是否反覆重啟。",
        evidence: health.body.slice(0, 300),
        where: healthUrl,
      }),
    );
  }

  if (health.durationMs > 3000) {
    findings.push(
      finding({
        ...base,
        id: "health.slow",
        severity: "medium",
        title: `${surface.label}：健康檢查回應過慢（${health.durationMs}ms）`,
        detail: "這個端點不做任何 I/O，慢代表事件迴圈被卡住——通常是某個同步運算或 GC 壓力，使用者端會表現為整站卡頓。",
        remediation: "檢查是否有同步的大量檔案處理或 JSON 解析佔用主執行緒。",
        where: healthUrl,
      }),
    );
  }

  if (!healthBody?.build?.sha) {
    findings.push(
      finding({
        ...base,
        id: "health.no-build-sha",
        severity: "low",
        title: `${surface.label}：健康檢查沒有 build SHA`,
        detail:
          "沒有版本識別就無法確認線上跑的是哪一版；出事時無法對應到 commit，三端版本漂移也偵測不到。",
        remediation: "在建置流程注入 BUILD_SHA（Dockerfile ARG→ENV），確認部署平台有傳入。",
        where: healthUrl,
      }),
    );
  }

  // ── /api/ready ──────────────────────────────────────────────────────────
  const readyUrl = join(surface.origin, "/api/ready");
  const ready = await tryProbe(readyUrl, { surface, timeoutMs, followRedirects: 2 });

  if (isProbeFailure(ready)) {
    findings.push(
      finding({
        ...base,
        id: "ready.unreachable",
        severity: "high",
        title: `${surface.label}：就緒端點無法連線`,
        detail: `健康檢查通過但就緒檢查連不上，通常是逾時（就緒會實際探測 DB 與儲存層）。原因：${ready.error}`,
        remediation: "查資料庫與儲存層的連線狀況；就緒端點逾時多半是 DB 連線池耗盡。",
        where: readyUrl,
      }),
    );
    return { ...base, completed: true, durationMs: elapsed(), findings, facts };
  }

  const readyBody = parseJson<ReadyPayload>(ready.body);
  facts.readyStatus = ready.status;
  facts.processRole = readyBody?.processRole ?? null;

  if (!readyBody) {
    findings.push(
      finding({
        ...base,
        id: "ready.unparseable",
        severity: "medium",
        title: `${surface.label}：就緒端點回應不是 JSON`,
        detail: "拿到的不是預期的就緒 JSON，可能是反向代理的錯誤頁蓋掉了應用回應。",
        remediation: "確認反向代理沒有攔截 /api/*，以及應用確實在監聽。",
        evidence: ready.body.slice(0, 300),
        where: readyUrl,
      }),
    );
    return { ...base, completed: true, durationMs: elapsed(), findings, facts };
  }

  const components = readyBody.components ?? {};
  facts.components = Object.fromEntries(Object.entries(components).map(([k, v]) => [k, componentState(v)]));

  const unknownComponents: string[] = [];
  for (const [name, comp] of Object.entries(components)) {
    const state = componentState(comp);
    if (state === "ok") continue;
    if (state === "unknown") {
      unknownComponents.push(name);
      continue;
    }
    const severity = COMPONENT_SEVERITY[name] ?? "medium";
    findings.push(
      finding({
        ...base,
        id: `ready.component.${name}`,
        severity,
        title: `${surface.label}：就緒分項「${name}」未通過`,
        detail: comp?.note
          ? `伺服器回報：${comp.note}`
          : `分項 ${name} 回報未就緒，且沒有附上說明。`,
        remediation:
          name === "db"
            ? "檢查部署平台 Variables 的 DATABASE_URL 與資料庫服務狀態。"
            : name === "storage"
              ? "確認持久 Volume 已掛載（/data 或 ASSET_DIR），或物件儲存設定正確——否則重啟即遺失素材。"
              : name === "provider"
                ? "設定媒體生成金鑰（FAL_KEY），否則所有生成請求都會失敗。"
                : "依伺服器回報的 note 排查對應子系統。",
        where: readyUrl,
      }),
    );
  }

  if (unknownComponents.length > 0) {
    findings.push(
      finding({
        ...base,
        id: "ready.component-shape",
        severity: "low",
        title: `${surface.label}：${unknownComponents.length} 個就緒分項的狀態判讀不出來`,
        detail:
          `分項 ${unknownComponents.join("、")} 的回應形狀不是本工具認得的（布林、狀態字串、或 { ok: boolean }）。` +
          "這些分項**本輪沒有被判定**——既沒說它們有問題，也不代表它們沒問題。",
        remediation: "把 /api/ready 的分項統一成 { ok: boolean, note?: string }，或告知本工具實際使用的格式。",
        evidence: ready.body.slice(0, 300),
        where: readyUrl,
      }),
    );
  }

  // ── 整體就緒狀態 ────────────────────────────────────────────────────────
  //
  // 這一段過去完全不存在，於是 /api/ready 回 HTTP 500 加 {"ok":false,"error":"db pool exhausted"}
  // （沒有 components 欄位）時，整個檢查回報零發現、標記完成，終端印出「✓ 沒有發現問題」——
  // 而站台此刻根本不能服務。這是這套系統最不能接受的一種輸出。
  //
  // 分項已經解釋了故障時就不重複報：讀者要的是故障點，不是再一句「總之沒就緒」。
  const readyOk = ready.status === 200 && readyBody.ok === true;
  const explainedByComponents = findings.some((f) => f.id.startsWith("ready.component."));

  if (!readyOk && !explainedByComponents) {
    const hasComponents = Object.keys(components).length > 0;
    findings.push(
      hasComponents
        ? finding({
            ...base,
            id: "ready.inconsistent",
            severity: "medium",
            title: `${surface.label}：整體回報未就緒，但所有分項都是通過`,
            detail: "整體狀態與分項互相矛盾，代表就緒判定裡有分項沒被列進 components，故障點看不見。",
            remediation: "檢查 /api/ready 的 ok 計算是否涵蓋所有納入判定的分項。",
            evidence: ready.body.slice(0, 400),
            where: readyUrl,
          })
        : finding({
            ...base,
            id: "ready.not-ok",
            severity: "high",
            title: `${surface.label}：就緒端點回報未就緒（HTTP ${ready.status}）`,
            detail:
              "站台自己說它還不能服務，而回應裡沒有附上分項，所以看不出是哪一塊壞了。" +
              "使用者此刻多半正在撞上錯誤畫面。",
            remediation: "查應用日誌找出未就緒的原因；並讓 /api/ready 回傳 components 分項，故障點才看得見。",
            evidence: ready.body.slice(0, 400),
            where: readyUrl,
          }),
    );
  }

  // ── runner 心跳（不參與 503，但會預告「任務都不動了」）────────────────
  for (const runner of readyBody.runners ?? []) {
    if (!runner?.name) continue;
    if (runner.started === false) {
      findings.push(
        finding({
          ...base,
          id: `ready.runner.stopped.${runner.name}`,
          severity: "medium",
          title: `${surface.label}：背景執行器 ${runner.name} 未啟動`,
          detail: "使用者送出的生成／匯出／工作流任務會一直卡在佇列，畫面上看起來像「按了沒反應」。",
          remediation: "確認該實例的 PROCESS_ROLE 是否應啟動此執行器，並查啟動日誌。",
          where: readyUrl,
        }),
      );
      continue;
    }
    const age = runner.lastTickAgeMs;
    if (typeof age === "number" && age > RUNNER_STALE_MS) {
      findings.push(
        finding({
          ...base,
          id: `ready.runner.stale.${runner.name}`,
          severity: "medium",
          title: `${surface.label}：背景執行器 ${runner.name} 心跳停滯（${Math.round(age / 1000)} 秒）`,
          detail: "執行器有啟動但已久未 tick，通常是被某個未逾時的外部請求卡住，佇列會持續堆積。",
          remediation: "檢查該執行器對外呼叫是否設有逾時；必要時重啟 worker 實例。",
          where: readyUrl,
        }),
      );
    }
    if (typeof runner.queueDepth === "number" && runner.queueDepth > 50) {
      findings.push(
        finding({
          ...base,
          id: `ready.runner.backlog.${runner.name}`,
          severity: "low",
          title: `${surface.label}：${runner.name} 佇列積壓（${runner.queueDepth} 筆）`,
          detail: "積壓表示產能跟不上送件速度，使用者體感是「排很久才輪到」。",
          remediation: "評估增加 worker 實例或提高該執行器的併發上限。",
          where: readyUrl,
        }),
      );
    }
  }

  facts.runners = readyBody.runners ?? [];
  facts.resources = readyBody.resources ?? null;

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
