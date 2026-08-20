/**
 * CORS 設定檢測。
 *
 * 最危險的組合是「反射任意 Origin ＋ allow-credentials」：
 * 任何網站都能用受害者的登入 Cookie 呼叫 Aios API 並讀走回應，等於帳號被遠端操作。
 *
 * 這種設定常見於「本來只想放行自家前端，卻寫成把 req.headers.origin 原樣回填」。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

/** 明顯不屬於任何自家部署的來源，用來測反射。 */
const EVIL_ORIGIN = "https://sentinel-cors-probe.invalid";

/**
 * 把來源正規化成可比對的形式。
 *
 * 直接用 `===` 比會漏掉最常見的一種反射寫法：伺服器把 Origin 正規化後回填
 * （`new URL(req.headers.origin).href` 會多出尾端斜線），或大小寫不同。
 * 那時 `===` 不成立、值也不是 `*` 或 `null`，於是一個「反射任意 Origin ＋ allow-credentials」
 * 的 critical 漏洞會得到零發現——這是這個偵測器最嚴重的失效方式。
 */
export function normalizeOrigin(value: string): string {
  try {
    return new URL(value).origin.toLowerCase();
  } catch {
    return value.trim().replace(/\/+$/, "").toLowerCase();
  }
}

export interface CorsObservation {
  allowOrigin: string | null;
  allowCredentials: string | null;
  allowMethods: string | null;
  allowHeaders: string | null;
}

export function analyzeCors(
  obs: CorsObservation,
  ctx: { surface: Surface["id"]; where: string; sentOrigin: string },
): Finding[] {
  const base = { check: "cors", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];
  const credentials = /^true$/i.test(obs.allowCredentials ?? "");
  const evidence = [
    `Access-Control-Allow-Origin: ${obs.allowOrigin ?? "（無）"}`,
    `Access-Control-Allow-Credentials: ${obs.allowCredentials ?? "（無）"}`,
  ].join("\n");

  if (obs.allowOrigin && normalizeOrigin(obs.allowOrigin) === normalizeOrigin(ctx.sentOrigin)) {
    out.push(
      finding({
        ...base,
        id: "cors.reflects-origin",
        severity: credentials ? "critical" : "high",
        title: credentials
          ? "CORS 反射任意 Origin 且允許帶憑證"
          : "CORS 反射任意 Origin",
        detail: credentials
          ? "伺服器把請求送來的 Origin 原樣回填，且允許夾帶 Cookie。任何惡意網站都能在使用者登入狀態下呼叫 Aios API 並讀取回應——專案內容、成員名單、資料庫都可被靜默竊取。"
          : "伺服器把任意 Origin 回填為允許來源。目前沒有放行憑證，傷害有限，但只要日後有人加上 credentials 就會立刻升級成帳號接管等級的漏洞。",
        remediation:
          "改用白名單比對：只有在 Origin 完全等於自家部署網域時才回填，其餘一律不回 Access-Control-Allow-Origin。",
        evidence,
      }),
    );
    return out;
  }

  if (obs.allowOrigin === "*") {
    out.push(
      finding({
        ...base,
        id: "cors.wildcard",
        severity: credentials ? "critical" : "low",
        title: credentials ? "CORS 同時使用 * 與 allow-credentials" : "CORS 允許任意來源（*）",
        detail: credentials
          ? "瀏覽器會拒絕這個組合（功能實際上是壞的），但若有中介層把 * 改寫成實際 Origin，就會變成完全開放的憑證存取。"
          : "任意網站可讀取此端點的回應。若端點只回公開資料則可接受，但要確認它不會因登入狀態而回傳不同內容。",
        remediation: credentials
          ? "移除 allow-credentials，或改為白名單回填具體來源。"
          : "確認此端點的回應與登入狀態無關；若有關，改為白名單。",
        evidence,
      }),
    );
  }

  if (obs.allowOrigin && /^null$/i.test(obs.allowOrigin)) {
    out.push(
      finding({
        ...base,
        id: "cors.null-origin",
        severity: "high",
        title: "CORS 允許 null 來源",
        detail: "沙箱化的 iframe 與本機檔案的 Origin 都是 null，放行等於對攻擊者最容易取得的執行環境開門。",
        remediation: "不要把 null 列入允許來源。",
        evidence,
      }),
    );
  }

  return out;
}

export async function checkCors(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "cors", category: "security" as const, surface: surface.id };

  // 挑有代表性的端點：tRPC 是資料主要出口，REST v1 是對外整合面。
  const targets = ["/api/trpc/system.storageStatus", "/api/v1/databases", "/api/health"];

  for (const path of targets) {
    const url = join(surface.origin, path);

    // 觀測反射一律用 GET。
    //
    // 舊版送 POST——註解說那是「預檢」，但 POST 不是預檢，而且 POST 到 /api/v1/databases
    // 是**寫入方法**：萬一該端點真的沒擋，掃描本身就會在使用者的正式資料庫上建東西。
    // 檢測系統不該污染它要測量的東西，所以這裡只送讀取方法。
    const reflect = await tryProbe(url, {
      surface,
      timeoutMs,
      method: "GET",
      headers: { origin: EVIL_ORIGIN },
      followRedirects: 0,
      maxBodyBytes: 8 * 1024,
    });
    if (isProbeFailure(reflect)) continue;

    // Access-Control-Allow-Methods／Allow-Headers 依規格只出現在 OPTIONS 回應上
    // （express 的 cors 套件也是這樣實作）。所以要看預檢就得真的送一次 OPTIONS——
    // 從 GET 回應去讀那兩個標頭永遠是 null，而把 null 寫進報告會被讀成
    //「預檢查過、沒放行任何方法」，實際上是根本沒測。
    const preflight = await tryProbe(url, {
      surface,
      timeoutMs,
      method: "OPTIONS",
      headers: {
        origin: EVIL_ORIGIN,
        "access-control-request-method": "GET",
        "access-control-request-headers": "content-type",
      },
      followRedirects: 0,
      maxBodyBytes: 4 * 1024,
    });

    const obs: CorsObservation = {
      allowOrigin: reflect.headers.get("access-control-allow-origin"),
      allowCredentials: reflect.headers.get("access-control-allow-credentials"),
      allowMethods: isProbeFailure(preflight) ? null : preflight.headers.get("access-control-allow-methods"),
      allowHeaders: isProbeFailure(preflight) ? null : preflight.headers.get("access-control-allow-headers"),
    };

    facts[path] = {
      ...obs,
      // 「沒觀測到」與「觀測到沒有」必須分得開，連在 facts 裡也一樣。
      preflight: isProbeFailure(preflight) ? `未觀測（${preflight.error}）` : `HTTP ${preflight.status}`,
    };

    if (!obs.allowOrigin) continue; // 完全沒有 CORS 標頭＝同源限制生效，這是最安全的預設
    findings.push(...analyzeCors(obs, { surface: surface.id, where: url, sentOrigin: EVIL_ORIGIN }));
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
