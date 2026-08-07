/**
 * 認證閘門檢測——「沒登入的人能拿到什麼」。
 *
 * 這是整套系統裡最有價值的一組檢查：標頭沒設好只是體質差，
 * 但受保護端點在未認證下回 200 是**現在就在外洩資料**。
 *
 * 端點清單對照 ai_os server/index.ts 的實際掛載點，不是通則猜測。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Severity, Surface } from "../core/types.js";

export interface GuardedEndpoint {
  path: string;
  method?: "GET" | "POST";
  label: string;
  /** 未認證時被視為「有正確擋下來」的狀態碼。 */
  expect: number[];
  /** 真的漏了的話有多嚴重。 */
  severity: Severity;
  /** 漏了會外洩什麼——寫進報告，讓人知道為什麼要現在修。 */
  exposes: string;
  body?: string;
  headers?: Record<string, string>;
}

/** 隨機但格式合法的 UUID：用真實存在的 id 才測得出 IDOR，但未認證階段只要看「有沒有先擋」。 */
const PROBE_UUID = "00000000-0000-4000-8000-000000000000";

export const GUARDED_ENDPOINTS: GuardedEndpoint[] = [
  {
    path: "/api/selftest",
    label: "開發者自我診斷",
    expect: [401, 403, 404],
    severity: "high",
    exposes: "生成模式、認證模式、內部組態與近期錯誤樣本——攻擊者用來規劃下一步的偵察資料。",
  },
  {
    path: "/api/v1/databases",
    label: "資料庫列表 REST API",
    expect: [401, 403],
    severity: "critical",
    exposes: "團隊的資料庫清單與結構。",
  },
  {
    path: `/api/v1/databases/${PROBE_UUID}/rows`,
    label: "資料庫資料列 REST API",
    expect: [401, 403, 404],
    severity: "critical",
    exposes: "資料庫內的實際資料列內容。",
  },
  {
    path: "/api/me/export",
    label: "個人資料匯出",
    expect: [401, 403],
    severity: "critical",
    exposes: "使用者的完整個人資料與專案內容匯出檔。",
  },
  {
    path: "/api/admin/backup/assets.tar.gz",
    label: "素材備份下載",
    expect: [401, 403, 404],
    severity: "critical",
    exposes: "整站素材的備份壓縮檔。",
  },
  {
    path: `/api/export/${PROBE_UUID}`,
    label: "專案匯出",
    expect: [401, 403, 404],
    severity: "high",
    exposes: "任意專案的完整匯出內容。",
  },
  {
    path: `/api/assets/${PROBE_UUID}/file`,
    label: "素材檔案",
    expect: [401, 403, 404],
    severity: "high",
    exposes: "上傳的素材原始檔（圖片、影音、文件）。",
  },
  {
    path: `/api/databases/${PROBE_UUID}/rows.csv`,
    label: "資料庫 CSV 匯出",
    expect: [401, 403, 404],
    severity: "critical",
    exposes: "資料庫全表以 CSV 形式下載。",
  },
  {
    path: "/api/trpc/system.storageStatus",
    label: "tRPC 儲存層狀態",
    expect: [200, 401, 403], // tRPC 慣例：錯誤也回 200 外殼，內容才是 UNAUTHORIZED，由下方內容判定
    severity: "medium",
    exposes: "儲存層持久性判定、備份時間與未落地素材統計。",
  },
  {
    path: "/api/trpc/admin.listUsers",
    label: "tRPC 使用者列表",
    expect: [200, 401, 403, 404],
    severity: "critical",
    exposes: "全站使用者名單與電子郵件。",
  },
];

/**
 * tRPC 即使未授權也回 HTTP 200，錯誤在 body 裡。
 * 所以判斷「有沒有擋下來」必須看內容：有 `error` 且 code 是 UNAUTHORIZED/FORBIDDEN 才算擋住。
 */
export function trpcBlocked(body: string): boolean {
  try {
    const parsed: unknown = JSON.parse(body);
    const entries = Array.isArray(parsed) ? parsed : [parsed];
    return entries.some((entry) => {
      const err = (entry as { error?: { data?: { code?: string }; message?: string } })?.error;
      if (!err) return false;
      const code = err.data?.code ?? "";
      return /UNAUTHORIZED|FORBIDDEN/i.test(code) || /登入|未授權/.test(err.message ?? "");
    });
  } catch {
    return false;
  }
}

/** 回應看起來像不像「有實際資料」——用來分辨真外洩與空殼 200。 */
export function looksLikeData(body: string, contentType: string): boolean {
  if (/application\/(zip|gzip|octet-stream)|text\/csv/i.test(contentType)) return body.length > 0;
  try {
    const parsed: unknown = JSON.parse(body);
    if (Array.isArray(parsed)) return parsed.length > 0;
    if (parsed && typeof parsed === "object") {
      const obj = parsed as Record<string, unknown>;
      if ("error" in obj) return false;
      return Object.keys(obj).length > 0;
    }
    return false;
  } catch {
    return body.trim().length > 0;
  }
}

export async function checkAuthGate(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "auth-gate", category: "security" as const, surface: surface.id };
  const observed: Record<string, string> = {};

  for (const endpoint of GUARDED_ENDPOINTS) {
    const url = join(surface.origin, endpoint.path);
    const res = await tryProbe(url, {
      surface,
      timeoutMs,
      method: endpoint.method ?? "GET",
      body: endpoint.body,
      headers: endpoint.headers,
      followRedirects: 0,
      maxBodyBytes: 64 * 1024,
    });

    if (isProbeFailure(res)) {
      observed[endpoint.path] = `連線失敗：${res.error}`;
      continue;
    }

    const contentType = res.headers.get("content-type") ?? "";
    const isTrpc = endpoint.path.startsWith("/api/trpc/");
    observed[endpoint.path] = `HTTP ${res.status}`;

    // 導向到登入頁也算有擋下來（SPA 的 Express 路由多半直接回 401，但代理層可能改成 302）。
    const redirectedToLogin =
      res.status >= 300 && res.status < 400 && /login|signin/i.test(res.headers.get("location") ?? "");
    if (redirectedToLogin) continue;

    if (isTrpc) {
      if (res.status === 200 && !trpcBlocked(res.body)) {
        findings.push(
          finding({
            ...base,
            id: `auth-gate.trpc.${endpoint.path}`,
            severity: endpoint.severity,
            title: `未認證即可呼叫 ${endpoint.label}`,
            detail: `這個 tRPC 程序在沒有登入的情況下回傳了結果，而非 UNAUTHORIZED。外洩內容：${endpoint.exposes}`,
            remediation: "把該程序改用 authedProcedure（或更嚴格的 adminProcedure），不要用 publicProcedure。",
            evidence: res.body.slice(0, 300),
            where: url,
          }),
        );
      }
      continue;
    }

    if (endpoint.expect.includes(res.status)) continue;

    if (res.status === 200) {
      const hasData = looksLikeData(res.body, contentType);
      findings.push(
        finding({
          ...base,
          id: `auth-gate.open.${endpoint.path}`,
          severity: hasData ? endpoint.severity : "medium",
          title: `未認證即可存取 ${endpoint.label}（HTTP 200）`,
          detail: hasData
            ? `端點在沒有任何憑證下回傳了內容。外洩內容：${endpoint.exposes}`
            : `端點在沒有憑證下回 200（內容為空）。即使目前沒吐資料，缺少認證閘門本身就是缺陷——換一個存在的識別碼就可能拿到資料。`,
          remediation: "在該路由前掛上認證中介層（requireUsableSession 或等價檢查），未登入一律回 401。",
          evidence: `content-type: ${contentType}\n${res.body.slice(0, 200)}`,
          where: url,
        }),
      );
    } else if (res.status >= 500) {
      findings.push(
        finding({
          ...base,
          id: `auth-gate.error.${endpoint.path}`,
          severity: "medium",
          title: `${endpoint.label} 在未認證請求下回 HTTP ${res.status}`,
          detail:
            "受保護端點應該乾脆地回 401，回 5xx 代表請求已經進到業務邏輯才爆掉——認證檢查的位置太後面，而且錯誤訊息可能洩漏內部細節。",
          remediation: "把認證檢查移到路由最前面，未登入直接回 401，不要進入後續處理。",
          evidence: res.body.slice(0, 200),
          where: url,
        }),
      );
    }
  }

  facts.observed = observed;
  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
