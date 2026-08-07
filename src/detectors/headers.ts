/**
 * 安全標頭稽核。
 *
 * 純分析函式（`analyzeSecurityHeaders`）吃一份 header map，網路層在 `runHeaderCheck`。
 * 分開的理由：規則要能單元測試，而測試不該依賴線上站當時的設定。
 */
import { finding } from "../core/findings.js";
import { analyzeCsp } from "./csp.js";
import type { Finding, SurfaceId } from "../core/types.js";

export interface HeaderContext {
  surface: SurfaceId | "all";
  where: string;
  /** 目標是否走 https。HSTS 只在 https 下有意義，本機 http 測試不該被誤報。 */
  https: boolean;
}

/** Headers → 小寫鍵的普通物件，方便測試直接餵字面量。 */
export function headersToObject(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  return out;
}

const HSTS_MIN_AGE = 15_552_000; // 180 天，主流掃描器與 preload 清單的門檻

export function analyzeSecurityHeaders(headers: Record<string, string>, ctx: HeaderContext): Finding[] {
  const base = { check: "security-headers", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];
  const get = (name: string) => headers[name.toLowerCase()] ?? null;

  // ── HSTS ────────────────────────────────────────────────────────────────
  const hsts = get("strict-transport-security");
  if (ctx.https) {
    if (!hsts) {
      out.push(
        finding({
          ...base,
          id: "headers.hsts.missing",
          severity: "high",
          title: "缺少 Strict-Transport-Security",
          detail:
            "沒有 HSTS 時，使用者在咖啡廳 Wi-Fi 上第一次以 http 連線就可能被降級攔截，登入 Cookie 以明文送出。App 與桌面殼層雖然寫死 https，但使用者仍會從瀏覽器分享連結進站。",
          remediation: "helmet 預設已含 HSTS；確認反向代理沒有把它剝掉，並設定 max-age≥15552000 與 includeSubDomains。",
        }),
      );
    } else {
      const maxAge = Number(/max-age=(\d+)/i.exec(hsts)?.[1] ?? "0");
      if (maxAge < HSTS_MIN_AGE) {
        out.push(
          finding({
            ...base,
            id: "headers.hsts.short",
            severity: "medium",
            title: `HSTS max-age 過短（${maxAge} 秒）`,
            detail: "有效期太短時，久未造訪的裝置會退回不受保護的狀態，降級攻擊的窗口重新打開。",
            remediation: "把 max-age 提高到至少 15552000（180 天）。",
            evidence: hsts,
          }),
        );
      }
      if (!/includeSubDomains/i.test(hsts)) {
        out.push(
          finding({
            ...base,
            id: "headers.hsts.no-subdomains",
            severity: "low",
            title: "HSTS 未含 includeSubDomains",
            detail: "子網域（預覽站、附件站）不受 HSTS 保護時，可被用來對主站的 Cookie 動手腳。",
            remediation: "在 HSTS 值加上 includeSubDomains（先確認所有子網域都已支援 https）。",
            evidence: hsts,
          }),
        );
      }
    }
  }

  // ── MIME 嗅探 ───────────────────────────────────────────────────────────
  const nosniff = get("x-content-type-options");
  if (!nosniff || nosniff.toLowerCase() !== "nosniff") {
    out.push(
      finding({
        ...base,
        id: "headers.nosniff",
        severity: "medium",
        title: "缺少 X-Content-Type-Options: nosniff",
        detail:
          "瀏覽器會猜測回應型別；使用者上傳的素材若被猜成 HTML／JS 就會在站台網域下執行，變成儲存型 XSS。Aios 有大量上傳與生成成品，這條特別重要。",
        remediation: "確認 helmet 未被關閉，且靜態檔／素材端點也帶上此標頭。",
        evidence: nosniff ?? undefined,
      }),
    );
  }

  // ── 點擊劫持 ────────────────────────────────────────────────────────────
  const xfo = get("x-frame-options");
  const csp = get("content-security-policy");
  const hasFrameAncestors = csp ? /frame-ancestors/i.test(csp) : false;
  if (!xfo && !hasFrameAncestors) {
    out.push(
      finding({
        ...base,
        id: "headers.clickjacking",
        severity: "medium",
        title: "沒有任何防點擊劫持設定",
        detail: "X-Frame-Options 與 CSP frame-ancestors 都不存在，任意網站都能把 Aios 疊在自己的頁面上誘導誤點。",
        remediation: "設定 X-Frame-Options: DENY，並在 CSP 加 frame-ancestors 'none'（新舊瀏覽器都要顧）。",
      }),
    );
  } else if (xfo && !/^(DENY|SAMEORIGIN)$/i.test(xfo.trim())) {
    out.push(
      finding({
        ...base,
        id: "headers.xfo.invalid",
        severity: "low",
        title: `X-Frame-Options 值不是有效選項（${xfo}）`,
        detail: "ALLOW-FROM 等舊語法已被所有主流瀏覽器忽略，實際等於沒有設定。",
        remediation: "改用 DENY 或 SAMEORIGIN，跨站嵌入需求改由 CSP frame-ancestors 表達。",
        evidence: xfo,
      }),
    );
  }

  // ── Referrer 外洩 ───────────────────────────────────────────────────────
  const referrer = get("referrer-policy");
  if (!referrer) {
    out.push(
      finding({
        ...base,
        id: "headers.referrer-policy",
        severity: "low",
        title: "缺少 Referrer-Policy",
        detail:
          "使用者從 /p/<專案id> 點外部連結時，完整網址（含專案識別碼）會被送到對方伺服器的存取紀錄裡。",
        remediation: "設定 Referrer-Policy: strict-origin-when-cross-origin 或更嚴格的 no-referrer。",
      }),
    );
  } else if (/^unsafe-url$/i.test(referrer.trim())) {
    out.push(
      finding({
        ...base,
        id: "headers.referrer-policy.unsafe",
        severity: "medium",
        title: "Referrer-Policy 為 unsafe-url",
        detail: "會把完整網址（含路徑與查詢字串）送給任何外部網站，等於主動外洩內部識別碼。",
        remediation: "改為 strict-origin-when-cross-origin。",
        evidence: referrer,
      }),
    );
  }

  // ── 權限政策 ────────────────────────────────────────────────────────────
  if (!get("permissions-policy")) {
    out.push(
      finding({
        ...base,
        id: "headers.permissions-policy",
        severity: "low",
        title: "缺少 Permissions-Policy",
        detail:
          "未宣告時，被嵌入的第三方內容可要求相機、麥克風、地理位置等權限。App 端（WebView）的權限提示會直接以「Aios」的名義出現，使用者難以分辨來源。",
        remediation: "設定 Permissions-Policy，明確關閉站台用不到的能力，例如 camera=(), microphone=(), geolocation=()。",
      }),
    );
  }

  // ── 跨源隔離 ────────────────────────────────────────────────────────────
  if (!get("cross-origin-opener-policy")) {
    out.push(
      finding({
        ...base,
        id: "headers.coop",
        severity: "low",
        title: "缺少 Cross-Origin-Opener-Policy",
        detail: "以 window.open 開啟的跨源分頁仍能取得 window 參照，可用於 tabnabbing 與跨源側通道。",
        remediation: "設定 Cross-Origin-Opener-Policy: same-origin。",
      }),
    );
  }

  // ── 版本／技術棧洩漏 ────────────────────────────────────────────────────
  const poweredBy = get("x-powered-by");
  if (poweredBy) {
    out.push(
      finding({
        ...base,
        id: "headers.x-powered-by",
        severity: "low",
        title: `回應洩漏技術棧（X-Powered-By: ${poweredBy}）`,
        detail: "讓攻擊者省下指紋辨識的步驟，可直接挑對應版本的已知漏洞來試。",
        remediation: "在 Express 呼叫 app.disable('x-powered-by')（helmet 亦會處理）。",
        evidence: poweredBy,
      }),
    );
  }
  const server = get("server");
  if (server && /\d+\.\d+/.test(server)) {
    out.push(
      finding({
        ...base,
        id: "headers.server-version",
        severity: "low",
        title: `Server 標頭帶版本號（${server}）`,
        detail: "精確版本號讓攻擊者能直接比對該版本的已知漏洞清單。",
        remediation: "在反向代理設定移除或簡化 Server 標頭。",
        evidence: server,
      }),
    );
  }

  // ── 快取（含敏感內容的頁面不該被中介快取）─────────────────────────────
  const cacheControl = get("cache-control");
  if (cacheControl && /public/i.test(cacheControl) && !/max-age=0/i.test(cacheControl)) {
    out.push(
      finding({
        ...base,
        id: "headers.cache-public",
        severity: "info",
        title: "HTML 回應允許公用快取",
        detail: "若這個回應會因登入狀態而不同，公用快取可能把某位使用者的畫面發給另一位。",
        remediation: "登入後的回應應為 Cache-Control: private, no-store。",
        evidence: cacheControl,
      }),
    );
  }

  // CSP 交給專門的分析器（它有完整的指令級規則）
  out.push(...analyzeCsp(csp, { surface: ctx.surface, where: ctx.where, check: "security-headers" }));

  return out;
}
