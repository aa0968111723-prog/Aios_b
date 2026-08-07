/**
 * CSP 指令分析。
 *
 * 純函式：吃 header 字串，吐 Finding。所有判定都能離線單元測試——
 * 資安規則最容易寫錯，而寫錯的規則會製造假綠燈，比沒檢查更危險。
 *
 * 對 ai_os 的已知脈絡（server/index.ts）：
 * - style-src 放行 'unsafe-inline' 是 React inline style 的既定取捨 → 只報 low 並註明。
 * - img/media 放行 https: 是為了 fal CDN 成品 → 不報。
 * 這些「已知且有理由」的放行必須被降噪，否則報告會被雜訊淹沒。
 */
import { finding } from "../core/findings.js";
import type { Finding, SurfaceId } from "../core/types.js";

export type CspDirectives = Map<string, string[]>;

/** 解析 CSP 字串成 `指令 → 來源清單`。指令名一律小寫；重複指令以第一次出現為準（瀏覽器行為）。 */
export function parseCsp(header: string): CspDirectives {
  const out: CspDirectives = new Map();
  for (const chunk of header.split(";")) {
    const parts = chunk.trim().split(/\s+/).filter(Boolean);
    const name = parts.shift()?.toLowerCase();
    if (!name) continue;
    if (out.has(name)) continue;
    out.set(name, parts);
  }
  return out;
}

/** 取指令值，缺的話沿用 default-src（CSP 的 fallback 規則）。 */
function effective(directives: CspDirectives, name: string): { sources: string[]; inherited: boolean } | null {
  const own = directives.get(name);
  if (own) return { sources: own, inherited: false };
  const fallback = directives.get("default-src");
  if (fallback) return { sources: fallback, inherited: true };
  return null;
}

const WILDCARD_SCHEMES = new Set(["*", "https:", "http:", "data:", "blob:"]);

export interface CspContext {
  surface: SurfaceId | "all";
  where: string;
  check?: string;
}

/**
 * 分析 CSP。`header` 為 null 代表整個標頭不存在。
 */
export function analyzeCsp(header: string | null, ctx: CspContext): Finding[] {
  const check = ctx.check ?? "csp";
  const base = { check, category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  if (!header || header.trim() === "") {
    return [
      finding({
        ...base,
        id: "csp.missing",
        severity: "high",
        title: "缺少 Content-Security-Policy",
        detail:
          "回應沒有 CSP 標頭。任何被注入的腳本（第三方套件被入侵、留言欄位的 XSS）都能直接執行並把登入 Cookie／專案內容送去外部網域。",
        remediation:
          "在 helmet 設定 contentSecurityPolicy，至少指定 default-src 'self'、script-src 'self'、object-src 'none'、base-uri 'self'、frame-ancestors 'none'。",
      }),
    ];
  }

  const directives = parseCsp(header);
  const evidence = header.length > 400 ? `${header.slice(0, 400)}…` : header;

  if (!directives.has("default-src")) {
    out.push(
      finding({
        ...base,
        id: "csp.no-default-src",
        severity: "medium",
        title: "CSP 沒有 default-src",
        detail:
          "沒有 default-src 就沒有兜底：任何未明確列出的資源類型（worker、manifest、font…）完全不受限制。",
        remediation: "加上 default-src 'self'，再針對確實需要放寬的類型個別開。",
        evidence,
      }),
    );
  }

  const script = effective(directives, "script-src");
  if (!script) {
    out.push(
      finding({
        ...base,
        id: "csp.script-src.unrestricted",
        severity: "high",
        title: "CSP 未限制 script-src",
        detail: "既沒有 script-src 也沒有 default-src，腳本來源等於完全開放，CSP 對 XSS 沒有任何防護價值。",
        remediation: "加上 script-src 'self'（成品若走 CDN 就列出該網域，不要用 https:）。",
        evidence,
      }),
    );
  } else {
    if (script.sources.includes("'unsafe-eval'")) {
      out.push(
        finding({
          ...base,
          id: "csp.script-src.unsafe-eval",
          severity: "high",
          title: "script-src 允許 'unsafe-eval'",
          detail:
            "'unsafe-eval' 讓 eval／new Function 可用，攻擊者能把任意字串變成可執行程式碼，等於繞過 CSP 的核心防線。",
          remediation: "移除 'unsafe-eval'；若是某套件需要，改用其預編譯版本或改用支援 CSP 的替代品。",
          evidence,
        }),
      );
    }
    if (script.sources.includes("'unsafe-inline'") && !script.sources.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"))) {
      out.push(
        finding({
          ...base,
          id: "csp.script-src.unsafe-inline",
          severity: "high",
          title: "script-src 允許 'unsafe-inline'（且無 nonce／hash）",
          detail:
            "允許 inline 腳本時，注入的 <script> 會直接執行——這是 CSP 最主要要擋的攻擊，等於防護被關掉。",
          remediation: "改用 nonce 或 hash 放行必要的 inline 腳本，並移除 'unsafe-inline'。",
          evidence,
        }),
      );
    }
    const wildcards = script.sources.filter((s) => WILDCARD_SCHEMES.has(s));
    if (wildcards.length > 0) {
      out.push(
        finding({
          ...base,
          id: "csp.script-src.wildcard",
          severity: wildcards.includes("*") ? "high" : "medium",
          title: `script-src 含過寬來源（${wildcards.join(" ")}）`,
          detail:
            "以 scheme 或 * 放行腳本，等於信任整個網際網路上任何一台伺服器；只要有一個被放行的來源被入侵，站台就跟著淪陷。",
          remediation: "改列具體網域（例如成品 CDN 的完整 host），移除 * 與裸 scheme。",
          evidence,
        }),
      );
    }
    if (script.inherited) {
      out.push(
        finding({
          ...base,
          id: "csp.script-src.inherited",
          severity: "info",
          title: "script-src 由 default-src 繼承",
          detail: "腳本規則目前跟其他資源共用同一份來源清單；日後放寬 default-src（例如為了圖片）會連帶放寬腳本。",
          remediation: "明確寫出 script-src，讓它與圖片／媒體的放寬互不牽連。",
          evidence,
        }),
      );
    }
  }

  const objectSrc = effective(directives, "object-src");
  if (!objectSrc || !objectSrc.sources.includes("'none'")) {
    out.push(
      finding({
        ...base,
        id: "csp.object-src",
        severity: "medium",
        title: "object-src 未設為 'none'",
        detail: "<object>／<embed> 可載入外掛內容並成為腳本執行的旁路，站台並不需要這個能力。",
        remediation: "加上 object-src 'none'。",
        evidence,
      }),
    );
  }

  if (!directives.has("base-uri")) {
    out.push(
      finding({
        ...base,
        id: "csp.base-uri",
        severity: "medium",
        title: "CSP 沒有 base-uri",
        detail:
          "注入的 <base href> 能把頁面上所有相對路徑資源（含腳本）改指到攻擊者的網域，而 script-src 'self' 擋不住這招。",
        remediation: "加上 base-uri 'self'。",
        evidence,
      }),
    );
  }

  const frameAncestors = directives.get("frame-ancestors");
  if (!frameAncestors) {
    out.push(
      finding({
        ...base,
        id: "csp.frame-ancestors",
        severity: "medium",
        title: "CSP 沒有 frame-ancestors",
        detail:
          "沒限制誰能把站台嵌進 iframe 就有點擊劫持風險：使用者以為在點別的東西，實際點到 Aios 裡的刪除或授權按鈕。frame-ancestors 不吃 default-src 的兜底。",
        remediation: "加上 frame-ancestors 'none'（或列出允許嵌入的自家網域）。",
        evidence,
      }),
    );
  } else if (frameAncestors.some((s) => s === "*" || s === "https:")) {
    out.push(
      finding({
        ...base,
        id: "csp.frame-ancestors.wildcard",
        severity: "medium",
        title: "frame-ancestors 允許任意網站嵌入",
        detail: "任何網站都能把 Aios 嵌進 iframe，點擊劫持完全成立。",
        remediation: "改成 frame-ancestors 'none' 或明確列出自家網域。",
        evidence,
      }),
    );
  }

  const style = effective(directives, "style-src");
  if (style && style.sources.includes("'unsafe-inline'")) {
    out.push(
      finding({
        ...base,
        id: "csp.style-src.unsafe-inline",
        severity: "low",
        title: "style-src 允許 'unsafe-inline'（React inline style 的已知取捨）",
        detail:
          "inline 樣式可被用來做版面詐騙與資料外洩旁路（例如以背景圖 URL 帶出內容），但風險遠低於腳本。ai_os 目前靠它渲染 React inline style。",
        remediation: "長期解法是改用 CSS 變數＋class，並以 nonce 放行必要的 style 標籤；短期可接受，但要記錄為已知取捨。",
        evidence,
      }),
    );
  }

  const connect = effective(directives, "connect-src");
  if (connect && connect.sources.includes("*")) {
    out.push(
      finding({
        ...base,
        id: "csp.connect-src.wildcard",
        severity: "low",
        title: "connect-src 為萬用字元",
        detail: "XSS 一旦成立，資料可被送往任意網域；收斂 connect-src 能把外洩管道縮小。",
        remediation: "列出實際會連的網域（自家 API、fal、即時協作 WS），移除 *。",
        evidence,
      }),
    );
  }

  if (directives.has("report-uri") || directives.has("report-to")) {
    out.push(
      finding({
        ...base,
        id: "csp.reporting.present",
        severity: "info",
        title: "CSP 已設定違規回報",
        detail: "有回報端點，代表線上真實違規看得見——這是好事，記錄下來供對照。",
        remediation: "無需處理；確認回報端點仍在收資料即可。",
        evidence,
      }),
    );
  } else {
    out.push(
      finding({
        ...base,
        id: "csp.reporting.missing",
        severity: "info",
        title: "CSP 未設定違規回報",
        detail: "沒有 report-to／report-uri，線上被 CSP 擋掉的資源不會有任何紀錄，收緊政策時難以判斷影響。",
        remediation: "設定 report-to 端點，先以 Content-Security-Policy-Report-Only 觀察再收緊。",
        evidence,
      }),
    );
  }

  return out;
}
