/**
 * Cookie 屬性稽核。
 *
 * 重點在**分辨會話 Cookie 與一般偏好 Cookie**：主題色少了 HttpOnly 不痛不癢，
 * 登入憑證少了 HttpOnly 等於 XSS 一旦成立就直接被接管帳號。一律同級告警只會讓人關掉告警。
 */
import { finding } from "../core/findings.js";
import type { Finding, SurfaceId } from "../core/types.js";

export interface ParsedCookie {
  name: string;
  value: string;
  attributes: Map<string, string>;
}

export function parseSetCookie(raw: string): ParsedCookie | null {
  const parts = raw.split(";");
  const first = parts.shift();
  if (!first) return null;
  const eq = first.indexOf("=");
  if (eq < 0) return null;
  const name = first.slice(0, eq).trim();
  if (!name) return null;
  const attributes = new Map<string, string>();
  for (const part of parts) {
    const [k, ...rest] = part.split("=");
    if (!k) continue;
    attributes.set(k.trim().toLowerCase(), rest.join("=").trim());
  }
  return { name, value: first.slice(eq + 1).trim(), attributes };
}

/** 名字看起來像會話／憑證的 Cookie。命名慣例涵蓋 express-session、自建 sid、JWT。 */
const SESSION_NAME = /(^|[._-])(sid|sess|session|token|auth|jwt|csrf|refresh)([._-]|$)/i;

export function looksLikeSessionCookie(name: string): boolean {
  return SESSION_NAME.test(name);
}

export interface CookieContext {
  surface: SurfaceId | "all";
  where: string;
  https: boolean;
}

export function analyzeCookies(setCookies: string[], ctx: CookieContext): Finding[] {
  const base = { check: "cookies", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  for (const raw of setCookies) {
    const cookie = parseSetCookie(raw);
    if (!cookie) continue;
    const isSession = looksLikeSessionCookie(cookie.name);
    const attrs = cookie.attributes;
    // 屬性值本身可能含憑證，證據只保留名稱與屬性清單。
    const evidence = `${cookie.name}; ${[...attrs.keys()].join("; ") || "（無屬性）"}`;

    if (!attrs.has("httponly")) {
      out.push(
        finding({
          ...base,
          id: `cookies.httponly.${cookie.name}`,
          severity: isSession ? "critical" : "low",
          title: `Cookie ${cookie.name} 缺少 HttpOnly`,
          detail: isSession
            ? "這看起來是會話憑證，卻能被 JavaScript 讀取。站上任何一處 XSS（含第三方套件被污染）都能直接竊取並冒用登入身分。"
            : "此 Cookie 可被 JavaScript 讀取；若日後改放敏感內容會直接暴露。",
          remediation: "設定 Cookie 時加上 HttpOnly。前端若需要判斷登入狀態，改用一個不含憑證的旗標 Cookie 或 API。",
          evidence,
        }),
      );
    }

    if (!attrs.has("secure") && ctx.https) {
      out.push(
        finding({
          ...base,
          id: `cookies.secure.${cookie.name}`,
          severity: isSession ? "high" : "low",
          title: `Cookie ${cookie.name} 缺少 Secure`,
          detail:
            "沒有 Secure 的 Cookie 會在任何 http 請求上以明文送出（例如使用者手打網址、舊書籤、被降級的連線）。",
          remediation: "設定 Cookie 時加上 Secure。",
          evidence,
        }),
      );
    }

    const sameSite = attrs.get("samesite")?.toLowerCase();
    if (!sameSite) {
      out.push(
        finding({
          ...base,
          id: `cookies.samesite.${cookie.name}`,
          severity: isSession ? "medium" : "info",
          title: `Cookie ${cookie.name} 未指定 SameSite`,
          detail:
            "瀏覽器雖多半預設 Lax，但各家實作與版本不一；明確指定才能穩定擋下跨站請求偽造（CSRF）。",
          remediation: "會話 Cookie 設 SameSite=Lax（或 Strict）。",
          evidence,
        }),
      );
    } else if (sameSite === "none" && !attrs.has("secure")) {
      out.push(
        finding({
          ...base,
          id: `cookies.samesite-none-insecure.${cookie.name}`,
          severity: "high",
          title: `Cookie ${cookie.name} 為 SameSite=None 但沒有 Secure`,
          detail: "這組合會被現代瀏覽器直接拒收，功能會壞掉；在舊瀏覽器上則是完全開放的跨站 Cookie。",
          remediation: "確實需要跨站送出時，SameSite=None 必須搭配 Secure；否則改用 Lax。",
          evidence,
        }),
      );
    } else if (sameSite === "none" && isSession) {
      out.push(
        finding({
          ...base,
          id: `cookies.samesite-none.${cookie.name}`,
          severity: "medium",
          title: `會話 Cookie ${cookie.name} 為 SameSite=None`,
          detail: "會話憑證會隨跨站請求送出，CSRF 防線只剩應用層的 token 檢查。",
          remediation: "除非確有跨站嵌入需求，改為 SameSite=Lax。",
          evidence,
        }),
      );
    }

    // 作用域過寬：Domain 設到父網域，等於把 Cookie 分享給所有子網域（含預覽站）。
    const domain = attrs.get("domain");
    if (domain && isSession && domain.split(".").filter(Boolean).length <= 2) {
      out.push(
        finding({
          ...base,
          id: `cookies.domain-scope.${cookie.name}`,
          severity: "medium",
          title: `會話 Cookie ${cookie.name} 的 Domain 涵蓋整個父網域（${domain}）`,
          detail: "所有子網域（含預覽站、第三方託管的子網域）都拿得到這個憑證，攻擊面被放大到整組網域。",
          remediation: "移除 Domain 屬性讓它綁定單一 host，或縮到實際使用的完整網域。",
          evidence,
        }),
      );
    }
  }

  return out;
}
