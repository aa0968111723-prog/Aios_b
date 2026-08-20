/**
 * HTTP 探針。
 *
 * 為什麼不直接用 fetch：偵測資安問題時，**重導向本身就是證據**（http→https 有沒有轉、
 * 401 有沒有變成 302 到登入頁）。fetch 預設 follow 會把這些吃掉，所以這裡一律
 * `redirect: "manual"`，要不要跟隨由呼叫端決定並記錄整條鏈。
 */
import type { Surface } from "./types.js";

export interface ProbeResponse {
  url: string;
  status: number;
  ok: boolean;
  headers: Headers;
  /** 依序記錄的重導向鏈（含最終落點）。 */
  redirects: Array<{ from: string; to: string; status: number }>;
  /** 回應內文（只讀前 `maxBodyBytes`，避免把成品檔整包拉進記憶體）。 */
  body: string;
  truncated: boolean;
  durationMs: number;
  /**
   * **整條重導向鏈上**的 Set-Cookie 原始值（依序）。
   *
   * 不是只有最終回應：express-session 的預設行為就是在第一個回應上種 cookie，
   * 而那個回應常常正是 302。只取最終落點的話，站台真正的會話 Cookie 完全不會被稽核——
   * 檢查照樣完成、照樣零發現。
   *
   * Headers.get 會把多個 cookie 併成一行導致無法解析，故走 getSetCookie。
   */
  setCookies: string[];
}

export interface ProbeOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  /** 最多跟隨幾次重導向；0＝不跟隨（預設，保留原始 3xx 供判定）。 */
  followRedirects?: number;
  maxBodyBytes?: number;
  surface?: Surface;
}

export class ProbeError extends Error {
  readonly url: string;

  constructor(message: string, url: string, cause?: unknown) {
    // cause 走 Error 的標準選項，別用參數屬性遮蔽基底類別的同名成員。
    super(message, { cause });
    this.name = "ProbeError";
    this.url = url;
  }
}

const DEFAULT_MAX_BODY = 512 * 1024;

/** getSetCookie 在 Node 20+ 的 undici Headers 上可用；舊環境退回單行值。 */
function readSetCookies(headers: Headers): string[] {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
  return [headers.get("set-cookie")].filter(Boolean) as string[];
}

/** 把 surface 人格（UA、殼層標頭）疊到請求上。呼叫端明確給的標頭優先。 */
function headersFor(options: ProbeOptions): Record<string, string> {
  const base: Record<string, string> = {};
  if (options.surface) {
    base["user-agent"] = options.surface.userAgent;
    Object.assign(base, options.surface.extraHeaders ?? {});
  }
  return { ...base, ...(options.headers ?? {}) };
}

async function readBody(res: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  if (!res.body) return { body: "", truncated: false };
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  try {
    while (size < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      size += value.byteLength;
    }
    // 還沒讀完就達到上限：標記截斷並放棄剩餘串流，別讓大檔拖住整輪掃描。
    if (size >= maxBytes) {
      truncated = true;
      await reader.cancel().catch(() => {});
    }
  } catch {
    // 讀到一半斷線：已讀到的部分仍有分析價值（例如 CSP meta 標籤就在 head）。
    truncated = true;
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) {
    merged.set(c, offset);
    offset += c.byteLength;
  }
  return { body: new TextDecoder().decode(merged), truncated };
}

/**
 * 送一個請求並蒐集所有判定需要的原始素材。
 *
 * 逾時用 AbortSignal.timeout：目標站掛掉時（資安掃描最常見的情境）不能讓整輪卡死。
 */
export async function probe(url: string, options: ProbeOptions = {}): Promise<ProbeResponse> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  const maxBody = options.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const maxHops = options.followRedirects ?? 0;
  const redirects: ProbeResponse["redirects"] = [];

  let current = url;
  let hops = 0;
  const startedAt = Date.now();
  const setCookies: string[] = [];

  for (;;) {
    let res: Response;
    try {
      res = await fetch(current, {
        method: options.method ?? "GET",
        headers: headersFor(options),
        body: options.body,
        redirect: "manual",
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      throw new ProbeError(`無法連線：${reason}`, current, err);
    }

    const location = res.headers.get("location");
    const isRedirect = res.status >= 300 && res.status < 400 && location;

    if (isRedirect && hops < maxHops) {
      const next = new URL(location, current).toString();
      redirects.push({ from: current, to: next, status: res.status });
      // 這一跳種下的 Cookie 要留著——會話 Cookie 常常就種在重導向那個回應上。
      setCookies.push(...readSetCookies(res.headers));
      // 讀掉 body 避免連線洩漏；重導向的 body 對判定沒有價值。
      await res.body?.cancel().catch(() => {});
      current = next;
      hops += 1;
      continue;
    }

    if (isRedirect) redirects.push({ from: current, to: new URL(location, current).toString(), status: res.status });

    const { body, truncated } = await readBody(res, maxBody);
    return {
      url: current,
      status: res.status,
      ok: res.ok,
      headers: res.headers,
      redirects,
      body,
      truncated,
      durationMs: Date.now() - startedAt,
      setCookies: [...setCookies, ...readSetCookies(res.headers)],
    };
  }
}

/** `probe` 但不丟例外——連不上時回 null，讓「站台不可達」由呼叫端決定嚴重度。 */
export async function tryProbe(url: string, options: ProbeOptions = {}): Promise<ProbeResponse | { error: string }> {
  try {
    return await probe(url, options);
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) };
  }
}

export function isProbeFailure(value: ProbeResponse | { error: string }): value is { error: string } {
  return "error" in value;
}

/** 安全地把路徑接到站台根上；`join("https://a.b/", "/api/x")` → `https://a.b/api/x` */
export function join(origin: string, path: string): string {
  return new URL(path, origin.endsWith("/") ? origin : `${origin}/`).toString();
}

/**
 * 這份回應到底是不是**應用**送出來的？
 *
 * 為什麼需要這個判斷：中間的代理／閘道（企業 proxy、WAF、平台的 502 頁）會攔下請求並
 * 自己回一個極簡回應。那種回應當然沒有 CSP、沒有 HSTS、沒有 nosniff——照常分析下去，
 * 報告會出現一整排「缺少安全標頭」，讀者以為站台裸奔，實際上根本沒碰到站台。
 * 這是掃描器最嚴重的失準方式：**把「沒測到」講成「測到很糟」**。
 *
 * 判準：狀態碼是錯誤、且內容不像應用回應（沒有 SPA 標記，也沒有應用的 JSON）。
 */
export function looksLikeGatewayInterception(input: {
  status: number;
  body: string;
  contentType: string;
}): boolean {
  if (input.status < 400) return false;
  // 應用自己的錯誤頁會帶 SPA 外殼或應用的 JSON 錯誤格式，那是真實觀測，要照常分析。
  if (/<div\s+id=["']root["']|<script[^>]+type=["']module["']/i.test(input.body)) return false;
  if (/application\/json/i.test(input.contentType) && /"(error|ok|code)"\s*:/.test(input.body)) return false;
  return true;
}

/** 解析 JSON，失敗回 null——目標回錯東西是常態，不該讓檢查器崩潰。 */
export function parseJson<T = unknown>(body: string): T | null {
  try {
    return JSON.parse(body) as T;
  } catch {
    return null;
  }
}
