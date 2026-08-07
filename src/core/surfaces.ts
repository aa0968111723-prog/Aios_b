/**
 * 三端 surface 定義。
 *
 * 事實依據（讀 ai_os 原始碼得到，不是猜的）：
 * - App：capacitor.config.ts 用 `server.url` 指向線上站，`appendUserAgent: "AiosApp/1.0"`，
 *   所以 App 端的請求 UA 尾巴一定帶 `AiosApp/1.0`——這是伺服器唯一能分辨 App 的訊號。
 * - 桌面：src-tauri/tauri.conf.json 的 main window `url` 也是同一個線上站，
 *   WebView 在 Linux/macOS 是 WebKit、Windows 是 WebView2，UA 會含 `Tauri`。
 *
 * 因此三端＝同一個站的三種載入方式。分開掃的價值在於：
 * 伺服器可能對不同 UA 給不同回應（壓縮、CSP、行動版分支），而**破口通常就藏在那個分支裡**。
 */
import type { Surface, SurfaceId } from "./types.js";

const CHROME = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

export const SURFACE_IDS: SurfaceId[] = ["web", "app", "desktop"];

/**
 * 建立三端 surface。
 *
 * 每端的 origin 可以各自覆寫（`AIOS_APP_TARGET` 等）：正式情境是三端指同一站，
 * 但發版期間 App／桌面可能被釘在舊版或 staging——那正是 build 漂移檢查要抓的東西。
 */
export function buildSurfaces(target: string, overrides: Partial<Record<SurfaceId, string>> = {}): Surface[] {
  const origin = (id: SurfaceId) => (overrides[id] || target).replace(/\/$/, "");

  return [
    {
      id: "web",
      label: "網站（瀏覽器）",
      origin: origin("web"),
      userAgent: CHROME,
      viewport: { width: 1280, height: 800 },
      isMobile: false,
    },
    {
      id: "app",
      label: "App（Capacitor Android 薄殼）",
      origin: origin("app"),
      userAgent:
        "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36 AiosApp/1.0",
      viewport: { width: 390, height: 844 },
      isMobile: true,
      // Capacitor WebView 以 https scheme 載入站台，Origin 與站同源。
      extraHeaders: { "sec-ch-ua-mobile": "?1" },
    },
    {
      id: "desktop",
      label: "桌面（Tauri WebView）",
      origin: origin("desktop"),
      userAgent:
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Tauri/2.0",
      viewport: { width: 1280, height: 820 },
      isMobile: false,
    },
  ];
}

export function pickSurfaces(all: Surface[], ids: SurfaceId[] | null): Surface[] {
  if (!ids || ids.length === 0) return all;
  const wanted = new Set(ids);
  return all.filter((s) => wanted.has(s.id));
}

export function isSurfaceId(value: string): value is SurfaceId {
  return (SURFACE_IDS as string[]).includes(value);
}
