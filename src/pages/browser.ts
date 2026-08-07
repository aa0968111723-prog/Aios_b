/**
 * 瀏覽器層的薄封裝。
 *
 * playwright 是 optionalDependency：只做資安／健康掃描的人不必裝 400MB 的瀏覽器。
 * 因此這裡用動態 import，缺套件時回傳明確的「跳過原因」，而不是讓整輪炸掉。
 * 「跳過」與「通過」在報告裡是不同狀態——這點很重要，否則沒裝瀏覽器會被當成頁面全綠。
 */
import type { Surface } from "../core/types.js";

// playwright 型別在未安裝時不存在，故以結構型別描述我們實際用到的部分。
export interface PageLike {
  goto(url: string, options?: Record<string, unknown>): Promise<unknown>;
  evaluate<T>(fn: (...args: never[]) => T, arg?: unknown): Promise<T>;
  waitForFunction(fn: (...args: never[]) => unknown, arg?: unknown, options?: Record<string, unknown>): Promise<unknown>;
  locator(selector: string): {
    waitFor(options?: Record<string, unknown>): Promise<void>;
    fill(value: string): Promise<void>;
    click(options?: Record<string, unknown>): Promise<void>;
    isVisible(): Promise<boolean>;
    count(): Promise<number>;
  };
  screenshot(options: Record<string, unknown>): Promise<unknown>;
  on(event: string, handler: (payload: never) => void): void;
  title(): Promise<string>;
  close(): Promise<void>;
}

export interface BrowserSession {
  newPage(surface: Surface): Promise<PageLike>;
  close(): Promise<void>;
  /** 供 a11y 模組判斷 axe 能不能用。 */
  axeAvailable: boolean;
}

export type BrowserLaunch = { ok: true; session: BrowserSession } | { ok: false; reason: string };

/**
 * 啟動 Chromium 並回傳可依 surface 開分頁的工作階段。
 *
 * 每個 surface 用**獨立的 browser context**：UA、視窗、行動裝置模擬要分開，
 * 而且 Cookie 也必須隔離——三端共用 context 會讓「網頁登入後 App 端也自動已登入」，
 * 那是測試假象，真實使用者沒有這種好事。
 */
export async function launchBrowser(): Promise<BrowserLaunch> {
  let playwright: typeof import("playwright");
  try {
    playwright = await import("playwright");
  } catch {
    return {
      ok: false,
      reason: "未安裝 playwright。執行 `npm i` 後再跑 `npm run browsers:install` 即可啟用頁面測試。",
    };
  }

  let browser: Awaited<ReturnType<typeof playwright.chromium.launch>>;
  try {
    browser = await playwright.chromium.launch({
      args: ["--no-sandbox", "--disable-dev-shm-usage"], // CI 容器內必要
      // 允許指向映像檔裡既有的 Chromium。CI 映像常常預裝了瀏覽器，但版本編號與
      // playwright 期望的不同，硬要它自己下載既慢又可能因為離線而失敗。
      ...(process.env.SENTINEL_CHROMIUM_PATH ? { executablePath: process.env.SENTINEL_CHROMIUM_PATH } : {}),
    });
  } catch (err) {
    return {
      ok: false,
      reason:
        `Chromium 無法啟動：${err instanceof Error ? err.message.split("\n")[0] : String(err)}。` +
        "請執行 `npm run browsers:install`，或用 SENTINEL_CHROMIUM_PATH 指向已安裝的 Chromium 執行檔。",
    };
  }

  let axeAvailable = false;
  try {
    await import("@axe-core/playwright");
    axeAvailable = true;
  } catch {
    axeAvailable = false;
  }

  const contexts: Array<{ close(): Promise<void> }> = [];

  return {
    ok: true,
    session: {
      axeAvailable,
      async newPage(surface: Surface) {
        const context = await browser.newContext({
          userAgent: surface.userAgent,
          viewport: surface.viewport,
          isMobile: surface.isMobile,
          hasTouch: surface.isMobile,
          deviceScaleFactor: surface.isMobile ? 3 : 1,
          extraHTTPHeaders: surface.extraHeaders,
          // 忽略憑證錯誤會讓 TLS 問題悄悄溜過；寧可讓頁面測試失敗也不要隱藏。
          ignoreHTTPSErrors: false,
        });
        contexts.push(context);
        return (await context.newPage()) as unknown as PageLike;
      },
      async close() {
        for (const c of contexts) await c.close().catch(() => {});
        await browser.close().catch(() => {});
      },
    },
  };
}
