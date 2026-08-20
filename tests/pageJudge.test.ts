import { describe, expect, it } from "vitest";
import { judgePage, type PageObservation } from "../src/pages/pageTest.js";
import { buildSurfaces } from "../src/core/surfaces.js";
import type { RouteSpec } from "../src/pages/routes.js";

const [web, app] = buildSurfaces("https://ai-os-app.zeabur.app");
const publicRoute: RouteSpec = { path: "/login", label: "登入", requiresAuth: false };
const protectedRoute: RouteSpec = { path: "/admin", label: "團隊管理", requiresAuth: true };

/** 一切正常的觀測值，各測試只覆寫要驗的欄位。 */
const healthy = (over: Partial<PageObservation> = {}): PageObservation => ({
  route: "https://ai-os-app.zeabur.app/login",
  status: 200,
  shellMounted: true,
  contentReady: true,
  title: "Aios",
  consoleErrors: [],
  pageErrors: [],
  failedRequests: [],
  badResponses: [],
  brokenImages: [],
  horizontalOverflow: null,
  smallTouchTargets: [],
  missingH1: false,
  loadMs: 1200,
  contentReadyMs: 1400,
  redirectedTo: null,
  navigationError: null,
  ...over,
});

const ids = (findings: ReturnType<typeof judgePage>) => findings.map((f) => f.id);

describe("judgePage", () => {
  it("一切正常時沒有發現", () => {
    expect(judgePage(healthy(), { surface: web!, route: publicRoute, authenticated: true })).toEqual([]);
  });

  it("SPA 沒掛起來是 critical，且不再產生後續次生告警", () => {
    const findings = judgePage(healthy({ shellMounted: false, contentReady: false, title: "", missingH1: true }), {
      surface: web!,
      route: publicRoute,
      authenticated: true,
    });
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe("critical");
    expect(findings[0]?.id).toContain("shell-not-mounted");
  });

  it("主內容卡在載入中報 high", () => {
    const findings = judgePage(healthy({ contentReady: false }), { surface: web!, route: publicRoute, authenticated: true });
    expect(ids(findings)).toContain("page.content-stuck./login");
  });

  it("未登入巡覽受保護頁時，卡在載入中不算問題（那是導向登入的正常行為）", () => {
    const findings = judgePage(healthy({ contentReady: false }), {
      surface: web!,
      route: protectedRoute,
      authenticated: false,
    });
    expect(ids(findings)).not.toContain("page.content-stuck./admin");
  });

  it("未登入時的 401 不報，登入後的 401 要報", () => {
    const obs = healthy({ badResponses: [{ url: "https://a.test/api/trpc/x", status: 401 }] });
    const anonymous = judgePage(obs, { surface: web!, route: protectedRoute, authenticated: false });
    const loggedIn = judgePage(obs, { surface: web!, route: protectedRoute, authenticated: true });
    expect(ids(anonymous)).not.toContain("page.bad-responses./admin");
    expect(ids(loggedIn)).toContain("page.bad-responses./admin");
  });

  it("5xx 的請求失敗比 4xx 嚴重", () => {
    const server = judgePage(healthy({ badResponses: [{ url: "u", status: 500 }] }), {
      surface: web!,
      route: publicRoute,
      authenticated: true,
    });
    const client = judgePage(healthy({ badResponses: [{ url: "u", status: 404 }] }), {
      surface: web!,
      route: publicRoute,
      authenticated: true,
    });
    expect(server.find((f) => f.id.startsWith("page.bad-responses"))?.severity).toBe("high");
    expect(client.find((f) => f.id.startsWith("page.bad-responses"))?.severity).toBe("medium");
  });

  it("未捕捉的 JS 例外報 high", () => {
    const findings = judgePage(healthy({ pageErrors: ["TypeError: x is not a function"] }), {
      surface: web!,
      route: publicRoute,
      authenticated: true,
    });
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.evidence).toContain("TypeError");
  });

  it("橫向溢出在手機端比桌面端嚴重", () => {
    const overflow = { horizontalOverflow: { scrollWidth: 500, clientWidth: 390 } };
    const onPhone = judgePage(healthy(overflow), { surface: app!, route: publicRoute, authenticated: true });
    const onDesktop = judgePage(healthy(overflow), { surface: web!, route: publicRoute, authenticated: true });
    expect(onPhone.find((f) => f.id.startsWith("page.overflow"))?.severity).toBe("medium");
    expect(onDesktop.find((f) => f.id.startsWith("page.overflow"))?.severity).toBe("low");
  });

  it("伺服器 5xx 報 critical", () => {
    const findings = judgePage(healthy({ status: 503 }), { surface: web!, route: publicRoute, authenticated: true });
    expect(findings.find((f) => f.id.startsWith("page.server-error"))?.severity).toBe("critical");
  });

  it("缺 h1 只在內容就緒時才報（載入中的頁面沒有 h1 是正常的）", () => {
    const ready = judgePage(healthy({ missingH1: true }), { surface: web!, route: publicRoute, authenticated: true });
    const loading = judgePage(healthy({ missingH1: true, contentReady: false }), {
      surface: web!,
      route: protectedRoute,
      authenticated: false,
    });
    expect(ids(ready)).toContain("page.no-h1./login");
    expect(ids(loading)).not.toContain("page.no-h1./admin");
  });

  it("每筆發現都有修法", () => {
    const findings = judgePage(
      healthy({
        consoleErrors: ["boom"],
        pageErrors: ["Error: boom"],
        brokenImages: ["/a.png"],
        failedRequests: [{ url: "u", reason: "ERR_FAILED" }],
        horizontalOverflow: { scrollWidth: 500, clientWidth: 390 },
        loadMs: 20_000,
        title: "",
      }),
      { surface: app!, route: publicRoute, authenticated: true },
    );
    expect(findings.length).toBeGreaterThan(4);
    for (const f of findings) expect(f.remediation && f.remediation.length > 0).toBe(true);
  });
});

/**
 * 以下這組全部來自同一類缺陷：**判定用錯了前提**。
 *
 * 三個具體症狀：把上一頁的觀測當成這一頁的、把「這條路由需不需要登入」當成「這一輪有沒有
 * 登入」、把我方的等待上限當成站台的載入時間。三者都不會讓程式報錯，只會讓報告說錯話。
 */
describe("judgePage — 前提正確性", () => {
  it("導覽失敗時直接收工，不拿上一頁的 DOM 當這一頁的觀測", () => {
    const findings = judgePage(
      healthy({
        navigationError: "Error: net::ERR_ABORTED",
        status: null,
        // 以下全是「上一頁」留下來的觀測值，看起來一切正常
        shellMounted: true,
        contentReady: true,
      }),
      { surface: web!, route: publicRoute, authenticated: false },
    );
    expect(ids(findings)).toEqual(["page.navigation-failed./login"]);
    expect(findings[0]?.detail).toContain("沒有任何有效觀測");
  });

  it("未登入時，公開路由上的 401 也是預期行為（前端一定會打 session 查詢）", () => {
    const findings = judgePage(
      healthy({ badResponses: [{ url: "https://ai-os-app.zeabur.app/api/trpc/auth.session", status: 401 }] }),
      { surface: web!, route: publicRoute, authenticated: false },
    );
    expect(ids(findings)).not.toContain("page.bad-responses./login");
  });

  it("同一筆 401 的 console 訊息也要一起被排除，否則豁免形同虛設", () => {
    const findings = judgePage(
      healthy({
        consoleErrors: ["Failed to load resource: the server responded with a status of 401 (Unauthorized) @ /api/trpc/auth.session"],
      }),
      { surface: web!, route: publicRoute, authenticated: false },
    );
    expect(ids(findings)).not.toContain("page.console-errors./login");
  });

  it("已登入時的 401 不再豁免——那時它是真的有問題", () => {
    const findings = judgePage(
      healthy({
        badResponses: [{ url: "https://ai-os-app.zeabur.app/api/trpc/projects.list", status: 401 }],
        consoleErrors: ["Failed to load resource: the server responded with a status of 401 (Unauthorized)"],
      }),
      { surface: web!, route: publicRoute, authenticated: true },
    );
    expect(ids(findings)).toContain("page.bad-responses./login");
    expect(ids(findings)).toContain("page.console-errors./login");
  });

  it("內容沒就緒時不報「慢」——那個數字會是我方的等待上限，不是站台的表現", () => {
    const findings = judgePage(healthy({ contentReady: false, loadMs: 20_100, contentReadyMs: 20_100 }), {
      surface: web!,
      route: publicRoute,
      authenticated: false,
    });
    expect(ids(findings)).toContain("page.content-stuck./login");
    expect(ids(findings)).not.toContain("page.slow./login");
  });

  it("內容確實出來但很慢時照報", () => {
    const findings = judgePage(healthy({ contentReady: true, loadMs: 12_000, contentReadyMs: 13_000 }), {
      surface: web!,
      route: publicRoute,
      authenticated: false,
    });
    expect(ids(findings)).toContain("page.slow./login");
  });

  it("未登入巡覽受保護頁時，content-stuck 與 slow 都豁免", () => {
    const findings = judgePage(healthy({ contentReady: false, loadMs: 20_100, contentReadyMs: 20_100 }), {
      surface: web!,
      route: protectedRoute,
      authenticated: false,
    });
    expect(ids(findings)).not.toContain("page.content-stuck./admin");
    expect(ids(findings)).not.toContain("page.slow./admin");
  });
});

describe("isNoise", () => {
  it("URL 樣式要比對 location 而不是訊息文字——Chromium 的載入錯誤訊息裡沒有 URL", async () => {
    const { isNoise } = await import("../src/pages/pageTest.js");
    const text = "Failed to load resource: the server responded with a status of 404 (Not Found)";
    expect(isNoise(text)).toBe(false);
    expect(isNoise(text, "https://ai-os-app.zeabur.app/favicon.ico")).toBe(true);
  });

  it("文字樣式照舊比對訊息", async () => {
    const { isNoise } = await import("../src/pages/pageTest.js");
    expect(isNoise("Download the React DevTools for a better experience")).toBe(true);
    expect(isNoise("[vite] connecting...")).toBe(true);
  });

  it("真正的錯誤不會被濾掉", async () => {
    const { isNoise } = await import("../src/pages/pageTest.js");
    expect(isNoise("TypeError: undefined is not a function", "https://ai-os-app.zeabur.app/assets/index.js")).toBe(false);
  });
});
