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
  redirectedTo: null,
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
