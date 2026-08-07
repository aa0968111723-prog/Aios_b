/**
 * 受測路由表。
 *
 * 對照 ai_os client/src/app/AppRoutes.tsx 與 SessionGate.tsx 的實際 <Route>，
 * 不是憑印象列的。動態路由（/p/:id、/chat/:peerId、/invite/:token）不放進預設清單——
 * 沒有真實識別碼時只會測到錯誤頁，那種綠燈沒有意義。要測的人用 --routes 自己帶。
 */

export interface RouteSpec {
  path: string;
  label: string;
  /** 需要登入才看得到真正內容。未提供帳密時，這些路由只驗「有沒有正確導到登入頁」。 */
  requiresAuth: boolean;
}

export const DEFAULT_ROUTES: RouteSpec[] = [
  { path: "/", label: "首頁／登入後儀表板", requiresAuth: false },
  { path: "/login", label: "登入", requiresAuth: false },
  { path: "/dashboard", label: "儀表板", requiresAuth: true },
  { path: "/admin", label: "團隊管理", requiresAuth: true },
  { path: "/options", label: "選項設定", requiresAuth: true },
  { path: "/logs", label: "紀錄", requiresAuth: true },
  { path: "/members", label: "成員", requiresAuth: true },
  { path: "/feedback", label: "意見回饋", requiresAuth: true },
  { path: "/settings", label: "個人設定", requiresAuth: true },
  { path: "/my-reports", label: "我的回報", requiresAuth: true },
  { path: "/models", label: "模型", requiresAuth: true },
  { path: "/help", label: "說明", requiresAuth: true },
  { path: "/mcp", label: "MCP", requiresAuth: true },
  { path: "/integrations", label: "整合", requiresAuth: true },
  { path: "/downloads", label: "下載", requiresAuth: true },
  { path: "/planner", label: "企劃", requiresAuth: true },
  { path: "/databases", label: "資料庫", requiresAuth: true },
  { path: "/community", label: "社群", requiresAuth: true },
  { path: "/chat", label: "訊息", requiresAuth: true },
  { path: "/desktop", label: "桌面版配對", requiresAuth: true },
];

/** ai_os 前端的實際選擇器（來自 client 的 AppShell 與登入頁）。 */
export const SELECTORS = {
  /** AppShell 無條件渲染，不等任何 API——用它判斷 SPA 有沒有掛起來。 */
  shell: "div.app",
  /** 只有登入後才出現，用來斷言登入狀態（不兼任「頁面可用」的判準）。 */
  authenticated: 'header.topbar button[aria-haspopup="menu"]',
  loginEmail: "#login-email",
  loginPassword: "#login-pw",
  loginSubmit: 'button[type="submit"]',
  main: "#main-content",
} as const;

export function parseRoutes(input: string | undefined): RouteSpec[] | null {
  if (!input) return null;
  const paths = input
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (paths.length === 0) return null;
  return paths.map((path) => {
    const known = DEFAULT_ROUTES.find((r) => r.path === path);
    return known ?? { path, label: path, requiresAuth: path !== "/" && path !== "/login" };
  });
}
