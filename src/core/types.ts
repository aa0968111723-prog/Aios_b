/**
 * Aios Sentinel — 核心型別。
 *
 * 設計原則：偵測器只回報「事實 + 判定」，不自己決定要不要讓 CI 失敗。
 * 嚴重度門檻是報告層與 CLI 的事，偵測器換位置或被單獨呼叫時行為都一樣。
 */

/** 嚴重度。critical→info 由高到低，`compareSeverity` 依這個順序排。 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * 三端 surface。
 *
 * aios 的 App（Capacitor 薄殼）與桌面（Tauri）都是 WebView 直連同一個線上站，
 * 所以「三端」不是三份程式碼，而是**同一個站被三種載體以不同 UA／視窗／能力載入**。
 * 檢測系統必須照這個現實建模：同源同時掃，但每端各自帶自己的人格與期望。
 */
export type SurfaceId = "web" | "app" | "desktop";

/** 檢測面向。決定報告怎麼分節，也決定 `--only` 能篩什麼。 */
export type Category =
  | "security" // 資訊安全：標頭、CSP、Cookie、認證閘門、資訊洩漏、CORS
  | "availability" // 可用性：健康檢查、就緒分項、連線
  | "page" // 頁面測試：掛載、console 錯誤、破圖、版面溢出
  | "a11y" // 無障礙
  | "integrity" // 一致性：三端 build 漂移、殼層設定與線上站是否對得起來
  | "monitoring"; // 監測：使用者行為分析（PostHog）、平台錯誤（Zeabur）、資料庫進出、裝置紀錄

export interface Finding {
  /** 穩定 id（`檢查名.問題名`），供去重、抑制清單、以及跨次執行比對「是不是同一件事」。 */
  id: string;
  /** 產出這筆的檢查名稱。 */
  check: string;
  category: Category;
  severity: Severity;
  /** 哪一端測到的；`all` 表示與載體無關（例如靜態設定稽核）。 */
  surface: SurfaceId | "all";
  title: string;
  /** 為什麼這是問題——寫給不一定懂資安的維運者看。 */
  detail: string;
  /** 實際觀測到的字串（標頭值、回應片段、選擇器）。報告會原樣附上，方便重現。 */
  evidence?: string;
  /** 怎麼修。沒有修法的發現不該存在——那只是抱怨。 */
  remediation?: string;
  /** 觸發的 URL 或檔案路徑。 */
  where?: string;
}

/** 單一檢查的執行結果。skipped 與 ok 必須分開：跳過不等於通過。 */
export interface CheckResult {
  check: string;
  category: Category;
  surface: SurfaceId | "all";
  /** 檢查本身是否跑完（不是「有沒有發現問題」）。 */
  completed: boolean;
  /** 被跳過的原因（缺環境變數、缺 playwright、目標無此功能）。 */
  skippedReason?: string;
  durationMs: number;
  findings: Finding[];
  /** 非問題但值得記錄的觀測值（build sha、回應時間、路由數）。 */
  facts?: Record<string, unknown>;
  /** 檢查自己爆掉（不是目標有問題，是檢測器有問題）——必須跟「發現問題」分開看。 */
  error?: string;
}

export interface Surface {
  id: SurfaceId;
  label: string;
  /** 這一端實際連的站。預設三端同源，可用環境變數指到不同部署（測 build 漂移）。 */
  origin: string;
  userAgent: string;
  viewport: { width: number; height: number };
  isMobile: boolean;
  /** 這一端額外會帶的請求標頭（例如 App 殼層的自訂 UA 標記）。 */
  extraHeaders?: Record<string, string>;
}

export interface SentinelConfig {
  /** 基準站台（三端預設都指這裡）。 */
  target: string;
  surfaces: Surface[];
  /** ai_os 原始碼路徑，殼層靜態稽核用。沒有就跳過那組檢查。 */
  repoPath?: string;
  /** 要巡覽的路由。空陣列＝用內建路由表。 */
  routes: string[];
  outDir: string;
  /** 達到或超過這個嚴重度就讓 CLI 以非 0 結束。 */
  failOn: Severity;
  /** 單一 HTTP 請求逾時（毫秒）。 */
  timeoutMs: number;
  /** 頁面測試登入用；沒設就只跑公開路由。 */
  credentials?: { email: string; password: string };
  /** 截圖存檔（頁面測試）。 */
  screenshots: boolean;
}

export interface RunReport {
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  target: string;
  surfaces: SurfaceId[];
  results: CheckResult[];
  summary: {
    total: number;
    completed: number;
    skipped: number;
    errored: number;
    findings: Record<Severity, number>;
    worst: Severity | null;
  };
}
