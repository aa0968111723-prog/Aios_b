/**
 * 就地尋找 ai_os 原始碼樹。
 *
 * 殼層稽核（Capacitor／AndroidManifest／Tauri）只能從原始碼取得——這些設定被編譯進
 * 安裝檔，線上永遠掃不到。過去必須每次手動帶 `--repo` 或設 `AIOS_REPO`，忘了帶就整組
 * 靜默跳過。這裡改為：若使用者沒有明講，就依慣例位置自動探測一份「就地的」ai_os 檢出，
 * 讓三端檢測預設就能連到真正的殼層設定。
 *
 * 判定依據是殼層設定檔本身（而非資料夾名稱或 .git），避免把任意同名資料夾誤認成 ai_os。
 * 檔案系統存取以注入方式提供，讓探測邏輯本身可離線測試。
 */
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";

/** 任一殼層設定檔存在，即視為有效的 ai_os 原始碼樹。 */
export const SHELL_MARKERS = [
  "capacitor.config.ts",
  "android/app/src/main/AndroidManifest.xml",
  "src-tauri/tauri.conf.json",
] as const;

type Exists = (filePath: string) => boolean;

export function looksLikeAiosRepo(dir: string, exists: Exists = existsSync): boolean {
  return SHELL_MARKERS.some((marker) => exists(path.join(dir, marker)));
}

export interface DiscoverOptions {
  cwd?: string;
  home?: string;
  exists?: Exists;
}

/**
 * 依慣例位置探測就地的 ai_os 檢出，回傳第一個看起來像 ai_os 的目錄。
 *
 * 位置順序刻意由「離工作目錄最近」到「使用者家目錄」：Cloud Agent 會把 ai_os 併排
 * 檢出（`~/ai_os`），本機開發則通常放在專案旁（`../ai_os`，見 README／.env.example）。
 */
export function discoverAiosRepo(options: DiscoverOptions = {}): string | undefined {
  const cwd = options.cwd ?? process.cwd();
  const home = options.home ?? os.homedir();
  const exists = options.exists ?? existsSync;

  const candidates = [
    path.join(cwd, "ai_os"),
    path.resolve(cwd, "..", "ai_os"),
    path.resolve(cwd, "..", "..", "ai_os"),
    path.join(home, "ai_os"),
  ];

  const seen = new Set<string>();
  for (const dir of candidates) {
    if (seen.has(dir)) continue;
    seen.add(dir);
    if (looksLikeAiosRepo(dir, exists)) return dir;
  }
  return undefined;
}
