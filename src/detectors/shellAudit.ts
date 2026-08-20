/**
 * App／桌面殼層的靜態設定稽核。
 *
 * 為什麼需要這個：網站的資安可以線上掃，但**殼層的設定是編譯進安裝檔的**——
 * APK 一旦側載到使用者手機，設定就固定了；線上掃描永遠看不到 `usesCleartextTraffic`
 * 或 Tauri 的 IPC 授權範圍。這組檢查讀 ai_os 原始碼，補上這個盲區。
 *
 * 每個分析函式都是純的（吃檔案內容字串），檔案 I/O 集中在 `checkShells`。
 */
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { finding } from "../core/findings.js";
import { stopwatch } from "../core/findings.js";
import type { CheckResult, Finding } from "../core/types.js";

const base = { check: "shell-audit", category: "security" as const, surface: "all" as const };

// ─────────────────────────────────────────────────────────────────────────────
// Capacitor（Android App 薄殼）
// ─────────────────────────────────────────────────────────────────────────────

export interface CapacitorFacts {
  serverUrl: string | null;
  androidScheme: string | null;
  cleartext: boolean;
  allowNavigation: string[];
}

/**
 * 剝除 JS／TS 註解。
 *
 * 沒有這道，被註解掉的本機開發設定會被當成正式設定回報：
 * `// url: "http://192.168.1.10:5173"` 與 `// cleartext: true` 是 Capacitor 設定檔裡
 * 極常見的寫法（切換本機／正式時整行註解掉），而稽核會照單全收，一次噴出三四筆 critical。
 * 那種假警報比漏報更傷——讀者第一次發現報告在說謊之後，就不會再讀第二份了。
 *
 * 行註解只吃「整行以空白＋// 開頭」的形式，刻意不處理行尾註解：
 * 要正確判斷行尾的 `//` 得先知道它在不在字串裡，而錯判會把 `https://` 從中間切斷，
 * 反而製造出更難查的錯誤。行尾註解由下面的「取區塊內第一個匹配」來擋。
 */
export function stripJsComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^[ \t]*\/\/.*$/gm, "");
}

/**
 * 取出某個鍵底下的區塊內容（大括號配對）。
 *
 * 為什麼要限定區塊：舊版直接在整份檔案裡找第一個 `url:`，於是 plugins 設定裡任何一個
 * `url` 都可能被誤認成 `server.url`——判定的對象根本不是 App 實際會載入的網址。
 *
 * 字串裡若含大括號會讓配對失準，但設定檔的 URL 與 scheme 不會出現大括號，
 * 為此引入一個 JS 解析器並不划算。
 */
function extractBlock(source: string, key: string): string | null {
  const opener = new RegExp(`(?:^|[\\s,{])${key}\\s*:\\s*\\{`).exec(source);
  if (!opener) return null;
  const start = opener.index + opener[0].length - 1;
  let depth = 0;
  for (let i = start; i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start + 1, i);
    }
  }
  return null;
}

export function parseCapacitorConfig(source: string): CapacitorFacts {
  const clean = stripJsComments(source);
  // server 區塊找不到時退回整份檔案：有些專案把設定拆檔或用展開運算子，
  // 退回全檔的漏報風險，低於「完全不看」。
  const scope = extractBlock(clean, "server") ?? clean;

  const serverUrl = /(?:^|[\s,{])url\s*:\s*["'`]([^"'`]+)["'`]/.exec(scope)?.[1] ?? null;
  const androidScheme = /(?:^|[\s,{])androidScheme\s*:\s*["'`]([^"'`]+)["'`]/.exec(scope)?.[1] ?? null;
  const cleartext = /(?:^|[\s,{])cleartext\s*:\s*true/.test(scope);
  const navBlock = /(?:^|[\s,{])allowNavigation\s*:\s*\[([^\]]*)\]/s.exec(scope)?.[1] ?? "";
  const allowNavigation = [...navBlock.matchAll(/["'`]([^"'`]+)["'`]/g)].map((m) => m[1] as string);
  return { serverUrl, androidScheme, cleartext, allowNavigation };
}

export function analyzeCapacitor(facts: CapacitorFacts, where: string): Finding[] {
  const out: Finding[] = [];

  if (facts.cleartext) {
    out.push(
      finding({
        ...base,
        id: "shell.capacitor.cleartext",
        severity: "high",
        title: "Capacitor 允許明文連線（cleartext: true）",
        detail:
          "App 的 WebView 會接受 http 連線。使用者在公共 Wi-Fi 上，登入憑證與專案內容可被同網路的人讀取或竄改，而 App 不會顯示任何警告——瀏覽器至少還會標「不安全」。",
        remediation: "移除 cleartext 設定，所有連線一律走 https。",
        where,
      }),
    );
  }

  if (facts.serverUrl && facts.serverUrl.startsWith("http://")) {
    out.push(
      finding({
        ...base,
        id: "shell.capacitor.http-url",
        severity: "critical",
        title: `Capacitor server.url 使用未加密連線（${facts.serverUrl}）`,
        detail: "App 每次啟動都以明文載入整個站台，中間人可以直接注入任意 JavaScript 到 App 裡。",
        remediation: "把 server.url 改為 https。",
        where,
      }),
    );
  }

  if (facts.androidScheme && facts.androidScheme !== "https") {
    out.push(
      finding({
        ...base,
        id: "shell.capacitor.scheme",
        severity: "medium",
        title: `Capacitor androidScheme 非 https（${facts.androidScheme}）`,
        detail:
          "非 https scheme 會讓 WebView 落在不同的安全來源上，Secure Cookie 與部分瀏覽器安全機制不會生效。",
        remediation: "設定 androidScheme: 'https'。",
        where,
      }),
    );
  }

  for (const pattern of facts.allowNavigation) {
    if (pattern === "*" || pattern.startsWith("*.") === false && pattern.includes("*")) {
      out.push(
        finding({
          ...base,
          id: `shell.capacitor.allow-navigation.${pattern}`,
          severity: "high",
          title: `Capacitor allowNavigation 含過寬的樣式（${pattern}）`,
          detail:
            "被放行的網域可以在 App 的 WebView 裡以第一方身分載入，取得與站台同等的儲存空間與權限。萬用字元等於把 App 開放給任意網站。",
          remediation: "只列出確實需要在 App 內開啟的完整網域。",
          where,
        }),
      );
    }
  }

  if (!facts.serverUrl) {
    out.push(
      finding({
        ...base,
        id: "shell.capacitor.no-server-url",
        severity: "info",
        title: "Capacitor 未設定 server.url（App 載入打包在本地的前端）",
        detail:
          "App 使用打包進安裝檔的前端資源，網站更新不會自動反映到 App。這不是漏洞，但代表 App 端的版本會落後，資安修補也需要重新發版。",
        remediation: "若採此模式，需建立 App 端的更新與強制升級機制。",
        where,
      }),
    );
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Android Manifest
// ─────────────────────────────────────────────────────────────────────────────

export interface ManifestFacts {
  cleartextTraffic: boolean | null;
  debuggable: boolean;
  allowBackup: boolean | null;
  permissions: string[];
  deepLinkHosts: string[];
  hasNetworkSecurityConfig: boolean;
  /** 這份 XML 有沒有被讀懂。false 代表稽核結果不可信，必須說出來而不是回報零發現。 */
  looksParseable: boolean;
}

/**
 * 布林屬性的比對式。
 *
 * 兩件事都是為了避免靜默漏判：
 * - 引號用反向參照鎖定成對——XML 規格裡單引號與雙引號完全等價，只認雙引號會讓
 *   `android:debuggable='true'` 這種合法寫法整份稽核靜默回空。
 * - 命名空間前綴放寬——多數專案用 `android:`，但前綴是可以自訂的。
 */
function boolAttr(name: string): RegExp {
  return new RegExp(`(?:[\\w-]+:)?${name}\\s*=\\s*(["'])(true|false)\\1`, "i");
}

export function parseAndroidManifest(xml: string): ManifestFacts {
  // XML 註解必須先剝除：被註解起來的 <uses-permission> 是 manifest 裡最常見的寫法
  // （「之後要做相機上傳再打開」），照收會憑空生出多餘權限的告警。
  const clean = xml.replace(/<!--[\s\S]*?-->/g, "");

  const cleartextRaw = boolAttr("usesCleartextTraffic").exec(clean)?.[2];
  const allowBackupRaw = boolAttr("allowBackup").exec(clean)?.[2];
  const debuggableRaw = boolAttr("debuggable").exec(clean)?.[2];
  return {
    cleartextTraffic: cleartextRaw === undefined ? null : cleartextRaw.toLowerCase() === "true",
    debuggable: debuggableRaw?.toLowerCase() === "true",
    allowBackup: allowBackupRaw === undefined ? null : allowBackupRaw.toLowerCase() === "true",
    permissions: [...clean.matchAll(/<uses-permission[^>]+?android:name\s*=\s*(["'])([^"']+)\1/g)].map((m) => m[2] as string),
    deepLinkHosts: [...clean.matchAll(/<data[^>]+?android:host\s*=\s*(["'])([^"']+)\1/g)].map((m) => m[2] as string),
    hasNetworkSecurityConfig: /(?:[\w-]+:)?networkSecurityConfig\s*=/.test(clean),
    // 連一個 manifest 元素都找不到＝這份 XML 沒被讀懂。此時「零發現」的意思是「沒看懂」，
    // 不是「沒問題」，所以要能讓 analyzeManifest 把它講出來。
    looksParseable: /<(?:manifest|application|uses-permission)[\s>/]/i.test(clean),
  };
}

/** 高風險權限：薄殼 App 只需要 INTERNET，其餘都要能說出為什麼。 */
const SENSITIVE_PERMISSIONS = new Set([
  "android.permission.READ_EXTERNAL_STORAGE",
  "android.permission.WRITE_EXTERNAL_STORAGE",
  "android.permission.READ_CONTACTS",
  "android.permission.ACCESS_FINE_LOCATION",
  "android.permission.ACCESS_COARSE_LOCATION",
  "android.permission.RECORD_AUDIO",
  "android.permission.CAMERA",
  "android.permission.READ_PHONE_STATE",
  "android.permission.REQUEST_INSTALL_PACKAGES",
]);

export function analyzeManifest(facts: ManifestFacts, where: string): Finding[] {
  const out: Finding[] = [];

  // 沒讀懂就不要再產生任何基於誤讀的判定。這裡直接收工，理由與 health 的
  // 「連不上就別產生次生告警」同源：從錯誤的前提推出來的結論，比沒有結論更糟。
  if (!facts.looksParseable) {
    out.push(
      finding({
        ...base,
        id: "shell.android.unparseable",
        severity: "low",
        title: "AndroidManifest.xml 沒有被讀懂，Android 殼層未稽核",
        detail:
          "這份檔案裡找不到任何 manifest 元素（<manifest>／<application>／<uses-permission>），代表解析失敗" +
          "（格式特殊、被前處理過，或根本不是 manifest）。" +
          "本輪沒有對 debuggable、明文流量、備份與權限做出任何判定——沒有發現不等於沒有問題。",
        remediation: "確認 --repo 指向的是 ai_os 原始碼樹，且 android/app/src/main/AndroidManifest.xml 是完整的 manifest。",
        where,
      }),
    );
    return out;
  }

  if (facts.cleartextTraffic === true) {
    out.push(
      finding({
        ...base,
        id: "shell.android.cleartext",
        severity: "high",
        title: "AndroidManifest 允許明文流量（usesCleartextTraffic=true）",
        detail: "App 可以發出 http 請求且不會被系統阻擋，公共網路下的流量可被讀取與竄改。",
        remediation: "移除該屬性（Android 9+ 預設即為 false），或改用 networkSecurityConfig 精確控制。",
        where,
      }),
    );
  }

  if (facts.debuggable) {
    out.push(
      finding({
        ...base,
        id: "shell.android.debuggable",
        severity: "critical",
        title: "AndroidManifest 標記為可偵錯（debuggable=true）",
        detail:
          "任何人只要能接上裝置就能附加偵錯器、讀取 App 私有目錄裡的資料（含登入憑證），並執行任意程式碼。這個屬性絕不能出現在發布版。",
        remediation: "移除 android:debuggable；讓建置類型自行決定（release 版一律 false）。",
        where,
      }),
    );
  }

  if (facts.allowBackup === true) {
    out.push(
      finding({
        ...base,
        id: "shell.android.allow-backup",
        severity: "medium",
        title: "AndroidManifest 允許系統備份（allowBackup=true）",
        detail:
          "App 的私有資料（WebView 的 Cookie 與 localStorage，也就是登入狀態）會被納入 adb backup 與雲端備份，可在另一台裝置還原成已登入狀態。",
        remediation: "設定 android:allowBackup=\"false\"，或用 dataExtractionRules 排除憑證相關目錄。",
        where,
      }),
    );
  }

  const sensitive = facts.permissions.filter((p) => SENSITIVE_PERMISSIONS.has(p));
  if (sensitive.length > 0) {
    out.push(
      finding({
        ...base,
        id: "shell.android.permissions",
        severity: "medium",
        title: `App 要求高風險權限（${sensitive.length} 項）`,
        detail:
          "薄殼 App 只需要 INTERNET。多餘的權限會擴大受害面（App 被入侵時攻擊者能拿到更多），也會降低使用者對安裝提示的信任。",
        remediation: "移除實際未使用的權限；確實需要的改為執行期動態請求並說明用途。",
        evidence: sensitive.join("\n"),
        where,
      }),
    );
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri（桌面）
// ─────────────────────────────────────────────────────────────────────────────

export interface TauriFacts {
  windowUrls: string[];
  devtools: boolean | null;
  csp: string | null;
  dangerousRemoteDomainIpcAccess: boolean;
}

export interface TauriCapability {
  identifier?: string;
  local?: boolean;
  remote?: { urls?: string[] };
  permissions?: string[];
}

export function parseTauriConfig(json: string): TauriFacts | null {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return null;
  }
  const app = (parsed.app ?? {}) as Record<string, unknown>;
  const security = (app.security ?? {}) as Record<string, unknown>;
  const windows = Array.isArray(app.windows) ? (app.windows as Array<Record<string, unknown>>) : [];
  return {
    windowUrls: windows.map((w) => String(w.url ?? "")).filter(Boolean),
    devtools: windows.length > 0 ? windows.some((w) => w.devtools === true) : null,
    csp: security.csp === null || security.csp === undefined ? null : String(security.csp),
    dangerousRemoteDomainIpcAccess: Boolean(security.dangerousRemoteDomainIpcAccess),
  };
}

/**
 * 放寬 JSON5 的兩個常見語法：註解與尾逗號。
 *
 * Tauri v2 的 capability 檔官方就支援 JSON5，所以帶行內註解的能力檔完全合法。
 * 用 JSON.parse 直接失敗然後靜默略過，等於對「那一份可能寫著 remote.urls: ["*"] 的檔案」視而不見。
 */
function relaxJson5(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/^[ \t]*\/\/.*$/gm, "")
    .replace(/,(\s*[}\]])/g, "$1");
}

/**
 * 解析一份 capability 檔。
 *
 * 一個檔案可以是單一能力物件，也可以是能力陣列（Tauri 兩種都吃）。
 * 完全解析不出來時回 null——由呼叫端產生「無法稽核」的發現，而不是當作這個檔案不存在。
 */
export function parseCapabilityFile(source: string): TauriCapability[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    try {
      parsed = JSON.parse(relaxJson5(source));
    } catch {
      return null;
    }
  }
  if (parsed === null || typeof parsed !== "object") return null;
  return Array.isArray(parsed) ? (parsed as TauriCapability[]) : [parsed as TauriCapability];
}

/**
 * 能力授權的網域範圍。
 *
 * 這三級不能混為一談：
 * - `whole-web`：`*`、`https://*`、以及 host 位置就是萬用的寫法——對整個網際網路開放，
 *   任何頁面都能呼叫本機能力。
 * - `subdomain-wildcard`：`https://*.你的網域` 加上路徑萬用——綁在一個具體的註冊網域上。仍然過寬
 *   （閒置子網域被接管是真實的攻擊路徑），但把它報成「對任意網域開放」是錯的，
 *   而錯誤的 critical 會讓人把整組告警關掉。
 * - `specific`：host 寫死、只有路徑用萬用——那是正常寫法，不報。
 */
export function classifyCapabilityScope(url: string): "whole-web" | "subdomain-wildcard" | "specific" {
  if (url === "*") return "whole-web";
  // host 位置緊接著就是 *：後面沒有東西、或接的是 /、: 、以及 *.* 這種等同全開的寫法。
  if (/^https?:\/\/\*(?:[/:]|$)/.test(url) || /^https?:\/\/\*\.\*/.test(url)) return "whole-web";
  if (/^https?:\/\/\*\.[^/*]+/.test(url)) return "subdomain-wildcard";
  return "specific";
}

export function analyzeTauri(facts: TauriFacts, capabilities: TauriCapability[], where: string): Finding[] {
  const out: Finding[] = [];

  for (const url of facts.windowUrls) {
    if (url.startsWith("http://")) {
      out.push(
        finding({
          ...base,
          id: "shell.tauri.http-window",
          severity: "critical",
          title: `Tauri 視窗以未加密連線載入（${url}）`,
          detail:
            "桌面應用每次啟動都以明文載入站台，中間人可注入任意 JavaScript——而桌面版還握有 IPC 橋接，注入的腳本可能觸及本機檔案能力。",
          remediation: "把視窗 url 改為 https。",
          where,
        }),
      );
    }
  }

  if (facts.csp === null) {
    out.push(
      finding({
        ...base,
        id: "shell.tauri.csp-null",
        severity: "medium",
        title: "Tauri 未設定應用層 CSP（security.csp 為 null）",
        detail:
          "桌面殼層完全依賴遠端站台送來的 CSP。站台的標頭一旦掉了（部署失誤、代理改寫），桌面版就毫無防護，而使用者不會像在瀏覽器裡那樣有任何線索。",
        remediation: "在 tauri.conf.json 設定與線上站一致的 csp 作為第二道防線。",
        where,
      }),
    );
  }

  if (facts.devtools === true) {
    out.push(
      finding({
        ...base,
        id: "shell.tauri.devtools",
        severity: "medium",
        title: "Tauri 視窗啟用開發者工具",
        detail: "發布版開著 devtools，任何拿到機器的人都能檢視應用內部狀態、憑證與 IPC 呼叫。",
        remediation: "把 devtools 設為 false（或僅在 debug 建置開啟）。",
        where,
      }),
    );
  }

  if (facts.dangerousRemoteDomainIpcAccess) {
    out.push(
      finding({
        ...base,
        id: "shell.tauri.dangerous-ipc",
        severity: "high",
        title: "Tauri 啟用 dangerousRemoteDomainIpcAccess",
        detail: "遠端網頁內容可直接呼叫本機 IPC 指令。網站上任何一個 XSS 都會升級成本機程式碼執行。",
        remediation: "改用 capabilities 精確授權特定來源與指令，關閉這個總開關。",
        where,
      }),
    );
  }

  for (const cap of capabilities) {
    const urls = cap.remote?.urls ?? [];
    for (const url of urls) {
      const scope = classifyCapabilityScope(url);
      if (scope === "whole-web") {
        out.push(
          finding({
            ...base,
            id: `shell.tauri.capability-wildcard.${cap.identifier ?? "unknown"}`,
            severity: "critical",
            title: `Tauri 能力「${cap.identifier ?? "未命名"}」對任意網域開放（${url}）`,
            detail:
              "任何被載入視窗的網站都能呼叫這組本機能力。只要使用者被導到惡意頁面（或站台被注入），本機檔案橋接就落入攻擊者手中。",
            remediation: "把 remote.urls 收斂成正式站的完整來源（例如 https://你的網域/*）。",
            where,
          }),
        );
      } else if (scope === "subdomain-wildcard") {
        out.push(
          finding({
            ...base,
            id: `shell.tauri.capability-subdomain.${cap.identifier ?? "unknown"}`,
            severity: "medium",
            title: `Tauri 能力「${cap.identifier ?? "未命名"}」對整個網域的所有子網域開放（${url}）`,
            detail:
              "授權範圍綁在一個具體的註冊網域上，不是整個網際網路——所以這不是全開。但只要任何一個子網域" +
              "（預覽站、文件站、被接管的閒置子網域）能載入內容，它就握有這組本機能力。",
            remediation: "把 remote.urls 收斂成實際會被載入的那一個來源，而不是整個網域的萬用。",
            where,
          }),
        );
      }
    }
    if (urls.length > 0 && cap.permissions?.some((p) => /^core:default$/.test(p)) && cap.local !== false) {
      out.push(
        finding({
          ...base,
          id: `shell.tauri.capability-local.${cap.identifier ?? "unknown"}`,
          severity: "low",
          title: `Tauri 能力「${cap.identifier ?? "未命名"}」同時開放本地與遠端`,
          detail: "遠端來源的能力授權應與本地分離，混用會讓授權範圍難以稽核。",
          remediation: "遠端能力設定 local: false，本地能力另建一組。",
          where,
        }),
      );
    }
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 三端一致性
// ─────────────────────────────────────────────────────────────────────────────

/**
 * 殼層寫死的網址是否與受測站台一致。
 *
 * 不一致的後果很具體：我們掃的是 A 站，但使用者手機裡的 App 連的是 B 站——
 * 報告全綠，實際上完全沒驗到 App 使用者真正接觸的系統。
 */
export function analyzeShellTargets(input: {
  target: string;
  capacitorUrl: string | null;
  tauriUrls: string[];
  deepLinkHosts: string[];
}): Finding[] {
  const out: Finding[] = [];
  const hostOf = (url: string | null): string | null => {
    if (!url) return null;
    try {
      return new URL(url).host;
    } catch {
      return null;
    }
  };

  const targetHost = hostOf(input.target);
  if (!targetHost) return out;

  const capHost = hostOf(input.capacitorUrl);
  if (capHost && capHost !== targetHost) {
    out.push(
      finding({
        ...base,
        category: "integrity",
        id: "shell.target-mismatch.capacitor",
        severity: "high",
        title: `App 殼層指向的站台與受測目標不同（${capHost} ≠ ${targetHost}）`,
        detail:
          "這份報告掃的是受測目標，但 App 使用者實際連的是另一個站。App 端的檢測結果對真實使用者沒有代表性。",
        remediation: `把掃描目標改成 ${capHost}，或修正 capacitor.config.ts 的 server.url。`,
      }),
    );
  }

  for (const url of input.tauriUrls) {
    const host = hostOf(url);
    if (host && host !== targetHost) {
      out.push(
        finding({
          ...base,
          category: "integrity",
          id: "shell.target-mismatch.tauri",
          severity: "high",
          title: `桌面殼層指向的站台與受測目標不同（${host} ≠ ${targetHost}）`,
          detail: "桌面使用者連的是另一個站，本次檢測涵蓋不到他們實際使用的系統。",
          remediation: `把掃描目標改成 ${host}，或修正 tauri.conf.json 的視窗 url。`,
        }),
      );
    }
  }

  if (capHost && input.deepLinkHosts.length > 0 && !input.deepLinkHosts.includes(capHost)) {
    out.push(
      finding({
        ...base,
        category: "integrity",
        id: "shell.deeplink-mismatch",
        severity: "medium",
        title: "Android 深層連結的 host 與 App 載入的站台不一致",
        detail:
          `深層連結設定為 ${input.deepLinkHosts.join("、")}，但 App 實際載入 ${capHost}。使用者點分享連結時不會開 App，或開了 App 卻導到別的站。`,
        remediation: "讓 AndroidManifest 的 <data android:host> 與 capacitor server.url 的網域一致。",
      }),
    );
  }

  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 執行
// ─────────────────────────────────────────────────────────────────────────────

async function readIfExists(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, "utf8");
  } catch {
    return null;
  }
}

export async function checkShells(repoPath: string | undefined, target: string): Promise<CheckResult> {
  const elapsed = stopwatch();
  if (!repoPath) {
    return {
      ...base,
      completed: false,
      skippedReason: "未指定 ai_os 原始碼路徑（--repo 或 AIOS_REPO）；殼層設定無法從線上掃描取得。",
      durationMs: elapsed(),
      findings: [],
    };
  }

  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};

  const capacitorPath = path.join(repoPath, "capacitor.config.ts");
  const manifestPath = path.join(repoPath, "android/app/src/main/AndroidManifest.xml");
  const tauriPath = path.join(repoPath, "src-tauri/tauri.conf.json");

  const [capacitorSrc, manifestSrc, tauriSrc] = await Promise.all([
    readIfExists(capacitorPath),
    readIfExists(manifestPath),
    readIfExists(tauriPath),
  ]);

  if (!capacitorSrc && !manifestSrc && !tauriSrc) {
    return {
      ...base,
      completed: false,
      skippedReason: `在 ${repoPath} 找不到任何殼層設定檔（capacitor.config.ts / AndroidManifest.xml / tauri.conf.json）。`,
      durationMs: elapsed(),
      findings: [],
    };
  }

  let capacitorFacts: CapacitorFacts | null = null;
  if (capacitorSrc) {
    capacitorFacts = parseCapacitorConfig(capacitorSrc);
    facts.capacitor = capacitorFacts;
    findings.push(...analyzeCapacitor(capacitorFacts, capacitorPath));
  }

  let manifestFacts: ManifestFacts | null = null;
  if (manifestSrc) {
    manifestFacts = parseAndroidManifest(manifestSrc);
    facts.android = manifestFacts;
    findings.push(...analyzeManifest(manifestFacts, manifestPath));
  }

  let tauriFacts: TauriFacts | null = null;
  if (tauriSrc) {
    tauriFacts = parseTauriConfig(tauriSrc);
    if (!tauriFacts) {
      findings.push(
        finding({
          ...base,
          id: "shell.tauri.unparseable",
          severity: "low",
          title: "tauri.conf.json 無法解析",
          detail: "設定檔不是有效 JSON，桌面殼層的資安設定無法稽核（建置時多半也會失敗）。",
          remediation: "修正 tauri.conf.json 的語法。",
          where: tauriPath,
        }),
      );
    } else {
      facts.tauri = tauriFacts;

      // capabilities 是獨立檔案。**必須列目錄，不能猜檔名**：Tauri v2 是把
      // src-tauri/capabilities/ 底下的每一個檔案都讀進來，識別靠檔案裡的 identifier 而非檔名。
      // 舊版只試三個寫死的名字，於是一份叫 remote.json、內容寫著 remote.urls: ["*"] 的能力檔
      // 會被完全跳過——稽核結果是「零發現」，而桌面端其實對整個網際網路開放本機能力。
      const capDir = path.join(repoPath, "src-tauri/capabilities");
      let capNames: string[] = [];
      try {
        capNames = (await readdir(capDir)).filter((n) => /\.(json|json5|toml)$/i.test(n)).sort();
      } catch {
        /* 目錄不存在：這個專案沒有用 capability，不是問題 */
      }

      const capabilities: TauriCapability[] = [];
      const capabilityFiles: Array<{ file: string; status: string }> = [];
      for (const name of capNames) {
        const capSrc = await readIfExists(path.join(capDir, name));
        if (capSrc === null) continue;

        if (/\.toml$/i.test(name)) {
          capabilityFiles.push({ file: name, status: "unaudited" });
          findings.push(
            finding({
              ...base,
              id: `shell.tauri.capability-unauditable.${name}`,
              severity: "low",
              title: `Tauri 能力檔 ${name} 是 TOML，本輪未稽核`,
              detail:
                "這個檔案定義了桌面端能開放哪些本機能力給哪些來源，但 TOML 需要額外的解析器，" +
                "本工具刻意不引入。它的內容**沒有被檢查**——不是沒問題，是沒看過。",
              remediation: "把能力檔改成 JSON（Tauri 兩種都吃），或人工確認其中的 remote.urls 沒有萬用授權。",
              where: path.join(capDir, name),
            }),
          );
          continue;
        }

        const parsed = parseCapabilityFile(capSrc);
        if (parsed === null) {
          capabilityFiles.push({ file: name, status: "unparseable" });
          findings.push(
            finding({
              ...base,
              id: `shell.tauri.capability-unparseable.${name}`,
              severity: "low",
              title: `Tauri 能力檔 ${name} 無法解析，本輪未稽核`,
              detail:
                "這個檔案定義了桌面端能開放哪些本機能力給哪些來源，解析失敗代表它的授權範圍沒有被檢查過。" +
                "這與 tauri.conf.json 解析失敗一樣要說出來——靜默略過會讓報告的零發現變成謊話。",
              remediation: "修正該檔的語法（JSON 或 JSON5 皆可）。",
              where: path.join(capDir, name),
            }),
          );
          continue;
        }

        capabilities.push(...parsed);
        capabilityFiles.push({ file: name, status: "parsed" });
      }

      facts.tauriCapabilities = capabilities;
      // 「讀了哪些檔」要留下來：讓讀者能分辨「沒有能力檔」與「我沒找到能力檔」。
      facts.tauriCapabilityFiles = capabilityFiles;
      findings.push(...analyzeTauri(tauriFacts, capabilities, tauriPath));
    }
  }

  findings.push(
    ...analyzeShellTargets({
      target,
      capacitorUrl: capacitorFacts?.serverUrl ?? null,
      tauriUrls: tauriFacts?.windowUrls ?? [],
      deepLinkHosts: manifestFacts?.deepLinkHosts ?? [],
    }),
  );

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
