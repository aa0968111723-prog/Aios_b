/**
 * App／桌面殼層的靜態設定稽核。
 *
 * 為什麼需要這個：網站的資安可以線上掃，但**殼層的設定是編譯進安裝檔的**——
 * APK 一旦側載到使用者手機，設定就固定了；線上掃描永遠看不到 `usesCleartextTraffic`
 * 或 Tauri 的 IPC 授權範圍。這組檢查讀 ai_os 原始碼，補上這個盲區。
 *
 * 每個分析函式都是純的（吃檔案內容字串），檔案 I/O 集中在 `checkShells`。
 */
import { readFile } from "node:fs/promises";
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

export function parseCapacitorConfig(source: string): CapacitorFacts {
  const serverUrl = /url\s*:\s*["'`]([^"'`]+)["'`]/.exec(source)?.[1] ?? null;
  const androidScheme = /androidScheme\s*:\s*["'`]([^"'`]+)["'`]/.exec(source)?.[1] ?? null;
  const cleartext = /cleartext\s*:\s*true/.test(source);
  const navBlock = /allowNavigation\s*:\s*\[([^\]]*)\]/s.exec(source)?.[1] ?? "";
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
}

export function parseAndroidManifest(xml: string): ManifestFacts {
  const cleartextRaw = /android:usesCleartextTraffic\s*=\s*"(true|false)"/.exec(xml)?.[1];
  const allowBackupRaw = /android:allowBackup\s*=\s*"(true|false)"/.exec(xml)?.[1];
  return {
    cleartextTraffic: cleartextRaw === undefined ? null : cleartextRaw === "true",
    debuggable: /android:debuggable\s*=\s*"true"/.test(xml),
    allowBackup: allowBackupRaw === undefined ? null : allowBackupRaw === "true",
    permissions: [...xml.matchAll(/<uses-permission[^>]+android:name\s*=\s*"([^"]+)"/g)].map((m) => m[1] as string),
    deepLinkHosts: [...xml.matchAll(/<data[^>]+android:host\s*=\s*"([^"]+)"/g)].map((m) => m[1] as string),
    hasNetworkSecurityConfig: /android:networkSecurityConfig\s*=/.test(xml),
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
      // `https://example.com/*` 是正常的路徑萬用；`*` 或 `https://*` 才是危險的
      const isWholeWeb = url === "*" || /^https?:\/\/\*/.test(url) || url === "https://*/*";
      if (isWholeWeb) {
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
      // capabilities 是獨立檔案，逐一讀取
      const capabilities: TauriCapability[] = [];
      for (const name of ["remote-main.json", "default.json", "main.json"]) {
        const capSrc = await readIfExists(path.join(repoPath, "src-tauri/capabilities", name));
        if (!capSrc) continue;
        try {
          capabilities.push(JSON.parse(capSrc) as TauriCapability);
        } catch {
          /* 壞掉的 capability 檔在 Tauri 建置時就會爆，這裡不重複報 */
        }
      }
      facts.tauriCapabilities = capabilities;
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
