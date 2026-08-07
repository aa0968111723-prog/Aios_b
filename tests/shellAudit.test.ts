import { describe, expect, it } from "vitest";
import {
  analyzeCapacitor,
  analyzeManifest,
  analyzeShellTargets,
  analyzeTauri,
  parseAndroidManifest,
  parseCapacitorConfig,
  parseTauriConfig,
} from "../src/detectors/shellAudit.js";

const WHERE = "capacitor.config.ts";
const ids = (findings: Array<{ id: string }>) => findings.map((f) => f.id);

/** ai_os 現況的 capacitor.config.ts 摘要——基準應該是乾淨的。 */
const AIOS_CAPACITOR = `
const config: CapacitorConfig = {
  appId: "app.aios.mobile",
  appName: "Aios",
  webDir: "dist/public",
  server: {
    url: "https://ai-os-app.zeabur.app",
    androidScheme: "https",
  },
};
`;

describe("parseCapacitorConfig / analyzeCapacitor", () => {
  it("讀出 server.url 與 androidScheme", () => {
    const facts = parseCapacitorConfig(AIOS_CAPACITOR);
    expect(facts.serverUrl).toBe("https://ai-os-app.zeabur.app");
    expect(facts.androidScheme).toBe("https");
    expect(facts.cleartext).toBe(false);
  });

  it("ai_os 現況不產生任何發現", () => {
    expect(analyzeCapacitor(parseCapacitorConfig(AIOS_CAPACITOR), WHERE)).toEqual([]);
  });

  it("http 的 server.url 是 critical——App 每次啟動都被中間人有機可乘", () => {
    const facts = parseCapacitorConfig(`server: { url: "http://staging.test", androidScheme: "https" }`);
    expect(analyzeCapacitor(facts, WHERE).find((f) => f.id === "shell.capacitor.http-url")?.severity).toBe("critical");
  });

  it("cleartext: true 報 high", () => {
    const facts = parseCapacitorConfig(`server: { url: "https://a.test", cleartext: true }`);
    expect(ids(analyzeCapacitor(facts, WHERE))).toContain("shell.capacitor.cleartext");
  });

  it("allowNavigation 用萬用字元報 high", () => {
    const facts = parseCapacitorConfig(`server: { url: "https://a.test", allowNavigation: ["*"] }`);
    expect(ids(analyzeCapacitor(facts, WHERE))).toContain("shell.capacitor.allow-navigation.*");
  });

  it("沒有 server.url 只是 info（改用本地打包，不是漏洞）", () => {
    const findings = analyzeCapacitor(parseCapacitorConfig(`const config = { webDir: "dist" };`), WHERE);
    expect(findings.find((f) => f.id === "shell.capacitor.no-server-url")?.severity).toBe("info");
  });
});

describe("parseAndroidManifest / analyzeManifest", () => {
  const AIOS_MANIFEST = `
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:allowBackup="true" android:label="@string/app_name">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <data android:scheme="https" android:host="ai-os-app.zeabur.app" />
      </intent-filter>
    </activity>
  </application>
  <uses-permission android:name="android.permission.INTERNET" />
</manifest>`;

  it("讀出深層連結 host 與權限", () => {
    const facts = parseAndroidManifest(AIOS_MANIFEST);
    expect(facts.deepLinkHosts).toEqual(["ai-os-app.zeabur.app"]);
    expect(facts.permissions).toEqual(["android.permission.INTERNET"]);
    expect(facts.allowBackup).toBe(true);
  });

  it("allowBackup=true 報 medium（備份會帶走已登入狀態）", () => {
    expect(analyzeManifest(parseAndroidManifest(AIOS_MANIFEST), "m").find((f) => f.id === "shell.android.allow-backup")?.severity).toBe(
      "medium",
    );
  });

  it("debuggable=true 是 critical", () => {
    const facts = parseAndroidManifest(`<application android:debuggable="true" />`);
    expect(analyzeManifest(facts, "m").find((f) => f.id === "shell.android.debuggable")?.severity).toBe("critical");
  });

  it("usesCleartextTraffic=true 報 high；未指定則不報", () => {
    const on = parseAndroidManifest(`<application android:usesCleartextTraffic="true" />`);
    const unset = parseAndroidManifest(`<application />`);
    expect(ids(analyzeManifest(on, "m"))).toContain("shell.android.cleartext");
    expect(ids(analyzeManifest(unset, "m"))).not.toContain("shell.android.cleartext");
  });

  it("只有 INTERNET 權限時不報高風險權限", () => {
    expect(ids(analyzeManifest(parseAndroidManifest(AIOS_MANIFEST), "m"))).not.toContain("shell.android.permissions");
  });

  it("多餘的敏感權限會被抓出來", () => {
    const facts = parseAndroidManifest(`
      <uses-permission android:name="android.permission.INTERNET" />
      <uses-permission android:name="android.permission.CAMERA" />
      <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />`);
    const hit = analyzeManifest(facts, "m").find((f) => f.id === "shell.android.permissions");
    expect(hit?.evidence).toContain("CAMERA");
  });
});

describe("parseTauriConfig / analyzeTauri", () => {
  const AIOS_TAURI = JSON.stringify({
    app: {
      security: { capabilities: ["remote-main"], csp: null },
      windows: [{ label: "main", url: "https://ai-os-app.zeabur.app", devtools: false }],
    },
  });

  it("讀出視窗網址與 CSP 狀態", () => {
    const facts = parseTauriConfig(AIOS_TAURI);
    expect(facts?.windowUrls).toEqual(["https://ai-os-app.zeabur.app"]);
    expect(facts?.csp).toBeNull();
    expect(facts?.devtools).toBe(false);
  });

  it("壞掉的 JSON 回 null 而不是丟例外", () => {
    expect(parseTauriConfig("{not json")).toBeNull();
  });

  it("csp: null 報 medium——桌面端完全靠遠端站的標頭撐著", () => {
    const facts = parseTauriConfig(AIOS_TAURI)!;
    expect(analyzeTauri(facts, [], "t").find((f) => f.id === "shell.tauri.csp-null")?.severity).toBe("medium");
  });

  it("ai_os 的 remote-main 能力（釘死正式來源）不被誤報成萬用字元", () => {
    const facts = parseTauriConfig(AIOS_TAURI)!;
    const findings = analyzeTauri(facts, [
      { identifier: "remote-main", local: false, remote: { urls: ["https://ai-os-app.zeabur.app/*"] }, permissions: ["core:default"] },
    ], "t");
    expect(ids(findings)).not.toContain("shell.tauri.capability-wildcard.remote-main");
  });

  it("能力對任意網域開放是 critical", () => {
    const facts = parseTauriConfig(AIOS_TAURI)!;
    const findings = analyzeTauri(facts, [{ identifier: "wide", remote: { urls: ["https://*"] } }], "t");
    expect(findings.find((f) => f.id === "shell.tauri.capability-wildcard.wide")?.severity).toBe("critical");
  });

  it("dangerousRemoteDomainIpcAccess 報 high", () => {
    const facts = parseTauriConfig(
      JSON.stringify({ app: { security: { dangerousRemoteDomainIpcAccess: true }, windows: [] } }),
    )!;
    expect(ids(analyzeTauri(facts, [], "t"))).toContain("shell.tauri.dangerous-ipc");
  });

  it("devtools 開著報 medium", () => {
    const facts = parseTauriConfig(
      JSON.stringify({ app: { security: { csp: "default-src 'self'" }, windows: [{ url: "https://a.test", devtools: true }] } }),
    )!;
    expect(ids(analyzeTauri(facts, [], "t"))).toContain("shell.tauri.devtools");
  });
});

describe("analyzeShellTargets", () => {
  it("三端與受測目標一致時不產生發現", () => {
    const findings = analyzeShellTargets({
      target: "https://ai-os-app.zeabur.app",
      capacitorUrl: "https://ai-os-app.zeabur.app",
      tauriUrls: ["https://ai-os-app.zeabur.app"],
      deepLinkHosts: ["ai-os-app.zeabur.app"],
    });
    expect(findings).toEqual([]);
  });

  it("掃錯站台會被指出——否則報告全綠卻沒驗到 App 使用者真正連的系統", () => {
    const findings = analyzeShellTargets({
      target: "https://staging.test",
      capacitorUrl: "https://ai-os-app.zeabur.app",
      tauriUrls: ["https://ai-os-app.zeabur.app"],
      deepLinkHosts: ["ai-os-app.zeabur.app"],
    });
    expect(ids(findings)).toContain("shell.target-mismatch.capacitor");
    expect(ids(findings)).toContain("shell.target-mismatch.tauri");
  });

  it("深層連結 host 與 App 載入的站不一致時提出", () => {
    const findings = analyzeShellTargets({
      target: "https://ai-os-app.zeabur.app",
      capacitorUrl: "https://ai-os-app.zeabur.app",
      tauriUrls: [],
      deepLinkHosts: ["old-domain.test"],
    });
    expect(ids(findings)).toContain("shell.deeplink-mismatch");
  });

  it("網址無法解析時安靜略過，不讓整項檢查爆掉", () => {
    expect(analyzeShellTargets({ target: "not-a-url", capacitorUrl: "x", tauriUrls: [], deepLinkHosts: [] })).toEqual([]);
  });
});
