import { describe, expect, it } from "vitest";
import {
  analyzeCapacitor,
  analyzeManifest,
  analyzeShellTargets,
  analyzeTauri,
  classifyCapabilityScope,
  parseAndroidManifest,
  parseCapabilityFile,
  parseCapacitorConfig,
  parseTauriConfig,
  stripJsComments,
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

/**
 * 以下這組全部來自同一類缺陷：**解析器把「沒生效的設定」當成生效的**。
 *
 * 它們的共同症狀是假警報——一份完全正常的專案被報出三四筆 critical。
 * 而假警報的代價比漏報更高：讀者第一次發現報告在說謊之後，就不會再讀第二份了。
 */
describe("設定解析：註解與引號", () => {
  it("剝除區塊註解與整行行註解，但不切斷 https:// 的雙斜線", () => {
    const cleaned = stripJsComments(`
      /* 舊設定
      url: "http://old.test",
      */
      // url: "http://192.168.1.10:5173",
      url: "https://ai-os-app.zeabur.app",
    `);
    expect(cleaned).not.toContain("old.test");
    expect(cleaned).not.toContain("192.168.1.10");
    expect(cleaned).toContain("https://ai-os-app.zeabur.app");
  });

  it("被註解掉的本機開發設定不會被當成正式設定（最常見的假警報來源）", () => {
    const facts = parseCapacitorConfig(`
      const config: CapacitorConfig = {
        server: {
          // 本機開發時再打開這兩行
          // url: "http://192.168.1.10:5173",
          // cleartext: true,
          url: "https://ai-os-app.zeabur.app",
          androidScheme: "https",
        },
      };
    `);
    expect(facts.serverUrl).toBe("https://ai-os-app.zeabur.app");
    expect(facts.cleartext).toBe(false);
    expect(analyzeCapacitor(facts, WHERE).filter((f) => f.severity !== "info")).toEqual([]);
  });

  it("只在 server 區塊裡找 url——別的區塊的 url 不是 App 實際載入的網址", () => {
    const facts = parseCapacitorConfig(`
      const config = {
        plugins: { SomePlugin: { url: "http://plugin.example" } },
        server: { url: "https://ai-os-app.zeabur.app", androidScheme: "https" },
      };
    `);
    expect(facts.serverUrl).toBe("https://ai-os-app.zeabur.app");
  });

  it("XML 註解裡的權限不算數", () => {
    const facts = parseAndroidManifest(`
      <manifest>
        <uses-permission android:name="android.permission.INTERNET" />
        <!-- 之後若要做相機上傳再打開
        <uses-permission android:name="android.permission.CAMERA" />
        -->
      </manifest>
    `);
    expect(facts.permissions).toEqual(["android.permission.INTERNET"]);
    expect(ids(analyzeManifest(facts, "m"))).not.toContain("shell.android.permissions");
  });

  it("單引號屬性是合法 XML，不能因此整組靜默漏判", () => {
    const facts = parseAndroidManifest(
      `<manifest><application android:debuggable='true' android:usesCleartextTraffic='true' android:allowBackup='true' /></manifest>`,
    );
    expect(facts.debuggable).toBe(true);
    expect(facts.cleartextTraffic).toBe(true);
    expect(facts.allowBackup).toBe(true);
    expect(ids(analyzeManifest(facts, "m"))).toContain("shell.android.debuggable");
  });

  it("完全讀不懂的 manifest 會說出來，而不是回報零發現", () => {
    const facts = parseAndroidManifest("<!doctype html><html><body>404</body></html>");
    expect(facts.looksParseable).toBe(false);
    const findings = analyzeManifest(facts, "m");
    expect(ids(findings)).toEqual(["shell.android.unparseable"]);
    expect(findings[0]?.detail).toContain("沒有發現不等於沒有問題");
  });
});

describe("classifyCapabilityScope", () => {
  it.each(["*", "https://*", "http://*/", "https://*/anything", "https://*.*"])("%s 是對整個網際網路開放", (url) => {
    expect(classifyCapabilityScope(url)).toBe("whole-web");
  });

  it("綁在具體註冊網域上的子網域萬用不是全開——報成 critical 會讓人把整組告警關掉", () => {
    expect(classifyCapabilityScope("https://*.aios-internal.com/*")).toBe("subdomain-wildcard");
  });

  it("host 寫死、只有路徑用萬用是正常寫法", () => {
    expect(classifyCapabilityScope("https://ai-os-app.zeabur.app/*")).toBe("specific");
  });

  it("三種範圍在 analyzeTauri 產生不同的嚴重度", () => {
    const conf = parseTauriConfig('{"app":{"security":{"csp":"default-src \'self\'"},"windows":[{"url":"https://a.test"}]}}')!;
    const whole = analyzeTauri(conf, [{ identifier: "w", remote: { urls: ["https://*"] } }], "t");
    const sub = analyzeTauri(conf, [{ identifier: "s", remote: { urls: ["https://*.a.test/*"] } }], "t");
    const specific = analyzeTauri(conf, [{ identifier: "p", remote: { urls: ["https://a.test/*"] } }], "t");
    expect(whole.find((f) => f.id.startsWith("shell.tauri.capability-wildcard"))?.severity).toBe("critical");
    expect(sub.find((f) => f.id.startsWith("shell.tauri.capability-subdomain"))?.severity).toBe("medium");
    expect(ids(specific).some((id) => id.startsWith("shell.tauri.capability-"))).toBe(false);
  });
});

describe("parseCapabilityFile", () => {
  it("單一物件與陣列兩種形狀都吃", () => {
    expect(parseCapabilityFile('{"identifier":"a"}')).toHaveLength(1);
    expect(parseCapabilityFile('[{"identifier":"a"},{"identifier":"b"}]')).toHaveLength(2);
  });

  it("帶註解與尾逗號的 JSON5 也解得出來（Tauri v2 官方支援）", () => {
    const parsed = parseCapabilityFile(`{
      // 遠端能力
      "identifier": "remote-main",
      "remote": { "urls": ["https://a.test/*"], },
    }`);
    expect(parsed?.[0]?.identifier).toBe("remote-main");
  });

  it("真的壞掉時回 null，讓呼叫端把「沒稽核到」講出來", () => {
    expect(parseCapabilityFile("這不是 JSON")).toBeNull();
    expect(parseCapabilityFile("null")).toBeNull();
  });
});
