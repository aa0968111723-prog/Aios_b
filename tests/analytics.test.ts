import { describe, expect, it } from "vitest";
import {
  analyzePosthogInsight,
  analyzePosthogRuntime,
  analyzePosthogSource,
  detectPosthogInBundle,
  parsePosthogSource,
  summarizePosthogEvents,
} from "../src/detectors/analytics.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;
const ids = (f: Array<{ id: string }>) => f.map((x) => x.id);

/** ai_os 現況 posthog.ts 的摘要：有接、用 env 金鑰、開例外擷取、關 console 擷取。 */
const AIOS_POSTHOG = `
const posthogKey = import.meta.env.VITE_POSTHOG_KEY;
client.init(posthogKey, {
  api_host: posthogHost,
  capture_exceptions: {
    capture_unhandled_errors: true,
    capture_unhandled_rejections: true,
    capture_console_errors: false,
  },
});
`;

/**
 * 延遲載入代理的真實形狀：靜態模組裡有 env／init 選項，本體用 dynamic import("posthog-js")。
 * 靜態解析仍應讀得出例外擷取設定。
 */
const AIOS_POSTHOG_DEFERRED_PROXY = `
const posthogKey = import.meta.env.VITE_POSTHOG_KEY;
const posthogHost = import.meta.env.VITE_POSTHOG_HOST;
async function load() {
  const mod = await import("posthog-js");
  const client = mod.default;
  client.init(posthogKey, {
    api_host: posthogHost,
    capture_exceptions: {
      capture_unhandled_errors: true,
      capture_unhandled_rejections: true,
      capture_console_errors: false,
    },
  });
}
export default { capture() {}, identify() {}, reset() {} };
`;

describe("parsePosthogSource / analyzePosthogSource", () => {
  it("讀出 ai_os 現況：有接、用 env、開例外擷取、關 console 擷取", () => {
    const f = parsePosthogSource(AIOS_POSTHOG);
    expect(f.wired).toBe(true);
    expect(f.usesEnvKey).toBe(true);
    expect(f.captureUnhandledErrors).toBe(true);
    expect(f.captureConsoleErrors).toBe(false);
    expect(f.personalKeyLeak).toBeNull();
  });

  it("延遲載入代理原始碼仍能讀出例外擷取與 env 金鑰", () => {
    const f = parsePosthogSource(AIOS_POSTHOG_DEFERRED_PROXY);
    expect(f.wired).toBe(true);
    expect(f.usesEnvKey).toBe(true);
    expect(f.captureUnhandledErrors).toBe(true);
    expect(f.captureConsoleErrors).toBe(false);
    const findings = analyzePosthogSource(f, "client/src/posthog.ts");
    expect(ids(findings)).toEqual(["analytics.posthog.no-console-capture"]);
  });

  it("延遲載入代理的 entry 殘留字串仍判定有載 PostHog", () => {
    // 代理進 entry 後 minify 仍會留下 posthog host／識別字串；本體 chunk 不在此。
    const entry = `const ga="https://us.posthog.com";function load(){return import("posthog-js")}`;
    expect(detectPosthogInBundle(entry)).toEqual({ present: true, host: "https://us.posthog.com" });
  });

  it("ai_os 現況只報「未擷取 console 錯誤」的 low", () => {
    const findings = analyzePosthogSource(parsePosthogSource(AIOS_POSTHOG), "posthog.ts");
    expect(ids(findings)).toEqual(["analytics.posthog.no-console-capture"]);
    expect(findings[0]!.severity).toBe("low");
  });

  it("關閉例外擷取＝medium 監測盲區", () => {
    const src = AIOS_POSTHOG.replace("capture_unhandled_errors: true", "capture_unhandled_errors: false");
    const findings = analyzePosthogSource(parsePosthogSource(src), "posthog.ts");
    expect(ids(findings)).toContain("analytics.posthog.no-exception-capture");
  });

  it("個人金鑰寫死在前端＝critical 外洩", () => {
    const src = `${AIOS_POSTHOG}\nconst leak = "phx_abcdefghijklmnop1234";`;
    const findings = analyzePosthogSource(parsePosthogSource(src), "posthog.ts");
    const leak = findings.find((f) => f.id === "analytics.posthog.personal-key-leak");
    expect(leak?.severity).toBe("critical");
  });
});

describe("detectPosthogInBundle / analyzePosthogRuntime", () => {
  it("bundle 有 posthog 與 host 就抓得到", () => {
    const { present, host } = detectPosthogInBundle(`init("phc_x",{api_host:"https://eu.posthog.com"})`);
    expect(present).toBe(true);
    expect(host).toContain("posthog.com");
  });

  it("正式站沒載 PostHog＝high（事件會靜默全掉）", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: "console.log('no analytics here')", cspScriptSrc: null, entryComplete: true },
      web,
      "app.js",
    );
    expect(ids(findings)).toEqual(["analytics.posthog.not-loaded"]);
    expect(findings[0]!.severity).toBe("high");
  });

  // entry chunk 動輒數 MB，而 probe 有讀取上限。沒讀完就不能說裡面沒有 PostHog——
  // 猜一個 high 出來，比沉默更糟：那是報告裡最像真問題的一種假警報。
  it("bundle 沒讀完整時不報「未載入」", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: "console.log('前 512KB 裡剛好沒有')", cspScriptSrc: null, entryComplete: false },
      web,
      "app.js",
    );
    expect(findings).toEqual([]);
  });

  // 「這份政策沒有規範腳本來源」與「script-src 明確不含 PostHog」是兩件事。
  // 混為一談的話，`frame-ancestors 'none'` 這種單指令政策會讓分析被判成擋掉。
  it("CSP 沒有可據以判定的來源清單時不報被擋", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: `api_host:"https://us.posthog.com"`, cspScriptSrc: null, entryComplete: true },
      web,
      "app.js",
    );
    expect(findings).toEqual([]);
  });

  it("有載但 CSP 沒放行 PostHog＝high（被瀏覽器擋掉）", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: `api_host:"https://us.posthog.com"`, cspScriptSrc: ["'self'"], entryComplete: true },
      web,
      "app.js",
    );
    expect(ids(findings)).toEqual(["analytics.posthog.csp-blocked"]);
  });

  it("有載且 CSP 放行 https://*.posthog.com＝無發現", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: `api_host:"https://us.posthog.com"`, cspScriptSrc: ["'self'", "https://*.posthog.com"], entryComplete: true },
      web,
      "app.js",
    );
    expect(findings).toEqual([]);
  });
});

describe("summarizePosthogEvents / analyzePosthogInsight", () => {
  it("彙整事件量、例外量與裝置分布", () => {
    const insight = summarizePosthogEvents([
      { event: "$pageview", count: 100, deviceType: "Desktop" },
      { event: "$pageview", count: 40, deviceType: "Mobile" },
      { event: "$exception", count: 3, deviceType: "Mobile" },
    ]);
    expect(insight.totalEvents).toBe(143);
    expect(insight.exceptionEvents).toBe(3);
    expect(insight.topEvents[0]).toEqual({ event: "$pageview", count: 140 });
    expect(insight.devices.find((d) => d.type === "Mobile")?.count).toBe(43);
  });

  it("觀測窗內 0 事件＝high（分析疑似靜默失效）", () => {
    const findings = analyzePosthogInsight(summarizePosthogEvents([]), 24);
    expect(ids(findings)).toContain("analytics.posthog.no-recent-events");
  });

  it("有前端例外＝medium", () => {
    const insight = summarizePosthogEvents([{ event: "$exception", count: 5 }]);
    expect(ids(analyzePosthogInsight(insight, 24))).toContain("analytics.posthog.exceptions-observed");
  });
});
