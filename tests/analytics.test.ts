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

describe("parsePosthogSource / analyzePosthogSource", () => {
  it("讀出 ai_os 現況：有接、用 env、開例外擷取、關 console 擷取", () => {
    const f = parsePosthogSource(AIOS_POSTHOG);
    expect(f.wired).toBe(true);
    expect(f.usesEnvKey).toBe(true);
    expect(f.captureUnhandledErrors).toBe(true);
    expect(f.captureConsoleErrors).toBe(false);
    expect(f.personalKeyLeak).toBeNull();
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
    const findings = analyzePosthogRuntime({ entryJs: "console.log('no analytics here')", cspScriptSrc: null }, web, "app.js");
    expect(ids(findings)).toEqual(["analytics.posthog.not-loaded"]);
    expect(findings[0]!.severity).toBe("high");
  });

  it("有載但 CSP 沒放行 PostHog＝high（被瀏覽器擋掉）", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: `api_host:"https://us.posthog.com"`, cspScriptSrc: ["'self'"] },
      web,
      "app.js",
    );
    expect(ids(findings)).toEqual(["analytics.posthog.csp-blocked"]);
  });

  it("有載且 CSP 放行 https://*.posthog.com＝無發現", () => {
    const findings = analyzePosthogRuntime(
      { entryJs: `api_host:"https://us.posthog.com"`, cspScriptSrc: ["'self'", "https://*.posthog.com"] },
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
