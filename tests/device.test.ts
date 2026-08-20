import { describe, expect, it } from "vitest";
import { afterEach, vi } from "vitest";
import { analyzeDeviceResponse, analyzePersonaConsistency, checkDevice, deviceRecordOf } from "../src/detectors/device.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const [web, app, desktop] = buildSurfaces("https://ai-os-app.zeabur.app");
const ids = (f: Array<{ id: string }>) => f.map((x) => x.id);

describe("deviceRecordOf", () => {
  it("把 App surface 轉成裝置紀錄（行動、觸控、帶殼層 UA）", () => {
    const record = deviceRecordOf(app!);
    expect(record.surface).toBe("app");
    expect(record.isMobile).toBe(true);
    expect(record.hasTouch).toBe(true);
    expect(record.userAgent).toContain("AiosApp/1.0");
  });
});

describe("analyzePersonaConsistency", () => {
  it("ai_os 現況三端人格都自洽（無發現）", () => {
    expect(analyzePersonaConsistency(deviceRecordOf(web!))).toEqual([]);
    expect(analyzePersonaConsistency(deviceRecordOf(app!))).toEqual([]);
    expect(analyzePersonaConsistency(deviceRecordOf(desktop!))).toEqual([]);
  });

  it("標為行動卻是桌面 UA／寬視窗＝low 人格不一致", () => {
    const broken = { ...deviceRecordOf(web!), isMobile: true };
    expect(ids(analyzePersonaConsistency(broken))).toContain("device.persona-mismatch.web");
  });
});

describe("analyzeDeviceResponse", () => {
  it("只有某裝置被擋（403）而其他端正常＝high 按裝置歧視", () => {
    const findings = analyzeDeviceResponse({
      record: deviceRecordOf(app!),
      status: 403,
      vary: null,
      peerStatuses: [200, 200],
    });
    expect(ids(findings)).toEqual(["device.blocked.app"]);
    expect(findings[0]!.severity).toBe("high");
  });

  it("全部端都 403（非針對特定裝置）＝不報 device.blocked", () => {
    const findings = analyzeDeviceResponse({
      record: deviceRecordOf(app!),
      status: 403,
      vary: null,
      peerStatuses: [403, 403],
    });
    expect(findings).toEqual([]);
  });

  it("正常 200＝無發現", () => {
    const findings = analyzeDeviceResponse({
      record: deviceRecordOf(web!),
      status: 200,
      vary: "User-Agent",
      peerStatuses: [200, 200],
    });
    expect(findings).toEqual([]);
  });
});

/**
 * 裝置紀錄的完整性。
 *
 * 這個檢查唯一的產出就是「我們當時是以什麼裝置在測」。舊版只把連得上的端放進帳本，
 * 於是三端裡兩端連不上時帳本只剩一筆、檢查照樣回 completed: true——
 * 報告在回答那個問題時說了謊，而讀者無從得知另外兩端沒被測到。
 */
describe("checkDevice — 帳本完整性", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("連不上的端也要留在帳本裡，並在發現清單上留下痕跡", async () => {
    vi.stubGlobal("fetch", async (input: string | URL) => {
      if (String(input).includes("broken")) throw new Error("ECONNREFUSED");
      return new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } });
    });

    const surfaces = buildSurfaces("https://ai-os-app.zeabur.app", { app: "https://broken.example.test" });
    const result = await checkDevice(surfaces, 1000);
    const ledger = result.facts?.deviceLedger as Array<{ surface: string; observed?: { status: number } }>;

    expect(ledger.map((r) => r.surface).sort()).toEqual(["app", "desktop", "web"]);
    expect(ledger.find((r) => r.surface === "app")?.observed?.status).toBe(0);
    expect(ids(result.findings)).toContain("device.unobserved.app");
    expect(result.completed).toBe(true);
  });

  it("全部連不上時標記為沒測到", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    const result = await checkDevice(buildSurfaces("https://ai-os-app.zeabur.app"), 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("無法建立裝置紀錄");
  });

  it("三端都正常時帳本齊全且零發現", async () => {
    vi.stubGlobal("fetch", async () => new Response("<html></html>", { status: 200, headers: { "content-type": "text/html" } }));
    const result = await checkDevice(buildSurfaces("https://ai-os-app.zeabur.app"), 1000);
    expect((result.facts?.deviceLedger as unknown[]).length).toBe(3);
    expect(result.findings).toEqual([]);
  });
});
