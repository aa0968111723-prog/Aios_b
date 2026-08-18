import { describe, expect, it } from "vitest";
import { analyzeDeviceResponse, analyzePersonaConsistency, deviceRecordOf } from "../src/detectors/device.js";
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
