/**
 * 裝置紀錄與一致性監測。
 *
 * 三端＝同一個站被三種載體以不同 UA／視窗／能力載入。這組檢查做兩件事：
 *
 * 1. **裝置紀錄**：把每一端實際用來請求的裝置人格（UA、視窗、行動裝置、觸控、殼層標頭）
 *    原樣記進報告 facts——出事時能回答「我們當時是以什麼裝置在測」，也讓三端的差異可稽核。
 * 2. **一致性**：伺服器有沒有對某個裝置回不同的結果？例如只對 App 的 UA 回 403（把行動使用者
 *    擋在門外），或根本不因 UA 調整回應（缺 Vary: User-Agent，代理快取可能把桌面版餵給手機）。
 *
 * 判定為純函式，實際發請求集中在 checkDevice。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

const base = { check: "device", category: "monitoring" as const };

export interface DeviceRecord {
  surface: string;
  label: string;
  userAgent: string;
  viewport: { width: number; height: number };
  isMobile: boolean;
  hasTouch: boolean;
  extraHeaders: Record<string, string>;
  /** 實測觀測到的回應狀態與 Vary 標頭；連不上時 status 為 0 並附上原因。 */
  observed?: { status: number; vary: string | null; contentType: string | null; error?: string };
}

/** 把一個 surface 轉成裝置紀錄（未含實測觀測值）。 */
export function deviceRecordOf(surface: Surface): DeviceRecord {
  return {
    surface: surface.id,
    label: surface.label,
    userAgent: surface.userAgent,
    viewport: surface.viewport,
    isMobile: surface.isMobile,
    hasTouch: surface.isMobile,
    extraHeaders: surface.extraHeaders ?? {},
  };
}

/** 裝置人格的內部一致性：行動端該有行動視窗與行動 UA，桌面端不該自稱 Mobile。 */
export function analyzePersonaConsistency(record: DeviceRecord): Finding[] {
  const out: Finding[] = [];
  const uaMobile = /Mobile|Android|iPhone/i.test(record.userAgent);
  if (record.isMobile && (!uaMobile || record.viewport.width > 600)) {
    out.push(
      finding({
        ...base,
        surface: record.surface as DeviceRecord["surface"] & Finding["surface"],
        id: `device.persona-mismatch.${record.surface}`,
        severity: "low",
        title: `${record.label}：裝置人格不一致`,
        detail:
          "這一端被標為行動裝置，但 UA 或視窗寬度看起來不像手機。人格對不齊會讓頁面測試測到的不是真實行動使用者的情境。",
        remediation: "校正該 surface 的 userAgent／viewport／isMobile，使其一致反映目標裝置。",
        evidence: `ua="${record.userAgent}" viewport=${record.viewport.width}x${record.viewport.height}`,
      }),
    );
  }
  return out;
}

export interface DeviceObservation {
  record: DeviceRecord;
  status: number;
  vary: string | null;
  /** 其他端觀測到的狀態，用來判斷是否只有這一端被擋。 */
  peerStatuses: number[];
}

export function analyzeDeviceResponse(obs: DeviceObservation): Finding[] {
  const out: Finding[] = [];
  const { record, status, peerStatuses } = obs;

  // 只有這一端被擋（403/451）而其他端正常＝伺服器按裝置歧視。
  const blocked = status === 403 || status === 451;
  const peersOk = peerStatuses.some((s) => s >= 200 && s < 400);
  if (blocked && peersOk) {
    out.push(
      finding({
        ...base,
        surface: record.surface as Finding["surface"],
        id: `device.blocked.${record.surface}`,
        severity: "high",
        title: `${record.label}：此裝置被伺服器擋下（HTTP ${status}）`,
        detail:
          "其他端可以正常載入，唯獨這個裝置的 UA 拿到 4xx。可能是 WAF／UA 過濾把真實使用者（尤其是 App WebView）誤擋，這種問題在桌面瀏覽器上永遠重現不出來。",
        remediation: "檢查反向代理／WAF 的 UA 規則，確認沒有把 App 或桌面殼層的 UA 列入封鎖。",
        evidence: `ua="${record.userAgent}" → ${status}`,
        where: undefined,
      }),
    );
  }

  return out;
}

export async function checkDevice(surfaces: Surface[], timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const meta = { ...base, surface: "all" as const };

  // 帳本要涵蓋**每一個受測端**，包含連不上的那些。
  //
  // 舊版只把成功的端放進 records，於是三端裡兩端連不上時，帳本只剩一筆、檢查照樣回
  // completed: true。這個檢查唯一的產出就是「我們當時是以什麼裝置在測」——帳本悄悄少掉兩端，
  // 等於報告在回答那個問題時說了謊。
  const records: DeviceRecord[] = [];
  const probed: Array<{ record: DeviceRecord; status: number; vary: string | null }> = [];
  const unreachable: string[] = [];

  for (const surface of surfaces) {
    const record = deviceRecordOf(surface);
    findings.push(...analyzePersonaConsistency(record));
    records.push(record);

    const res = await tryProbe(surface.origin, { surface, timeoutMs, followRedirects: 2 });
    if (isProbeFailure(res)) {
      record.observed = { status: 0, vary: null, contentType: null, error: res.error };
      unreachable.push(surface.id);
      probed.push({ record, status: 0, vary: null });
      continue;
    }
    const vary = res.headers.get("vary");
    record.observed = { status: res.status, vary, contentType: res.headers.get("content-type") };
    probed.push({ record, status: res.status, vary });
  }

  for (const p of probed) {
    const peerStatuses = probed.filter((o) => o.record.surface !== p.record.surface).map((o) => o.status);
    findings.push(...analyzeDeviceResponse({ record: p.record, status: p.status, vary: p.vary, peerStatuses }));
  }

  const observedCount = probed.length - unreachable.length;

  // 部分端沒被觀測到，要在發現清單上留下痕跡。帳本裡有那筆紀錄，但 observed.status 為 0——
  // 而讀者不會逐筆去看 facts，只會看發現清單。
  for (const id of unreachable) {
    const record = records.find((r) => r.surface === id);
    findings.push(
      finding({
        ...base,
        surface: id as Finding["surface"],
        id: `device.unobserved.${id}`,
        severity: "low",
        title: `${record?.label ?? id}：這一端沒有被觀測到`,
        detail:
          `以這個裝置人格請求站台失敗（${record?.observed?.error ?? "原因不明"}）。` +
          "裝置紀錄裡留有它的人格，但沒有實測回應——跨端比對也因此缺了這一端，" +
          "「只有某個裝置被擋下」這類問題本輪對它無從判定。",
        remediation: "確認該端的 target 設定正確且從此網路環境連得到；三端應指向同一個部署，除非刻意分開。",
        evidence: record?.observed?.error ?? undefined,
      }),
    );
  }

  return {
    ...meta,
    completed: observedCount > 0,
    skippedReason: observedCount === 0 ? "所有裝置都連不到站台，無法建立裝置紀錄。" : undefined,
    durationMs: elapsed(),
    findings,
    // 裝置紀錄：報告 JSON 會原樣保留，作為「本次以什麼裝置測」的稽核憑據。
    facts: { deviceLedger: records, unobserved: unreachable },
  };
}
