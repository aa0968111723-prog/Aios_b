/**
 * 連通性前置檢查。
 *
 * 動機來自一次實測：在有出口代理的環境跑掃描，代理對每個請求回 403。
 * 各項檢查各自「沒有發現問題」，報告最後印出「✓ 沒有發現問題」——
 * 看起來全綠，實際上一個請求都沒到達站台。
 *
 * 這是檢測系統最不能接受的失效：**沉默的假綠燈**。與其讓每個偵測器各自誤判，
 * 不如在開跑前先確認這一端真的連得到；連不到就把該端的所有網路檢查標記為跳過，
 * 讓報告明白寫出「沒測到」而不是「沒問題」。
 */
import { isProbeFailure, join, looksLikeGatewayInterception, tryProbe } from "./http.js";
import type { Surface } from "./types.js";

export type Reachability = { ok: true } | { ok: false; reason: string };

export async function preflight(surface: Surface, timeoutMs: number): Promise<Reachability> {
  const url = join(surface.origin, "/");
  const res = await tryProbe(url, { surface, timeoutMs, followRedirects: 3, maxBodyBytes: 32 * 1024 });

  if (isProbeFailure(res)) {
    return {
      ok: false,
      reason: `${surface.label}：無法連線至 ${surface.origin}（${res.error}）。該端的所有網路檢查均未執行。`,
    };
  }

  if (
    looksLikeGatewayInterception({
      status: res.status,
      body: res.body,
      contentType: res.headers.get("content-type") ?? "",
    })
  ) {
    return {
      ok: false,
      reason:
        `${surface.label}：${surface.origin} 回應 HTTP ${res.status} 且內容不是應用回應，` +
        "判定為中介層（代理／WAF／平台閘道）攔截。該端的所有網路檢查均未實際觸及站台，" +
        "請從能直連目標的網路環境重跑。",
    };
  }

  return { ok: true };
}
