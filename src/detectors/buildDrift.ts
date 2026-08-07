/**
 * 三端版本漂移檢測。
 *
 * 這是「連動三端」最實質的一項。aios 的 App 與桌面都是 WebView 直連線上站，
 * 所以正常情況下三端拿到的 build SHA 必然相同——**不同就是異常**，而且是那種
 * 「使用者回報的 bug 在網頁上重現不出來」的異常來源：
 *   - CDN／邊緣快取只更新了一部分節點；
 *   - App 或桌面被釘在不同環境（staging／舊部署）；
 *   - 藍綠部署切換到一半，不同連線落到不同版本。
 *
 * 判定函式是純的，測試不需要網路。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, parseJson, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

export interface SurfaceBuild {
  surface: SurfaceId;
  origin: string;
  sha: string | null;
  branch: string | null;
  builtAt: string | null;
  reachable: boolean;
}

/**
 * 比對三端建置資訊。
 *
 * 只在「兩端指向同一個 origin」時把不一致判為 high——同源卻拿到不同版本代表快取／部署出了問題。
 * 刻意指向不同 origin（例如桌面測 staging）時降為 info，因為那是設定意圖，不是故障。
 */
export function analyzeBuildDrift(builds: SurfaceBuild[]): Finding[] {
  const base = { check: "build-drift", category: "integrity" as const, surface: "all" as const };
  const out: Finding[] = [];
  const reachable = builds.filter((b) => b.reachable);

  if (reachable.length < 2) return out; // 少於兩端可比就沒有漂移可言

  const withSha = reachable.filter((b) => b.sha);
  if (withSha.length < reachable.length) {
    const missing = reachable.filter((b) => !b.sha).map((b) => b.surface);
    out.push(
      finding({
        ...base,
        id: "build-drift.sha-missing",
        severity: "low",
        title: `部分端點沒有回報 build SHA（${missing.join("、")}）`,
        detail: "缺少版本識別的那一端無法納入漂移比對，等於在版本一致性上有盲區。",
        remediation: "確認建置流程對所有部署目標都注入 BUILD_SHA。",
      }),
    );
  }

  if (withSha.length < 2) return out;

  const shas = new Set(withSha.map((b) => b.sha as string));
  if (shas.size > 1) {
    // 同源 vs 異源：決定這是故障還是設定意圖
    const originsBySha = new Map<string, Set<string>>();
    for (const b of withSha) {
      const set = originsBySha.get(b.sha as string) ?? new Set<string>();
      set.add(b.origin);
      originsBySha.set(b.sha as string, set);
    }
    const allOrigins = new Set(withSha.map((b) => b.origin));
    const sameOrigin = allOrigins.size === 1;

    out.push(
      finding({
        ...base,
        id: "build-drift.sha-mismatch",
        severity: sameOrigin ? "high" : "info",
        title: sameOrigin
          ? "同一個站台對不同端回傳不同的 build 版本"
          : "三端指向不同部署，版本不一致（設定使然）",
        detail: sameOrigin
          ? "三端連的是同一個網址，卻拿到不同的 build SHA。代表有節點沒更新到（邊緣快取、藍綠部署切換未完成、或多實例部署不同步）。使用者會遇到「同樣操作在不同裝置行為不同」，而且工程師在自己的瀏覽器上重現不出來。"
          : "各端指向不同部署，版本自然不同。這是刻意設定時的預期結果，記錄下來供對照。",
        remediation: sameOrigin
          ? "清除邊緣快取並確認所有實例都跑同一版；檢查部署平台是否有實例卡在舊版沒被輪替。"
          : "若非刻意，請把三端的 target 設回同一個部署。",
        evidence: withSha.map((b) => `${b.surface}（${b.origin}）→ ${b.sha}`).join("\n"),
      }),
    );
  }

  const branches = new Set(withSha.map((b) => b.branch).filter(Boolean) as string[]);
  if (branches.size > 1) {
    out.push(
      finding({
        ...base,
        id: "build-drift.branch-mismatch",
        severity: "medium",
        title: "三端來自不同的 Git 分支",
        detail: "不同端跑在不同分支上，功能與修補的落差難以追蹤，回報問題時也無法確定該看哪份程式碼。",
        remediation: "確認正式部署一律來自預設分支。",
        evidence: withSha.map((b) => `${b.surface} → ${b.branch ?? "（無）"}`).join("\n"),
      }),
    );
  }

  return out;
}

interface HealthPayload {
  build?: { sha?: string | null; branch?: string | null; builtAt?: string | null };
}

export async function checkBuildDrift(surfaces: Surface[], timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const base = { check: "build-drift", category: "integrity" as const, surface: "all" as const };
  const builds: SurfaceBuild[] = [];

  for (const surface of surfaces) {
    const url = join(surface.origin, "/api/health");
    const res = await tryProbe(url, { surface, timeoutMs, followRedirects: 2 });
    if (isProbeFailure(res)) {
      builds.push({ surface: surface.id, origin: surface.origin, sha: null, branch: null, builtAt: null, reachable: false });
      continue;
    }
    const body = parseJson<HealthPayload>(res.body);
    builds.push({
      surface: surface.id,
      origin: surface.origin,
      sha: body?.build?.sha ?? null,
      branch: body?.build?.branch ?? null,
      builtAt: body?.build?.builtAt ?? null,
      reachable: true,
    });
  }

  const findings: Finding[] = analyzeBuildDrift(builds);
  return { ...base, completed: true, durationMs: elapsed(), findings, facts: { builds } };
}
