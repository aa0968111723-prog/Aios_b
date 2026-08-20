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
 * 把 origin 正規化成比對用的鍵。
 *
 * 直接比字串會把同一個部署當成兩個：主機名在 DNS 上不分大小寫（`https://Prod.test` 與
 * `https://prod.test` 是同一台），顯式的預設埠（`:443`）也一樣。誤判成「異源」的代價很具體——
 * 真正的同源漂移會被降級成 info，也就是那句「這是刻意設定時的預期結果」，然後沒有人去查。
 *
 * 與 core/runner.ts 的 perOrigin 一樣以 origin 為單位，兩處對「同不同源」必須給出同一個答案。
 */
export function originKey(origin: string): string {
  try {
    const url = new URL(origin);
    return `${url.origin.toLowerCase()}${url.pathname.replace(/\/+$/, "")}`;
  } catch {
    return origin.replace(/\/+$/, "").toLowerCase();
  }
}

/**
 * 比對三端建置資訊。
 *
 * 判準是**以 origin 分組**，不是「全體是否同源」：
 * 三端裡只要有一端刻意指向 staging，舊版就會把整組判為異源，於是另外兩端之間真正的
 * 同源漂移（快取沒更新、實例沒輪替）被降成 info 並附上一句「這是預期結果」——
 * 那正是這項檢查存在的唯一理由，卻被自己的降噪規則吃掉了。
 *
 * 所以現在兩件事分開講：同一個 origin 內的不一致是故障（high），
 * 不同 origin 之間的差異是設定意圖（info）。兩者可以同時出現。
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

  const byOrigin = new Map<string, SurfaceBuild[]>();
  for (const b of withSha) {
    const key = originKey(b.origin);
    byOrigin.set(key, [...(byOrigin.get(key) ?? []), b]);
  }

  // ── 同一個 origin 內的漂移＝故障 ────────────────────────────────────────
  for (const [key, group] of byOrigin) {
    if (group.length < 2) continue;

    const shas = new Set(group.map((b) => b.sha as string));
    if (shas.size > 1) {
      out.push(
        finding({
          ...base,
          id: "build-drift.sha-mismatch",
          severity: "high",
          title: "同一個站台對不同端回傳不同的 build 版本",
          detail:
            "這幾端連的是同一個網址，卻拿到不同的 build SHA。代表有節點沒更新到（邊緣快取、藍綠部署切換未完成、" +
            "或多實例部署不同步）。使用者會遇到「同樣操作在不同裝置行為不同」，而且工程師在自己的瀏覽器上重現不出來。",
          remediation: "清除邊緣快取並確認所有實例都跑同一版；檢查部署平台是否有實例卡在舊版沒被輪替。",
          evidence: group.map((b) => `${b.surface}（${b.origin}）→ ${b.sha}`).join("\n"),
          where: key,
        }),
      );
    }

    // 分支比對套用同一條分組規則：跨部署的分支差異本來就是設定意圖，
    // 只有同一個 origin 同時吐出兩個分支才是真的異常。
    const branches = new Set(group.map((b) => b.branch).filter(Boolean) as string[]);
    if (branches.size > 1) {
      out.push(
        finding({
          ...base,
          id: "build-drift.branch-mismatch",
          severity: "medium",
          title: "同一個站台對不同端回傳不同的 Git 分支",
          detail: "同一個部署不可能同時來自兩個分支，這代表實例之間跑著不同的建置產物，行為差異無從追蹤。",
          remediation: "確認所有實例都由同一條建置流水線產出，且正式部署一律來自預設分支。",
          evidence: group.map((b) => `${b.surface} → ${b.branch ?? "（無）"}`).join("\n"),
          where: key,
        }),
      );
    }
  }

  // ── 跨 origin 的差異＝設定意圖 ──────────────────────────────────────────
  if (byOrigin.size > 1) {
    const distinct = new Set(withSha.map((b) => b.sha as string));
    if (distinct.size > 1) {
      out.push(
        finding({
          ...base,
          id: "build-drift.cross-origin",
          severity: "info",
          title: "各端指向不同部署，版本不一致（設定使然）",
          detail:
            "這些端連的不是同一個站，版本自然不同。這是 AIOS_APP_TARGET／AIOS_DESKTOP_TARGET 這類設定的預期結果，" +
            "記錄下來供對照——若非刻意，請把三端的 target 設回同一個部署。",
          remediation: "若非刻意，把三端的 target 設回同一個部署。",
          evidence: withSha.map((b) => `${b.surface}（${b.origin}）→ ${b.sha}／${b.branch ?? "（無分支）"}`).join("\n"),
        }),
      );
    }
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
  const comparable = builds.filter((b) => b.reachable && b.sha);

  // 沒有比較基準時，「零發現」的意思是「沒比對」，不是「三端版本一致」。
  // cli.ts 只要有任一端可連就會排入這項檢查，所以單端掃描（--surfaces web）與
  // 三端裡兩端連不上，都會走到這裡；回 completed: true 會讓報告把「沒比對」畫成綠勾。
  if (comparable.length < 2) {
    const reachableCount = builds.filter((b) => b.reachable).length;
    return {
      ...base,
      completed: false,
      skippedReason:
        reachableCount < 2
          ? `只有 ${reachableCount} 端可連，沒有比較基準，本輪未做版本漂移判定。`
          : `只有 ${comparable.length} 端回報了 build SHA，沒有比較基準，本輪未做版本漂移判定。`,
      durationMs: elapsed(),
      findings,
      facts: { builds },
    };
  }

  return { ...base, completed: true, durationMs: elapsed(), findings, facts: { builds } };
}
