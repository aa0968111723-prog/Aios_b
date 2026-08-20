/**
 * 健康與就緒檢測的測試。
 *
 * 這組檢查回答的是最基本的問題：「站台現在能不能服務？」——所以它答錯的代價特別直接。
 * 這裡盯住兩個具體的失效方向：
 *
 * 1. **假綠燈**：站台自己說「我還不能服務」，而報告印出「✓ 沒有發現問題」。
 * 2. **假警報**：分項用字串狀態（`{"db":"ok"}`）而不是 `{ok:true}`，於是一個健康的站台
 *    被報成 db／boot／storage 全掛。
 *
 * 測試以假的 fetch 驅動 checkHealth，不發出任何真實網路請求。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkHealth, componentState } from "../src/detectors/health.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const web = buildSurfaces("https://ai-os-app.zeabur.app")[0]!;
const ids = (findings: Array<{ id: string }>) => findings.map((f) => f.id);

const HEALTHY = JSON.stringify({ ok: true, time: "2026-08-20T00:00:00Z", build: { sha: "abc1234", branch: "main" } });

/** 依 URL 分派回應：/api/health 一律健康，/api/ready 由測試指定。 */
function stub(ready: { status: number; body: string }): void {
  vi.stubGlobal("fetch", async (input: string | URL) => {
    const url = String(input);
    if (url.includes("/api/ready")) {
      return new Response(ready.body, { status: ready.status, headers: { "content-type": "application/json" } });
    }
    return new Response(HEALTHY, { status: 200, headers: { "content-type": "application/json" } });
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("componentState", () => {
  it("布林與 { ok: boolean } 兩種寫法都認得", () => {
    expect(componentState(true)).toBe("ok");
    expect(componentState(false)).toBe("failed");
    expect(componentState({ ok: true })).toBe("ok");
    expect(componentState({ ok: false })).toBe("failed");
  });

  it("狀態字串也認得——各家健康檢查慣例的通過字樣", () => {
    expect(componentState("ok")).toBe("ok");
    expect(componentState("UP")).toBe("ok");
    expect(componentState("healthy")).toBe("ok");
    expect(componentState("skipped")).toBe("ok");
    expect(componentState("failed")).toBe("failed");
    expect(componentState("down")).toBe("failed");
  });

  it("認不得的一律回 unknown——猜錯的方向兩邊都有代價，所以不猜", () => {
    expect(componentState(undefined)).toBe("unknown");
    expect(componentState({})).toBe("unknown");
    expect(componentState({ note: "沒有 ok 欄位" })).toBe("unknown");
    expect(componentState("藍色")).toBe("unknown");
    expect(componentState(42)).toBe("unknown");
  });
});

describe("checkHealth — 整體就緒狀態", () => {
  it("就緒回 500 且沒有分項時報 high，不是零發現", async () => {
    stub({ status: 500, body: JSON.stringify({ ok: false, error: "db pool exhausted" }) });
    const result = await checkHealth(web, 1000);
    const notOk = result.findings.find((f) => f.id === "ready.not-ok");
    expect(notOk?.severity).toBe("high");
    expect(notOk?.evidence).toContain("db pool exhausted");
  });

  it("就緒回 503 且沒有分項時同樣報 high", async () => {
    stub({ status: 503, body: JSON.stringify({ ok: false, error: "booting" }) });
    expect(ids((await checkHealth(web, 1000)).findings)).toContain("ready.not-ok");
  });

  it("狀態 200 但 ok:false（自相矛盾）也要報", async () => {
    stub({ status: 200, body: JSON.stringify({ ok: false }) });
    expect(ids((await checkHealth(web, 1000)).findings)).toContain("ready.not-ok");
  });

  it("分項已經指出故障點時不重複報——讀者要的是故障點，不是再一句「總之沒就緒」", async () => {
    stub({
      status: 503,
      body: JSON.stringify({ ok: false, components: { db: { ok: false, note: "connection refused" }, boot: { ok: true } } }),
    });
    const found = ids((await checkHealth(web, 1000)).findings);
    expect(found).toContain("ready.component.db");
    expect(found).not.toContain("ready.not-ok");
  });

  it("整體未就緒但所有分項都通過＝判定不一致", async () => {
    stub({ status: 503, body: JSON.stringify({ ok: false, components: { db: { ok: true }, boot: { ok: true } } }) });
    expect(ids((await checkHealth(web, 1000)).findings)).toContain("ready.inconsistent");
  });

  it("一切正常時零發現", async () => {
    stub({ status: 200, body: JSON.stringify({ ok: true, components: { db: { ok: true }, storage: { ok: true } } }) });
    const result = await checkHealth(web, 1000);
    expect(result.findings).toEqual([]);
    expect(result.completed).toBe(true);
  });
});

describe("checkHealth — 分項形狀", () => {
  it("分項用字串狀態時不會被誤報成全掛（過去會噴出五筆 critical／high）", async () => {
    stub({
      status: 200,
      body: JSON.stringify({
        ok: true,
        processRole: "web",
        components: { db: "ok", boot: "ok", storage: "ok", runner: "skipped", provider: "ok" },
      }),
    });
    const result = await checkHealth(web, 1000);
    expect(result.findings).toEqual([]);
  });

  it("字串狀態表示故障時照樣抓得到", async () => {
    stub({ status: 503, body: JSON.stringify({ ok: false, components: { db: "down", boot: "ok" } }) });
    expect((await checkHealth(web, 1000)).findings.find((f) => f.id === "ready.component.db")?.severity).toBe("critical");
  });

  it("判讀不出來的分項回報成 low 的「沒判定」，而不是故障", async () => {
    stub({ status: 200, body: JSON.stringify({ ok: true, components: { db: { note: "沒有 ok 欄位" } } }) });
    const findings = (await checkHealth(web, 1000)).findings;
    expect(ids(findings)).toContain("ready.component-shape");
    expect(ids(findings)).not.toContain("ready.component.db");
    expect(findings.find((f) => f.id === "ready.component-shape")?.detail).toContain("本輪沒有被判定");
  });
});
