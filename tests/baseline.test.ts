import { describe, expect, it } from "vitest";
import {
  diffFindings,
  findingKey,
  hasNewFindings,
  isEscalation,
  parseBaseline,
  summarizeDiff,
} from "../src/core/baseline.js";
import { dedupe } from "../src/core/findings.js";
import type { Finding } from "../src/core/types.js";

/** 只填比對用得到的欄位，其餘給無關痛癢的預設，讓每個測試的意圖一眼看得出來。 */
const mk = (over: Partial<Finding> & Pick<Finding, "id" | "severity">): Finding => ({
  check: "headers",
  category: "security",
  surface: "web",
  title: over.id,
  detail: "測試用",
  remediation: "測試用",
  ...over,
});

const ids = (findings: Finding[]) => findings.map((f) => f.id);

const HSTS = mk({ id: "headers.hsts.missing", severity: "high", where: "https://a.test/" });
const NOSNIFF = mk({ id: "headers.nosniff", severity: "medium", where: "https://a.test/" });

describe("findingKey", () => {
  it("與 dedupe() 用同一把鍵——去重會折掉的兩筆，比對也必須視為同一件事", () => {
    const a = mk({ id: "headers.hsts.missing", severity: "high", where: "https://a.test/" });
    const b = mk({ id: "headers.hsts.missing", severity: "critical", where: "https://a.test/" });
    expect(dedupe([a, b])).toHaveLength(1);
    expect(findingKey(a)).toBe(findingKey(b));
    expect(findingKey(a)).toBe("headers.hsts.missing::https://a.test/");
  });

  it("沒有 where 的發現以空字串入鍵，不會與有 where 的同 id 混為一談", () => {
    const global = mk({ id: "csp.missing", severity: "high" });
    const scoped = mk({ id: "csp.missing", severity: "high", where: "https://a.test/" });
    expect(findingKey(global)).toBe("csp.missing::");
    expect(findingKey(global)).not.toBe(findingKey(scoped));
  });
});

describe("diffFindings", () => {
  it("上次沒有、這次才出現的算新增", () => {
    const diff = diffFindings([HSTS], [HSTS, NOSNIFF]);
    expect(ids(diff.added)).toEqual(["headers.nosniff"]);
    expect(ids(diff.unchanged)).toEqual(["headers.hsts.missing"]);
    expect(diff.fixed).toEqual([]);
  });

  it("上次有、這次沒有的算已修復", () => {
    const diff = diffFindings([HSTS, NOSNIFF], [HSTS]);
    expect(ids(diff.fixed)).toEqual(["headers.nosniff"]);
    expect(diff.added).toEqual([]);
  });

  it("兩次都在且嚴重度相同的是存量問題，留在 unchanged 而不是 changed", () => {
    const diff = diffFindings([HSTS], [HSTS]);
    expect(ids(diff.unchanged)).toEqual(["headers.hsts.missing"]);
    expect(diff.changed).toEqual([]);
    expect(diff.added).toEqual([]);
    expect(diff.fixed).toEqual([]);
  });

  it("嚴重度變高列入 changed，且判定為惡化", () => {
    const worse = mk({ ...HSTS, severity: "critical" });
    const diff = diffFindings([HSTS], [worse]);
    expect(diff.changed).toHaveLength(1);
    const change = diff.changed[0];
    expect(change?.key).toBe(findingKey(HSTS));
    expect(change?.before.severity).toBe("high");
    expect(change?.after.severity).toBe("critical");
    expect(change && isEscalation(change)).toBe(true);
  });

  it("嚴重度變低是減輕，不是惡化", () => {
    const better = mk({ ...HSTS, severity: "low" });
    const diff = diffFindings([HSTS], [better]);
    expect(diff.changed).toHaveLength(1);
    expect(diff.changed[0] && isEscalation(diff.changed[0])).toBe(false);
  });

  it("同一個 id 出現在不同 where 是不同筆——路徑換了就是換了一件事", () => {
    const onOther = mk({ ...HSTS, where: "https://b.test/" });
    const diff = diffFindings([HSTS], [onOther]);
    expect(diff.added).toEqual([onOther]);
    expect(diff.fixed).toEqual([HSTS]);
    expect(diff.changed).toEqual([]);
  });

  it("unchanged 留的是這次的觀測，證據以最新為準", () => {
    const fresher = mk({ ...HSTS, evidence: "本次觀測" });
    const diff = diffFindings([mk({ ...HSTS, evidence: "上次觀測" })], [fresher]);
    expect(diff.unchanged[0]?.evidence).toBe("本次觀測");
  });

  it("基準有重複鍵時以第一筆為準（與 dedupe 同規則，避免結果隨執行順序飄移）", () => {
    const first = mk({ ...HSTS, severity: "high" });
    const dup = mk({ ...HSTS, severity: "low" });
    const diff = diffFindings([first, dup], [mk({ ...HSTS, severity: "high" })]);
    expect(diff.changed).toEqual([]);
    expect(ids(diff.unchanged)).toEqual(["headers.hsts.missing"]);
  });

  it("本次有重複鍵時只算一筆新增", () => {
    const diff = diffFindings([], [HSTS, mk({ ...HSTS, severity: "low" })]);
    expect(diff.added).toHaveLength(1);
    expect(diff.added[0]?.severity).toBe("high");
  });

  it("空基準代表上次全綠：這次每一筆都是新增", () => {
    const diff = diffFindings([], [HSTS, NOSNIFF]);
    expect(ids(diff.added)).toEqual(["headers.hsts.missing", "headers.nosniff"]);
    expect(diff.fixed).toEqual([]);
    expect(diff.unchanged).toEqual([]);
  });

  it("兩次都沒有發現時四個欄位都是空的", () => {
    expect(diffFindings([], [])).toEqual({ added: [], fixed: [], unchanged: [], changed: [] });
  });
});

describe("summarizeDiff", () => {
  it("惡化與減輕分開計數，存量另計", () => {
    const previous = [
      HSTS,
      NOSNIFF,
      mk({ id: "cookies.httponly.sid", severity: "low", where: "https://a.test/" }),
      mk({ id: "csp.missing", severity: "high" }),
    ];
    const current = [
      HSTS,
      mk({ ...NOSNIFF, severity: "low" }),
      mk({ id: "cookies.httponly.sid", severity: "critical", where: "https://a.test/" }),
      mk({ id: "cors.reflects-origin", severity: "critical", where: "https://a.test/api" }),
    ];
    expect(summarizeDiff(diffFindings(previous, current))).toEqual({
      added: 1,
      fixed: 1,
      unchanged: 1,
      escalated: 1,
      improved: 1,
    });
  });
});

describe("parseBaseline", () => {
  it("讀得懂完整報告的 results[].findings[]，並帶出基準的站台與時間", () => {
    const json = JSON.stringify({
      startedAt: "2026-08-19T01:00:00.000Z",
      target: "https://aios.test",
      results: [
        { check: "transport", findings: [HSTS] },
        { check: "csp", findings: [NOSNIFF] },
      ],
    });
    const { snapshot, error } = parseBaseline(json);
    expect(error).toBeNull();
    expect(ids(snapshot?.findings ?? [])).toEqual(["headers.hsts.missing", "headers.nosniff"]);
    expect(snapshot?.target).toBe("https://aios.test");
    expect(snapshot?.startedAt).toBe("2026-08-19T01:00:00.000Z");
  });

  it("被跳過的檢查沒有 findings 欄位也不會讓解析失敗", () => {
    const json = JSON.stringify({ results: [{ check: "pages", skippedReason: "缺 playwright" }, { findings: [HSTS] }] });
    const { snapshot, error } = parseBaseline(json);
    expect(error).toBeNull();
    expect(ids(snapshot?.findings ?? [])).toEqual(["headers.hsts.missing"]);
  });

  it("接受只有 findings 陣列的精簡格式（此時沒有 target 可比，回 null）", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify({ findings: [HSTS] }));
    expect(error).toBeNull();
    expect(ids(snapshot?.findings ?? [])).toEqual(["headers.hsts.missing"]);
    expect(snapshot?.target).toBeNull();
    expect(snapshot?.startedAt).toBeNull();
  });

  it("也接受裸的發現陣列", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify([HSTS, NOSNIFF]));
    expect(error).toBeNull();
    expect(snapshot?.findings).toHaveLength(2);
  });

  it("缺少顯示欄位的舊紀錄照樣還原，不因為少一句修法就作廢整份基準", () => {
    const { snapshot, error } = parseBaseline(
      JSON.stringify([{ id: "headers.nosniff", severity: "medium", where: "https://a.test/" }]),
    );
    expect(error).toBeNull();
    const restored = snapshot?.findings[0];
    expect(restored?.title).toBe("headers.nosniff");
    expect(restored?.check).toBe("headers");
    expect(restored?.where).toBe("https://a.test/");
  });

  it("壞掉的 JSON 回 error 而不是丟例外", () => {
    const { snapshot, error } = parseBaseline("{ 這不是 JSON");
    expect(snapshot).toBeNull();
    expect(error).toMatch(/不是合法 JSON/);
  });

  it("認不出的結構回 error，不會被當成空基準吞掉", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify({ hello: "world" }));
    expect(snapshot).toBeNull();
    expect(error).toMatch(/認不出來/);
  });

  it("紀錄缺 id 時整份判定失敗——靜默丟掉那筆會讓這次的同一個問題被誤報成新增", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify({ findings: [HSTS, { severity: "high" }] }));
    expect(snapshot).toBeNull();
    expect(error).toMatch(/第 2 筆/);
    expect(error).toMatch(/缺少 id/);
  });

  it("severity 不是合法等級時同樣回 error（分不出惡化與減輕的基準不可信）", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify([{ id: "headers.nosniff", severity: "urgent" }]));
    expect(snapshot).toBeNull();
    expect(error).toMatch(/severity/);
  });

  it("空基準與沒有基準是兩件事：前者是可信的「上次全綠」，後者是無從比較", () => {
    const empty = parseBaseline(JSON.stringify({ startedAt: "2026-08-19T01:00:00.000Z", target: "https://aios.test", results: [] }));
    expect(empty.error).toBeNull();
    expect(empty.snapshot?.findings).toEqual([]);
    expect(ids(diffFindings(empty.snapshot?.findings ?? [], [HSTS]).added)).toEqual(["headers.hsts.missing"]);

    const broken = parseBaseline("nope");
    expect(broken.snapshot).toBeNull();
    expect(broken.error).not.toBeNull();
  });

  it("基準測的是別的站時照樣比對，但 target 要回得出來讓呼叫端提醒讀者", () => {
    const { snapshot } = parseBaseline(JSON.stringify({ target: "https://staging.aios.test", findings: [HSTS] }));
    expect(snapshot?.target).toBe("https://staging.aios.test");
    expect(diffFindings(snapshot?.findings ?? [], [HSTS]).unchanged).toHaveLength(1);
  });
});

describe("hasNewFindings", () => {
  it("新增的問題達到門檻就要擋", () => {
    const diff = diffFindings([], [mk({ id: "cors.reflects-origin", severity: "critical" })]);
    expect(hasNewFindings(diff, "high")).toBe(true);
  });

  it("新增但未達門檻不擋（門檻語意是達到或超過）", () => {
    const diff = diffFindings([], [NOSNIFF]);
    expect(hasNewFindings(diff, "high")).toBe(false);
    expect(hasNewFindings(diff, "medium")).toBe(true);
  });

  it("存量問題不擋 CI——就算它是 critical", () => {
    const legacy = mk({ id: "disclosure.env", severity: "critical", where: "https://a.test/.env" });
    const diff = diffFindings([legacy], [legacy]);
    expect(diff.unchanged).toHaveLength(1);
    expect(hasNewFindings(diff, "critical")).toBe(false);
  });

  it("已修復的問題當然不擋", () => {
    expect(hasNewFindings(diffFindings([mk({ id: "csp.missing", severity: "high" })], []), "high")).toBe(false);
  });

  it("存量問題惡化到門檻要擋——危害不會因為它上次就在而減少", () => {
    const diff = diffFindings(
      [mk({ id: "cookies.httponly.sid", severity: "low", where: "https://a.test/" })],
      [mk({ id: "cookies.httponly.sid", severity: "critical", where: "https://a.test/" })],
    );
    expect(hasNewFindings(diff, "high")).toBe(true);
  });

  it("惡化但未達門檻不擋", () => {
    const diff = diffFindings(
      [mk({ id: "headers.coop", severity: "info" })],
      [mk({ id: "headers.coop", severity: "low" })],
    );
    expect(hasNewFindings(diff, "medium")).toBe(false);
  });

  it("嚴重度下降不算惡化，不擋", () => {
    const diff = diffFindings(
      [mk({ id: "cors.wildcard", severity: "critical", where: "https://a.test/api" })],
      [mk({ id: "cors.wildcard", severity: "low", where: "https://a.test/api" })],
    );
    expect(hasNewFindings(diff, "critical")).toBe(false);
  });
});
