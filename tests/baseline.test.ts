import { describe, expect, it } from "vitest";
import {
  diffFindings,
  findingKey,
  hasNewFindings,
  isEscalation,
  isImprovement,
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

  it("不改動傳進來的陣列——呼叫端手上的那份報告不該因為比對而變樣", () => {
    const previous = [HSTS, NOSNIFF];
    const current = [NOSNIFF];
    diffFindings(previous, current);
    expect(ids(previous)).toEqual(["headers.hsts.missing", "headers.nosniff"]);
    expect(ids(current)).toEqual(["headers.nosniff"]);
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

  it("沒有任何變化時五項都是 0", () => {
    expect(summarizeDiff({ added: [], fixed: [], unchanged: [], changed: [] })).toEqual({
      added: 0,
      fixed: 0,
      unchanged: 0,
      escalated: 0,
      improved: 0,
    });
  });

  it("嚴重度沒變的 changed 既不算惡化也不算減輕——報告不該多出一件根本沒發生的好消息", () => {
    // diffFindings 不會產出這種項目，但 ReportDiff 是公開型別，手工組或反序列化回來的都可能有。
    const flat = { key: findingKey(HSTS), before: HSTS, after: mk({ ...HSTS, evidence: "本次觀測" }) };
    expect(isEscalation(flat)).toBe(false);
    expect(isImprovement(flat)).toBe(false);
    expect(summarizeDiff({ added: [], fixed: [], unchanged: [], changed: [flat] })).toMatchObject({
      escalated: 0,
      improved: 0,
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

  it("空檔案有自己的說法，而不是丟一句 JSON 解析錯誤給維運者", () => {
    // 上一輪還沒寫完報告就掛掉、CI 快取還原出 0 位元組——這是實務上最常見的壞基準。
    const { snapshot, error } = parseBaseline("   ");
    expect(snapshot).toBeNull();
    expect(error).toMatch(/基準檔是空的/);
  });

  it("上一輪一項檢查都沒跑完的報告不可當基準——那是「什麼都沒驗」，不是「上次全綠」", () => {
    const json = JSON.stringify({
      target: "https://aios.test",
      results: [{ check: "headers", completed: false, skippedReason: "連不到站" }],
      summary: { total: 1, completed: 0 },
    });
    const { snapshot, error } = parseBaseline(json);
    expect(snapshot).toBeNull();
    expect(error).toMatch(/一項檢查都沒跑完/);
  });

  it("有檢查真的跑完、只是零發現的報告仍是可信的空基準", () => {
    const json = JSON.stringify({
      target: "https://aios.test",
      results: [{ check: "headers", completed: true, findings: [] }],
      summary: { total: 1, completed: 1 },
    });
    const { snapshot, error } = parseBaseline(json);
    expect(error).toBeNull();
    expect(snapshot?.findings).toEqual([]);
  });

  it("同時有頂層 findings 與 results 時回 error，不靜默挑一邊", () => {
    // 挑錯邊的代價不對稱地大：少讀到基準會讓存量問題整片變成「新增」而淹沒 CI。
    const { snapshot, error } = parseBaseline(JSON.stringify({ findings: [], results: [{ findings: [HSTS] }] }));
    expect(snapshot).toBeNull();
    expect(error).toMatch(/看不出哪一份/);
  });

  it("報告裡被抑制的發現不進基準——比對比的是讀者實際看得到的那份清單", () => {
    const json = JSON.stringify({
      target: "https://aios.test",
      summary: { total: 1, completed: 1 },
      results: [{ check: "headers", findings: [NOSNIFF] }],
      suppressed: [{ finding: HSTS, reason: "已知取捨", expires: null, owner: null }],
    });
    const { snapshot, error } = parseBaseline(json);
    expect(error).toBeNull();
    expect(ids(snapshot?.findings ?? [])).toEqual(["headers.nosniff"]);
    // 抑制規則被拿掉、那筆重新出現在報告上時，它對讀者而言就是新的。
    expect(ids(diffFindings(snapshot?.findings ?? [], [NOSNIFF, HSTS]).added)).toEqual(["headers.hsts.missing"]);
  });

  it("results 裡形狀不對的一筆會讓整份基準判定失敗，而不是被跳過", () => {
    expect(parseBaseline(JSON.stringify({ results: [null] })).error).toMatch(/results\[0\]/);
    expect(parseBaseline(JSON.stringify({ results: [{ check: "a", findings: 3 }] })).error).toMatch(/不是陣列/);
  });

  it("where 不是字串時回 error——鍵會算錯，整份比對就不可信了", () => {
    const { snapshot, error } = parseBaseline(JSON.stringify([{ id: "headers.nosniff", severity: "medium", where: 5 }]));
    expect(snapshot).toBeNull();
    expect(error).toMatch(/where/);
  });

  it("認不得的 category／surface 退回預設，空白標題退回 id，不把陌生字串當成合法值", () => {
    const { snapshot, error } = parseBaseline(
      JSON.stringify([{ id: "headers.nosniff", severity: "medium", category: "banana", surface: "ios", title: "  " }]),
    );
    expect(error).toBeNull();
    const restored = snapshot?.findings[0];
    expect(restored?.category).toBe("security");
    expect(restored?.surface).toBe("all");
    expect(restored?.title).toBe("headers.nosniff");
  });

  it("手工基準裡多打的空白不會讓同一筆問題變成「又新增又修好」", () => {
    const { snapshot } = parseBaseline(
      JSON.stringify([{ id: " headers.nosniff ", severity: "medium", where: " https://a.test/ " }]),
    );
    const diff = diffFindings(snapshot?.findings ?? [], [NOSNIFF]);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.added).toEqual([]);
    expect(diff.fixed).toEqual([]);
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
