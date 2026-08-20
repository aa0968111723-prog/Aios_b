import { describe, expect, it } from "vitest";
import { finding } from "../src/core/findings.js";
import {
  EXAMPLE_SUPPRESSION_FILE,
  applySuppressions,
  describeSuppression,
  expiryInstant,
  isExpired,
  matchesId,
  parseSuppressions,
  ruleMatches,
  toSuppressedRecords,
} from "../src/core/suppress.js";
import type { SuppressionRule } from "../src/core/suppress.js";
import type { Finding, Severity } from "../src/core/types.js";

/** 掃描當下的固定時間。到期判定不可以依賴執行機器的時鐘，否則測試會在某一天自己變紅。 */
const NOW = new Date("2026-08-20T10:00:00Z");

const mk = (id: string, severity: Severity = "medium", where?: string): Finding =>
  finding({
    id,
    check: "demo",
    category: "security",
    severity,
    surface: "web",
    title: `測試用發現：${id}`,
    detail: "測試用，不代表真實判定。",
    remediation: "測試用。",
    where,
  });

const rule = (partial: Partial<SuppressionRule> & { id: string }): SuppressionRule => ({
  reason: "已知取捨，測試用。",
  ...partial,
});

const ids = (findings: Finding[]): string[] => findings.map((f) => f.id);

describe("parseSuppressions", () => {
  it("接受頂層陣列", () => {
    const { rules, problems } = parseSuppressions('[{"id":"cookies.samesite.theme","reason":"主題偏好，無風險"}]');
    expect(problems).toEqual([]);
    expect(rules).toEqual([{ id: "cookies.samesite.theme", reason: "主題偏好，無風險" }]);
  });

  it("接受 { suppressions: [...] } 物件", () => {
    const { rules, problems } = parseSuppressions('{"suppressions":[{"id":"csp.style-src.unsafe-inline","reason":"React inline style"}]}');
    expect(problems).toEqual([]);
    expect(rules.map((r) => r.id)).toEqual(["csp.style-src.unsafe-inline"]);
  });

  it("壞掉的 JSON 只回一筆 problem，不丟例外", () => {
    const { rules, problems } = parseSuppressions("{ 這不是 JSON ");
    expect(rules).toEqual([]);
    expect(problems).toHaveLength(1);
    expect(problems[0]?.rule).toBeNull();
  });

  it("頂層既不是陣列也不是含 suppressions 的物件時明講", () => {
    const { rules, problems } = parseSuppressions('{"rules":[]}');
    expect(rules).toEqual([]);
    expect(problems[0]?.message).toContain("suppressions");
  });

  it("一筆寫錯不會拖垮整份清單——好的照收、壞的進 problems", () => {
    const { rules, problems } = parseSuppressions(
      JSON.stringify([
        { id: "headers.coop", reason: "尚未評估影響" },
        { id: "headers.server-version" }, // 缺 reason
        { id: "cookies.samesite.theme", reason: "主題偏好" },
      ]),
    );
    expect(rules.map((r) => r.id)).toEqual(["headers.coop", "cookies.samesite.theme"]);
    expect(problems).toHaveLength(1);
    expect(problems[0]?.raw).toEqual({ id: "headers.server-version" });
  });

  it("reason 只有空白字元等同沒寫", () => {
    const { rules, problems } = parseSuppressions('[{"id":"headers.coop","reason":"   "}]');
    expect(rules).toEqual([]);
    expect(problems[0]?.message).toContain("reason");
  });

  it("純 * 被拒——那不是抑制，是把檢測關掉", () => {
    const { rules, problems } = parseSuppressions('[{"id":"*","reason":"先讓 CI 過"}]');
    expect(rules).toEqual([]);
    expect(problems[0]?.message).toContain("萬用字元");
  });

  it("萬用字元不在結尾一律被拒", () => {
    const { problems } = parseSuppressions('[{"id":"cookies.*.sid","reason":"想蓋掉全部 sid"}]');
    expect(problems).toHaveLength(1);
  });

  it("不允許抑制 suppress.* ——那會讓抑制清單自己不再受檢", () => {
    const { rules, problems } = parseSuppressions('[{"id":"suppress.no-expiry","reason":"太吵"}]');
    expect(rules).toEqual([]);
    expect(problems).toHaveLength(1);
  });

  it("缺 id 被拒", () => {
    const { problems } = parseSuppressions('[{"reason":"忘了寫 id"}]');
    expect(problems[0]?.message).toContain("id");
  });

  it("不是物件的項目被拒而不是被硬轉", () => {
    const { rules, problems } = parseSuppressions('["cookies.samesite.theme"]');
    expect(rules).toEqual([]);
    expect(problems).toHaveLength(1);
  });

  it("expires 不是真實日期被拒（2026-02-30 不可以被悄悄捲成 3 月 2 日）", () => {
    const { rules, problems } = parseSuppressions('[{"id":"headers.coop","reason":"排程中","expires":"2026-02-30"}]');
    expect(rules).toEqual([]);
    expect(problems[0]?.message).toContain("expires");
  });

  it("月份超出範圍的 expires 也被拒", () => {
    const { problems } = parseSuppressions('[{"id":"headers.coop","reason":"排程中","expires":"2026-13-01"}]');
    expect(problems).toHaveLength(1);
  });

  it("expires 沒帶時區的時間被拒（否則不同機器在不同時刻到期）", () => {
    const { problems } = parseSuppressions('[{"id":"headers.coop","reason":"排程中","expires":"2026-09-01T12:00:00"}]');
    expect(problems).toHaveLength(1);
  });

  it("欄位名稱拼錯被當場退件，不會靜靜變成永久抑制", () => {
    const { rules, problems } = parseSuppressions('[{"id":"headers.coop","reason":"排程中","expiry":"2026-09-01"}]');
    expect(rules).toEqual([]);
    expect(problems[0]?.message).toContain("expiry");
  });

  it("acknowledgeCritical 必須是布林值", () => {
    const { problems } = parseSuppressions('[{"id":"cookies.httponly.sid","reason":"暫緩","acknowledgeCritical":"true"}]');
    expect(problems).toHaveLength(1);
  });

  it("欄位前後空白會被去掉，避免 where 因空白而永遠對不上", () => {
    const { rules } = parseSuppressions('[{"id":" headers.coop ","reason":" 排程中 ","where":" https://a.test/ ","owner":" ops "}]');
    expect(rules[0]).toEqual({ id: "headers.coop", reason: "排程中", where: "https://a.test/", owner: "ops" });
  });

  it("範例檔本身就是一份合法清單（貼上去就能用）", () => {
    const { rules, problems } = parseSuppressions(EXAMPLE_SUPPRESSION_FILE);
    expect(problems).toEqual([]);
    expect(rules).toHaveLength(2);
    expect(rules.every((r) => r.reason.length > 0 && r.expires && r.owner)).toBe(true);
  });

  it("空清單是合法的：沒有規則，也不該報成一筆問題", () => {
    expect(parseSuppressions("[]")).toEqual({ rules: [], problems: [] });
    expect(parseSuppressions('{"suppressions":[]}')).toEqual({ rules: [], problems: [] });
  });

  // 呼叫端（annotate.ts）用 problem.rule?.id 組出 suppress.invalid-rule 的發現 id。
  // 認不出規則時只能退回「第 N 筆」，而 N 會隨著清單被編輯而移動——同一個錯誤換了 id，
  // 跨次比對就會報成「舊的修好了、又多一個新的」。所以壞規則也必須帶得回自己的 id。
  it("認得出 id 的壞規則會帶回規則回音，問題的身分不隨它在清單裡的位置改變", () => {
    const broken = { id: "headers.coop", expiry: "2026-09-01", reason: "打錯欄位名" };
    const first = parseSuppressions(JSON.stringify([broken]));
    const shifted = parseSuppressions(
      JSON.stringify([{ id: "cookies.samesite.theme", reason: "主題偏好" }, broken]),
    );
    expect(first.problems[0]?.rule?.id).toBe("headers.coop");
    expect(shifted.problems[0]?.rule?.id).toBe("headers.coop");
  });

  it("缺 reason 的規則也認得出 id，reason 明寫「未填寫」而不是留白讓人以為沒事", () => {
    const { problems } = parseSuppressions('[{"id":"headers.server-version"}]');
    expect(problems[0]?.rule).toEqual({ id: "headers.server-version", reason: "（未填寫）" });
  });

  it("連 id 都認不出來時 rule 就是 null，不硬掰一個身分出來", () => {
    const { problems } = parseSuppressions('[{"reason":"忘了寫 id"},"整條都不是物件"]');
    expect(problems.map((p) => p.rule)).toEqual([null, null]);
  });
});

describe("matchesId 與 ruleMatches", () => {
  it("結尾萬用字元命中整個家族", () => {
    expect(matchesId("cookies.*", "cookies.httponly.sid")).toBe(true);
    expect(matchesId("csp.script-src.*", "csp.script-src.unsafe-eval")).toBe(true);
  });

  it("萬用字元不會外溢到別的家族", () => {
    expect(matchesId("cookies.*", "csp.script-src.unsafe-eval")).toBe(false);
    expect(matchesId("csp.script-src.*", "csp.object-src")).toBe(false);
  });

  it("沒有萬用字元時必須完全相同", () => {
    expect(matchesId("cookies.httponly", "cookies.httponly.sid")).toBe(false);
    expect(matchesId("cookies.httponly.sid", "cookies.httponly.sid")).toBe(true);
  });

  it("where 有給時必須完全相同才命中", () => {
    const r = rule({ id: "headers.coop", where: "https://a.test/" });
    expect(ruleMatches(r, mk("headers.coop", "low", "https://a.test/"))).toBe(true);
    expect(ruleMatches(r, mk("headers.coop", "low", "https://a.test/admin"))).toBe(false);
    expect(ruleMatches(r, mk("headers.coop", "low"))).toBe(false);
  });

  it("where 沒給時只比對 id，發現在哪一端都算命中", () => {
    const r = rule({ id: "headers.coop" });
    expect(ruleMatches(r, mk("headers.coop", "low", "https://b.test/"))).toBe(true);
  });
});

describe("expiryInstant 與 isExpired", () => {
  it("只寫日期時算到那一天結束——到期日當天仍然有效", () => {
    expect(isExpired(rule({ id: "x", expires: "2026-08-20" }), NOW)).toBe(false);
    expect(expiryInstant("2026-08-20")).toBe(Date.parse("2026-08-20T23:59:59.999Z"));
  });

  it("隔天就失效", () => {
    expect(isExpired(rule({ id: "x", expires: "2026-08-19" }), NOW)).toBe(true);
  });

  it("沒有 expires 不算過期（是永久抑制，另外提醒）", () => {
    expect(isExpired(rule({ id: "x" }), NOW)).toBe(false);
  });

  it("看不懂的日期視同已過期，不可以變成永久抑制", () => {
    expect(isExpired(rule({ id: "x", expires: "下個月" }), NOW)).toBe(true);
  });

  // 空字串是「寫了但寫壞了」，不是「沒有寫」。若落到永久抑制那一側，
  // 一個手滑清空的欄位就換到無限期的靜音，而且不會留下任何痕跡。
  it("expires 是空字串等同寫壞了，視同已過期而不是永久抑制", () => {
    expect(isExpired(rule({ id: "x", expires: "" }), NOW)).toBe(true);
    expect(isExpired(rule({ id: "x", expires: "   " }), NOW)).toBe(true);
  });

  it("到期邊界精確到毫秒：當天最後一毫秒仍有效，再過 1 毫秒就失效", () => {
    const lastMoment = new Date("2026-08-20T23:59:59.999Z");
    expect(isExpired(rule({ id: "x", expires: "2026-08-20" }), lastMoment)).toBe(false);
    expect(isExpired(rule({ id: "x", expires: "2026-08-20" }), new Date(lastMoment.getTime() + 1))).toBe(true);
  });

  it("帶時區的完整時間以該時刻為準，不會被補成當天結束", () => {
    expect(expiryInstant("2026-08-20T09:00:00+08:00")).toBe(Date.parse("2026-08-20T01:00:00Z"));
    expect(isExpired(rule({ id: "x", expires: "2026-08-20T09:00:00+08:00" }), NOW)).toBe(true);
  });
});

describe("applySuppressions", () => {
  it("命中的發現進 suppressed 並附上規則，不再出現在 kept", () => {
    const findings = [mk("headers.coop", "low"), mk("headers.nosniff")];
    const out = applySuppressions(findings, [rule({ id: "headers.coop", expires: "2026-12-31" })], NOW);
    expect(ids(out.kept)).toEqual(["headers.nosniff"]);
    expect(out.suppressed).toHaveLength(1);
    expect(out.suppressed[0]?.rule.id).toBe("headers.coop");
  });

  it("萬用字元規則一次蓋住整個家族", () => {
    const findings = [mk("cookies.samesite.theme", "info"), mk("cookies.secure.theme", "low"), mk("headers.coop", "low")];
    const out = applySuppressions(findings, [rule({ id: "cookies.*", expires: "2026-12-31" })], NOW);
    expect(out.suppressed).toHaveLength(2);
    expect(ids(out.kept)).toEqual(["headers.coop"]);
  });

  it("沒有規則時原封不動", () => {
    const findings = [mk("headers.coop", "low")];
    const out = applySuppressions(findings, [], NOW);
    expect(out.kept).toEqual(findings);
    expect(out.suppressed).toEqual([]);
    expect(out.notes).toEqual([]);
  });

  it("過期規則不套用，發現重新浮現並附一筆 suppress.expired（low）", () => {
    const findings = [mk("headers.coop", "low")];
    const out = applySuppressions(findings, [rule({ id: "headers.coop", expires: "2026-01-31" })], NOW);
    expect(ids(out.kept)).toEqual(["headers.coop"]);
    expect(out.suppressed).toEqual([]);
    const note = out.notes.find((n) => n.id === "suppress.expired");
    expect(note?.severity).toBe("low");
    expect(note?.detail).toContain("2026-01-31");
  });

  it("到期日當天仍然有效——不會在期限那天突然噴出一排告警", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop", expires: "2026-08-20" })], NOW);
    expect(out.suppressed).toHaveLength(1);
    expect(out.notes.map((n) => n.id)).not.toContain("suppress.expired");
  });

  it("過期後即使規則有 acknowledgeCritical 也不再套用", () => {
    const out = applySuppressions(
      [mk("cookies.httponly.sid", "critical")],
      [rule({ id: "cookies.httponly.sid", expires: "2026-08-19", acknowledgeCritical: true })],
      NOW,
    );
    expect(ids(out.kept)).toEqual(["cookies.httponly.sid"]);
    expect(out.notes.map((n) => n.id)).toEqual(["suppress.expired"]);
  });

  it("要蓋 critical 卻沒有明示承認時不套用，並報 suppress.critical-requires-ack（medium）", () => {
    const findings = [mk("cookies.httponly.sid", "critical")];
    const out = applySuppressions(findings, [rule({ id: "cookies.httponly.sid", expires: "2026-12-31" })], NOW);
    expect(ids(out.kept)).toEqual(["cookies.httponly.sid"]);
    expect(out.suppressed).toEqual([]);
    expect(out.notes.find((n) => n.id === "suppress.critical-requires-ack")?.severity).toBe("medium");
  });

  it("明寫 acknowledgeCritical 後才蓋得掉 critical，且不再提醒", () => {
    const out = applySuppressions(
      [mk("cookies.httponly.sid", "critical")],
      [rule({ id: "cookies.httponly.sid", expires: "2026-12-31", acknowledgeCritical: true, owner: "sec@aios" })],
      NOW,
    );
    expect(out.kept).toEqual([]);
    expect(out.suppressed).toHaveLength(1);
    expect(out.notes.map((n) => n.id)).not.toContain("suppress.critical-requires-ack");
  });

  it("critical 的攔截是逐筆的：同一條規則的非 critical 發現仍照常被蓋", () => {
    const findings = [mk("cookies.httponly.sid", "critical"), mk("cookies.samesite.theme", "info")];
    const out = applySuppressions(findings, [rule({ id: "cookies.*", expires: "2026-12-31" })], NOW);
    expect(ids(out.kept)).toEqual(["cookies.httponly.sid"]);
    expect(out.suppressed.map((s) => s.finding.id)).toEqual(["cookies.samesite.theme"]);
  });

  it("整輪沒命中的規則報 suppress.stale（info）——問題可能修好了，規則卻還留著", () => {
    const out = applySuppressions([mk("headers.nosniff")], [rule({ id: "headers.coop", expires: "2026-12-31" })], NOW);
    const note = out.notes.find((n) => n.id === "suppress.stale");
    expect(note?.severity).toBe("info");
    expect(note?.where).toBe("headers.coop");
  });

  it("沒有 expires 且有命中的規則報 suppress.no-expiry（info）", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop" })], NOW);
    expect(out.suppressed).toHaveLength(1);
    expect(out.notes.find((n) => n.id === "suppress.no-expiry")?.severity).toBe("info");
  });

  it("有 expires 就不會被當成永久抑制", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop", expires: "2026-12-31" })], NOW);
    expect(out.notes).toEqual([]);
  });

  it("沒命中的永久規則只報 stale，不重複報 no-expiry", () => {
    const out = applySuppressions([mk("headers.nosniff")], [rule({ id: "headers.coop" })], NOW);
    expect(out.notes.map((n) => n.id)).toEqual(["suppress.stale"]);
  });

  it("where 精確比對：只放行指定端點的那一筆，其他端點照常回報", () => {
    const findings = [mk("headers.coop", "low", "https://a.test/"), mk("headers.coop", "low", "https://b.test/")];
    const out = applySuppressions(
      findings,
      [rule({ id: "headers.coop", where: "https://a.test/", expires: "2026-12-31" })],
      NOW,
    );
    expect(out.suppressed.map((s) => s.finding.where)).toEqual(["https://a.test/"]);
    expect(out.kept.map((f) => f.where)).toEqual(["https://b.test/"]);
  });

  it("同一筆被兩條規則命中時只記一次，由先命中的規則負責", () => {
    const findings = [mk("cookies.samesite.theme", "info")];
    const out = applySuppressions(
      findings,
      [
        rule({ id: "cookies.*", expires: "2026-12-31", reason: "整批已知取捨" }),
        rule({ id: "cookies.samesite.theme", expires: "2026-12-31", reason: "個別取捨" }),
      ],
      NOW,
    );
    expect(out.suppressed).toHaveLength(1);
    expect(out.suppressed[0]?.rule.reason).toBe("整批已知取捨");
  });

  it("抑制清單自己的提醒不會被任何規則蓋掉", () => {
    const findings = [mk("suppress.no-expiry", "info"), mk("headers.coop", "low")];
    const out = applySuppressions(findings, [rule({ id: "s*", expires: "2026-12-31" })], NOW);
    expect(ids(out.kept)).toContain("suppress.no-expiry");
  });

  it("kept 保持原本的順序，讀者的閱讀順序不會因為抑制而跳動", () => {
    const findings = [mk("a.one"), mk("b.two"), mk("c.three")];
    const out = applySuppressions(findings, [rule({ id: "b.two", expires: "2026-12-31" })], NOW);
    expect(ids(out.kept)).toEqual(["a.one", "c.three"]);
  });

  it("每一筆提醒都符合發現的規格：有修法、歸在 integrity／all／suppress", () => {
    const findings = [mk("cookies.httponly.sid", "critical"), mk("headers.coop", "low")];
    const out = applySuppressions(
      findings,
      [rule({ id: "cookies.httponly.sid" }), rule({ id: "headers.nosniff", expires: "2026-01-01" })],
      NOW,
    );
    expect(out.notes.length).toBeGreaterThan(0);
    for (const note of out.notes) {
      expect(note.check).toBe("suppress");
      expect(note.category).toBe("integrity");
      expect(note.surface).toBe("all");
      expect(note.remediation ?? "").not.toBe("");
      expect(note.id.startsWith("suppress.")).toBe(true);
      expect(note.evidence ?? "").toContain("reason:");
    }
  });

  it("提醒的 id 不含時間戳或隨機值，跨次執行才比對得起來", () => {
    const findings = [mk("headers.coop", "low")];
    const rules = [rule({ id: "headers.coop" })];
    const first = applySuppressions(findings, rules, NOW);
    const second = applySuppressions(findings, rules, new Date(NOW.getTime() + 86_400_000));
    expect(ids(first.notes)).toEqual(ids(second.notes));
    expect(first.notes.map((n) => n.where)).toEqual(second.notes.map((n) => n.where));
  });

  // annotate.ts 靠物件同一性把留下的發現放回各自的 CheckResult
  // （`const kept = new Set(outcome.kept)` 再逐一 filter）。這裡若複製一份新物件，
  // 那個 filter 會一筆都對不上，整份報告的發現會被清空——而且不會有任何錯誤訊息。
  it("回傳的是原本那些發現物件，不是複製品（呼叫端靠物件同一性把它們放回檢查結果）", () => {
    const findings = [mk("headers.coop", "low"), mk("headers.nosniff")];
    const out = applySuppressions(findings, [rule({ id: "headers.coop", expires: "2026-12-31" })], NOW);
    expect(out.suppressed[0]?.finding).toBe(findings[0]);
    expect(out.kept[0]).toBe(findings[1]);
  });

  // 三端掃同一個站時，同一處的同一個問題會由不同 surface 各回報一次：
  // id 與 where 相同（穩定鍵相同），但物件不同，嚴重度也可能因端而異。
  // 攔截若認物件、認領若認鍵，被擋下的那筆 critical 會從孿生物件的鍵溜進 suppressed——
  // 一個沒有人看得見的假綠燈，正是抑制清單最不能犯的錯。
  it("同一把鍵上的 critical 被攔下時，同鍵的其他回報也不會偷偷被蓋掉", () => {
    const findings = [
      mk("headers.hsts.missing", "critical", "https://a.test/"),
      mk("headers.hsts.missing", "high", "https://a.test/"),
    ];
    const out = applySuppressions(findings, [rule({ id: "headers.*", expires: "2026-12-31" })], NOW);
    expect(out.suppressed).toEqual([]);
    expect(out.kept).toEqual(findings);
    expect(out.notes.find((n) => n.id === "suppress.critical-requires-ack")?.severity).toBe("medium");
  });

  // 廣泛規則管一整個家族、另立一條具名規則承擔那筆 critical，是實務上正確的寫法。
  // 此時廣泛規則的提醒若照發，報告會出現一句與事實相反的話（「該筆照常回報」但它其實被蓋住了），
  // 那比不寫還糟：讀者會去主清單找一筆根本不在那裡的發現。
  it("critical 已被另一條有 ack 的規則合法蓋住時，不留下與事實相反的提醒", () => {
    const findings = [mk("cookies.httponly.sid", "critical"), mk("cookies.samesite.theme", "info")];
    const out = applySuppressions(
      findings,
      [
        rule({ id: "cookies.*", expires: "2026-12-31", reason: "整批已知取捨" }),
        rule({ id: "cookies.httponly.sid", expires: "2026-12-31", acknowledgeCritical: true, owner: "sec@aios" }),
      ],
      NOW,
    );
    expect(out.kept).toEqual([]);
    expect(out.suppressed.map((s) => s.rule.owner)).toEqual(["sec@aios", undefined]);
    expect(ids(out.notes)).not.toContain("suppress.critical-requires-ack");
  });

  // 解析階段就會擋掉純 *，但 applySuppressions 是公開的純函式，規則也可能是別處手工組出來的。
  // 判定本身必須自己站得住：任何一條「等於關掉檢測」的規則都不該有機會生效。
  it("純 * 規則就算繞過解析直接送進來，也蓋不掉任何東西", () => {
    const findings = [mk("headers.coop", "low"), mk("cookies.httponly.sid", "critical")];
    const out = applySuppressions(findings, [{ id: "*", reason: "先讓 CI 過" }], NOW);
    expect(out.kept).toEqual(findings);
    expect(ids(out.notes)).toEqual(["suppress.stale"]);
  });

  it("不會改動傳入的發現與規則陣列——後續的報告與比對都還要用同一份資料", () => {
    const findings = [mk("headers.coop", "low"), mk("cookies.httponly.sid", "critical")];
    const rules = [rule({ id: "headers.*" })];
    const findingsCopy = [...findings];
    const rulesCopy = structuredClone(rules);
    applySuppressions(findings, rules, NOW);
    expect(findings).toEqual(findingsCopy);
    expect(rules).toEqual(rulesCopy);
  });
});

describe("toSuppressedRecords", () => {
  it("攤平成報告層要的四件事：問題、理由、到期日、負責人", () => {
    const out = applySuppressions(
      [mk("headers.coop", "low")],
      [rule({ id: "headers.coop", reason: "等平台支援", expires: "2026-12-31", owner: "ops@aios" })],
      NOW,
    );
    expect(toSuppressedRecords(out.suppressed)).toEqual([
      { finding: out.suppressed[0]?.finding, reason: "等平台支援", expires: "2026-12-31", owner: "ops@aios" },
    ]);
  });

  it("永久抑制與未具名要明確轉成 null，報告才標示得出來", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop" })], NOW);
    const record = toSuppressedRecords(out.suppressed)[0];
    expect(record?.expires).toBeNull();
    expect(record?.owner).toBeNull();
  });
});

describe("describeSuppression", () => {
  it("有抑制時說出被蓋掉幾筆、幾條規則、還剩幾筆", () => {
    const findings = [mk("cookies.samesite.theme", "info"), mk("cookies.secure.theme", "low"), mk("headers.coop", "low")];
    const line = describeSuppression(applySuppressions(findings, [rule({ id: "cookies.*", expires: "2026-12-31" })], NOW));
    expect(line).toContain("2 筆發現被 1 條規則");
    expect(line).toContain("1 筆照常回報");
  });

  it("一筆都沒抑制時也要講——讀者必須知道自己看的是不是被篩過的報告", () => {
    const line = describeSuppression(applySuppressions([mk("headers.coop", "low")], [], NOW));
    expect(line).toContain("沒有任何發現被抑制");
  });

  it("有提醒時一併帶出數量", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop" })], NOW);
    expect(describeSuppression(out)).toContain("1 筆關於抑制清單本身的提醒");
  });

  it("永遠是單行，終端排版不會被撐開", () => {
    const out = applySuppressions([mk("headers.coop", "low")], [rule({ id: "headers.coop" })], NOW);
    expect(describeSuppression(out)).not.toContain("\n");
  });
});
