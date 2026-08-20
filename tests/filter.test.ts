import { describe, expect, it } from "vitest";
import {
  KNOWN_CATEGORIES,
  describeFilter,
  matchesFilter,
  parseFilter,
  partitionChecks,
  unknownTokens,
} from "../src/core/filter.js";
import type { CheckFilter, FilterTarget } from "../src/core/filter.js";

/** 取自 cli.ts 的實際檢查清單：測試要對著真的會被篩掉的東西寫，不是對著假想的名字。 */
const CHECKS: FilterTarget[] = [
  { name: "health", category: "availability" },
  { name: "transport", category: "security" },
  { name: "auth-gate", category: "security" },
  { name: "disclosure", category: "security" },
  { name: "cors", category: "security" },
  { name: "build-drift", category: "integrity" },
  { name: "analytics", category: "monitoring" },
  { name: "page-test", category: "page" },
  { name: "a11y", category: "a11y" },
];

const names = (items: FilterTarget[]): string[] => items.map((i) => i.name);
const mk = (only: string[] = [], skip: string[] = []): CheckFilter => ({ only, skip });
const keptNames = (filter: CheckFilter): string[] => names(partitionChecks(CHECKS, filter).kept);

describe("parseFilter", () => {
  it("逗號分隔的檢查名各自成為一個 token", () => {
    expect(parseFilter("cors,auth-gate", undefined)).toEqual({ only: ["cors", "auth-gate"], skip: [] });
  });

  it("容忍大小寫與空白——終端機打進來的東西不會乾淨", () => {
    expect(parseFilter(" CORS , Auth-Gate ", undefined).only).toEqual(["cors", "auth-gate"]);
  });

  it("尾逗號產生的空 token 被丟掉，不會變成一個什麼都不命中的條件", () => {
    expect(parseFilter("cors,,", undefined).only).toEqual(["cors"]);
    expect(parseFilter("   ", undefined).only).toEqual([]);
  });

  it("重複的 token 只留一份，摘要才不會印出「只執行 cors、cors」", () => {
    expect(parseFilter("cors, CORS ,cors", undefined).only).toEqual(["cors"]);
  });

  it("skip 走同一套正規化，兩個旗標的行為不該有差別", () => {
    expect(parseFilter(undefined, " A11Y , page-test ")).toEqual({ only: [], skip: ["a11y", "page-test"] });
  });

  it("兩個旗標都沒給時是空過濾器（代表不限制，不是代表什麼都不跑）", () => {
    const filter = parseFilter(undefined, undefined);
    expect(filter).toEqual({ only: [], skip: [] });
    expect(keptNames(filter)).toEqual(names(CHECKS));
  });
});

describe("matchesFilter", () => {
  it("only 給檢查名時只留下那一項", () => {
    expect(keptNames(mk(["cors"]))).toEqual(["cors"]);
  });

  it("only 給分類名時整組留下——排查資安問題時要的就是這個粒度", () => {
    expect(keptNames(mk(["security"]))).toEqual(["transport", "auth-gate", "disclosure", "cors"]);
  });

  it("only 可以混用檢查名與分類名", () => {
    expect(keptNames(mk(["monitoring", "health"]))).toEqual(["health", "analytics"]);
  });

  it("skip 給分類名時整組剔除，其餘照跑", () => {
    expect(keptNames(mk([], ["security"]))).toEqual(["health", "build-drift", "analytics", "page-test", "a11y"]);
  });

  it("skip 優先於 only：--only security --skip cors 讀起來就是「資安那組，但別碰 cors」", () => {
    expect(keptNames(mk(["security"], ["cors"]))).toEqual(["transport", "auth-gate", "disclosure"]);
  });

  it("同一個 token 同時出現在 only 與 skip 時，該項不執行——衝突一律往保守解", () => {
    expect(keptNames(mk(["cors"], ["cors"]))).toEqual([]);
  });

  it("不做前綴比對：--skip auth 不可以順手把 auth-gate 關掉", () => {
    expect(matchesFilter({ name: "auth-gate", category: "security" }, mk([], ["auth"]))).toBe(true);
    expect(matchesFilter({ name: "auth-gate", category: "security" }, mk(["auth"]))).toBe(false);
  });

  it("手寫的 filter 沒走過 parseFilter 也要判對——判定不該取決於呼叫路徑", () => {
    expect(matchesFilter({ name: "cors", category: "security" }, mk([" CORS "]))).toBe(true);
  });

  it("只由空白組成的 only 等同沒給——保守解是全部照跑，不是靜默地把每一項都篩掉", () => {
    // 照字面解讀成「有指定 only」的話，每一項都不命中而被剔除，產出一份零發現、
    // 外觀完全正常的報告；那個 token 印出來又是一片空白，連警告都指不出是哪裡錯。
    expect(keptNames(mk(["  ", ""]))).toEqual(names(CHECKS));
  });

  it("只由空白組成的 skip 不會誤剔除任何一項", () => {
    expect(keptNames(mk([], ["   "]))).toEqual(names(CHECKS));
  });

  it("手寫 filter 與 parseFilter 對同一份輸入結論一致——涵蓋範圍不該因為走哪條路而改變", () => {
    const raw = " CORS , ,cors ";
    expect(keptNames(mk(raw.split(",")))).toEqual(keptNames(parseFilter(raw, undefined)));
  });
});

describe("partitionChecks", () => {
  it("兩堆加總不重不漏，報告的檢查總數才對得起來", () => {
    const { kept, excluded } = partitionChecks(CHECKS, mk(["security"], ["cors"]));
    expect(kept.length + excluded.length).toBe(CHECKS.length);
    expect([...names(kept), ...names(excluded)].sort()).toEqual(names(CHECKS).sort());
  });

  it("被篩掉的檢查原樣交還，呼叫端才有東西可以標記成「跳過＋原因」", () => {
    const { excluded } = partitionChecks(CHECKS, mk(["cors"]));
    expect(names(excluded)).toEqual(names(CHECKS).filter((n) => n !== "cors"));
  });

  it("兩堆各自維持輸入順序，報告的閱讀順序才可預期", () => {
    const { kept } = partitionChecks(CHECKS, mk(["security", "monitoring"]));
    expect(names(kept)).toEqual(["transport", "auth-gate", "disclosure", "cors", "analytics"]);
  });

  it("空過濾器留下全部，excluded 為空", () => {
    const { kept, excluded } = partitionChecks(CHECKS, mk());
    expect(kept).toEqual(CHECKS);
    expect(excluded).toEqual([]);
  });

  it("token 打錯字時全部落入 excluded，沒有任何一項被靜默丟掉", () => {
    const { kept, excluded } = partitionChecks(CHECKS, mk(["secuirty"]));
    expect(kept).toEqual([]);
    expect(excluded).toHaveLength(CHECKS.length);
  });

  it("FilterTarget 以外的欄位原樣保留——cli.ts 靠它把被篩掉的 PlannedCheck 取回來標成跳過", () => {
    const planned = CHECKS.map((c) => ({ ...c, run: () => c.name }));
    const { kept, excluded } = partitionChecks(planned, mk(["cors"]));
    expect(kept[0]?.run()).toBe("cors");
    expect(excluded.every((c) => typeof c.run === "function")).toBe(true);
  });

  it("不改動傳進來的陣列——呼叫端還要拿原清單去對總數", () => {
    const input = [...CHECKS];
    partitionChecks(input, mk(["security"], ["cors"]));
    expect(input).toEqual(CHECKS);
  });
});

describe("unknownTokens", () => {
  it("打錯字的 only token 被抓出來——否則就是一份零發現的假綠燈報告", () => {
    expect(unknownTokens(parseFilter("secuirty", undefined), CHECKS)).toEqual(["secuirty"]);
  });

  it("正確的檢查名與分類名不會被誤報", () => {
    expect(unknownTokens(parseFilter("cors,monitoring", "a11y"), CHECKS)).toEqual([]);
  });

  it("拼字正確但這一輪沒有那項檢查，同樣算沒有對應到——結果一樣是什麼都不會跑", () => {
    const scanOnly = CHECKS.filter((c) => c.category !== "page" && c.category !== "a11y");
    expect(unknownTokens(parseFilter("a11y", undefined), scanOnly)).toEqual(["a11y"]);
  });

  it("skip 的錯字也要報：以為排除掉了卻沒有，是另一種白費的排查", () => {
    expect(unknownTokens(parseFilter(undefined, "corss"), CHECKS)).toEqual(["corss"]);
  });

  it("只回報真的沒對應到的那些，正確的 token 不混進來", () => {
    expect(unknownTokens(parseFilter("cors,typo-a", "typo-b,a11y"), CHECKS)).toEqual(["typo-a", "typo-b"]);
  });

  it("同一個錯字重複出現在 only 與 skip 只報一次", () => {
    expect(unknownTokens(mk(["Typo"], [" typo "]), CHECKS)).toEqual(["typo"]);
  });

  it("空白 token 不會被報成一則看不見的警告，它本來也篩不掉任何檢查", () => {
    const filter = mk(["  "], [""]);
    expect(unknownTokens(filter, CHECKS)).toEqual([]);
    expect(keptNames(filter)).toEqual(names(CHECKS));
  });

  it("known 清單為空時照樣把 token 全報出來——沒有東西可比不等於條件沒問題", () => {
    expect(unknownTokens(parseFilter("cors", undefined), [])).toEqual(["cors"]);
  });
});

describe("describeFilter", () => {
  it("沒有過濾時回空字串——沒被縮小範圍的報告本來就涵蓋全部，不必多說一句", () => {
    expect(describeFilter(mk())).toBe("");
  });

  it("有過濾就要把篩了什麼講完整，only 與 skip 都不能漏", () => {
    const line = describeFilter(parseFilter("security,health", "cors"));
    for (const token of ["security", "health", "cors"]) expect(line).toContain(token);
  });

  it("摘要是可嵌進別人句子的片語：不自帶抬頭、不自帶句號、單行", () => {
    // 呼叫端會把它包進自己的句子（cli.ts 有兩處），自帶抬頭會變成「檢查範圍：檢查過濾：…」的疊字，
    // 自帶整句則讓跳過理由的句法崩掉——而那句話會原樣寫進每一個被過濾檢查的 skippedReason。
    const line = describeFilter(parseFilter("health", "cors"));
    expect(line).toBe("只執行 health；略過 cors");
    expect(line).not.toMatch(/[。：]/);
    expect(line.split("\n")).toHaveLength(1);
    expect(`依 ${line} 排除，本輪未執行——未執行不等於通過。`).toBe(
      "依 只執行 health；略過 cors 排除，本輪未執行——未執行不等於通過。",
    );
  });

  it("摘要用收斂後的 token——印出重複或空白的條件，讀者就無法用這行字回推涵蓋範圍", () => {
    expect(describeFilter(mk([" CORS ", "cors", "  "]))).toBe("只執行 cors");
  });

  it("只有 only 或只有 skip 時，摘要不會提到另一半", () => {
    expect(describeFilter(mk(["cors"]))).not.toContain("略過");
    expect(describeFilter(mk([], ["cors"]))).not.toContain("只執行");
  });
});

describe("KNOWN_CATEGORIES", () => {
  it("涵蓋實際檢查用到的每一個分類——少一個就會讓合法的 --only 提示查不到", () => {
    for (const check of CHECKS) expect(KNOWN_CATEGORIES).toContain(check.category);
  });

  it("沒有重複項——重複會讓「可以填哪些分類」的提示看起來像壞掉了", () => {
    expect(new Set(KNOWN_CATEGORIES).size).toBe(KNOWN_CATEGORIES.length);
  });

  it("每個分類名都能當成 only token 使用", () => {
    for (const category of KNOWN_CATEGORIES) {
      expect(matchesFilter({ name: "任意檢查", category }, mk([category]))).toBe(true);
    }
  });
});
