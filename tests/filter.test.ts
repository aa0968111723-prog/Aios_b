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
});

describe("describeFilter", () => {
  it("沒有過濾時回空字串——沒被縮小範圍的報告本來就涵蓋全部，不必多說一句", () => {
    expect(describeFilter(mk())).toBe("");
  });

  it("有過濾就要講清楚篩了什麼，並提醒沒跑到不等於通過", () => {
    const line = describeFilter(parseFilter("security", "cors"));
    expect(line).toContain("security");
    expect(line).toContain("cors");
    expect(line).toContain("不代表通過");
    expect(line.split("\n")).toHaveLength(1);
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

  it("每個分類名都能當成 only token 使用", () => {
    for (const category of KNOWN_CATEGORIES) {
      expect(matchesFilter({ name: "任意檢查", category }, mk([category]))).toBe(true);
    }
  });
});
