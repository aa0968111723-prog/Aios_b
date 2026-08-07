import { describe, expect, it } from "vitest";
import { countBySeverity, shouldFail, sortFindings, worstSeverity } from "../src/core/severity.js";
import { finding } from "../src/core/findings.js";
import type { Finding, Severity } from "../src/core/types.js";

const make = (severity: Severity, id: string = severity): Finding =>
  finding({
    id,
    check: "test",
    category: "security",
    severity,
    surface: "web",
    title: id,
    detail: "d",
    remediation: "r",
  });

describe("worstSeverity", () => {
  it("空陣列回 null——「沒發現」不是一種嚴重度", () => {
    expect(worstSeverity([])).toBeNull();
  });

  it("取最嚴重的一筆", () => {
    expect(worstSeverity([make("low"), make("critical"), make("medium")])).toBe("critical");
  });
});

describe("shouldFail", () => {
  it("門檻含本級（failOn high 被 high 觸發）", () => {
    expect(shouldFail([make("high")], "high")).toBe(true);
  });

  it("比門檻更嚴重也觸發", () => {
    expect(shouldFail([make("critical")], "high")).toBe(true);
  });

  it("比門檻輕不觸發", () => {
    expect(shouldFail([make("medium")], "high")).toBe(false);
  });

  it("沒有任何發現時，即使門檻設到 info 也不失敗", () => {
    expect(shouldFail([], "info")).toBe(false);
  });
});

describe("sortFindings", () => {
  it("依嚴重度排序，同級維持原順序", () => {
    const input = [make("low", "l1"), make("critical", "c1"), make("low", "l2"), make("high", "h1")];
    expect(sortFindings(input).map((f) => f.id)).toEqual(["c1", "h1", "l1", "l2"]);
  });

  it("不改動原陣列", () => {
    const input = [make("low", "l1"), make("critical", "c1")];
    sortFindings(input);
    expect(input.map((f) => f.id)).toEqual(["l1", "c1"]);
  });
});

describe("countBySeverity", () => {
  it("所有等級都出現在結果裡（含 0），報告表格才不會缺列", () => {
    const counts = countBySeverity([make("high"), make("high", "h2")]);
    expect(counts).toEqual({ critical: 0, high: 2, medium: 0, low: 0, info: 0 });
  });
});
