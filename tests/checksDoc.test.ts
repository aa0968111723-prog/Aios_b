/**
 * 文件走樣的守門測試。
 *
 * `docs/CHECKS.md` 的開頭寫著：「每一筆發現都有穩定的 `id`⋯⋯可用於抑制清單、跨次執行比對，
 * 以及在這份文件裡查到判定依據。`id` 一旦發布就不改。」
 *
 * 那段話只有在文件真的跟得上程式碼時才成立。而文件走樣不會讓任何測試變紅——它只是慢慢地
 * 讓那份對照表變成一份不能相信的清單，然後有人照著它寫抑制規則，蓋掉一個根本不存在的 id。
 *
 * 所以這裡把「每個 finding id 都要在對照表裡查得到」變成一條會失敗的規則。
 * 新增偵測器時要一起更新文件——那不是額外的工作，那是這個 id 的定義本身。
 */
import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

const SRC = path.resolve(import.meta.dirname, "../src");
const DOC = path.resolve(import.meta.dirname, "../docs/CHECKS.md");

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = path.join(dir, entry);
    if (statSync(full).isDirectory()) return walk(full);
    return full.endsWith(".ts") ? [full] : [];
  });
}

/**
 * 從原始碼抓出所有 finding id 的**字面前綴**。
 *
 * 樣板字串（`` `auth-gate.open.${path}` ``）取到第一個插值之前為止，因為文件登錄的是
 * `auth-gate.open.<path>` 這種形式——比對前綴才不會逼文件去窮舉每一個可能的後綴。
 */
function collectIdStems(): Map<string, string[]> {
  const stems = new Map<string, string[]>();
  for (const file of walk(SRC)) {
    // 報告層的 id 是輸出格式自己的識別碼（SARIF 的 notification descriptor），不是發現。
    if (file.includes(`${path.sep}report${path.sep}`)) continue;
    const source = readFileSync(file, "utf8");
    for (const match of source.matchAll(/id:\s*(?:"([^"]+)"|`([^`]+)`)/g)) {
      const raw = match[1] ?? match[2] ?? "";
      const stem = raw.split("${")[0] ?? "";
      // finding id 一律是 `檢查名.問題名` 的階層字串；其他用途的 id 欄位（設定檔識別碼等）不算。
      if (!/^[a-z][a-z0-9]*[.-]/.test(stem)) continue;
      stems.set(stem, [...(stems.get(stem) ?? []), path.relative(SRC, file)]);
    }
  }
  return stems;
}

describe("docs/CHECKS.md 與程式碼同步", () => {
  const stems = collectIdStems();
  const doc = readFileSync(DOC, "utf8");

  it("抓得到足夠多的 id——比對本身沒有失效", () => {
    // 這條是給上面那個正則的保險：正則寫壞時它會靜默地抓到零個 id，
    // 於是下面那條「全部都有登錄」會憑空通過，而這正是假綠燈的定義。
    expect(stems.size).toBeGreaterThan(100);
  });

  it("每個 finding id 都在對照表裡查得到", () => {
    const missing = [...stems.entries()]
      .filter(([stem]) => !doc.includes(stem))
      .map(([stem, files]) => `${stem}（${[...new Set(files)].join("、")}）`);

    expect(missing, `這些 finding id 沒有登錄在 docs/CHECKS.md：\n${missing.join("\n")}`).toEqual([]);
  });
});
