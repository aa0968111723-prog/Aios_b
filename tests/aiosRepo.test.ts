import { describe, expect, it } from "vitest";
import path from "node:path";
import { discoverAiosRepo, looksLikeAiosRepo, SHELL_MARKERS } from "../src/core/aiosRepo.js";

/** 以一組「存在的檔案」集合造出注入用的 exists 假件。 */
const existsFrom = (present: string[]) => {
  const set = new Set(present);
  return (filePath: string) => set.has(filePath);
};

describe("looksLikeAiosRepo", () => {
  it("任一殼層設定檔存在即視為 ai_os", () => {
    for (const marker of SHELL_MARKERS) {
      const exists = existsFrom([path.join("/x", marker)]);
      expect(looksLikeAiosRepo("/x", exists)).toBe(true);
    }
  });

  it("沒有任何殼層設定檔則否——避免把同名資料夾誤認", () => {
    const exists = existsFrom(["/x/package.json", "/x/README.md"]);
    expect(looksLikeAiosRepo("/x", exists)).toBe(false);
  });
});

describe("discoverAiosRepo", () => {
  it("找到併排檢出的 ~/ai_os（Cloud Agent 情境）", () => {
    const home = "/home/ubuntu";
    const exists = existsFrom([path.join(home, "ai_os", "capacitor.config.ts")]);
    expect(discoverAiosRepo({ cwd: "/workspace", home, exists })).toBe(path.join(home, "ai_os"));
  });

  it("找到專案旁的 ../ai_os（本機開發情境）", () => {
    const exists = existsFrom([path.resolve("/work/sentinel", "..", "ai_os", "src-tauri/tauri.conf.json")]);
    expect(discoverAiosRepo({ cwd: "/work/sentinel", home: "/home/dev", exists })).toBe(
      path.resolve("/work/sentinel", "..", "ai_os"),
    );
  });

  it("就近優先：cwd 底下的 ai_os 勝過家目錄的", () => {
    const cwd = "/workspace";
    const home = "/home/ubuntu";
    const exists = existsFrom([
      path.join(cwd, "ai_os", "capacitor.config.ts"),
      path.join(home, "ai_os", "capacitor.config.ts"),
    ]);
    expect(discoverAiosRepo({ cwd, home, exists })).toBe(path.join(cwd, "ai_os"));
  });

  it("都找不到時回傳 undefined（維持「沒測到」而非假通過）", () => {
    expect(discoverAiosRepo({ cwd: "/workspace", home: "/home/ubuntu", exists: () => false })).toBeUndefined();
  });
});
