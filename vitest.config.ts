import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // 檢測系統本身的測試必須離線可跑：所有純分析函式（CSP／標頭／殼層設定）
    // 都不碰網路，需要網路的偵測器一律靠注入的 fetch 假件測試。
    testTimeout: 15_000,
  },
});
