#!/usr/bin/env bash
# Aios Sentinel — Cloud Agent 安裝腳本。
# 冪等：可重複執行；不啟動任何常駐程序。
set -euo pipefail

# 1) 專案自身依賴。
npm ci

# 2) 頁面測試用的 Chromium（playwright 是 optionalDependency，這裡補上瀏覽器）。
npm run browsers:install

# 3) 深度連結 ai_os 原始碼。
#    殼層稽核（Capacitor／AndroidManifest／Tauri）只能從原始碼取得——這些設定被編譯進
#    安裝檔，線上永遠掃不到。把 ai_os 併排檢出到 ~/ai_os，CLI 會自動探測到它，於是
#    `npm run sentinel -- all` 不帶任何旗標就能跑完整三端檢測（含殼層）。
#
#    取不到 ai_os 時「不」讓環境建置失敗：殼層稽核會自行標記跳過並回 exit 3，
#    這正是本工具「沒測到 ≠ 沒問題」的核心設計，比假裝通過安全得多。
AIOS_DIR="${AIOS_REPO:-$HOME/ai_os}"
AIOS_URL="https://github.com/aa0968111723-prog/ai_os.git"
if [ -d "$AIOS_DIR/.git" ]; then
  echo "更新既有的 ai_os 檢出：$AIOS_DIR"
  git -C "$AIOS_DIR" fetch --depth 1 origin HEAD && git -C "$AIOS_DIR" reset --hard FETCH_HEAD \
    || echo "警告：ai_os 更新失敗，沿用既有檢出。"
else
  echo "取出 ai_os 原始碼到：$AIOS_DIR"
  git clone --depth 1 "$AIOS_URL" "$AIOS_DIR" \
    || echo "警告：ai_os 取出失敗——殼層稽核將標記跳過（非阻斷）。"
fi
