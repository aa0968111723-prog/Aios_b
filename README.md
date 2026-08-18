# Aios Sentinel

連動 **aios 網站／App／桌面** 三端的錯誤、資訊安全與頁面檢測系統。

一條指令掃完三端，產出可直接交給非工程背景同仁閱讀的報告，並在 CI 上把「有問題」與
「**沒測到**」清楚分開——後者是這類工具最常見、也最危險的失效方式。

```bash
npm install
npm run sentinel -- all --repo ../ai_os
```

---

## 為什麼是「三端」

讀 `ai_os` 原始碼可以確認，三端並不是三份程式碼：

| 端 | 載體 | 實際載入 | 依據 |
| --- | --- | --- | --- |
| 網站 | 瀏覽器 | 部署站 | `client/` + `server/index.ts` |
| App | Capacitor Android 薄殼（WebView） | **同一個部署站** | `capacitor.config.ts` 的 `server.url` |
| 桌面 | Tauri WebView | **同一個部署站** | `src-tauri/tauri.conf.json` 的視窗 `url` |

也就是說：**同一個站被三種載體以不同 UA、視窗與能力載入**。所以本系統的做法是

1. 用三種 surface 人格分別掃同一個站（伺服器可能對不同 UA 給不同分支，破口常藏在那裡）；
2. 比對三端拿到的 build 版本是否一致（同源卻不同版＝快取或部署沒同步）；
3. 額外靜態稽核殼層設定——那些設定被編譯進安裝檔，**線上掃描永遠看不到**。

---

## 檢測涵蓋範圍

### 資訊安全

| 檢查 | 內容 |
| --- | --- |
| `transport` | HSTS、nosniff、點擊劫持、Referrer-Policy、Permissions-Policy、COOP、版本洩漏、快取；http→https 導向、混合內容、meta 與標頭 CSP 衝突 |
| `csp`（含於 transport） | 指令級分析：`unsafe-eval`／`unsafe-inline`（含 nonce 例外）、萬用來源、`object-src`、`base-uri`、`frame-ancestors`（不吃 `default-src` 兜底）、違規回報 |
| `cookies`（含於 transport） | HttpOnly／Secure／SameSite／Domain 作用域，**依 Cookie 用途分級**（會話憑證缺 HttpOnly＝critical，主題偏好＝low） |
| `auth-gate` | 未登入直接打受保護端點：`/api/selftest`、`/api/v1/databases`、`/api/me/export`、素材備份、專案匯出、tRPC 程序…。tRPC 未授權也回 HTTP 200，故改看回應內容判定 |
| `disclosure` | `.env`、`.git`、原始碼、備份檔、`.npmrc`；source map；錯誤回應洩漏堆疊；目錄列表。**每一筆都先排除 SPA 兜底頁**，否則整排假警報 |
| `cors` | 反射任意 Origin、`*`、`null` 來源，並與 `allow-credentials` 交叉判定 |
| `shell-audit` | Capacitor（cleartext、http url、allowNavigation）、AndroidManifest（debuggable、allowBackup、明文流量、多餘權限）、Tauri（`csp: null`、devtools、能力萬用授權、危險 IPC） |

### 可用性與一致性

| 檢查 | 內容 |
| --- | --- |
| `health` | `/api/health` 與 `/api/ready`；把 503 的分項（db／boot／storage／runner／provider）翻成人看得懂的故障判定，並抓 runner 心跳停滯與佇列積壓 |
| `build-drift` | 三端 build SHA／分支比對。**同源不同版＝high**（快取或部署沒同步）；刻意指向不同部署＝info |
| `shell-audit` | 殼層寫死的網址是否與受測目標一致——不一致代表「報告全綠，但沒驗到 App 使用者真正連的系統」 |

### 頁面測試

| 檢查 | 內容 |
| --- | --- |
| `page-test` | 逐路由巡覽：SPA 是否掛載、主內容是否卡在載入中、未捕捉 JS 例外、console 錯誤、請求失敗與 4xx/5xx、破圖、橫向溢出、行動端觸控目標、缺 title／h1、載入耗時 |
| `a11y` | axe-core（WCAG 2.0/2.1 A+AA），只報 serious 以上並跨路由聚合 |

---

## 使用方式

```bash
npm run sentinel -- <指令> [選項]
```

| 指令 | 說明 | 需要 |
| --- | --- | --- |
| `scan` | 資安與可用性掃描 | 網路 |
| `pages` | 頁面測試與無障礙掃描 | 網路 + playwright |
| `shells` | 殼層設定稽核 | `ai_os` 原始碼 |
| `all` | 以上全部 | — |

常用選項：

> `shells`／`all` 會**自動探測**就地的 ai_os 檢出（`./ai_os`、`../ai_os`、`~/ai_os`），
> 找到就直接連上跑殼層稽核，不必每次帶 `--repo`。優先序：`--repo` ＞ `AIOS_REPO` ＞ 自動探測。
> 探測依據是殼層設定檔本身（capacitor.config.ts／AndroidManifest.xml／tauri.conf.json），
> 不會把同名資料夾誤認成 ai_os；都找不到時殼層稽核照舊標記跳過，不會假裝通過。

```
--target <url>        受測站台（預設 https://ai-os-app.zeabur.app）
--surfaces <list>     web,app,desktop（預設全部）
--repo <path>         ai_os 原始碼路徑（未指定則自動探測就地檢出）
--routes <list>       自訂受測路由
--out <dir>           報告輸出目錄（預設 ./reports）
--fail-on <severity>  達此嚴重度即以非 0 結束（預設 high）
--no-screenshots      不存截圖
--json                只輸出 JSON 到 stdout
```

環境變數：

```
AIOS_TARGET / AIOS_REPO                          同 --target / --repo
AIOS_WEB_TARGET / AIOS_APP_TARGET /
AIOS_DESKTOP_TARGET                              個別覆寫某一端（用於偵測版本漂移）
TEST_EMAIL / TEST_PW                             頁面測試登入；不提供則只測公開路由
SENTINEL_CHROMIUM_PATH                           指向映像檔既有的 Chromium
```

範例：

```bash
# 完整檢測（含殼層稽核）
npm run sentinel -- all --repo ../ai_os

# 只掃 App 與桌面兩端，門檻拉緊
npm run sentinel -- scan --surfaces app,desktop --fail-on medium

# 登入後巡覽全部路由
TEST_EMAIL=qa@example.com TEST_PW=... npm run sentinel -- pages
```

### 報告

每次執行輸出三份到 `--out`：

- `report.html` — 單一自足檔案的儀表板，可直接寄出；深淺色皆可讀，支援嚴重度篩選
- `report.md` — 貼進 PR 或 issue
- `report.json` — 給程式消費

### 結束碼

| 碼 | 意義 |
| --- | --- |
| 0 | 通過 |
| 1 | 有達到 `--fail-on` 門檻的發現 |
| 2 | 檢查器自身出錯 |
| 3 | **什麼都沒實際執行**（連不到站、缺瀏覽器） |

3 是刻意分出來的。全部被跳過時若回 0，CI 會顯示綠燈，而那個綠燈的意思其實是
「我們什麼都沒驗」——這種假綠燈比紅燈危險得多。

---

## 設計原則

**「沒測到」永遠不會被講成「沒問題」。**
實測踩過：在有出口代理的環境跑掃描，代理對所有請求回 403，報告於是列出
「缺 HSTS／缺 CSP／缺 nosniff」一整排 high——全部無效，因為請求根本沒到達站台。
現在每一端開跑前先做連通性前置檢查，判定為中介層攔截就整組標記跳過並寫明原因。

**每筆發現都必須帶修法。** 沒有修法的告警會被無視，被無視的告警等於沒有檢測。

**嚴重度看用途，不看缺陷種類。** 會話 Cookie 缺 HttpOnly 是 critical，主題偏好缺
HttpOnly 是 low。一律同級只會讓人整批關掉告警。

**降噪是正經工作。** SPA 對未知路徑一律回 index.html 200；未登入巡覽受保護頁時 401
是正確行為；`style-src 'unsafe-inline'` 是 ai_os 已知的 React 取捨。這些都要主動排除，
否則真正的問題會被雜訊淹沒。

**檢查器爆掉不能拖垮整輪。** 每項都獨立捕捉例外，轉成 `error` 欄位並與「發現問題」分開統計。

**序列執行，不並行。** 並行掃描會對小型部署造成突發負載，然後把自己造成的 5xx
報成「站台有問題」。檢測系統不該污染它要測量的東西。

---

## 開發

```bash
npm test          # 129 項單元測試，全部離線可跑
npm run typecheck
```

所有判定邏輯都寫成純函式（`analyzeCsp`、`analyzeSecurityHeaders`、`analyzeCookies`、
`analyzeBuildDrift`、`analyzeCapacitor`／`analyzeManifest`／`analyzeTauri`、`judgePage`），
網路與檔案 I/O 集中在各偵測器的 `check*` 進入點。資安規則最容易寫錯，而寫錯的規則
會製造假綠燈——所以規則必須能在沒有網路、不依賴線上站當時設定的情況下被測試。

```
src/
  core/       型別、嚴重度、HTTP 探針、surface 定義、連通性前置檢查、執行編排
  detectors/  health / transport / csp / headers / cookies / authGate /
              disclosure / cors / buildDrift / shellAudit
  pages/      browser（playwright 薄封裝）/ routes / pageTest / a11y
  report/     console / markdown / html
```

## 涵蓋不到的部分

自動化只能判定客觀可判定的事。以下仍需人工審查：

- 業務邏輯授權（A 團隊能不能讀到 B 團隊的專案）——需要兩組真實帳號做交叉驗證
- 資料隔離與 IDOR——需要真實存在的識別碼
- 上傳檔案的內容安全（惡意檔案、解壓縮炸彈）
- 視覺正確性——需要 baseline 與人工判讀
