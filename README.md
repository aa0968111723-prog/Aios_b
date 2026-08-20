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
| `tls` | 憑證到期（7／14／30 天分級）、主機名不符（萬用 SAN 依規格只吃一層）、自簽、弱簽章、過長效期、TLSv1／1.1、弱金鑰。連不上 443 一律標記跳過——把代理擋掉報成憑證問題是嚴重誤判 |
| `methods` | TRACE 是否開啟與是否回吐請求（Cross-Site Tracing）、`Allow` 洩漏危險方法。**只送 OPTIONS 與 TRACE**——絕不對真實端點送寫入方法 |
| `redirect` | 開放重導向：常見回跳參數逐一探測，處理協定相對、反斜線、`@` 混淆、子網域四種繞法；落在自家網域不報 |
| `supply-chain` | 第三方腳本與樣式表盤點、SRI 缺失、有 integrity 卻沒 crossorigin（瀏覽器會直接拒載，靜默壞掉）、http 子資源。只看初始 HTML，動態插入的看不到 |
| `wellknown` | `robots.txt` 是否把敏感路徑公告出去、`security.txt`（RFC 9116）是否存在且未過期 |
| `rate-limit` | 登入端點的速率限制。**預設不執行**，需 `--probe-rate-limit` 明確授權——它會送出數次失敗嘗試，可能觸發帳號鎖定或資安告警 |
| `shell-audit` | Capacitor（cleartext、http url、allowNavigation）、AndroidManifest（debuggable、allowBackup、明文流量、多餘權限）、Tauri（`csp: null`、devtools、能力萬用授權、危險 IPC）。解析前一律剝除註解——被註解掉的本機開發設定照收，會讓正常專案噴出整排 critical |

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

### 深度監測（`monitor`）

深度連結 aios 的實際運行面——不是「有沒有設定」，而是「線上到底發生了什麼」。

| 檢查 | 內容 |
| --- | --- |
| `analytics` | PostHog 使用者行為監測：用戶端設定稽核（例外／console 擷取、個人金鑰外洩）、正式站是否真的載入 PostHog、CSP 有沒有把分析請求擋掉；選配以 PostHog API 拉近期事件量、前端例外與裝置分布——**分析靜默失效比沒裝分析更危險** |
| `zeabur` | 平台層錯誤：把邊緣 5xx（代理連不到後端／冷啟動）與應用自身的 5xx 分開，抓素材存在非持久磁碟（重新部署即遺失）；選配以 Zeabur API 拉部署狀態 |
| `db-traffic` | 資料庫進出：連續取樣會實打 DB 的 `/api/ready`，觀測連線、往返延遲與間歇逾時（連線池耗盡）；並稽核連線字串是否漏進前端 |
| `device` | 裝置紀錄：把三端的裝置人格與實測回應原樣記入報告，抓「只有某個裝置被 WAF 擋下」這種桌面瀏覽器永遠重現不出來的問題 |

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
| `monitor` | 深度監測：PostHog 使用者行為、Zeabur 平台錯誤、資料庫進出、裝置紀錄 | 網路（＋選配 API 金鑰） |
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
--formats <list>      輸出格式：json,md,html,sarif,junit（預設前三者）
--only <list>         只執行這些檢查或分類（例：--only security、--only csp,cors）
--skip <list>         略過這些檢查或分類
--baseline <path>     以既有的 report.json 為基準，比對出新增與已修復
--suppress <path>     抑制清單 JSON（用 --init-suppress 產生範本）
--fail-on <severity>  達此嚴重度即以非 0 結束（預設 high）
--fail-on-new         只有新增與惡化才以非 0 結束（需搭配 --baseline）
--probe-rate-limit    授權對登入端點做速率限制探測（預設不做，見下）
--no-screenshots      不存截圖
--json                只輸出 JSON 到 stdout
```

> `--only` 與 `--skip` **不會讓被篩掉的檢查從報告上消失**——它們會變成「跳過＋原因」。
> 直接拿掉的話，一份 `--only csp` 的報告看起來會跟一份跑完全部後全綠的報告一模一樣。

環境變數：

```
AIOS_TARGET / AIOS_REPO                          同 --target / --repo
AIOS_WEB_TARGET / AIOS_APP_TARGET /
AIOS_DESKTOP_TARGET                              個別覆寫某一端（用於偵測版本漂移）
TEST_EMAIL / TEST_PW                             頁面測試登入；不提供則只測公開路由
SENTINEL_CHROMIUM_PATH                           指向映像檔既有的 Chromium
POSTHOG_API_KEY / POSTHOG_PROJECT_ID / POSTHOG_HOST
                                                 monitor 深度拉取近期使用者行為與前端例外；不提供則略過該段
ZEABUR_API_TOKEN / ZEABUR_SERVICE_ID             monitor 深度拉取 Zeabur 部署狀態；不提供則略過該段
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

預設輸出三份到 `--out`（用 `--formats` 可加選另外兩種）：

- `report.html` — 單一自足檔案的儀表板，可直接寄出；深淺色皆可讀，支援嚴重度篩選
- `report.md` — 貼進 PR 或 issue
- `report.json` — 給程式消費，同時也是下一次執行的**基準檔**
- `report.sarif` — SARIF 2.1.0，上傳到 GitHub code scanning 就能在 PR 上就地標示
- `report.junit.xml` — JUnit XML，讓 CI 既有的測試面板直接顯示三端狀態

SARIF 與 JUnit 都把「跳過」與「執行錯誤」如實帶出去（SARIF 走
`invocations[].toolExecutionNotifications`，JUnit 走 `<skipped>` 與 `<error>`）。
兩種格式的預設語意都是「沒有 failure 就是綠的」，直接映射會把「沒測到」畫成一排綠勾——
那正是這套系統最反對的失效方式。

---

## 跨次執行比對

一次執行只是一張快照。真正要回答的問題是「這次多了什麼」與「上次那件修好了沒」：

```bash
# 昨天的 report.json 當基準
npm run sentinel -- all --baseline reports/report.json
```

報告會多出一區：**新增／已修復／嚴重度惡化／持續**，主清單上的新增發現也會被標記。
搭配 `--fail-on-new` 時，存量問題不擋 CI，但新增與惡化要擋——這是把檢測導入既有專案的
務實做法：第一次跑完滿江紅、接著整個檢查被關掉，那等於沒有檢測。

三件事刻意做成不會安靜出錯：

- 基準檔讀不出來 → 產生一筆 `baseline.unreadable`（medium），**不會**當成空基準。
  當成空基準會讓所有存量問題被報成新增；當成沒有變化則會讓真正的新增被吃掉。
- 基準檔測的是別的站 → 報告明白寫出兩邊的目標，別把部署差異當成「這次改壞了」。
- 沒有基準可比時 `--fail-on-new` 退回一般門檻判定——絕不因為拿不到基準就放行。

CI 已接好：每天的排程會用快取滾動保存上一輪的 `report.json`，於是每天都是在跟昨天比。

---

## 抑制清單

任何檢測系統活過三個月都會需要抑制清單——已知取捨、待排程的問題、第三方無法修的東西。
但抑制清單本身是這類系統最常見的死法：有人為了讓 CI 變綠把整批告警關掉，
半年後沒人記得為什麼關、也沒人重新檢視。

所以這裡的立場是：**抑制是一種有期限、要具名、且永遠留在報告上的決定，
不是讓問題消失的開關。**

```bash
npm run sentinel -- --init-suppress > .sentinel-suppressions.json
npm run sentinel -- all --suppress .sentinel-suppressions.json
```

```json
[
  {
    "id": "csp.style-src.unsafe-inline",
    "reason": "React inline style 的已知取捨，等 CSS-in-JS 遷移完成後移除",
    "expires": "2026-12-31",
    "owner": "平台組"
  }
]
```

規則：

| 行為 | 結果 |
| --- | --- |
| `reason` 空白或缺少 | 規則不生效，並產生 `suppress.invalid-rule`（medium） |
| `expires` 已過 | 規則不生效，發現重新浮現，並附上 `suppress.expired`（low） |
| 缺 `expires` | 允許，但產生 `suppress.no-expiry`（info）——永久抑制應該極少 |
| 規則沒命中任何發現 | `suppress.stale`（info）：死規則會在問題復發時把它靜默吃掉 |
| 蓋掉 critical 級發現 | 需要 `"acknowledgeCritical": true`，否則照常回報 |

被抑制的發現連同理由、到期日、負責人留在報告的「已抑制」一區，計數也留在總覽。

---

## 結束碼

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
npm test          # 758 項測試，全部離線可跑（含以本機假站台驅動的端到端測試）
npm run typecheck
```

所有判定邏輯都寫成純函式（`analyzeCsp`、`analyzeSecurityHeaders`、`analyzeCookies`、
`analyzeBuildDrift`、`analyzeCapacitor`／`analyzeManifest`／`analyzeTauri`、`judgePage`），
網路與檔案 I/O 集中在各偵測器的 `check*` 進入點。資安規則最容易寫錯，而寫錯的規則
會製造假綠燈——所以規則必須能在沒有網路、不依賴線上站當時設定的情況下被測試。

測試分三層，各自擋不同的失效方式：

| 層 | 驗什麼 | 為什麼純函式測試不夠 |
| --- | --- | --- |
| 純函式 | 判定規則本身 | — |
| 假 fetch 驅動的 `check*` | `completed` 與 `skippedReason` 的語意 | 「跳過還是通過」是 IO 層的決定，純函式看不到 |
| `tests/cli.e2e.test.ts` | 接線 | 一個忘了接上的偵測器，在報告上看起來就跟「這項沒發現問題」一模一樣 |

端到端測試起一個本機假站台（SPA 兜底、健康端點、沒有安全標頭），用子行程跑真正的 CLI 打它，
不碰外部網路。

```
src/
  core/       型別、嚴重度、HTTP 探針、surface 定義、連通性前置檢查、執行編排、ai_os 探測、
              跨次比對（baseline）、抑制清單（suppress）、檢查過濾（filter）、報告後製（annotate）
  detectors/  health / transport / csp / headers / cookies / authGate /
              disclosure / cors / buildDrift / shellAudit / tls / methods /
              redirect / supplyChain / wellknown / rateLimit /
              analytics（PostHog）/ zeabur / dbTraffic / device
  pages/      browser（playwright 薄封裝）/ routes / pageTest / a11y
  report/     console / markdown / html / sarif / junit
```

## 涵蓋不到的部分

自動化只能判定客觀可判定的事。以下仍需人工審查：

- 業務邏輯授權（A 團隊能不能讀到 B 團隊的專案）——需要兩組真實帳號做交叉驗證
- 資料隔離與 IDOR——需要真實存在的識別碼
- 上傳檔案的內容安全（惡意檔案、解壓縮炸彈）
- 視覺正確性——需要 baseline 與人工判讀
