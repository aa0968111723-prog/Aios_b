# 檢查項目對照表

每一筆發現都有穩定的 `id`，可用於抑制清單、跨次執行比對，以及在這份文件裡查到判定依據。
`id` 一旦發布就不改——改了會讓歷史比對斷掉。

## 嚴重度定義

| 等級 | 意義 | 處理時限 |
| --- | --- | --- |
| `critical` | **現在就在外洩資料或可被接管**。未認證取得資料、憑證可被竊、可執行任意程式碼 | 立即 |
| `high` | 明確的攻擊路徑或使用者當下就受影響（頁面全壞、站台不可用） | 當週 |
| `medium` | 防護缺口，需搭配其他條件才成災；或部分使用者受影響 | 當月 |
| `low` | 體質問題、資訊洩漏、體驗瑕疵 | 排入待辦 |
| `info` | 觀測記錄與已知取捨，不需處理 | — |

嚴重度**看用途，不看缺陷種類**：`cookies.httponly.sid` 是 critical，
`cookies.httponly.theme` 是 low——同一個缺陷，風險完全不同。

---

## security-headers / csp

| id | 等級 | 判定 |
| --- | --- | --- |
| `headers.hsts.missing` | high | https 目標無 HSTS |
| `headers.hsts.short` | medium | `max-age` < 15552000（180 天） |
| `headers.hsts.no-subdomains` | low | 缺 `includeSubDomains` |
| `headers.nosniff` | medium | 缺 `X-Content-Type-Options: nosniff`（上傳素材站的儲存型 XSS 風險） |
| `headers.clickjacking` | medium | `X-Frame-Options` 與 CSP `frame-ancestors` 皆缺 |
| `headers.xfo.invalid` | low | `X-Frame-Options` 用已失效語法（如 `ALLOW-FROM`） |
| `headers.referrer-policy` | low | 缺 `Referrer-Policy` |
| `headers.referrer-policy.unsafe` | medium | 值為 `unsafe-url` |
| `headers.permissions-policy` | low | 缺 `Permissions-Policy` |
| `headers.coop` | low | 缺 `Cross-Origin-Opener-Policy` |
| `headers.x-powered-by` / `headers.server-version` | low | 洩漏技術棧與版本 |
| `headers.cache-public` | info | HTML 允許公用快取 |
| `csp.missing` | high | 無 CSP。此時**只報這一筆**，不連帶噴出指令級告警 |
| `csp.no-default-src` | medium | 無 `default-src` 兜底 |
| `csp.script-src.unrestricted` | high | 既無 `script-src` 也無 `default-src` |
| `csp.script-src.unsafe-eval` | high | 允許 `eval` |
| `csp.script-src.unsafe-inline` | high | 允許 inline 腳本**且無 nonce/hash**（有 nonce 時現代瀏覽器會忽略它，故不報） |
| `csp.script-src.wildcard` | high／medium | `*` 為 high，裸 scheme（`https:`）為 medium |
| `csp.script-src.inherited` | info | `script-src` 由 `default-src` 繼承 |
| `csp.object-src` | medium | 未設為 `'none'` |
| `csp.base-uri` | medium | 缺 `base-uri`（注入 `<base>` 可繞過 `script-src 'self'`） |
| `csp.frame-ancestors` | medium | 缺 `frame-ancestors`。**此指令不吃 `default-src` 兜底**，是規格特例 |
| `csp.style-src.unsafe-inline` | low | ai_os 已知取捨（React inline style），標為 low 並註明 |
| `csp.connect-src.wildcard` | low | `connect-src *` 放大 XSS 的外洩管道 |
| `csp.reporting.*` | info | 是否設定違規回報 |

## cookies

| id | 等級 | 判定 |
| --- | --- | --- |
| `cookies.httponly.<name>` | critical／low | 會話類 Cookie 缺 `HttpOnly` 為 critical，其餘 low |
| `cookies.secure.<name>` | high／low | 同上分級（僅 https 目標） |
| `cookies.samesite.<name>` | medium／info | 未指定 `SameSite` |
| `cookies.samesite-none-insecure.<name>` | high | `SameSite=None` 未配 `Secure`（會被瀏覽器拒收） |
| `cookies.samesite-none.<name>` | medium | 會話 Cookie 為 `SameSite=None` |
| `cookies.domain-scope.<name>` | medium | 會話 Cookie 的 `Domain` 開到父網域 |

會話類的判定樣式：`sid` `sess` `session` `token` `auth` `jwt` `csrf` `refresh`。
證據欄位**不含 Cookie 值**——報告本身不能變成外洩管道。

## transport

| id | 等級 | 判定 |
| --- | --- | --- |
| `transport.no-https-redirect` | high／medium | http 未導向 https（回 200 為 high） |
| `transport.mixed-content` | medium | 首頁含 http 子資源（`localhost` 不算） |
| `transport.duplicate-csp` | low | meta 與標頭 CSP 並存（取交集，難排查） |

## auth-gate

未登入直接請求受保護端點。tRPC 未授權**也回 HTTP 200**，故改看回應內容判定。

| id | 等級 | 判定 |
| --- | --- | --- |
| `auth-gate.open.<path>` | 依端點 | 回 200。有實際內容時用端點原定等級，空內容降為 medium |
| `auth-gate.trpc.<path>` | 依端點 | tRPC 回 200 且內容不是 `UNAUTHORIZED`／`FORBIDDEN` |
| `auth-gate.error.<path>` | medium | 回 5xx——認證檢查位置太後面，且錯誤可能洩漏內部細節 |

導向登入頁視為**有正確擋下**。

## disclosure

| id | 等級 | 判定 |
| --- | --- | --- |
| `disclosure.file./.env` | critical | 內容符合 `KEY=value` 特徵 |
| `disclosure.file./.git/HEAD` `/.git/config` | critical | 符合 git 檔案特徵 |
| `disclosure.file./.npmrc` `/backup.sql` `/server/index.ts` | critical | 各有內容特徵 |
| `disclosure.file./docker-compose.yml` | high | — |
| `disclosure.file./package.json` `/.env.example` | low | — |
| `disclosure.sourcemap` | medium | 正式站可下載 `.map` |
| `disclosure.stack-trace.*` | medium | 錯誤回應含 V8 堆疊或伺服器絕對路徑 |
| `disclosure.dir-listing.*` | high | 目錄索引可瀏覽 |

**每一筆都先排除 SPA 兜底頁**（`text/html` 且含 `<div id="root">` 或 module script），
再要求內容符合特徵。少了這道，SPA 對未知路徑一律回 200 會讓每條路徑都變成假警報。

## cors

| id | 等級 | 判定 |
| --- | --- | --- |
| `cors.reflects-origin` | critical／high | 反射任意 Origin；搭配 `allow-credentials` 為 critical |
| `cors.wildcard` | critical／low | `*`；搭配 credentials 為 critical |
| `cors.null-origin` | high | 允許 `null` 來源 |

## health

| id | 等級 | 判定 |
| --- | --- | --- |
| `health.unreachable` | critical | 健康檢查連不上。**此時直接收工**，不產生次生告警 |
| `health.not-ok` | critical | 非 200 或 `ok !== true` |
| `health.slow` | medium | > 3 秒（此端點不做 I/O，慢＝事件迴圈被卡） |
| `health.no-build-sha` | low | 無版本識別 |
| `ready.unreachable` | high | 就緒端點連不上（多為 DB 連線池耗盡） |
| `ready.unparseable` | medium | 回應不是 JSON |
| `ready.component.db` | critical | — |
| `ready.component.boot` / `.storage` | high | — |
| `ready.component.runner` / `.provider` | medium | — |
| `ready.inconsistent` | medium | 整體 503 但所有分項都通過 |
| `ready.runner.stopped.<name>` | medium | 執行器未啟動 |
| `ready.runner.stale.<name>` | medium | 心跳停滯 > 120 秒 |
| `ready.runner.backlog.<name>` | low | 佇列 > 50 |

## build-drift

| id | 等級 | 判定 |
| --- | --- | --- |
| `build-drift.sha-mismatch` | high／info | **同源**不同版為 high（快取或部署沒同步）；異源為 info（設定意圖） |
| `build-drift.branch-mismatch` | medium | 三端來自不同分支 |
| `build-drift.sha-missing` | low | 部分端無 SHA，比對有盲區 |

少於兩端可連時不做判定——沒有比較基準。

## shell-audit

| id | 等級 | 判定 |
| --- | --- | --- |
| `shell.capacitor.http-url` | critical | `server.url` 走 http |
| `shell.capacitor.cleartext` | high | `cleartext: true` |
| `shell.capacitor.scheme` | medium | `androidScheme` 非 https |
| `shell.capacitor.allow-navigation.*` | high | 含萬用字元 |
| `shell.capacitor.no-server-url` | info | 改用本地打包（非漏洞，但 App 版本會落後） |
| `shell.android.debuggable` | critical | `debuggable=true` |
| `shell.android.cleartext` | high | `usesCleartextTraffic=true`（未指定時不報） |
| `shell.android.allow-backup` | medium | `allowBackup=true`（備份會帶走已登入狀態） |
| `shell.android.permissions` | medium | 薄殼 App 出現高風險權限 |
| `shell.tauri.capability-wildcard.*` | critical | 能力對任意網域開放（`https://網域/*` 是正常的路徑萬用，不報） |
| `shell.tauri.http-window` | critical | 視窗以 http 載入 |
| `shell.tauri.dangerous-ipc` | high | `dangerousRemoteDomainIpcAccess` |
| `shell.tauri.csp-null` | medium | `security.csp` 為 null（桌面端完全靠遠端站標頭撐著） |
| `shell.tauri.devtools` | medium | 發布版開著 devtools |
| `shell.target-mismatch.capacitor` / `.tauri` | high | 殼層指向的站與受測目標不同 |
| `shell.deeplink-mismatch` | medium | 深層連結 host 與 App 載入的站不一致 |

## page-test

| id | 等級 | 判定 |
| --- | --- | --- |
| `page.server-error.<route>` | critical | HTTP 5xx |
| `page.shell-not-mounted.<route>` | critical | `div.app` 15 秒內未出現。**此時直接收工**，不產生次生告警 |
| `page.content-stuck.<route>` | high | 主內容 20 秒仍只有「載入中…」佔位 |
| `page.js-exception.<route>.*` | high | 未捕捉的 JS 例外 |
| `page.bad-responses.<route>` | high／medium | 請求回 4xx/5xx（最高 5xx 為 high） |
| `page.console-errors.<route>` | medium | console.error |
| `page.failed-requests.<route>` | medium | 資源連線層失敗（被 CSP 擋、網域解析失敗） |
| `page.overflow.<route>` | medium／low | 橫向溢出，行動端為 medium |
| `page.slow.<route>` | medium | 載入 > 10 秒 |
| `page.broken-images.<route>` | low | 圖片 `naturalWidth === 0` |
| `page.touch-targets.<route>` | low | 行動端觸控目標 < 44px |
| `page.no-title.<route>` / `page.no-h1.<route>` | low | 缺標題（h1 僅在內容就緒時才判） |
| `page.login-failed` | high | 提供了帳密卻登入失敗——**所有需登入頁面實際上都沒被測到** |

**降噪規則**（沒有這些，報告會失去可信度）：

- 未登入巡覽受保護路由時，401/403 與「卡在載入中」都是**正確行為**，不報
- console 噪音過濾：favicon、React DevTools 提示、vite HMR、ResizeObserver loop
- `ERR_ABORTED`（換頁取消）不算請求失敗

## a11y

axe-core WCAG 2.0/2.1 A+AA。impact 對應：`critical`→high、`serious`→medium、
`moderate`→low、`minor` 不報。同規則跨路由聚合成一筆，附上出現的頁面清單。

只在網頁端跑一次——三端載的是同一份 DOM，重複掃只會產生三份一模一樣的違規清單。

---

# 監測（monitor）

`monitor` 指令深度連結 aios 的實際運行面：使用者行為分析、平台錯誤、資料庫進出、裝置。
原始碼類判定（PostHog 用戶端設定、DB 暴露）只在 **web 端跑一次**，避免三端重複同一份判定。

## analytics（PostHog 使用者行為）

| id | 等級 | 判定 |
| --- | --- | --- |
| `analytics.posthog.personal-key-leak` | critical | 前端疑似寫死 `phx_`／`phs_` 個人金鑰（公開的 `phc_` 專案金鑰不報） |
| `analytics.posthog.no-exception-capture` | medium | 未開 `capture_unhandled_errors`，前端例外不進監測 |
| `analytics.posthog.no-console-capture` | low | 未擷取 console 錯誤（ai_os 現況取捨） |
| `analytics.posthog.not-loaded` | high | 正式站進入點找不到 PostHog——金鑰漏設時事件會靜默全掉 |
| `analytics.posthog.csp-blocked` | high | 有載 PostHog 但 CSP `script-src` 未放行其來源，請求會被瀏覽器擋掉 |
| `analytics.posthog.no-recent-events` | high | （需 API 金鑰）觀測窗內 0 事件，分析疑似靜默失效 |
| `analytics.posthog.exceptions-observed` | medium | （需 API 金鑰）觀測到前端例外事件 |

深度段需 `POSTHOG_API_KEY`／`POSTHOG_PROJECT_ID`／`POSTHOG_HOST`；未提供時記錄 `insightSkipped`，不假裝有拉到資料。

## zeabur（平台錯誤）

| id | 等級 | 判定 |
| --- | --- | --- |
| `zeabur.edge-5xx` | high | 反向代理回 502/503/504 且非應用頁面（後端當掉／冷啟動） |
| `zeabur.gateway-intercept` | medium | 回應被中介層攔截，本輪其實沒觸及站台 |
| `zeabur.ephemeral-storage` | high | 就緒 storage 分項顯示素材存非持久磁碟，重新部署即遺失 |
| `zeabur.deploy-failed` | high | （需 API token）最近一次部署狀態為 FAILED/ERROR |

應用自己回的 5xx（帶 SPA 外殼或應用 JSON）歸類為 `app-error`，交由 health/page-test 處理，不在此重報。
深度段需 `ZEABUR_API_TOKEN`／`ZEABUR_SERVICE_ID`。

## db-traffic（資料庫進出）

連續取樣 `/api/ready`（會實打 DB）觀測連線與往返，序列進行以免造成突發負載。

| id | 等級 | 判定 |
| --- | --- | --- |
| `db.unreachable` | critical | db 分項失敗，讀寫進出中斷 |
| `db.ready-timeout` | high | 取樣全數逾時，連線池疑似耗盡 |
| `db.slow-roundtrip` | medium | 就緒平均延遲 > 1500ms（DB 往返偏慢） |
| `db.url-in-client` | critical | 連線字串疑似出現在前端 |
| `db.public-studio` | high | 疑似有公開的資料庫管理介面 |

## device（裝置紀錄）

把每一端的裝置人格（UA、視窗、行動、觸控、殼層標頭）與實測回應原樣記入 `facts.deviceLedger`。

| id | 等級 | 判定 |
| --- | --- | --- |
| `device.persona-mismatch.<surface>` | low | 該端裝置人格內部不一致（標為行動卻是桌面 UA／寬視窗） |
| `device.blocked.<surface>` | high | 只有此裝置被伺服器回 403/451 而其他端正常（按裝置歧視／WAF 誤擋） |
