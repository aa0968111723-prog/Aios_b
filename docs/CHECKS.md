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
| `csp.missing` | high | 標頭與 meta 都沒有 CSP。此時**只報這一筆**，不連帶噴出指令級告警 |
| `csp.header-missing-meta-only` | medium | 政策只寫在 `<meta>`。它確實生效，所以不報 `csp.missing`；但 `frame-ancestors` 與回報端點在 meta 版本會被瀏覽器忽略，且政策要解析到那一行才開始套用 |
| `csp.no-default-src` | medium | 無 `default-src` 兜底 |
| `csp.script-src.unrestricted` | high | 既無 `script-src` 也無 `default-src` |
| `csp.script-src.unsafe-eval` | high | 允許 `eval` |
| `csp.script-src.unsafe-inline` | high | 允許 inline 腳本**且無 nonce/hash**（有 nonce 時現代瀏覽器會忽略它，故不報） |
| `csp.script-src.wildcard` | high／medium | `*` 為 high，裸 scheme（`https:`）為 medium。**含 `'strict-dynamic'` 時不報**——依 CSP3，那些來源會被瀏覽器忽略，它們是留給舊瀏覽器的回退值 |
| `csp.script-src.strict-dynamic-without-nonce` | high | 有 `'strict-dynamic'` 卻沒有任何 nonce／hash：腳本全被擋掉（功能壞掉），或在舊瀏覽器退回萬用來源（防護等於沒有） |
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

會話類的判定用**斷詞**而非子字串或分隔符比對：名稱先依 `._-` 與 camelCase／PascalCase 邊界切開，
任一詞落在 `sid` `sess` `session` `token` `auth` `jwt` `csrf` `xsrf` `refresh` 即為會話類。
只認分隔符的話 `authToken`／`sessionToken` 會被判為非會話，同一個缺陷從 critical 被降成 low——
而駝峰正是 JS 生態最常見的寫法。另外也單獨列出各框架的預設名（`csrftoken`、`JSESSIONID`…），
那些拆不開。

除了名稱，**值的形狀**也算證據：JWT（`eyJ…`）與 express `cookie-parser` 的簽章前綴（`s:`）
是無歧義的憑證特徵，名字取成什麼都一樣。刻意不用「夠長就算」這種門檻——`_ga` 之類的
分析 Cookie 也又長又亂，那條規則會把一批本來就必須讓 JS 讀得到的 Cookie 全部誤報成 critical。

證據欄位**不含 Cookie 值**——報告本身不能變成外洩管道。

## transport

`https` 與 Cookie 的判定都跟著重導向走到**實際落點**，不是設定裡寫的那個 origin；
`Set-Cookie` 取的是**整條重導向鏈**——express-session 的預設行為就是在第一個回應（常常正是 302）上種 cookie。

| id | 等級 | 判定 |
| --- | --- | --- |
| `transport.plaintext` | high | 非本機目標全程走 http。此時 HSTS 與 Cookie Secure 等判定失去意義而未執行——這份報告的資安結論不適用於沒有加密的部署 |
| `transport.no-https-redirect` | high／medium | http 未導向 https（回 200 為 high） |
| `transport.mixed-content` | medium | 首頁含 http 子資源（`localhost` 不算）。判定先認標籤：`<a>` 是導覽連結不是子資源，`<link>` 只有會載入資源的 `rel` 才算 |
| `transport.duplicate-csp` | low | meta 與標頭 CSP 並存（取交集，難排查） |

## auth-gate

未登入直接請求受保護端點。tRPC 未授權**也回 HTTP 200**，故改看回應內容判定。

| id | 等級 | 判定 |
| --- | --- | --- |
| `auth-gate.open.<path>` | 依端點 | 回 200。有實際內容時用端點原定等級，空內容降為 medium |
| `auth-gate.trpc.<path>` | 依端點 | tRPC 回 200 且內容不是 `UNAUTHORIZED`／`FORBIDDEN` |
| `auth-gate.error.<path>` | medium | 回 5xx——認證檢查位置太後面，且錯誤可能洩漏內部細節 |

導向登入頁視為**有正確擋下**。tRPC 的未授權判定會先剝掉 transformer（superjson）的 `error.json` 外殼，
並一併接受 `data.httpStatus` 為 401/403 與 JSON-RPC 錯誤碼 `-32001`／`-32003`。

**每一筆都先排除 SPA 兜底頁。** SPA 對未知路徑一律回 index.html 200，而 `looksLikeData` 對非 JSON
只看「有沒有內容」——HTML 當然有內容，於是一條根本不存在的 `/api/me/export` 會被報成 critical 外洩。
更進一步：**所有**受保護端點都落到兜底頁時，代表這個站沒有掛載 aios 的 API，整項檢查回
`completed: false`——此時「沒有發現」的真正意思是「沒有驗到任何認證閘門」。

## disclosure

| id | 等級 | 判定 |
| --- | --- | --- |
| `disclosure.file./.env` | critical | 內容符合 `KEY=value` 特徵 |
| `disclosure.file./.git/HEAD` `/.git/config` | critical | 符合 git 檔案特徵 |
| `disclosure.file./.npmrc` `/backup.sql` `/server/index.ts` | critical | 各有內容特徵 |
| `disclosure.file./docker-compose.yml` | high | — |
| `disclosure.file./package.json` `/.env.example` | low | — |
| `disclosure.sourcemap` | medium | 正式站可下載 `.map` |
| `disclosure.sourcemap.unverified` | low | bundle 超過讀取上限且伺服器不支援 Range，檔尾的 `sourceMappingURL` 沒讀到——**本輪沒有驗證**，不是沒有 |
| `disclosure.stack-trace.*` | medium | 錯誤回應含 V8 堆疊或伺服器絕對路徑 |
| `disclosure.dir-listing.*` | high | 目錄索引可瀏覽 |

目錄列表的判定**先比對目錄索引特徵再排除 SPA 兜底頁**：Python http.server 的索引輸出帶 `<!DOCTYPE HTML>`，
會命中兜底判準的寬鬆分支，順序反過來的話那段程式永遠不會執行。

其餘每一筆都先排除 SPA 兜底頁（`text/html` 且含 `<div id="root">` 或 module script），
再要求內容符合特徵。少了這道，SPA 對未知路徑一律回 200 會讓每條路徑都變成假警報。

## cors

觀測反射一律送 **GET**，看預檢另送一次真正的 **OPTIONS**。絕不對 API 送寫入方法——
萬一該端點真的沒擋，掃描本身就會在正式資料庫上建東西。OPTIONS 送不出去時記為「未觀測」
而不是 `null`（`null` 會被讀成「預檢查過、沒放行任何方法」）。

| id | 等級 | 判定 |
| --- | --- | --- |
| `cors.reflects-origin` | critical／high | 反射任意 Origin；搭配 `allow-credentials` 為 critical。比對前先正規化（尾端斜線、大小寫、預設埠）——伺服器把 Origin 正規化後回填是最常見的寫法 |
| `cors.wildcard` | critical／low | `*`；搭配 credentials 為 critical |
| `cors.null-origin` | high | 允許 `null` 來源 |

## tls

憑證是少數會讓三端**同時**全掛的東西——網站、Capacitor WebView、Tauri WebView 用的是同一張。
而且它的失效方式極其突然：前一天全綠，隔天早上全站白畫面。既有檢查全部走 HTTP 層看不到憑證本身。

| id | 等級 | 判定 |
| --- | --- | --- |
| `tls.cert.expired` | critical | 憑證已過期 |
| `tls.cert.expiring` | critical／high／medium | 剩 7 天內／14 天內／30 天內。分級的意思是「這週末就會掛」對上「該排進待辦」 |
| `tls.cert.not-yet-valid` | critical | `validFrom` 在未來（換錯憑證或伺服器時鐘錯亂） |
| `tls.cert.hostname-mismatch` | critical | host 不符 CN 也不符任一 SAN。萬用字元 SAN 依規格只吃**一層**：`*.a.com` 匹配 `x.a.com`，不匹配 `a.com`，也不匹配 `x.y.a.com` |
| `tls.cert.self-signed` | high | 自簽憑證 |
| `tls.cert.weak-signature` | high | 簽章演算法含 sha1／md5 |
| `tls.cert.long-validity` | low | 有效期 > 398 天（超過 CA/B 論壇上限，憑證來源可疑） |
| `tls.key.weak` | high | RSA 金鑰 < 2048 bits。**ECDSA 不套這條門檻**（bits 語意不同），判斷不了就不報 |
| `tls.protocol.legacy` | high | 協定為 TLSv1／TLSv1.1 |
| `tls.protocol.version` | info | 記錄實際協定與加密套件 |

連線時用 `rejectUnauthorized: false`：憑證有問題時才最需要看清楚它，拒絕連線只會讓我們什麼都看不到。
連不上 443（企業代理常擋直連）一律標記跳過，**不會**變成發現——把代理造成的失敗報成憑證問題是嚴重誤判。

## methods

反向代理與框架常留下沒人用到的方法。TRACE 會把請求原樣回吐（Cross-Site Tracing，
可用來取得本該被 HttpOnly 保護的 Cookie）；OPTIONS 的 `Allow` 標頭則把「這個端點還接受 PUT/DELETE」
直接告訴攻擊者。

| id | 等級 | 判定 |
| --- | --- | --- |
| `methods.trace.echo` | high | TRACE 回應把請求標頭原樣回吐，Cross-Site Tracing 成立 |
| `methods.trace.enabled` | medium | TRACE 回 2xx（有 echo 時只報上面那筆，不重複） |
| `methods.dangerous-allowed` | medium | `Allow` 含 PUT／DELETE／PATCH。這是標頭的**自述**，不代表未授權就能用——需人工確認有認證保護 |
| `methods.allow-verbose` | low | `Allow` 列出的方法異常多，洩漏框架預設設定 |
| `methods.trace.unknown` | info | TRACE 送不到（被代理擋掉），記錄為「未判定」 |

**只送 OPTIONS 與 TRACE。** 絕不實際送出 PUT／DELETE／PATCH 到真實端點——那可能真的改到正式資料。
危險方法的存在改用 `Allow` 判定，判不到就誠實標為未判定，而不是為了拿到結論去動使用者的資料。

## redirect

開放重導向單看不痛不癢，但它是釣魚與 OAuth 憑證竊取的標準第一步：連結長得像自家網域
（使用者與郵件過濾器都信任），點下去卻落到攻擊者的站。

| id | 等級 | 判定 |
| --- | --- | --- |
| `redirect.open.<param>` | high | 3xx 的 `Location` 落在外部網域 |
| `redirect.open-meta.<param>` | medium | 回 200 但內文含指向外部網域的 meta refresh 或 `location.href=` 賦值 |
| `redirect.reflected.<param>` | low | 沒有實際導向，但參數值原樣出現在回應內文——體質提醒，不等於已可利用 |

導向落在自家網域或相對路徑**不報**（那是登入回跳的正確行為）。網址解析必須處理四種繞法：
協定相對（`//evil.test`，很多過濾器只擋 `http://` 開頭）、反斜線變體、
使用者名稱混淆（`https://自家網域@evil.test` 實際會連到 evil.test），以及子網域
（`evil.example.com` 不等於 `example.com`，要報）。

## supply-chain

頁面上每一支第三方腳本都握有與自家程式完全相同的權限——可以讀 DOM、讀 localStorage、
改任何請求。第三方 CDN 被入侵時，站台自身一行程式都沒改就被接管。既有檢查會看 CSP
允許什麼，但沒有人盤點「實際上到底載了誰」。

| id | 等級 | 判定 |
| --- | --- | --- |
| `supply-chain.insecure-subresource` | high | https 頁面載入 http 子資源 |
| `supply-chain.script-no-sri.<host>` | medium | 第三方腳本沒有 `integrity` |
| `supply-chain.sri-without-crossorigin.<host>` | medium | 有 `integrity` 卻沒有 `crossorigin`，瀏覽器會**直接拒絕載入**——以為加了防護，實際上把功能弄壞了，而且是靜默失敗 |
| `supply-chain.stylesheet-no-sri.<host>` | low | 第三方樣式表沒有 `integrity`（攻擊面比腳本小） |
| `supply-chain.third-party-inventory` | info | 第三方來源盤點。**即使全部都有 SRI 也照樣輸出**——盤點本身就是價值，讓人能定期問「這個還需要嗎」 |

同源子資源不報 SRI（那是自家部署，SRI 只增加發版負擔而沒有對應威脅）。
限制要講清楚：**只看初始 HTML，動態插入的腳本看不到**——那是 `pages` 端頁面測試的守備範圍。

## health

| id | 等級 | 判定 |
| --- | --- | --- |
| `health.unreachable` | critical | 健康檢查連不上。**此時直接收工**，不產生次生告警 |
| `health.not-ok` | critical | 非 200 或 `ok !== true` |
| `health.slow` | medium | > 3 秒（此端點不做 I/O，慢＝事件迴圈被卡） |
| `health.no-build-sha` | low | 無版本識別 |
| `ready.unreachable` | high | 就緒端點連不上（多為 DB 連線池耗盡） |
| `ready.unparseable` | medium | 回應不是 JSON |
| `ready.not-ok` | high | 整體回報未就緒且**沒有附上分項**，看不出哪一塊壞了。分項已指出故障點時不重複報 |
| `ready.component-shape` | low | 分項的形狀不是布林／狀態字串／`{ok:boolean}`，**本輪無法判定**——既不是通過也不是故障 |
| `ready.component.db` | critical | — |
| `ready.component.boot` / `.storage` | high | — |
| `ready.component.runner` / `.provider` | medium | — |
| `ready.inconsistent` | medium | 整體未就緒但所有分項都通過（有 components 才可能成立） |
| `ready.runner.stopped.<name>` | medium | 執行器未啟動 |
| `ready.runner.stale.<name>` | medium | 心跳停滯 > 120 秒 |
| `ready.runner.backlog.<name>` | low | 佇列 > 50 |

## build-drift

| id | 等級 | 判定 |
| --- | --- | --- |
| `build-drift.sha-mismatch` | high | **同一個 origin 內**出現不同 SHA（快取或部署沒同步）。`where` 為該 origin |
| `build-drift.cross-origin` | info | 不同 origin 之間版本不同——那是設定意圖（`AIOS_APP_TARGET` 等） |
| `build-drift.branch-mismatch` | medium | **同一個 origin 內**出現不同分支。跨部署的分支差異不報 |
| `build-drift.sha-missing` | low | 部分端無 SHA，比對有盲區 |

判準是**以 origin 分組**，不是「全體是否同源」：三端裡只要有一端刻意指向 staging，
「全體同源」的寫法就會把另外兩端之間真正的漂移一起降成 info。origin 比對前先正規化
（主機名大小寫、顯式預設埠、尾端斜線），與 `runner.perOrigin` 用同一把鍵。

可比對的端少於兩個時整項回 `completed: false`——沒有比較基準時，「零發現」的意思是
「沒比對」，不是「三端版本一致」。

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
| `shell.android.unparseable` | low | manifest 沒被讀懂（找不到任何 manifest 元素）。此時**直接收工**，不從錯誤的前提再推出任何結論 |
| `shell.tauri.capability-wildcard.*` | critical | 能力對**整個網際網路**開放（`*`、`https://*`…） |
| `shell.tauri.capability-subdomain.*` | medium | 綁在具體註冊網域上的子網域萬用。仍然過寬（閒置子網域被接管是真實路徑），但不是全開——錯誤的 critical 會讓人把整組告警關掉 |
| `shell.tauri.capability-unparseable.*` | low | 能力檔解析失敗，該檔的授權範圍**未稽核** |
| `shell.tauri.capability-unauditable.*` | low | 能力檔是 TOML，本工具不引入額外解析器，該檔**未稽核** |
| `shell.tauri.http-window` | critical | 視窗以 http 載入 |
| `shell.tauri.dangerous-ipc` | high | `dangerousRemoteDomainIpcAccess` |
| `shell.tauri.csp-null` | medium | `security.csp` 為 null（桌面端完全靠遠端站標頭撐著） |
| `shell.tauri.devtools` | medium | 發布版開著 devtools |
| `shell.target-mismatch.capacitor` / `.tauri` | high | 殼層指向的站與受測目標不同 |
| `shell.deeplink-mismatch` | medium | 深層連結 host 與 App 載入的站不一致 |

**解析前一律剝除註解。** 被註解掉的本機開發設定（`// url: "http://192.168.1.10:5173"`、
被 `<!-- -->` 包起來的 `<uses-permission>`）是設定檔裡極常見的寫法，照收會讓一份完全正常的
專案噴出三四筆 critical。XML 屬性的引號用反向參照鎖定成對——單引號在 XML 裡完全等價，
只認雙引號會讓整組 Android 稽核靜默回空。

**Tauri 能力檔是列目錄，不是猜檔名。** Tauri v2 讀 `src-tauri/capabilities/` 底下的每一個檔案，
識別靠檔案裡的 `identifier` 而非檔名；只試幾個寫死的名字，會讓一份叫 `remote.json`、
內容寫著 `remote.urls: ["*"]` 的能力檔被完全跳過。

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
