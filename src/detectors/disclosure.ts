/**
 * 資訊洩漏檢測。
 *
 * 兩類：
 * 1. 不該存在的檔案被部署出去（.env、.git、原始碼、備份檔）——直接給出憑證或原始碼。
 * 2. 錯誤處理洩漏內部細節（堆疊追蹤、框架版本、檔案路徑）——給攻擊者地圖。
 *
 * SPA 的關鍵陷阱：Vite 建置的站台會把**所有**未知路徑回傳 index.html（HTTP 200）。
 * 若照「200＝檔案存在」判定，這裡會產生一整排假警報。所以每一筆命中都必須先
 * 用 `looksLikeSpaFallback` 排除掉 SPA 兜底回應。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Severity, Surface } from "../core/types.js";

export interface SensitivePath {
  path: string;
  label: string;
  severity: Severity;
  /** 內容要含這些特徵才算真的命中（避免 SPA 兜底頁被誤判）。 */
  signature: RegExp;
  detail: string;
  remediation: string;
}

export const SENSITIVE_PATHS: SensitivePath[] = [
  {
    path: "/.env",
    label: "環境變數檔",
    severity: "critical",
    signature: /^[A-Z0-9_]+=/m,
    detail: "環境變數檔被當成靜態資源提供，資料庫連線字串、API 金鑰、簽章密鑰全都在裡面。",
    remediation: "立刻從部署產物移除，並輪換檔案中出現過的所有金鑰——已經外流的憑證不能只靠刪檔補救。",
  },
  {
    path: "/.env.example",
    label: "環境變數範本",
    severity: "low",
    signature: /^[A-Z0-9_]+=/m,
    detail: "範本檔本身不含真實憑證，但會完整列出系統使用的第三方服務與設定項，是很好的偵察素材。",
    remediation: "把 .env.example 排除在部署產物之外（.dockerignore／建置階段刪除）。",
  },
  {
    path: "/.git/HEAD",
    label: "Git 版控目錄",
    severity: "critical",
    signature: /^ref:\s+refs\//m,
    detail: ".git 目錄被部署出去，攻擊者可以把整個原始碼庫連同歷史紀錄（含曾經 commit 過的金鑰）下載回去。",
    remediation: "從部署產物移除 .git；檢查歷史中是否曾提交過憑證並全部輪換。",
  },
  {
    path: "/.git/config",
    label: "Git 設定檔",
    severity: "critical",
    signature: /\[core\]|\[remote/,
    detail: "洩漏原始碼庫位置，若 remote URL 含權杖則等同交出寫入權。",
    remediation: "從部署產物移除 .git。",
  },
  {
    path: "/package.json",
    label: "套件清單",
    severity: "low",
    signature: /"dependencies"\s*:/,
    detail: "完整的依賴與版本清單讓攻擊者能直接比對已知漏洞，不必自己探測。",
    remediation: "確認靜態檔根目錄只含建置產物（dist/public），不要把專案根目錄整個 serve 出去。",
  },
  {
    path: "/server/index.ts",
    label: "伺服器原始碼",
    severity: "critical",
    signature: /import\s+.*from|app\.(get|post|use)\(/,
    detail: "伺服器原始碼可被直接讀取，等於把所有認證邏輯與內部端點攤開給攻擊者看。",
    remediation: "靜態檔目錄必須指向建置產物，絕不能指向專案根目錄。",
  },
  {
    path: "/docker-compose.yml",
    label: "容器編排設定",
    severity: "high",
    signature: /services\s*:/,
    detail: "洩漏內部服務拓樸、埠號與可能寫在檔案裡的環境變數。",
    remediation: "從部署產物移除。",
  },
  {
    path: "/.npmrc",
    label: "npm 設定",
    severity: "critical",
    signature: /_authToken|registry=/,
    detail: "可能含私有 registry 的存取權杖，外流即可讀取（甚至發布）私有套件。",
    remediation: "從部署產物移除並輪換權杖。",
  },
  {
    path: "/backup.sql",
    label: "資料庫備份",
    severity: "critical",
    signature: /CREATE TABLE|INSERT INTO/i,
    detail: "資料庫備份可被公開下載，全站資料等同外流。",
    remediation: "立刻移除，並檢視存取紀錄評估是否已被下載。",
  },
];

/**
 * 判斷回應是不是 SPA 的兜底 index.html。
 *
 * 判準：HTML 型別 + 有 <div id="root"> 或 <script type="module">（Vite 產物特徵）。
 * 這比「看有沒有 <html>」精確——真的洩漏出來的設定檔不會有這些。
 */
export function looksLikeSpaFallback(body: string, contentType: string): boolean {
  if (!/text\/html/i.test(contentType)) return false;
  return /<div\s+id=["']root["']|<script[^>]+type=["']module["']|<!doctype html>/i.test(body);
}

/** 從 HTML／JS 內容找出堆疊追蹤特徵。 */
export function findStackTrace(body: string): string | null {
  const patterns = [
    /\bat\s+[\w.$<>[\]]+\s+\((?:\/|[A-Za-z]:\\)[^)]+:\d+:\d+\)/, // V8 堆疊
    /Error:\s+.*\n\s+at\s+/,
    /\/(?:home|usr|app|var|root)\/[\w./-]+\.(?:ts|js|mjs):\d+/, // 伺服器絕對路徑
  ];
  for (const p of patterns) {
    const hit = p.exec(body);
    if (hit) return hit[0].slice(0, 300);
  }
  return null;
}

export async function checkDisclosure(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const base = { check: "disclosure", category: "security" as const, surface: surface.id };
  const checked: string[] = [];

  for (const item of SENSITIVE_PATHS) {
    const url = join(surface.origin, item.path);
    const res = await tryProbe(url, { surface, timeoutMs, followRedirects: 0, maxBodyBytes: 32 * 1024 });
    if (isProbeFailure(res)) continue;
    checked.push(`${item.path} → ${res.status}`);
    if (res.status !== 200) continue;

    const contentType = res.headers.get("content-type") ?? "";
    if (looksLikeSpaFallback(res.body, contentType)) continue; // SPA 兜底，不是真的檔案
    if (!item.signature.test(res.body)) continue; // 內容對不上特徵，不誤報

    findings.push(
      finding({
        ...base,
        id: `disclosure.file${item.path.replace(/\//g, ".")}`,
        severity: item.severity,
        title: `${item.label}可被公開下載（${item.path}）`,
        detail: item.detail,
        remediation: item.remediation,
        evidence: res.body.slice(0, 200),
        where: url,
      }),
    );
  }

  // ── Source map ──────────────────────────────────────────────────────────
  // 正式站附 source map 等於附原始碼。先讀首頁找出主要 bundle，再看它有沒有指向 .map。
  const rootRes = await tryProbe(join(surface.origin, "/"), { surface, timeoutMs, followRedirects: 3 });
  if (!isProbeFailure(rootRes)) {
    const bundle = /<script[^>]+src=["']([^"']+\.js)["']/i.exec(rootRes.body)?.[1];
    if (bundle) {
      const bundleUrl = join(surface.origin, bundle);
      const js = await tryProbe(bundleUrl, { surface, timeoutMs, maxBodyBytes: 2 * 1024 * 1024 });
      if (!isProbeFailure(js)) {
        const mapRef = /\/\/#\s*sourceMappingURL=(\S+)/.exec(js.body)?.[1];
        if (mapRef && !mapRef.startsWith("data:")) {
          const mapUrl = new URL(mapRef, bundleUrl).toString();
          const map = await tryProbe(mapUrl, { surface, timeoutMs, maxBodyBytes: 16 * 1024 });
          if (!isProbeFailure(map) && map.status === 200 && /"sources"\s*:/.test(map.body)) {
            findings.push(
              finding({
                ...base,
                id: "disclosure.sourcemap",
                severity: "medium",
                title: "正式站可下載 source map",
                detail:
                  "source map 內含未壓縮的原始碼（含註解與內部命名），攻擊者可以完整還原前端邏輯，包括權限判斷寫在哪、哪些 API 存在。",
                remediation: "建置時關閉 sourcemap（vite build 的 build.sourcemap: false），或只上傳到錯誤追蹤服務而不部署到公開路徑。",
                evidence: mapUrl,
                where: mapUrl,
              }),
            );
          }
        }
      }
    }
  }

  // ── 錯誤處理是否洩漏堆疊 ────────────────────────────────────────────────
  // 兩種觸發：不存在的 API 路徑，以及格式錯誤的 tRPC 輸入。
  const errorProbes = [
    { url: join(surface.origin, "/api/__sentinel_not_found__"), label: "不存在的 API 路徑" },
    { url: join(surface.origin, "/api/trpc/system.storageStatus?input=%7Bnot-json"), label: "格式錯誤的 tRPC 輸入" },
  ];
  for (const p of errorProbes) {
    const res = await tryProbe(p.url, { surface, timeoutMs, followRedirects: 0, maxBodyBytes: 32 * 1024 });
    if (isProbeFailure(res)) continue;
    const stack = findStackTrace(res.body);
    if (stack) {
      findings.push(
        finding({
          ...base,
          id: `disclosure.stack-trace.${encodeURIComponent(p.label)}`,
          severity: "medium",
          title: `錯誤回應洩漏堆疊追蹤（${p.label}）`,
          detail:
            "回應裡帶了伺服器的檔案路徑與函式呼叫鏈，攻擊者可據此推斷框架版本、目錄結構與程式流程，大幅降低後續攻擊的成本。",
          remediation: "正式環境的錯誤處理只回一般化訊息與 requestId，堆疊只寫進伺服器日誌。",
          evidence: stack,
          where: p.url,
        }),
      );
    }
  }

  // ── 目錄列表 ────────────────────────────────────────────────────────────
  for (const dir of ["/assets/", "/uploads/", "/.data/"]) {
    const url = join(surface.origin, dir);
    const res = await tryProbe(url, { surface, timeoutMs, followRedirects: 0, maxBodyBytes: 16 * 1024 });
    if (isProbeFailure(res) || res.status !== 200) continue;
    const contentType = res.headers.get("content-type") ?? "";
    if (looksLikeSpaFallback(res.body, contentType)) continue;
    if (/<title>Index of|Directory listing for/i.test(res.body)) {
      findings.push(
        finding({
          ...base,
          id: `disclosure.dir-listing${dir.replace(/\//g, ".")}`,
          severity: "high",
          title: `目錄列表可瀏覽（${dir}）`,
          detail: "任何人都能列出目錄下的全部檔案，不需要知道檔名就能把上傳的素材一個個抓下來。",
          remediation: "關閉靜態伺服器的目錄索引（express.static 的 index/dotfiles 選項）。",
          evidence: res.body.slice(0, 200),
          where: url,
        }),
      );
    }
  }

  facts.checked = checked;
  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
