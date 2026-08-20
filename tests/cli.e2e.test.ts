/**
 * CLI 的端到端測試。
 *
 * 為什麼需要這一層：所有判定邏輯都有純函式的單元測試，但**沒有任何測試驗過接線**——
 * 檢查有沒有真的被排進執行清單、跳過的理由有沒有進到報告、`--only` 有沒有把被篩掉的
 * 檢查留成「跳過」而不是讓它們憑空消失、結束碼對不對。這些全是「規則寫得再對也沒用」
 * 的失效方式：一個忘了接上的偵測器，在報告上看起來就跟「這項沒發現問題」一模一樣。
 *
 * 做法是起一個**本機**的假站台，用子行程跑真正的 CLI 打它。不碰外部網路，
 * 所以在 CI 與離線環境都跑得起來——這是這個專案對測試的一貫要求。
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { spawn } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { RunReport } from "../src/core/types.js";

/** 假站台的行為刻意貼近 ai_os：SPA 兜底、健康端點、沒有安全標頭。 */
const SPA_HTML = `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <title>Aios</title>
  <script type="module" src="/assets/index.js"></script>
  <script src="https://cdn.example.test/analytics.js"></script>
</head>
<body>
  <div id="root"></div>
  <div class="app"><h1>Aios</h1></div>
  <footer><a href="http://partner.example.org">合作夥伴</a></footer>
</body>
</html>`;

let server: Server;
let origin: string;

beforeAll(async () => {
  server = createServer((req, res) => {
    const path = (req.url ?? "/").split("?")[0] ?? "/";

    if (path === "/api/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, build: { sha: "abc1234", branch: "main" } }));
      return;
    }
    if (path === "/api/ready") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, components: { db: { ok: true }, storage: { ok: true } } }));
      return;
    }
    if (path === "/robots.txt") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("User-agent: *\nDisallow: /admin-panel\n");
      return;
    }
    if (path === "/assets/index.js") {
      res.writeHead(200, { "content-type": "application/javascript" });
      res.end("console.log('aios');\n");
      return;
    }
    // 其餘一律 SPA 兜底——Vite 建置的站台就是這樣，也是最多假警報的來源。
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(SPA_HTML);
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("測試伺服器沒有拿到埠號");
  origin = `http://127.0.0.1:${address.port}`;
});

afterAll(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

interface CliRun {
  code: number | null;
  report: RunReport;
}

async function runCli(args: string[]): Promise<CliRun> {
  return new Promise((resolve, reject) => {
    const child = spawn("npx", ["tsx", "src/cli.ts", ...args, "--json"], {
      cwd: process.cwd(),
      // 本機位址絕不能走出口代理，否則測的是代理不是站台。
      env: { ...process.env, NO_PROXY: "127.0.0.1,localhost", no_proxy: "127.0.0.1,localhost" },
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += String(chunk)));
    child.stderr.on("data", (chunk) => (stderr += String(chunk)));
    child.on("error", reject);
    child.on("close", (code) => {
      try {
        resolve({ code, report: JSON.parse(stdout) as RunReport });
      } catch (err) {
        reject(new Error(`CLI 輸出不是 JSON（exit=${code}）：\n${stdout.slice(0, 500)}\n${stderr.slice(0, 500)}\n${String(err)}`));
      }
    });
  });
}

const checkNames = (report: RunReport) => [...new Set(report.results.map((r) => r.check))];
const findingIds = (report: RunReport) => report.results.flatMap((r) => r.findings.map((f) => f.id));
const resultFor = (report: RunReport, check: string) => report.results.find((r) => r.check === check);

describe("CLI scan 端到端", () => {
  let run: CliRun;

  beforeAll(async () => {
    run = await runCli(["scan", "--target", origin, "--surfaces", "web"]);
  }, 120_000);

  it("每一項 scan 檢查都真的被排進執行清單", () => {
    expect(checkNames(run.report)).toEqual(
      expect.arrayContaining([
        "health",
        "transport",
        "auth-gate",
        "disclosure",
        "cors",
        "tls",
        "methods",
        "redirect",
        "supply-chain",
        "wellknown",
        "rate-limit",
      ]),
    );
  });

  it("報告的形狀完整，摘要與實際發現對得起來", () => {
    const total = findingIds(run.report).length;
    const counted = Object.values(run.report.summary.findings).reduce((a, b) => a + b, 0);
    expect(counted).toBe(total);
    expect(run.report.target).toBe(origin);
    expect(run.report.summary.suppressed).toBe(0);
  });

  it("http 目標沒有憑證可驗，tls 標記跳過而不是通過", () => {
    const tls = resultFor(run.report, "tls");
    expect(tls?.completed).toBe(false);
    expect(tls?.skippedReason ?? "").not.toBe("");
  });

  it("速率限制探測預設不執行，且說得出為什麼", () => {
    const rate = resultFor(run.report, "rate-limit");
    expect(rate?.completed).toBe(false);
    expect(rate?.skippedReason ?? "").toContain("probe-rate-limit");
  });

  it("受保護端點全部落到 SPA 兜底時，auth-gate 標記為沒驗到——而不是零發現的綠勾", () => {
    const gate = resultFor(run.report, "auth-gate");
    expect(gate?.completed).toBe(false);
    expect(gate?.skippedReason ?? "").toContain("SPA 兜底頁");
    expect(gate?.findings).toEqual([]);
  });

  it("SPA 兜底不會讓 disclosure 把每條路徑都報成檔案外洩", () => {
    expect(findingIds(run.report).filter((id) => id.startsWith("disclosure.file."))).toEqual([]);
  });

  it("第三方腳本被盤點下來", () => {
    expect(findingIds(run.report)).toContain("supply-chain.third-party-inventory");
  });

  it("頁尾的 http 外部連結不算混合內容", () => {
    expect(findingIds(run.report)).not.toContain("transport.mixed-content");
  });

  it("本機位址的 http 不報明文（那是正常的開發情境）", () => {
    expect(findingIds(run.report)).not.toContain("transport.plaintext");
  });

  it("缺安全標頭確實被抓到——證明這一輪真的有觸及站台", () => {
    expect(findingIds(run.report)).toContain("csp.missing");
    expect(findingIds(run.report)).toContain("headers.nosniff");
  });
});

describe("CLI --only 端到端", () => {
  it("被篩掉的檢查留在報告上（跳過＋原因），不是憑空消失", async () => {
    const run = await runCli(["scan", "--target", origin, "--surfaces", "web", "--only", "health"]);
    const health = resultFor(run.report, "health");
    const transport = resultFor(run.report, "transport");

    expect(health?.completed).toBe(true);
    expect(transport).toBeDefined();
    expect(transport?.completed).toBe(false);
    expect(transport?.skippedReason ?? "").toContain("未執行不等於通過");
    expect(run.report.filter).toEqual({ only: ["health"], skip: [] });
  }, 120_000);
});
