/**
 * well-known 檔案檢測的測試。
 *
 * 這一項的價值幾乎全在「判對了沒有」，而它有三種失效方向，各自都有測試盯著：
 *
 * - 假警報：SPA 對 `/robots.txt` 回 200 index.html，被讀成「有一份內容很奇怪的 robots.txt」；
 *   或一頁純文字錯誤頁被讀成「有 security.txt 但缺 Contact」。維運者會照著這種結論
 *   去找一個不存在的檔案。
 * - 假綠燈：兩份檔案都沒取到，卻回 completed: true 加零發現——讀者會理解成「都查過了」。
 * - 判定漂移：Expires 沒帶時區時 `new Date` 以當地時間解讀，同一份檔案在不同時區的 CI 上
 *   會得到不同的過期結論。判定只能取決於被測的站台。
 *
 * 所有案例都離線：純函式直接餵字串，IO 進入點餵假 fetch，不發出任何真實請求。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  analyzeRobots,
  analyzeSecurityTxt,
  checkWellKnown,
  classifyWellKnownFile,
  findSensitiveDisallows,
  looksLikeSpaFallback,
  parseRobots,
  parseSecurityTxt,
} from "../src/detectors/wellknown.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const robotsCtx = { surface: "web" as const, where: "https://example.test/robots.txt" };
const securityCtx = {
  surface: "web" as const,
  where: "https://example.test/.well-known/security.txt",
  now: new Date("2026-08-20T00:00:00Z"),
};
const ids = (findings: ReturnType<typeof analyzeRobots>) => findings.map((f) => f.id);

/** Vite 建置的 SPA 兜底頁；`/robots.txt` 不存在時伺服器回的就是這個（HTTP 200）。 */
const SPA_INDEX = `<!doctype html><html><head><script type="module" src="/assets/index-a1b2.js"></script></head><body><div id="root"></div></body></html>`;

describe("parseRobots", () => {
  it("拆出 Disallow 與 Sitemap", () => {
    const analysis = parseRobots("User-agent: *\nDisallow: /api/\nDisallow: /private/\nSitemap: https://example.test/sitemap.xml");
    expect(analysis.present).toBe(true);
    expect(analysis.disallowed).toEqual(["/api/", "/private/"]);
    expect(analysis.sitemaps).toEqual(["https://example.test/sitemap.xml"]);
    expect(analysis.allowsAll).toBe(false);
  });

  it("行首與行內註解都不影響解析", () => {
    const analysis = parseRobots("# 全站設定\nUser-agent: *   # 對所有爬蟲\nDisallow: /api/  # 內部 API\n");
    expect(analysis.disallowed).toEqual(["/api/"]);
  });

  it("CRLF 換行照樣拆得開（這份檔案常是在 Windows 上編輯的）", () => {
    const analysis = parseRobots("User-agent: *\r\nDisallow: /admin/\r\nSitemap: https://example.test/sitemap.xml\r\n");
    expect(analysis.disallowed).toEqual(["/admin/"]);
    expect(analysis.sitemaps).toEqual(["https://example.test/sitemap.xml"]);
  });

  it("多個 User-agent 區塊的規則全部收集，不是只讀第一區塊", () => {
    const analysis = parseRobots(
      ["User-agent: Googlebot", "Disallow: /admin/", "", "User-agent: Bingbot", "User-agent: Slurp", "Disallow: /internal/"].join("\n"),
    );
    expect(analysis.disallowed).toEqual(["/admin/", "/internal/"]);
  });

  it("限制只針對特定爬蟲時，對一般爬蟲仍是全開——allowsAll 要看的是 `*` 那一組", () => {
    const analysis = parseRobots("User-agent: Googlebot\nDisallow: /admin/\n\nUser-agent: *\nDisallow:\n");
    expect(analysis.disallowed).toEqual(["/admin/"]);
    expect(analysis.allowsAll).toBe(true);
  });

  it("`Disallow:` 空值代表什麼都不擋，不能被當成一條限制", () => {
    const analysis = parseRobots("User-agent: *\nDisallow:\n");
    expect(analysis.disallowed).toEqual([]);
    expect(analysis.allowsAll).toBe(true);
  });

  it("欄位名大小寫不敏感", () => {
    const analysis = parseRobots("USER-AGENT: *\nDISALLOW: /Admin/\nSITEMAP: https://example.test/s.xml");
    expect(analysis.disallowed).toEqual(["/Admin/"]);
    expect(analysis.sitemaps).toEqual(["https://example.test/s.xml"]);
  });

  it("空檔與只有註解的檔案都算沒有 robots.txt——效果與不放這份檔案完全相同", () => {
    expect(parseRobots("").present).toBe(false);
    expect(parseRobots("\n\n# 這裡什麼都還沒寫\n").present).toBe(false);
  });

  it("SPA 兜底頁解析不出任何指令，所以不會被誤讀成「內容很奇怪的 robots.txt」", () => {
    expect(looksLikeSpaFallback(SPA_INDEX, "text/html; charset=utf-8")).toBe(true);
    expect(parseRobots(SPA_INDEX).present).toBe(false);
  });
});

describe("findSensitiveDisallows", () => {
  it("管理、內部、備份、組態、金鑰類路徑會被命中", () => {
    const hits = findSensitiveDisallows(["/admin-panel/", "/internal/tools", "/backups/", "/api-keys", "/.env"]);
    expect(hits.map((h) => h.path)).toEqual(["/admin-panel/", "/internal/tools", "/backups/", "/api-keys", "/.env"]);
  });

  it("一般路徑不命中——關鍵字只是字首相同不算（否則這條規則會變成純噪音）", () => {
    expect(findSensitiveDisallows(["/search", "/api/trpc", "/devices", "/configurator", "/*?sort="])).toEqual([]);
  });
});

describe("analyzeRobots", () => {
  it("敏感路徑報 low，證據要指出是哪一條命中哪個關鍵字", () => {
    const findings = analyzeRobots(parseRobots("User-agent: *\nDisallow: /admin-panel/\nDisallow: /search\n"), robotsCtx);
    const hit = findings.find((f) => f.id === "wellknown.robots.sensitive-paths");
    expect(hit?.severity).toBe("low");
    expect(hit?.evidence).toContain("/admin-panel/");
    expect(hit?.evidence).not.toContain("/search");
    // 這一項的重點是「robots.txt 不是存取控制」，敘述必須把話說清楚，不能只說「不建議寫」。
    expect(hit?.detail).toContain("存取控制");
  });

  it("只有無害路徑時不產生任何發現", () => {
    expect(analyzeRobots(parseRobots("User-agent: *\nDisallow: /search\nAllow: /\n"), robotsCtx)).toEqual([]);
  });

  it("沒有 robots.txt 只記 info，且明說不構成資安問題", () => {
    const findings = analyzeRobots(parseRobots(""), robotsCtx);
    const missing = findings.find((f) => f.id === "wellknown.robots.missing");
    expect(missing?.severity).toBe("info");
    expect(missing?.detail).toContain("不構成資安問題");
    expect(ids(findings)).not.toContain("wellknown.robots.sensitive-paths");
  });
});

describe("parseSecurityTxt", () => {
  it("欄位名大小寫不敏感，值原樣保留", () => {
    const analysis = parseSecurityTxt("CONTACT: mailto:security@example.test\nexpires: 2027-01-01T00:00:00Z\n");
    expect(analysis.fields.contact).toEqual(["mailto:security@example.test"]);
    expect(analysis.expires).toBe("2027-01-01T00:00:00Z");
    expect(analysis.present).toBe(true);
  });

  it("同名欄位可重複，依出現順序全部保留（多個窗口是規格鼓勵的寫法）", () => {
    const analysis = parseSecurityTxt(
      "Contact: mailto:security@example.test\nContact: https://example.test/report\nPreferred-Languages: zh-TW, en\n",
    );
    expect(analysis.fields.contact).toEqual(["mailto:security@example.test", "https://example.test/report"]);
  });

  it("註解、空行與 PGP 簽章外殼不會混進欄位", () => {
    const analysis = parseSecurityTxt(
      [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA256",
        "",
        "# 回報請寄這裡",
        "Contact: mailto:security@example.test",
        "",
        "-----BEGIN PGP SIGNATURE-----",
        "Version: GnuPG v2",
        "-----END PGP SIGNATURE-----",
      ].join("\n"),
    );
    expect(Object.keys(analysis.fields)).toEqual(["contact"]);
  });

  it("SPA 兜底頁不會被解析成一份 security.txt", () => {
    expect(parseSecurityTxt(SPA_INDEX).present).toBe(false);
  });

  it("空檔判為不存在", () => {
    expect(parseSecurityTxt("").present).toBe(false);
    expect(parseSecurityTxt("").expires).toBeNull();
  });
});

describe("analyzeSecurityTxt", () => {
  const valid = "Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z\n";

  it("欄位齊全且未過期時不產生任何發現", () => {
    expect(analyzeSecurityTxt(parseSecurityTxt(valid), securityCtx)).toEqual([]);
  });

  it("沒有 security.txt 報 low，並解釋通報者會直接放棄", () => {
    const findings = analyzeSecurityTxt(parseSecurityTxt(""), securityCtx);
    expect(findings.find((f) => f.id === "wellknown.security-txt.missing")?.severity).toBe("low");
    // 檔案不存在時不該再追問裡面的欄位——那只會讓同一件事被報三次。
    expect(findings).toHaveLength(1);
  });

  it("有檔案但缺 Contact 報 low（那是 RFC 唯一的必填欄位）", () => {
    const findings = analyzeSecurityTxt(parseSecurityTxt("Expires: 2027-01-01T00:00:00Z\n"), securityCtx);
    expect(findings.find((f) => f.id === "wellknown.security-txt.no-contact")?.severity).toBe("low");
  });

  it("Expires 已過報 expired，證據帶上判定基準時間", () => {
    const findings = analyzeSecurityTxt(
      parseSecurityTxt("Contact: mailto:security@example.test\nExpires: 2025-01-01T00:00:00Z\n"),
      securityCtx,
    );
    const expired = findings.find((f) => f.id === "wellknown.security-txt.expired");
    expect(expired?.severity).toBe("low");
    expect(expired?.evidence).toContain("2026-08-20T00:00:00.000Z");
    expect(findings.map((f) => f.id)).not.toContain("wellknown.security-txt.no-expires");
  });

  it("Expires 未過就不報——邊界靠注入的 now 釘死，不隨執行日期漂移", () => {
    const findings = analyzeSecurityTxt(parseSecurityTxt(valid), { ...securityCtx, now: new Date("2026-12-31T23:59:59Z") });
    expect(findings).toEqual([]);
  });

  it("缺 Expires 只記 info", () => {
    const findings = analyzeSecurityTxt(parseSecurityTxt("Contact: mailto:security@example.test\n"), securityCtx);
    expect(findings.find((f) => f.id === "wellknown.security-txt.no-expires")?.severity).toBe("info");
  });

  it("Expires 解析不出來時，講成「沒有可用的 Expires」而不是偷偷放過", () => {
    const findings = analyzeSecurityTxt(
      parseSecurityTxt("Contact: mailto:security@example.test\nExpires: 明年\n"),
      securityCtx,
    );
    const noExpires = findings.find((f) => f.id === "wellknown.security-txt.no-expires");
    expect(noExpires?.evidence).toContain("明年");
    expect(findings.map((f) => f.id)).not.toContain("wellknown.security-txt.expired");
  });

  it("每一筆發現都帶得走修法", () => {
    const all = [
      ...analyzeSecurityTxt(parseSecurityTxt(""), securityCtx),
      ...analyzeSecurityTxt(parseSecurityTxt("Expires: 2025-01-01T00:00:00Z\n"), securityCtx),
      ...analyzeRobots(parseRobots("User-agent: *\nDisallow: /admin/\n"), robotsCtx),
      ...analyzeRobots(parseRobots(""), robotsCtx),
    ];
    expect(all.length).toBeGreaterThan(0);
    for (const f of all) expect(f.remediation ?? "").not.toBe("");
  });
});

describe("classifyWellKnownFile", () => {
  it("SPA 對未知路徑回的 200 index.html 是「沒有這份檔案」，不是「有」", () => {
    const state = classifyWellKnownFile({ status: 200, body: SPA_INDEX, contentType: "text/html; charset=utf-8" });
    expect(state.state).toBe("absent");
  });

  it("真正的 robots.txt（200 + text/plain）才算取得", () => {
    const state = classifyWellKnownFile({ status: 200, body: "User-agent: *\nDisallow:\n", contentType: "text/plain" });
    expect(state.state).toBe("present");
  });

  it("404 是伺服器明確說沒有，必須判成 absent 而不是「沒測到」", () => {
    expect(classifyWellKnownFile({ status: 404, body: "Not Found", contentType: "text/plain" }).state).toBe("absent");
  });

  it("502 這種中介層回應判成 unverified——沒測到不可以被講成沒問題", () => {
    const state = classifyWellKnownFile({ status: 502, body: "<html><body>Bad Gateway</body></html>", contentType: "text/html" });
    expect(state.state).toBe("unverified");
  });
});

/**
 * robots.txt 的敏感路徑判定。
 *
 * 這條規則的風險是兩面的：太鬆會把 `/administration-guide` 這種無害路徑報成敏感，
 * 太緊則會漏掉真正把後台位址公告出去的那一筆。所以比對用的是詞邊界而不是子字串。
 */
describe("findSensitiveDisallows", () => {
  const keywords = (paths: string[]) => findSensitiveDisallows(paths).map((h) => h.keyword);

  it("抓得到公告出去的後台與內部路徑", () => {
    expect(keywords(["/admin-panel", "/internal/tools", "/backup/2026"])).toEqual(["admin", "internal", "backup"]);
  });

  it("點檔名也算——那是最不該被寫進公開檔案的一種", () => {
    expect(keywords(["/.env", "/.git/"])).toEqual([".env", ".git"]);
  });

  it("複數形照樣命中", () => {
    expect(keywords(["/backups/"])).toEqual(["backup"]);
  });

  it("一般路徑不誤中——關鍵字只是別的字的一部分時不算", () => {
    expect(findSensitiveDisallows(["/administration-guide", "/configurator", "/products", "/secretary"])).toEqual([]);
  });

  it("同一條路徑只算一個關鍵字，不會重複報同一筆", () => {
    expect(findSensitiveDisallows(["/admin/config"])).toHaveLength(1);
  });

  it("空清單不會爆", () => {
    expect(findSensitiveDisallows([])).toEqual([]);
  });
});

/**
 * 取檔結果的分類。
 *
 * 三種答案必須分得開：**有這份檔案**、**確定沒有**、**沒測到**。
 * 把第三種講成前兩種的任何一種，都是這個專案最反對的那類錯誤結論。
 */
describe("classifyWellKnownFile", () => {
  const SPA = '<!doctype html><html><body><div id="root"></div></body></html>';

  it("200 加真實內容＝有這份檔案", () => {
    const out = classifyWellKnownFile({ status: 200, body: "User-agent: *\n", contentType: "text/plain" });
    expect(out.state).toBe("present");
  });

  it("SPA 兜底頁不是「有這份檔案」，是「這個站沒有這份檔案」", () => {
    const out = classifyWellKnownFile({ status: 200, body: SPA, contentType: "text/html" });
    expect(out.state).toBe("absent");
    expect(out.state === "absent" && out.reason).toContain("SPA 兜底");
  });

  it.each([404, 410])("HTTP %i 是伺服器對「有沒有這份檔案」最明確的否定答覆", (status) => {
    expect(classifyWellKnownFile({ status, body: "Not Found", contentType: "text/plain" }).state).toBe("absent");
  });

  it("404 要先於中介層判定——否則每個正常的 404 都會被講成「沒測到」", () => {
    // 這個 404 的內容不像應用回應，剛好會命中攔截啟發式；順序寫反時它會變成 unverified。
    expect(classifyWellKnownFile({ status: 404, body: "nginx", contentType: "text/plain" }).state).toBe("absent");
  });

  it("被中介層攔截時是「沒測到」，不是「沒有這份檔案」", () => {
    const out = classifyWellKnownFile({ status: 403, body: "Blocked by WAF", contentType: "text/plain" });
    expect(out.state).toBe("unverified");
  });

  it("其他非 200 狀態一律「沒測到」", () => {
    expect(classifyWellKnownFile({ status: 500, body: '{"error":"boom"}', contentType: "application/json" }).state).toBe(
      "unverified",
    );
  });
});
