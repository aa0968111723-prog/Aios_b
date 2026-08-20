import { describe, expect, it } from "vitest";
import {
  analyzeSubresources,
  extractSubresources,
  inventoryByHost,
  type Subresource,
} from "../src/detectors/supplyChain.js";

const PAGE = "https://app.aios.test/";
const ctx = { surface: "web" as const, where: PAGE, https: true };
const ids = (findings: ReturnType<typeof analyzeSubresources>) => findings.map((f) => f.id);

/** 測試用的子資源建構子：只寫出這一筆要驗的欄位，其餘取安全預設。 */
function res(partial: Partial<Subresource> & Pick<Subresource, "kind" | "url">): Subresource {
  const host = (() => {
    try {
      return new URL(partial.url).hostname.toLowerCase();
    } catch {
      return null;
    }
  })();
  return {
    host,
    integrity: null,
    crossorigin: null,
    isThirdParty: host !== null && host !== "app.aios.test",
    isInsecure: partial.url.startsWith("http://"),
    ...partial,
  };
}

describe("extractSubresources", () => {
  it("抓出外部腳本與樣式表，內嵌 script 不算子資源", () => {
    const html = `
      <script src="https://cdn.example.test/lib.js"></script>
      <script>window.__BOOT__ = 1;</script>
      <link rel="stylesheet" href="https://fonts.example.test/x.css">
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.kind)).toEqual(["script", "stylesheet"]);
    expect(found.map((r) => r.url)).toEqual([
      "https://cdn.example.test/lib.js",
      "https://fonts.example.test/x.css",
    ]);
  });

  it("屬性順序任意、單雙引號、無引號都要解析得出來", () => {
    const html = `
      <script defer src="https://a.example.test/1.js" integrity="sha384-aaa"></script>
      <script src='https://b.example.test/2.js' async></script>
      <script src=https://c.example.test/3.js></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.host)).toEqual(["a.example.test", "b.example.test", "c.example.test"]);
    expect(found[0]?.integrity).toBe("sha384-aaa");
  });

  it("標籤與屬性大小寫混雜不影響判定（HTML 本來就不分大小寫）", () => {
    const html = `<SCRIPT SRC="https://cdn.example.test/a.js" INTEGRITY="sha384-x" CROSSORIGIN="anonymous"></SCRIPT>
      <LINK REL="StyleSheet" HREF="https://cdn.example.test/a.css">`;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.kind)).toEqual(["script", "stylesheet"]);
    expect(found[0]?.integrity).toBe("sha384-x");
    expect(found[0]?.crossorigin).toBe("anonymous");
  });

  it("屬性之間換行與 self-closing 寫法都要接住", () => {
    const html = `<script
        src="https://cdn.example.test/a.js"
        integrity="sha384-x"
        crossorigin="anonymous"
      ></script>
      <link
        rel="stylesheet"
        href="https://cdn.example.test/a.css" />`;
    const found = extractSubresources(html, PAGE);
    expect(found).toHaveLength(2);
    expect(found[1]?.url).toBe("https://cdn.example.test/a.css");
  });

  it("相對路徑、絕對路徑、協定相對網址都用頁面網址解析成絕對網址", () => {
    const html = `
      <script src="./assets/main.js"></script>
      <script src="/assets/vendor.js"></script>
      <script src="//cdn.example.test/edge.js"></script>
    `;
    const found = extractSubresources(html, "https://app.aios.test/dashboard/");
    expect(found.map((r) => r.url)).toEqual([
      "https://app.aios.test/dashboard/assets/main.js",
      "https://app.aios.test/assets/vendor.js",
      "https://cdn.example.test/edge.js",
    ]);
  });

  it("rel 不是 stylesheet 的 link 不算子資源（preload／icon／manifest）", () => {
    const html = `
      <link rel="preload" as="style" href="https://cdn.example.test/a.css">
      <link rel="icon" href="/favicon.ico">
      <link rel="manifest" href="/manifest.json">
    `;
    expect(extractSubresources(html, PAGE)).toEqual([]);
  });

  it("被 HTML 註解包住的引用不算——註解裡的舊 CDN 會變成永遠修不掉的假警報", () => {
    const html = `
      <!-- <script src="https://old-cdn.example.test/legacy.js"></script> -->
      <script src="https://cdn.example.test/current.js"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.host)).toEqual(["cdn.example.test"]);
  });

  it("integrity 空字串等同沒有；crossorigin 裸屬性是空字串而不是缺少", () => {
    const html = `<script src="https://cdn.example.test/a.js" integrity="" crossorigin></script>`;
    const found = extractSubresources(html, PAGE);
    expect(found[0]?.integrity).toBeNull();
    expect(found[0]?.crossorigin).toBe("");
  });

  it("屬性值裡含 > 的網址不會把標籤提早截斷", () => {
    const html = `<script src="https://cdn.example.test/a.js?q=1>2"></script><link rel="stylesheet" href="/a.css">`;
    const found = extractSubresources(html, PAGE);
    expect(found).toHaveLength(2);
    expect(found[0]?.host).toBe("cdn.example.test");
  });

  it("空 HTML、無 src 的 script、解析不出來的網址都只是略過，不丟例外", () => {
    expect(extractSubresources("", PAGE)).toEqual([]);
    expect(extractSubresources("<script></script><script src=''></script>", PAGE)).toEqual([]);
    expect(extractSubresources(`<script src="http://[bad"></script>`, PAGE)).toEqual([]);
  });

  it("data: 與 javascript: 這類非網路來源沒有主機，也不算第三方", () => {
    const html = `<script src="data:text/javascript,1"></script>`;
    const found = extractSubresources(html, PAGE);
    expect(found[0]?.host).toBeNull();
    expect(found[0]?.isThirdParty).toBe(false);
  });

  it("同一個主機是第一方，其他主機（含子網域）是第三方", () => {
    const html = `
      <script src="/assets/app.js"></script>
      <script src="https://cdn.aios.test/edge.js"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found[0]?.isThirdParty).toBe(false);
    expect(found[1]?.isThirdParty).toBe(true);
  });

  it("http 子資源標記為不安全，但本機位址不算", () => {
    const html = `
      <script src="http://cdn.example.test/a.js"></script>
      <script src="http://localhost:5173/@vite/client"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found[0]?.isInsecure).toBe(true);
    expect(found[1]?.isInsecure).toBe(false);
  });
});

describe("analyzeSubresources", () => {
  it("同源子資源不報 SRI——自家部署沒有對應威脅，硬加只會增加發版負擔", () => {
    const findings = analyzeSubresources(
      [
        res({ kind: "script", url: "https://app.aios.test/assets/app.js" }),
        res({ kind: "stylesheet", url: "https://app.aios.test/assets/app.css" }),
      ],
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("第三方腳本沒有 integrity 報 medium，id 帶主機名以便逐一抑制", () => {
    const findings = analyzeSubresources([res({ kind: "script", url: "https://cdn.example.test/a.js" })], ctx);
    const hit = findings.find((f) => f.id === "supply-chain.script-no-sri.cdn.example.test");
    expect(hit?.severity).toBe("medium");
    expect(hit?.detail).toContain("A/B");
  });

  it("同一個主機的多支腳本折成一筆，id 不含任何會變動的值", () => {
    const findings = analyzeSubresources(
      [
        res({ kind: "script", url: "https://cdn.example.test/a.js" }),
        res({ kind: "script", url: "https://cdn.example.test/b.js" }),
      ],
      ctx,
    );
    expect(ids(findings).filter((id) => id.startsWith("supply-chain.script-no-sri"))).toEqual([
      "supply-chain.script-no-sri.cdn.example.test",
    ]);
    const hit = findings.find((f) => f.id === "supply-chain.script-no-sri.cdn.example.test");
    expect(hit?.evidence).toContain("https://cdn.example.test/b.js");
  });

  it("第三方樣式表沒有 integrity 只報 low——攻擊面比腳本小，但不是沒有", () => {
    const findings = analyzeSubresources(
      [res({ kind: "stylesheet", url: "https://cdn.example.test/a.css" })],
      ctx,
    );
    expect(findings.find((f) => f.id === "supply-chain.stylesheet-no-sri.cdn.example.test")?.severity).toBe("low");
  });

  it("有 integrity 卻沒有 crossorigin 報 medium——資源會被瀏覽器直接拒載", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "https://cdn.example.test/a.js", integrity: "sha384-x" })],
      ctx,
    );
    const hit = findings.find((f) => f.id === "supply-chain.sri-without-crossorigin.cdn.example.test");
    expect(hit?.severity).toBe("medium");
    expect(ids(findings)).not.toContain("supply-chain.script-no-sri.cdn.example.test");
  });

  it("crossorigin 是裸屬性（等同 anonymous）時不報，否則會把正確設定判成壞掉", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "https://cdn.example.test/a.js", integrity: "sha384-x", crossorigin: "" })],
      ctx,
    );
    expect(ids(findings)).not.toContain("supply-chain.sri-without-crossorigin.cdn.example.test");
  });

  it("同源資源有 integrity 沒 crossorigin 不報——同源不需要 CORS 就驗得起來", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "https://app.aios.test/assets/app.js", integrity: "sha384-x" })],
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("https 頁面載入 http 子資源報 high 並列出實際網址", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "http://cdn.example.test/a.js", integrity: "sha384-x", crossorigin: "anonymous" })],
      ctx,
    );
    const hit = findings.find((f) => f.id === "supply-chain.insecure-subresource");
    expect(hit?.severity).toBe("high");
    expect(hit?.evidence).toContain("http://cdn.example.test/a.js");
  });

  it("http 頁面不報 http 子資源——那是 transport 檢查的守備範圍，這裡重複只是噪音", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "http://cdn.example.test/a.js" })],
      { ...ctx, https: false },
    );
    expect(ids(findings)).not.toContain("supply-chain.insecure-subresource");
  });

  it("第三方全部都有 SRI 時仍輸出盤點——清單本身就是價值", () => {
    const findings = analyzeSubresources(
      [
        res({
          kind: "script",
          url: "https://cdn.example.test/a.js",
          integrity: "sha384-x",
          crossorigin: "anonymous",
        }),
      ],
      ctx,
    );
    const inventory = findings.find((f) => f.id === "supply-chain.third-party-inventory");
    expect(inventory?.severity).toBe("info");
    expect(inventory?.evidence).toContain("cdn.example.test");
  });

  it("盤點把每個第三方主機都列進證據，並註明只涵蓋初始 HTML", () => {
    const findings = analyzeSubresources(
      [
        res({ kind: "script", url: "https://b.example.test/a.js" }),
        res({ kind: "stylesheet", url: "https://a.example.test/a.css" }),
        res({ kind: "script", url: "https://app.aios.test/assets/app.js" }),
      ],
      ctx,
    );
    const inventory = findings.find((f) => f.id === "supply-chain.third-party-inventory");
    expect(inventory?.evidence).toContain("a.example.test");
    expect(inventory?.evidence).toContain("b.example.test");
    expect(inventory?.evidence).not.toContain("app.aios.test");
    expect(inventory?.detail).toContain("動態插入");
  });

  it("完全沒有第三方時不產生任何發現（含盤點）——沒有對象可以定期檢視", () => {
    expect(analyzeSubresources([res({ kind: "script", url: "https://app.aios.test/a.js" })], ctx)).toEqual([]);
    expect(analyzeSubresources([], ctx)).toEqual([]);
  });

  it("內容會變動的服務會在證據裡註明無法上 SRI，避免有人去試不可能成功的修法", () => {
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "https://www.googletagmanager.com/gtm.js?id=GTM-X" })],
      ctx,
    );
    const hit = findings.find((f) => f.id === "supply-chain.script-no-sri.www.googletagmanager.com");
    expect(hit?.evidence).toContain("無法提供固定雜湊");
  });

  it("每一筆發現都有修法——沒有修法的告警會被無視", () => {
    const findings = analyzeSubresources(
      [
        res({ kind: "script", url: "http://cdn.example.test/a.js" }),
        res({ kind: "stylesheet", url: "https://cdn.example.test/a.css" }),
        res({ kind: "script", url: "https://other.example.test/b.js", integrity: "sha384-x" }),
      ],
      ctx,
    );
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) expect(f.remediation).toBeTruthy();
  });

  it("整段真實 HTML 走完整條路徑：解析後的判定與逐筆建構的結果一致", () => {
    const html = `<!doctype html>
      <html><head>
        <link rel="stylesheet" href="/assets/app.css">
        <link rel="stylesheet" href="https://fonts.example.test/x.css">
        <script type="module" src="/assets/index-abc123.js"></script>
        <script src="http://legacy.example.test/old.js"></script>
        <script src="https://cdn.example.test/lib.js" integrity="sha384-x"></script>
      </head><body><div id="root"></div></body></html>`;
    const findings = analyzeSubresources(extractSubresources(html, PAGE), ctx);
    expect(ids(findings).sort()).toEqual(
      [
        "supply-chain.insecure-subresource",
        "supply-chain.script-no-sri.legacy.example.test",
        "supply-chain.sri-without-crossorigin.cdn.example.test",
        "supply-chain.stylesheet-no-sri.fonts.example.test",
        "supply-chain.third-party-inventory",
      ].sort(),
    );
  });
});

describe("inventoryByHost", () => {
  it("依主機名排序並統計 SRI 數量——證據每次執行都一樣，跨次比對才不會誤判成有變動", () => {
    const summary = inventoryByHost([
      res({ kind: "script", url: "https://z.example.test/a.js", integrity: "sha384-x" }),
      res({ kind: "script", url: "https://z.example.test/b.js" }),
      res({ kind: "stylesheet", url: "https://a.example.test/a.css" }),
    ]);
    expect(summary.map((h) => h.host)).toEqual(["a.example.test", "z.example.test"]);
    expect(summary[1]).toMatchObject({ scripts: 2, stylesheets: 0, withIntegrity: 1, thirdParty: true });
  });

  it("data: 這類沒有主機的引用不進盤點", () => {
    const summary = inventoryByHost([
      { kind: "script", url: "data:text/javascript,1", host: null, integrity: null, crossorigin: null, isThirdParty: false, isInsecure: false },
    ]);
    expect(summary).toEqual([]);
  });
});
