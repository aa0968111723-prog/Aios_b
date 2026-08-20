/**
 * 前端供應鏈檢測的測試。
 *
 * 三個焦點，各對應一種這個偵測器會出現的失效方向：
 *
 * - **假警報**：解析必須跟著瀏覽器的規則走。內嵌腳本裡的字串、註解掉的舊 CDN、
 *   type 不是 JS 的資料區塊——這些瀏覽器都不會去載，報出來就是要人去修一個不存在的問題。
 *   同源資源不報 SRI 也屬於這一類：那是自家部署，硬加只有發版負擔。
 * - **說錯話**：module 腳本本來就走 CORS，缺 crossorigin 不會被拒載。
 *   對它報「瀏覽器會直接拒絕載入」是在報告裡寫下一句不實的話，而讀者抓到一次就不會再相信整份報告。
 * - **假綠燈**：讀不到首頁（連不上、被中介層攔截、非 HTML、錯誤頁、重導向沒收斂、內容被截斷）時，
 *   盤點結果必然是空的。那種空清單一旦以 completed: true 送出去，讀起來就是「這個站沒有第三方資源」。
 *
 * 需要 I/O 的部分一律用注入的 fetch 假件驅動，不發出任何真實網路請求。
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  analyzeSubresources,
  checkSupplyChain,
  extractSubresources,
  inventoryByHost,
  type Subresource,
} from "../src/detectors/supplyChain.js";
import { buildSurfaces } from "../src/core/surfaces.js";

const PAGE = "https://app.aios.test/";
const ctx = { surface: "web" as const, where: PAGE, https: true };
const ids = (findings: Array<{ id: string }>) => findings.map((f) => f.id);
const web = buildSurfaces("https://app.aios.test")[0]!;

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
    isModule: false,
    isThirdParty: host !== null && host !== "app.aios.test",
    isInsecure: partial.url.startsWith("http://"),
    ...partial,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

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

  it("內嵌腳本的內容是純文字，裡面長得像標籤的字串不算子資源", () => {
    // 老式的廣告／聊天外掛就是用 document.write 拼字串把腳本插進來的。
    // 不把 <script>…</script> 之間當成純文字跳過，這裡會盤點出一個查不到出處、也修不掉的第三方。
    const html = `
      <script>
        var tag = '<script src="https://phantom.example.test/x.js"><\\/script>';
        var css = '<link rel="stylesheet" href="https://phantom.example.test/x.css">';
      </script>
      <script src="https://cdn.example.test/real.js"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.url)).toEqual(["https://cdn.example.test/real.js"]);
  });

  it("<base href> 會改變相對路徑的解析基準，但同源判定仍以頁面來源為準", () => {
    // 資產搬到自家 CDN 時常見的寫法。忽略 <base> 的話，那些檔案會被算成第一方，
    // 於是整份第三方盤點靜靜地變成空的——沒有任何一條告警，讀起來像是站台很乾淨。
    const html = `
      <base href="https://static.aios.test/build/">
      <script src="app.js"></script>
      <link rel="stylesheet" href="app.css">
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.url)).toEqual([
      "https://static.aios.test/build/app.js",
      "https://static.aios.test/build/app.css",
    ]);
    expect(found.every((r) => r.isThirdParty)).toBe(true);
  });

  it("只有第一個 base 生效，寫在 base 之前的引用不受影響（瀏覽器是邊解析邊發請求的）", () => {
    const html = `
      <script src="/early.js"></script>
      <base href="https://static.aios.test/build/">
      <script src="late.js"></script>
      <base href="https://ignored.example.test/">
      <script src="later.js"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.url)).toEqual([
      "https://app.aios.test/early.js",
      "https://static.aios.test/build/late.js",
      "https://static.aios.test/build/later.js",
    ]);
  });

  it("type 不是 JavaScript 的 script 是資料區塊，瀏覽器不會下載它", () => {
    const html = `
      <script type="application/ld+json" src="https://cdn.example.test/data.json"></script>
      <script type="text/template" src="https://cdn.example.test/tpl.html"></script>
      <script type="text/javascript" src="https://cdn.example.test/classic.js"></script>
      <script type="module" src="https://cdn.example.test/esm.js"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => r.url)).toEqual([
      "https://cdn.example.test/classic.js",
      "https://cdn.example.test/esm.js",
    ]);
    expect(found.map((r) => r.isModule)).toEqual([false, true]);
  });

  it("完全相同的重複引用只算一次，屬性有差異的則兩筆都留", () => {
    // 瀏覽器對同一個網址只會取一次；算成兩支會讓盤點數字與「N 個子資源」的標題虛胖。
    const html = `
      <script src="https://cdn.example.test/a.js"></script>
      <script src="https://cdn.example.test/a.js"></script>
      <script src="https://cdn.example.test/b.js"></script>
      <script src="https://cdn.example.test/b.js" integrity="sha384-x"></script>
    `;
    const found = extractSubresources(html, PAGE);
    expect(found.map((r) => [r.url, r.integrity])).toEqual([
      ["https://cdn.example.test/a.js", null],
      ["https://cdn.example.test/b.js", null],
      ["https://cdn.example.test/b.js", "sha384-x"],
    ]);
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

  it("畸形頁面不能拖住掃描器：兩萬個沒有收尾的 script 標籤仍要一瞬間解析完", () => {
    // 受測站的內容不該有能力決定掃描要跑多久。這條守的是「每個 script 標籤都往文件尾
    // 找一次 </script>」的二次方掃描：同一份輸入在修正前要 3.7 秒，修正後是數十毫秒。
    // 門檻取 1.5 秒——遠高於正常值（不會因 CI 機器忙碌就變紅燈），也遠低於退化後的數量級。
    const hostile = "<script src=/a.js>".repeat(20_000) + "x".repeat(200_000);
    const startedAt = Date.now();
    const found = extractSubresources(hostile, PAGE);
    expect(Date.now() - startedAt).toBeLessThan(1_500);
    expect(found.map((r) => r.url)).toEqual(["https://app.aios.test/a.js"]);
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

  it("module 腳本缺 crossorigin 不報——它本來就走 CORS，說「會被拒載」是說錯話", () => {
    const module = analyzeSubresources(
      [res({ kind: "script", url: "https://cdn.example.test/esm.js", integrity: "sha384-x", isModule: true })],
      ctx,
    );
    expect(ids(module)).not.toContain("supply-chain.sri-without-crossorigin.cdn.example.test");
    // 同樣寫法的 classic 腳本則確實會被拒載，必須報——這條規則不是整個關掉，是只對 module 不成立。
    const classic = analyzeSubresources(
      [res({ kind: "script", url: "https://cdn.example.test/classic.js", integrity: "sha384-x" })],
      ctx,
    );
    expect(ids(classic)).toContain("supply-chain.sri-without-crossorigin.cdn.example.test");
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

  it("host 為 null 的畸形輸入不會生出 supply-chain.script-no-sri.null 這種假 id", () => {
    // id 是抑制清單與跨次比對的鍵。一個從壞掉的輸入長出來的 id 會被寫進抑制清單，
    // 之後永遠對不到任何東西，而寫的人以為自己已經處理過了。
    const findings = analyzeSubresources(
      [res({ kind: "script", url: "data:text/javascript,1", host: null, isThirdParty: true })],
      ctx,
    );
    expect(ids(findings).some((id) => id.includes("null"))).toBe(false);
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
    const summary = inventoryByHost([res({ kind: "script", url: "data:text/javascript,1", host: null })]);
    expect(summary).toEqual([]);
  });
});

/**
 * checkSupplyChain 的每一條跳過路徑都要驗：這些分支就是「沒測到不可以講成沒問題」的實作，
 * 而它們失效時不會有任何錯誤訊息——只會多出一份看起來很乾淨的空盤點。
 */
describe("checkSupplyChain", () => {
  /** 分塊送出的回應內文：一次送完的回應讀得完，只有真的超過上限才會被標成截斷。 */
  function chunkedBody(chunks: number, bytes: number): ReadableStream<Uint8Array> {
    const chunk = new TextEncoder().encode("x".repeat(bytes));
    let sent = 0;
    return new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent >= chunks) {
          controller.close();
          return;
        }
        sent += 1;
        controller.enqueue(chunk);
      },
    });
  }

  it("首頁連不上時回未完成，不是回一份沒有第三方的乾淨清單", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("connect ECONNREFUSED 10.0.0.1:443");
    });
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("首頁無法連線");
    expect(result.findings).toEqual([]);
  });

  it("中介層攔截時回未完成——中介層的頁面不是站台的頁面", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response("502 Bad Gateway", { status: 502, headers: { "content-type": "text/plain" } }),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("中介層攔截");
  });

  it("首頁回錯誤狀態時回未完成，即使錯誤頁長得跟 SPA 一模一樣", async () => {
    // 這是最容易漏掉的假綠燈：SPA 的錯誤頁帶著 <div id="root">，
    // 所以中介層判定不會攔它，而它的 HTML 裡當然一支第三方腳本都沒有。
    vi.stubGlobal("fetch", async () =>
      new Response('<!doctype html><html><body><div id="root"></div></body></html>', {
        status: 500,
        headers: { "content-type": "text/html" },
      }),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("HTTP 500");
    expect(result.findings).toEqual([]);
  });

  it("重導向跟隨上限用完仍是 3xx 時回未完成——手上那份是中繼回應，不是首頁", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response("Redirecting…", {
        status: 302,
        headers: { location: "https://app.aios.test/next", "content-type": "text/html" },
      }),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("重導向");
  });

  it("首頁不是 HTML 時回未完成，並說明沒有子資源可盤點", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response('{"ok":true}', { status: 200, headers: { "content-type": "application/json" } }),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("content-type");
  });

  it("HTML 被讀取上限截斷時回未完成——不完整的盤點會被讀成完整清單", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response(chunkedBody(6, 200_000), { status: 200, headers: { "content-type": "text/html" } }),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("截斷");
    expect(result.facts?.truncated).toBe(true);
  });

  it("正常首頁：只送一個 GET，盤點寫進 facts，第三方問題寫進 findings", async () => {
    const html = `<!doctype html>
      <html><head>
        <link rel="stylesheet" href="/assets/app.css">
        <script type="module" crossorigin src="/assets/index-abc123.js"></script>
        <script src="https://cdn.example.test/lib.js"></script>
      </head><body><div id="root"></div></body></html>`;
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (input: string | URL, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(input)}`);
      return new Response(html, { status: 200, headers: { "content-type": "text/html; charset=utf-8" } });
    });

    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(true);
    // 檢測系統不該污染它要測量的東西：一次讀取就夠，而且只能是讀取方法。
    expect(calls).toEqual(["GET https://app.aios.test/"]);
    expect(result.facts?.subresources).toBe(3);
    expect(result.facts?.thirdPartyHosts).toEqual(["cdn.example.test"]);
    expect(ids(result.findings)).toEqual([
      "supply-chain.script-no-sri.cdn.example.test",
      "supply-chain.third-party-inventory",
    ]);
    expect(result.findings[0]?.where).toBe("https://app.aios.test/");
  });

  it("首頁完全沒有第三方資源時完成且零發現——那是真的測到了「沒有」", async () => {
    vi.stubGlobal("fetch", async () =>
      new Response(
        '<!doctype html><html><head><script type="module" src="/assets/index.js"></script></head>' +
          '<body><div id="root"></div></body></html>',
        { status: 200, headers: { "content-type": "text/html" } },
      ),
    );
    const result = await checkSupplyChain(web, 1000);
    expect(result.completed).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.facts?.thirdPartyHosts).toEqual([]);
  });
});
