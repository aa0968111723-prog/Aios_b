import { describe, expect, it } from "vitest";
import {
  EVIL_REDIRECT_HOST,
  EVIL_REDIRECT_TARGET,
  REDIRECT_PARAMS,
  analyzeRedirect,
  classifyRedirectProbe,
  decideRedirectCoverage,
  findClientRedirect,
  findReflection,
  isSameHost,
  resolveLocation,
  type RedirectObservation,
} from "../src/detectors/redirect.js";

const REQUEST_URL = `https://example.test/login?next=${encodeURIComponent(EVIL_REDIRECT_TARGET)}`;
const ctx = { surface: "web" as const, originHost: "example.test", evilHost: EVIL_REDIRECT_HOST };

/** 預設是「登入頁回 200、沒有導向」，各測試只覆寫自己在意的欄位。 */
function observe(partial: Partial<RedirectObservation> = {}): RedirectObservation {
  return {
    param: "next",
    requestUrl: REQUEST_URL,
    sentTarget: EVIL_REDIRECT_TARGET,
    status: 200,
    location: null,
    bodySnippet: null,
    ...partial,
  };
}

const ids = (findings: ReturnType<typeof analyzeRedirect>) => findings.map((f) => f.id);

describe("REDIRECT_PARAMS", () => {
  it("維持在 15 個以內且沒有重複——請求量是路徑數乘上這個長度", () => {
    expect(REDIRECT_PARAMS.length).toBeLessThanOrEqual(15);
    expect(new Set(REDIRECT_PARAMS).size).toBe(REDIRECT_PARAMS.length);
  });

  it("涵蓋 aios 實際會用到的回跳參數與 OAuth 的授權碼回傳點", () => {
    expect(REDIRECT_PARAMS).toContain("next");
    expect(REDIRECT_PARAMS).toContain("redirect_uri");
    expect(REDIRECT_PARAMS).toContain("returnTo");
  });

  it("探針目標落在保留網域，送出去也不會有第三方收到請求", () => {
    expect(EVIL_REDIRECT_TARGET).toContain(".invalid");
    expect(EVIL_REDIRECT_TARGET).toContain(EVIL_REDIRECT_HOST);
  });
});

describe("resolveLocation", () => {
  it("絕對網址：直接取主機", () => {
    expect(resolveLocation("https://evil.test/x", REQUEST_URL).host).toBe("evil.test");
  });

  it("相對路徑：解析回自家主機（登入頁的正常回跳長這樣）", () => {
    expect(resolveLocation("/dashboard", REQUEST_URL).host).toBe("example.test");
  });

  // 過濾器多半只擋 `http://` 開頭，於是這一種是實務上最常漏掉的。
  it("協定相對網址 //evil.test/x 會沿用當前協定連到 evil.test", () => {
    expect(resolveLocation("//evil.test/x", REQUEST_URL).host).toBe("evil.test");
  });

  // URL 規範在 http(s) 這類特殊 scheme 下把 `\` 視同 `/`，所以它跟 `//evil.test` 等價。
  it("反斜線變體 /\\evil.test 等同協定相對網址", () => {
    expect(resolveLocation("/\\evil.test", REQUEST_URL).host).toBe("evil.test");
    expect(resolveLocation("/\\/evil.test/path", REQUEST_URL).host).toBe("evil.test");
  });

  // `@` 前面全是認證資訊：瀏覽器連的是 evil.test，但 startsWith("https://example.test") 會回 true。
  it("帶使用者名稱的 https://自家網域@evil.test 實際落點是 evil.test", () => {
    expect(resolveLocation("https://example.test@evil.test/x", REQUEST_URL).host).toBe("evil.test");
  });

  it("畸形、空值與沒有主機的 scheme 一律回 null，不回空字串", () => {
    expect(resolveLocation("http://", REQUEST_URL).host).toBeNull();
    expect(resolveLocation("", REQUEST_URL).host).toBeNull();
    expect(resolveLocation("   ", REQUEST_URL).host).toBeNull();
    expect(resolveLocation("javascript:alert(1)", REQUEST_URL).host).toBeNull();
  });

  it("raw 保留原始字串，證據要能一字不差地重現", () => {
    expect(resolveLocation("//evil.test/x", REQUEST_URL).raw).toBe("//evil.test/x");
  });

  it("大小寫與結尾的根網域點都不影響主機比對", () => {
    expect(resolveLocation("https://EVIL.TEST./x", REQUEST_URL).host).toBe("evil.test");
  });
});

describe("isSameHost", () => {
  // 後綴比對是這類漏洞最經典的錯誤修法，判定端若也用後綴就會吞掉最該抓的那一類。
  it("只認完全相同：evil.example.com 不等於 example.com", () => {
    expect(isSameHost("evil.example.com", "example.com")).toBe(false);
    expect(isSameHost("evilexample.com", "example.com")).toBe(false);
    expect(isSameHost("Example.com.", "example.com")).toBe(true);
  });
});

describe("analyzeRedirect：伺服器端導向", () => {
  it("導向自家網域不報——那是登入回跳的正確行為", () => {
    const findings = analyzeRedirect(
      observe({ status: 302, location: "https://example.test/dashboard" }),
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("導向相對路徑不報", () => {
    expect(analyzeRedirect(observe({ status: 302, location: "/dashboard" }), ctx)).toEqual([]);
  });

  it("導向探針主機報 high，id 帶參數名", () => {
    const findings = analyzeRedirect(
      observe({ status: 302, location: `${EVIL_REDIRECT_TARGET}` }),
      ctx,
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe("redirect.open.next");
    expect(findings[0]?.severity).toBe("high");
    expect(findings[0]?.where).toBe(REQUEST_URL);
    expect(findings[0]?.evidence).toContain(EVIL_REDIRECT_HOST);
  });

  it("協定相對與反斜線的 Location 同樣算導向外部", () => {
    for (const location of [`//${EVIL_REDIRECT_HOST}/probe`, `/\\${EVIL_REDIRECT_HOST}/probe`]) {
      const findings = analyzeRedirect(observe({ status: 302, location }), ctx);
      expect(ids(findings)).toEqual(["redirect.open.next"]);
    }
  });

  it("@ 混淆的 Location 看的是實際落點而不是字串開頭", () => {
    const findings = analyzeRedirect(
      observe({ status: 302, location: `https://example.test@${EVIL_REDIRECT_HOST}/probe` }),
      ctx,
    );
    expect(ids(findings)).toEqual(["redirect.open.next"]);
  });

  // 攻擊者能自助註冊或接管子網域；只有完全相同的主機名才算自家。
  it("導向自家網域的子網域仍要報——子網域不等於自家", () => {
    const subdomainCtx = { ...ctx, originHost: "example.com", evilHost: "evil.example.com" };
    const findings = analyzeRedirect(
      observe({ status: 302, location: "https://evil.example.com/probe" }),
      subdomainCtx,
    );
    expect(ids(findings)).toEqual(["redirect.open.next"]);
    expect(findings[0]?.severity).toBe("high");
  });

  it("導向與我們送出的值無關的第三方主機不報——那代表參數沒被採用", () => {
    const findings = analyzeRedirect(
      observe({ status: 302, location: "https://accounts.google.com/o/oauth2/auth" }),
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("3xx 卻沒有 Location：畸形回應，沒有落點可判，不臆測", () => {
    expect(analyzeRedirect(observe({ status: 302, location: null }), ctx)).toEqual([]);
  });

  it("3xx 的內文不看——瀏覽器不會渲染它，那裡的 meta refresh 對使用者不存在", () => {
    const findings = analyzeRedirect(
      observe({
        status: 302,
        location: "/dashboard",
        bodySnippet: `<meta http-equiv="refresh" content="0;url=${EVIL_REDIRECT_TARGET}">`,
      }),
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("OAuth 的 redirect_uri 會在 detail 講清楚授權碼會被送到攻擊者手上", () => {
    const findings = analyzeRedirect(
      observe({ param: "redirect_uri", status: 302, location: EVIL_REDIRECT_TARGET }),
      ctx,
    );
    expect(findings[0]?.id).toBe("redirect.open.redirect_uri");
    expect(findings[0]?.detail).toContain("授權碼");
  });
});

describe("analyzeRedirect：內文層導向", () => {
  it("meta refresh 指向外部報 medium", () => {
    const findings = analyzeRedirect(
      observe({
        bodySnippet: `<html><head><meta http-equiv="refresh" content="0; url=${EVIL_REDIRECT_TARGET}"></head></html>`,
      }),
      ctx,
    );
    expect(findings[0]?.id).toBe("redirect.open-meta.next");
    expect(findings[0]?.severity).toBe("medium");
  });

  it("location.href 賦值指向外部報 medium", () => {
    const findings = analyzeRedirect(
      observe({ bodySnippet: `<script>window.location.href = "${EVIL_REDIRECT_TARGET}";</script>` }),
      ctx,
    );
    expect(findings[0]?.id).toBe("redirect.open-meta.next");
    expect(findings[0]?.severity).toBe("medium");
  });

  it("location.replace 與協定相對目標一樣抓得到", () => {
    const findings = analyzeRedirect(
      observe({ bodySnippet: `<script>location.replace('//${EVIL_REDIRECT_HOST}/probe')</script>` }),
      ctx,
    );
    expect(ids(findings)).toEqual(["redirect.open-meta.next"]);
  });

  // 這是降噪的關鍵：探針主機出現在內文裡，不代表它是導向目標。
  it("導向目標其實是自家路徑、探針值只在查詢字串裡時不報 open-meta", () => {
    const findings = analyzeRedirect(
      observe({
        bodySnippet: `<meta http-equiv="refresh" content="0;url=/login?next=${EVIL_REDIRECT_TARGET}">`,
      }),
      ctx,
    );
    expect(ids(findings)).not.toContain("redirect.open-meta.next");
  });
});

describe("analyzeRedirect：純反射", () => {
  it("值原樣出現在內文但沒有實際導向，報 low 並寫明這是體質提醒", () => {
    const findings = analyzeRedirect(
      observe({ bodySnippet: `<input type="hidden" name="next" value="${EVIL_REDIRECT_TARGET}">` }),
      ctx,
    );
    expect(findings[0]?.id).toBe("redirect.reflected.next");
    expect(findings[0]?.severity).toBe("low");
    expect(findings[0]?.detail).toContain("不等於已經可以利用");
  });

  it("內文只是把當前網址整串印回來（canonical）不算反射——那對 15 個參數都會成立", () => {
    const findings = analyzeRedirect(
      observe({ bodySnippet: `<link rel="canonical" href="${REQUEST_URL}">` }),
      ctx,
    );
    expect(findings).toEqual([]);
  });

  it("自我回聲的 & 被逸出成 &amp; 時一樣要扣掉", () => {
    const requestUrl = `${REQUEST_URL}&lang=zh`;
    const body = `<link rel="canonical" href="${requestUrl.replace(/&/g, "&amp;")}">`;
    expect(findReflection(body, requestUrl, EVIL_REDIRECT_HOST)).toBeNull();
  });

  it("內文完全沒提到探針值就什麼都不報", () => {
    expect(analyzeRedirect(observe({ bodySnippet: "<div id=\"root\"></div>" }), ctx)).toEqual([]);
  });
});

describe("finding 的形狀", () => {
  it("每一種判定都帶 remediation，id 穩定且不含時間戳或亂數", () => {
    const cases = [
      analyzeRedirect(observe({ status: 302, location: EVIL_REDIRECT_TARGET }), ctx),
      analyzeRedirect(
        observe({ bodySnippet: `<meta http-equiv="refresh" content="0;url=${EVIL_REDIRECT_TARGET}">` }),
        ctx,
      ),
      analyzeRedirect(observe({ bodySnippet: `value="${EVIL_REDIRECT_TARGET}"` }), ctx),
    ].flat();
    expect(cases).toHaveLength(3);
    for (const f of cases) {
      expect(f.remediation).toBeTruthy();
      expect(f.check).toBe("redirect");
      expect(f.category).toBe("security");
      expect(f.id).toMatch(/^redirect\.(open|open-meta|reflected)\.[A-Za-z_]+$/);
      expect(f.where).toBe(REQUEST_URL);
    }
  });

  it("同一次觀測只會產出一筆——同一件事報兩次會稀釋掉真正要修的那筆", () => {
    const findings = analyzeRedirect(
      observe({ bodySnippet: `<meta http-equiv="refresh" content="0;url=${EVIL_REDIRECT_TARGET}">` }),
      ctx,
    );
    expect(findings).toHaveLength(1);
  });
});

describe("findReflection：自我回聲的兩種編碼都要扣掉", () => {
  // 這一條是實測出來的假警報：我們送出去的是百分號編碼版（searchParams.set 的結果），
  // 但伺服器手上拿到的是解碼後的值，印回 canonical 時也是解碼的。
  // 只扣掉編碼版的話，每一個把當前網址印回頁面的正常站台都會生出一整排 low。
  it("伺服器把網址解碼後再印回來（canonical）不算反射", () => {
    const decodedEcho = `https://example.test/login?next=${EVIL_REDIRECT_TARGET}`;
    expect(findReflection(`<link rel="canonical" href="${decodedEcho}">`, REQUEST_URL, EVIL_REDIRECT_HOST)).toBeNull();
  });

  it("form action 把當前查詢字串原樣接上去也不算反射", () => {
    const body = `<form action="/login?next=${EVIL_REDIRECT_TARGET}" method="post">`;
    expect(findReflection(body, REQUEST_URL, EVIL_REDIRECT_HOST)).toBeNull();
  });

  // 扣掉回聲之後仍然找得到，才是這個參數真的被單獨處理過。
  it("扣掉回聲之後，hidden input 裡的值仍然要報出來", () => {
    const body = `<input type="hidden" name="next" value="${EVIL_REDIRECT_TARGET}">`;
    expect(findReflection(body, REQUEST_URL, EVIL_REDIRECT_HOST)).toContain(EVIL_REDIRECT_HOST);
  });

  // 證據要能被拿去原始碼裡搜尋；附一段被剪過的 HTML 等於沒有附證據。
  it("證據片段取自原始內文，不是被挖過洞的版本", () => {
    const body = `<div class="wrap"><input name="next" value="${EVIL_REDIRECT_TARGET}"></div>`;
    expect(findReflection(body, REQUEST_URL, EVIL_REDIRECT_HOST)).toBe(body);
  });
});

describe("純函式的防呆：壞輸入不該長出發現，也不該讓整輪檢查爆掉", () => {
  // indexOf("") 回 0，於是每一個 200 回應都會變成一筆「反射」。
  // 憑空生出來的發現比漏報更傷：沒有人查得出它從哪來，只會學會不要相信這份報告。
  it("evilHost 是空字串時不報任何反射", () => {
    expect(findReflection("<div id=\"root\"></div>", REQUEST_URL, "")).toBeNull();
    expect(findReflection("<div id=\"root\"></div>", REQUEST_URL, "   ")).toBeNull();
  });

  it("requestUrl 畸形時照樣回答，不丟例外", () => {
    expect(() => findReflection(`x ${EVIL_REDIRECT_HOST} y`, "not a url", EVIL_REDIRECT_HOST)).not.toThrow();
    expect(findReflection(`x ${EVIL_REDIRECT_HOST} y`, "not a url", EVIL_REDIRECT_HOST)).toContain(EVIL_REDIRECT_HOST);
  });

  it("analyzeRedirect 收到畸形 requestUrl 不會讓整輪檢查中斷", () => {
    expect(() =>
      analyzeRedirect(observe({ requestUrl: "not a url", bodySnippet: "<div id=\"root\"></div>" }), ctx),
    ).not.toThrow();
  });

  // 基準網址壞掉不該連累已經看得見的絕對落點——那是自己製造漏報。
  it("requestUrl 畸形時，絕對網址的落點仍然解析得出來", () => {
    expect(resolveLocation("https://evil.test/x", "not a url").host).toBe("evil.test");
    expect(resolveLocation("/dashboard", "not a url").host).toBeNull();
  });

  it("空內文與空 Location 都只是「沒東西可判」，不是發現", () => {
    expect(analyzeRedirect(observe({ bodySnippet: null }), ctx)).toEqual([]);
    expect(analyzeRedirect(observe({ bodySnippet: "" }), ctx)).toEqual([]);
    expect(analyzeRedirect(observe({ status: 302, location: "" }), ctx)).toEqual([]);
  });
});

describe("findClientRedirect", () => {
  it("meta refresh 的目標整串抽出來解析，不是看探針主機有沒有出現過", () => {
    const hit = findClientRedirect(
      `<meta http-equiv="refresh" content="0; url=${EVIL_REDIRECT_TARGET}">`,
      REQUEST_URL,
      EVIL_REDIRECT_HOST,
    );
    expect(hit?.kind).toBe("meta");
    expect(hit?.target).toBe(EVIL_REDIRECT_TARGET);
  });

  it("location.assign 與 document.location 賦值都算", () => {
    expect(
      findClientRedirect(`<script>location.assign("${EVIL_REDIRECT_TARGET}")</script>`, REQUEST_URL, EVIL_REDIRECT_HOST)
        ?.kind,
    ).toBe("script");
    expect(
      findClientRedirect(
        `<script>document.location = '${EVIL_REDIRECT_TARGET}'</script>`,
        REQUEST_URL,
        EVIL_REDIRECT_HOST,
      )?.kind,
    ).toBe("script");
  });

  it("導向自家路徑時不算——那是登入頁把人送回自己的正常寫法", () => {
    expect(
      findClientRedirect(
        `<script>location.href = "/dashboard"</script>`,
        REQUEST_URL,
        EVIL_REDIRECT_HOST,
      ),
    ).toBeNull();
  });

  // JSON 裡的 "location" 欄位、比較運算式都不是導向，抓進來就是假警報。
  it("不是賦值的 location 字樣不算", () => {
    expect(
      findClientRedirect(`{"location":"${EVIL_REDIRECT_TARGET}"}`, REQUEST_URL, EVIL_REDIRECT_HOST),
    ).toBeNull();
  });

  it("字串串接的目標抓不到，這是刻意的取捨——寧可漏也不要猜", () => {
    expect(
      findClientRedirect(`<script>location.href = base + next</script>`, REQUEST_URL, EVIL_REDIRECT_HOST),
    ).toBeNull();
  });
});

describe("analyzeRedirect：其他邊界", () => {
  // 瀏覽器只在 3xx 才跟隨 Location；200 帶 Location 是伺服器寫錯，不是導向。
  // 內文給一段真的會命中反射的字串，才驗得出判定確實走了內文那條路，而不是碰巧回空陣列。
  it("200 帶 Location 不當成導向，判定改看內文", () => {
    const findings = analyzeRedirect(
      observe({
        status: 200,
        location: EVIL_REDIRECT_TARGET,
        bodySnippet: `<input name="next" value="${EVIL_REDIRECT_TARGET}">`,
      }),
      ctx,
    );
    expect(ids(findings)).toEqual(["redirect.reflected.next"]);
  });

  it("探針主機的子網域也算落在探針上——有些站會把值包進自己的前後綴再導出去", () => {
    const findings = analyzeRedirect(
      observe({ status: 307, location: `https://x.${EVIL_REDIRECT_HOST}/probe` }),
      ctx,
    );
    expect(ids(findings)).toEqual(["redirect.open.next"]);
  });

  it("308 與 303 一樣算導向", () => {
    for (const status of [303, 308]) {
      expect(ids(analyzeRedirect(observe({ status, location: EVIL_REDIRECT_TARGET }), ctx))).toEqual([
        "redirect.open.next",
      ]);
    }
  });

  it("meta refresh 與純反射同時成立時只報較嚴重的那一筆", () => {
    const findings = analyzeRedirect(
      observe({
        bodySnippet:
          `<meta http-equiv="refresh" content="0;url=${EVIL_REDIRECT_TARGET}">` +
          `<input name="next" value="${EVIL_REDIRECT_TARGET}">`,
      }),
      ctx,
    );
    expect(ids(findings)).toEqual(["redirect.open-meta.next"]);
  });
});

describe("classifyRedirectProbe：站台答的、還是中間有人代答", () => {
  // 這一條擋的是整個偵測器最貴的失效方式：一個再平常不過的 404 把整項檢查標成「被攔截」，
  // 連另一條路徑上已經測到的真發現一起丟掉。
  it("express 預設 404 頁是站台答的，不是中介層攔截", () => {
    const body = '<!DOCTYPE html>\n<html lang="en"><head><title>Error</title></head><body><pre>Cannot GET /login</pre></body></html>';
    expect(classifyRedirectProbe({ status: 404, body, contentType: "text/html; charset=utf-8" }).state).toBe("absent");
  });

  it("nginx 預設 404 頁同樣算 absent", () => {
    const body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body><center><h1>404 Not Found</h1></center></body>\r\n</html>";
    expect(classifyRedirectProbe({ status: 404, body, contentType: "text/html" }).state).toBe("absent");
  });

  it("POST-only 登入端點對 GET 回 405 也是 absent——站台答了，只是沒東西可判", () => {
    expect(classifyRedirectProbe({ status: 405, body: "", contentType: "" }).state).toBe("absent");
  });

  // WAF 的封鎖頁同樣是帶 doctype 的 HTML，所以 SPA 判定必須排在中介層判定之後。
  it("WAF 的 403 封鎖頁算中介層攔截，不能被誤讀成 SPA 兜底頁", () => {
    const verdict = classifyRedirectProbe({
      status: 403,
      body: "<!DOCTYPE html><html><head><title>Access Denied</title></head><body>Blocked by policy</body></html>",
      contentType: "text/html",
    });
    expect(verdict.state).toBe("intercepted");
  });

  it("平台閘道的 502 算中介層攔截", () => {
    expect(classifyRedirectProbe({ status: 502, body: "Bad Gateway", contentType: "text/plain" }).state).toBe(
      "intercepted",
    );
  });

  it("SPA 兜底 index.html 是站台答的，但要標記出來——那條路徑的回跳邏輯在瀏覽器裡", () => {
    const verdict = classifyRedirectProbe({
      status: 200,
      body: '<!doctype html><div id="root"></div><script type="module" src="/a.js"></script>',
      contentType: "text/html",
    });
    expect(verdict.state).toBe("answered");
    expect(verdict.state === "answered" && verdict.spaFallback).toBe(true);
  });

  it("3xx 是最有價值的回應，永遠算站台答的", () => {
    const verdict = classifyRedirectProbe({ status: 302, body: "", contentType: "" });
    expect(verdict.state).toBe("answered");
    expect(verdict.state === "answered" && verdict.spaFallback).toBe(false);
  });

  it("連不上是「沒測到」，原文照抄讓讀者自己分辨", () => {
    const verdict = classifyRedirectProbe({ error: "無法連線：timeout" });
    expect(verdict.state).toBe("unreachable");
    expect(verdict.state === "unreachable" && verdict.reason).toContain("timeout");
  });
});

describe("decideRedirectCoverage：跳過不等於通過", () => {
  it("只要有一次拿到站台回應就算跑過了——不能因為別條路徑被擋掉就丟掉真發現", () => {
    expect(decideRedirectCoverage({ answered: 15, absent: 15, intercepted: 0, unreachable: 0 })).toEqual({
      completed: true,
    });
    expect(decideRedirectCoverage({ answered: 1, absent: 0, intercepted: 29, unreachable: 0 })).toEqual({
      completed: true,
    });
  });

  it("全部被中介層攔下：整組標為未執行，並說清楚測到的是中介層不是站台", () => {
    const verdict = decideRedirectCoverage({ answered: 0, absent: 0, intercepted: 30, unreachable: 0 });
    expect(verdict.completed).toBe(false);
    expect(verdict.completed === false && verdict.skippedReason).toContain("中介層");
  });

  it("受測路徑全都不存在：不可以講成「沒有開放重導向」", () => {
    const verdict = decideRedirectCoverage({ answered: 0, absent: 30, intercepted: 0, unreachable: 0 });
    expect(verdict.completed).toBe(false);
    expect(verdict.completed === false && verdict.skippedReason).toContain("不代表站台沒有開放重導向");
  });

  it("全部連不上：一樣是未執行", () => {
    const verdict = decideRedirectCoverage({ answered: 0, absent: 0, intercepted: 0, unreachable: 30 });
    expect(verdict.completed).toBe(false);
    expect(verdict.completed === false && verdict.skippedReason).toContain("連不上");
  });

  // 一次都沒送出去卻回綠燈，是這類工具最典型的假綠燈。
  it("一次探針都沒送出去時不可以回 completed", () => {
    expect(decideRedirectCoverage({ answered: 0, absent: 0, intercepted: 0, unreachable: 0 }).completed).toBe(false);
  });
});
