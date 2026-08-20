import { describe, expect, it } from "vitest";
import {
  EVIL_REDIRECT_HOST,
  EVIL_REDIRECT_TARGET,
  REDIRECT_PARAMS,
  analyzeRedirect,
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
