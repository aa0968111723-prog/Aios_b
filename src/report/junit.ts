/**
 * JUnit XML 匯出。
 *
 * 為什麼要有這個：多數 CI 介面——GitHub Actions 的測試摘要、Jenkins、GitLab——都吃 JUnit XML。
 * 把檢測結果轉成測試報告，維運者不必為了看三端狀態去學一套新工具，既有面板就會顯示。
 *
 * 關鍵取捨：**被跳過的檢查一定要輸出成 `<skipped>`，不可以當成通過**。
 * JUnit 的預設語意是「沒有 failure 就是綠的」，把 CheckResult 直接映射過去，
 * 一輪什麼都沒測到的執行會在面板上變成一排綠勾——那正是這套系統最反對的失效方式。
 * 同理，檢查器自己爆掉要輸出 `<error>`（是探針有問題）而不是 `<failure>`（是受測目標有問題）：
 * 兩者混在一起，讀者就分不清「站台壞了」跟「我們的檢測壞了」，而這兩件事的處理方式完全不同。
 */
import { severityRank } from "../core/severity.js";
import type { CheckResult, Finding, RunReport, Severity } from "../core/types.js";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "極嚴重",
  high: "高",
  medium: "中",
  low: "低",
  info: "參考",
};

/**
 * XML 1.0 的文件字元集只收 tab、換行、歸位這三個控制字元，其餘 C0 控制字元
 * （以及 U+FFFE／U+FFFF）**沒有任何合法表示法**——連 `&#0;` 都不行。
 * 所以只能移除而不是跳脫：留著的話解析器不是忽略那個字元，是拒收整份檔案，
 * 結果 CI 面板一筆結果都讀不到。回應內容（尤其是誤當文字讀進來的二進位片段）
 * 常常混進這種字元，所以這條規則不是理論上的潔癖，是實際會發生的整份報告消失。
 */
const XML_ILLEGAL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g;

/** 屬性值與文字節點共用一套跳脫：屬性用雙引號，內文可能被貼進別處，寧可一律跳脫。 */
export function escapeXml(text: string): string {
  return text
    .replace(XML_ILLEGAL, "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * 屬性值專用的跳脫：在 `escapeXml` 之上，再把 tab／換行／歸位換成字元參照。
 *
 * 這三個字元在屬性裡是合法的，問題在於 XML 規定解析器讀屬性值時要把它們**正規化成空白**。
 * 於是一段多行的執行錯誤（`SyntaxError: …\n    at …`）寫進 `message` 後，面板上收到的是
 * 被壓成一行、看不出層次的字串——資料還在，但堆疊的形狀沒了。寫成 `&#10;` 就不受正規化影響，
 * 讀者拿到的與檢查器當初記下的是同一段文字。文字節點沒有這個問題，所以那邊仍然用 `escapeXml`，
 * 讓原始檔本身保持人眼可讀。
 */
function escapeAttr(text: string): string {
  return escapeXml(text).replace(/\t/g, "&#9;").replace(/\n/g, "&#10;").replace(/\r/g, "&#13;");
}

/** 一筆 testcase。kind 決定它在面板上是紅的、灰的還是綠的——這個對應關係就是本模組的重點。 */
interface Testcase {
  name: string;
  classname: string;
  kind: "pass" | "failure" | "error" | "skipped";
  /** failure／error／skipped 的 message 屬性：面板收合時只看得到這一行。 */
  message?: string;
  /** failure 的 type 屬性，填嚴重度，讓等級不必展開就看得見。 */
  type?: string;
  /** 元素內文：failure／error 放完整說明，通過的項目放 system-out。 */
  body?: string;
  /** 這一筆講的是哪一處。同名 testcase 撞在一起時，用它把兩者分開（見 `withUniqueNames`）。 */
  where?: string;
}

interface Testsuite {
  name: string;
  classname: string;
  durationMs: number;
  properties: Array<[string, string]>;
  cases: Testcase[];
}

/**
 * 秒數。非有限值一律當 0。
 *
 * `time` 在 JUnit 的 schema 裡是數字，而 `NaN`／`Infinity` 印出來就是那幾個字母——
 * 嚴格一點的消費端（Jenkins 會拿 XSD 驗）會因此拒收整份檔案，於是所有結果一起消失。
 * 耗時只是輔助資訊，為了它賠上整份報告不划算，寧可顯示 0。
 */
function seconds(ms: number): string {
  return (Number.isFinite(ms) ? Math.max(0, ms) / 1000 : 0).toFixed(3);
}

function count(cases: Testcase[], kind: Testcase["kind"]): number {
  return cases.filter((c) => c.kind === kind).length;
}

/** 證據可能是整份回應標頭；不截斷的話一份報告會膨脹到沒有人願意打開。 */
const EVIDENCE_LIMIT = 1200;

function clipEvidence(evidence: string): string {
  if (evidence.length <= EVIDENCE_LIMIT) return evidence;
  // JavaScript 的字串以 UTF-16 計長，而表情符號與部分 CJK 擴充字佔兩個單位。
  // 剛好切在中間會留下半個代理對——那不是合法字元，寫進檔案時會變成一個問號方塊，
  // 而讀者會以為是站台真的回了亂碼。少留一個字元，比留下一段假的觀測值好。
  const head = evidence.charCodeAt(EVIDENCE_LIMIT - 1) >= 0xd800 && evidence.charCodeAt(EVIDENCE_LIMIT - 1) <= 0xdbff
    ? EVIDENCE_LIMIT - 1
    : EVIDENCE_LIMIT;
  return `${evidence.slice(0, head)}…（證據已截斷）`;
}

/**
 * failure 與 system-out 共用的內文。
 * 一定要帶修法：面板上只有一個標題加紅叉的話，讀者除了把它關掉以外沒有別的事可做。
 */
function describeFinding(f: Finding): string {
  const lines = [f.detail];
  if (f.where) lines.push(`位置：${f.where}`);
  lines.push(`修法：${f.remediation ?? "（未提供）"}`);
  if (f.evidence) lines.push(`證據：${clipEvidence(f.evidence)}`);
  return lines.join("\n");
}

function casesForResult(r: CheckResult, failOn: Severity): Testcase[] {
  const classname = `aios-sentinel.${r.category}`;

  const cases: Testcase[] = r.findings.map((f): Testcase => {
    const base = { name: f.id, classname: `aios-sentinel.${f.category}`, where: f.where };
    // 達門檻的才算 failure。門檻以下的發現仍然要看得見，但不該讓建置變紅——
    // 一個因為 info 級提示天天紅燈的面板，最後會被整組關掉，連 critical 都沒人看。
    if (severityRank(f.severity) <= severityRank(failOn)) {
      return { ...base, kind: "failure", type: f.severity, message: f.title, body: describeFinding(f) };
    }
    return { ...base, kind: "pass", body: `[${SEVERITY_LABEL[f.severity]}] ${f.title}\n${describeFinding(f)}` };
  });

  if (r.error) {
    cases.push({
      name: `${r.check} 執行錯誤`,
      classname,
      kind: "error",
      message: r.error,
      // 錯誤原文在 message 與內文各放一次：JUnit 的慣例是內文擺堆疊，而不同面板顯示的位置不一樣
      // （有的只列 message，有的只在展開時給內文）。診斷檢測器故障靠的就是這段原文，不能賭它會被顯示。
      body: `檢查器本身沒有跑完，這一項在本次執行中沒有任何結論——不是通過。\n${r.error}`,
    });
  } else if (!r.completed) {
    // 沒填 skippedReason 的未完成檢查也要落在 skipped：不能因為少一段文字就被當成通過。
    cases.push({
      name: `${r.check} 未執行`,
      classname,
      kind: "skipped",
      message: r.skippedReason ?? "檢查未完成，且沒有記錄原因——本次對這一項沒有結論。",
    });
  } else if (cases.length === 0) {
    cases.push({ name: `${r.check} 無發現`, classname, kind: "pass" });
  }

  return cases;
}

/**
 * 被抑制的發現。
 * 抑制是一個決定，不是讓問題消失的開關——其他報告層都會列出它，JUnit 沒有例外的理由。
 * 輸出成 skipped 而不是 pass：這些問題還在，只是這一輪不讓它擋建置。
 */
function suppressedSuite(report: RunReport): Testsuite[] {
  const suppressed = report.suppressed ?? [];
  if (suppressed.length === 0) return [];
  return [
    {
      name: "已抑制的發現",
      classname: "aios-sentinel.suppressed",
      durationMs: 0,
      properties: [["suppressed", String(suppressed.length)]],
      cases: suppressed.map(
        (s): Testcase => ({
          name: s.finding.id,
          classname: `aios-sentinel.${s.finding.category}`,
          where: s.finding.where,
          kind: "skipped",
          message: `依抑制清單移出主清單：${s.reason}（到期：${s.expires ?? "永久"}）。問題本身仍然存在。`,
        }),
      ),
    },
  ];
}

/**
 * 涵蓋範圍告示。
 * 被 --only／--skip 縮小過的執行，在面板上跟完整檢測長得一模一樣。
 * 補一個 skipped 項目，讓「這次只測了一部分」跟結果出現在同一個畫面上，而不是只寫在別的檔案裡。
 */
function coverageSuite(report: RunReport): Testsuite[] {
  const filter = report.filter;
  if (!filter || (filter.only.length === 0 && filter.skip.length === 0)) return [];
  const parts: string[] = [];
  if (filter.only.length > 0) parts.push(`只執行 ${filter.only.join("、")}`);
  if (filter.skip.length > 0) parts.push(`略過 ${filter.skip.join("、")}`);
  return [
    {
      name: "檢測涵蓋範圍",
      classname: "aios-sentinel.coverage",
      durationMs: 0,
      properties: [["target", report.target]],
      cases: [
        {
          name: "本次檢測範圍被縮小",
          classname: "aios-sentinel.coverage",
          kind: "skipped",
          message: `${parts.join("；")}。未執行的項目在這份報告裡沒有任何結論——不代表通過。`,
        },
      ],
    },
  ];
}

/**
 * 一份 testcase 全空的報告。
 *
 * `tests="0"` 在每一個面板上都是綠的：沒有失敗、沒有跳過、沒有任何字提醒讀者這裡是空的，
 * 看起來就跟一輪順利跑完的檢測一模一樣。而它真正的意思是「這一輪連一項結果都沒有記錄下來」
 * ——過濾條件把全部檢查都排掉、或編排根本沒跑起來。CLI 那邊這種執行會以結束碼 3 收場，
 * 但面板讀的是這個檔案，不是結束碼，所以這裡必須自己講出來。
 */
function emptyRunSuite(report: RunReport): Testsuite {
  return {
    name: "沒有任何檢查被執行",
    classname: "aios-sentinel.coverage",
    durationMs: 0,
    properties: [["target", report.target]],
    cases: [
      {
        name: "本次執行沒有任何檢查結果",
        classname: "aios-sentinel.coverage",
        kind: "skipped",
        message:
          "這份報告裡一項檢查結果都沒有——不是全部通過，是什麼都沒測。" +
          "請確認執行參數（--only／--skip 是否把所有檢查都排除了）與檢測器有沒有真的啟動。",
      },
    ],
  };
}

/**
 * 讓同一個 testsuite 裡的 testcase 身分唯一。
 *
 * 同一種問題出現在多個位置時，`id` 會重複而 `where` 不同——`findingKey` 用 id 加 where 當鍵，
 * 就是承認這件事會發生。但 JUnit 的消費端（Jenkins、GitLab、GitHub Actions 的測試摘要）
 * 一律以 classname 加 name 當測試的主鍵，同名的兩筆會被折成一筆：兩個 failure 在面板上只剩一個，
 * 而少掉的那個不會有任何提示，讀者會以為問題只有一處。
 *
 * 撞名時才補位置，沒撞就維持純 id——名稱是讀者跨次執行辨認同一項的依據，能不動就不動。
 * 連位置都一樣（同一處的兩筆同 id 發現）時再補序號，確保最後一定分得開。
 */
function withUniqueNames(cases: Testcase[]): Testcase[] {
  const bare = new Map<string, number>();
  for (const c of cases) bare.set(c.name, (bare.get(c.name) ?? 0) + 1);

  const qualified = cases.map((c) =>
    (bare.get(c.name) ?? 0) > 1 && c.where ? { ...c, name: `${c.name}（${c.where}）` } : c,
  );

  const used = new Map<string, number>();
  return qualified.map((c) => {
    const nth = (used.get(c.name) ?? 0) + 1;
    used.set(c.name, nth);
    return nth === 1 ? c : { ...c, name: `${c.name} #${nth}` };
  });
}

function renderCase(tc: Testcase, time: string): string[] {
  const head = `    <testcase name="${escapeAttr(tc.name)}" classname="${escapeAttr(tc.classname)}" time="${time}"`;
  if (tc.kind === "pass" && !tc.body) return [`${head} />`];

  const lines = [`${head}>`];
  const body = escapeXml(tc.body ?? "");
  const message = escapeAttr(tc.message ?? "");
  if (tc.kind === "failure") {
    lines.push(`      <failure type="${escapeAttr(tc.type ?? "")}" message="${message}">${body}</failure>`);
  } else if (tc.kind === "error") {
    lines.push(`      <error message="${message}">${body}</error>`);
  } else if (tc.kind === "skipped") {
    lines.push(`      <skipped message="${message}" />`);
  } else {
    // 門檻以下的發現：面板上算通過，但點開看得到完整說明與修法。
    lines.push(`      <system-out>${body}</system-out>`);
  }
  lines.push("    </testcase>");
  return lines;
}

function renderSuite(suite: Testsuite, timestamp: string): string[] {
  const cases = withUniqueNames(suite.cases);
  // 單筆發現沒有各自的耗時。把檢查耗時平均攤到 testcase 上，面板加總才會等於實際時間；
  // 每筆都填整個檢查的時間，會讓一個十筆發現的檢查看起來跑了十倍久。
  const perCase = seconds(cases.length > 0 ? suite.durationMs / cases.length : 0);
  const lines = [
    `  <testsuite name="${escapeAttr(suite.name)}" classname="${escapeAttr(suite.classname)}"` +
      ` tests="${cases.length}" failures="${count(cases, "failure")}" errors="${count(cases, "error")}"` +
      ` skipped="${count(cases, "skipped")}" time="${seconds(suite.durationMs)}"` +
      ` timestamp="${escapeAttr(timestamp)}">`,
  ];
  if (suite.properties.length > 0) {
    lines.push("    <properties>");
    for (const [name, value] of suite.properties) {
      lines.push(`      <property name="${escapeAttr(name)}" value="${escapeAttr(value)}" />`);
    }
    lines.push("    </properties>");
  }
  for (const tc of cases) lines.push(...renderCase(tc, perCase));
  lines.push("  </testsuite>");
  return lines;
}

/**
 * 把一份 RunReport 轉成 JUnit XML。
 *
 * `failOn` 決定紅線畫在哪裡：達到或超過門檻的發現才是 failure，語意與 `shouldFail` 一致。
 * 這樣「CI 結束碼是紅的」跟「面板上有紅叉」永遠是同一件事，不會互相打臉。
 */
export function renderJunit(report: RunReport, failOn: Severity): string {
  const suites: Testsuite[] = [
    ...report.results.map(
      (r): Testsuite => ({
        name: r.check,
        classname: `aios-sentinel.${r.category}`,
        durationMs: r.durationMs,
        // 同一個檢查會在三端各跑一次，而 testsuite 名稱只有檢查名。
        // 不把 surface 寫成 property，面板上就會出現三個長得一模一樣、分不出是哪一端的區塊。
        properties: [
          ["surface", r.surface],
          ["target", report.target],
        ],
        cases: casesForResult(r, failOn),
      }),
    ),
    ...suppressedSuite(report),
    ...coverageSuite(report),
  ];
  // 一筆 testcase 都沒有的輸出會被面板讀成綠燈，所以空報告要自己補上一句「這裡是空的」。
  if (suites.every((s) => s.cases.length === 0)) suites.push(emptyRunSuite(report));

  const all = suites.flatMap((s) => s.cases);
  const lines: string[] = ['<?xml version="1.0" encoding="UTF-8"?>'];
  lines.push(
    `<testsuites name="Aios Sentinel" tests="${all.length}" time="${seconds(report.durationMs)}"` +
      ` failures="${count(all, "failure")}" errors="${count(all, "error")}"` +
      ` skipped="${count(all, "skipped")}">`,
  );
  for (const suite of suites) lines.push(...renderSuite(suite, report.startedAt));
  lines.push("</testsuites>");
  return `${lines.join("\n")}\n`;
}
