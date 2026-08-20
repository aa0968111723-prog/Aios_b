/**
 * HTML 儀表板。
 *
 * 存在的理由：資安報告的讀者不只工程師。專案負責人要能打開一個檔案就看懂
 * 「現在有幾件事要處理、哪一件最急、修法是什麼」。所以是單一自足檔案
 * （無外部資源、可直接寄出或放進 CI 產物），且深淺色都能讀。
 */
import { sortFindings, severityRank } from "../core/severity.js";
import { findingKey } from "../core/findings.js";
import { allFindings } from "../core/runner.js";
import type { Finding, RunReport, Severity } from "../core/types.js";

const SEVERITY_META: Record<Severity, { label: string; color: string }> = {
  critical: { label: "極嚴重", color: "#c0392b" },
  high: { label: "高", color: "#d35400" },
  medium: { label: "中", color: "#b7950b" },
  low: { label: "低", color: "#2471a3" },
  info: { label: "參考", color: "#6b7280" },
};

const CATEGORY_LABEL: Record<string, string> = {
  security: "資訊安全",
  availability: "可用性",
  page: "頁面",
  a11y: "無障礙",
  integrity: "一致性",
  monitoring: "監測",
};

function esc(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

/**
 * 涵蓋範圍告示。
 * 有過濾就代表這份報告不是完整檢測——放在最上方，讓人在看到「零發現」之前就先看到範圍。
 */
function coverageBanner(report: RunReport): string {
  const filter = report.filter;
  if (!filter || (filter.only.length === 0 && filter.skip.length === 0)) return "";
  const parts: string[] = [];
  if (filter.only.length > 0) parts.push(`只執行 <code>${esc(filter.only.join("、"))}</code>`);
  if (filter.skip.length > 0) parts.push(`略過 <code>${esc(filter.skip.join("、"))}</code>`);
  return `<div class="banner warn"><b>本次檢測範圍被縮小：${parts.join("；")}。</b>
    未執行的項目在這份報告裡沒有任何結論——不代表通過。</div>`;
}

/** 與基準的比對區塊。 */
function diffBlock(report: RunReport): string {
  const diff = report.diff;
  if (!diff) return "";
  const escalated = diff.changed.filter((c) => severityRank(c.after.severity) < severityRank(c.before.severity));
  const improved = diff.changed.filter((c) => severityRank(c.after.severity) > severityRank(c.before.severity));

  const mismatch =
    diff.baselineTarget && diff.baselineTarget !== report.target
      ? `<div class="banner warn">基準檔測的是 <code>${esc(diff.baselineTarget)}</code>，與本次目標不同。
         跨站台比對只能參考，差異可能來自部署本身而非變更。</div>`
      : "";

  const row = (label: string, count: number, color: string) =>
    `<div class="card" data-empty="${count === 0}"><div class="dot" style="background:${color}"></div>
      <div class="num">${count}</div><div class="lbl">${label}</div></div>`;

  const list = (title: string, items: Finding[]) =>
    items.length === 0
      ? ""
      : `<h3 class="dh">${title}</h3><ul class="dlist">${sortFindings(items)
          .map(
            (f) =>
              `<li><span class="pill" style="background:${SEVERITY_META[f.severity].color}">${SEVERITY_META[f.severity].label}</span>
               ${esc(f.title)} <code>${esc(f.id)}</code></li>`,
          )
          .join("")}</ul>`;

  const changedList =
    escalated.length === 0
      ? ""
      : `<h3 class="dh">嚴重度惡化</h3><ul class="dlist">${escalated
          .map(
            (c) =>
              `<li><span class="pill" style="background:${SEVERITY_META[c.after.severity].color}">${
                SEVERITY_META[c.before.severity].label
              } → ${SEVERITY_META[c.after.severity].label}</span> ${esc(c.after.title)} <code>${esc(c.after.id)}</code></li>`,
          )
          .join("")}</ul>`;

  return `<h2>與基準比對${diff.baselineStartedAt ? `<span class="meta"> · 基準時間 ${esc(diff.baselineStartedAt)}</span>` : ""}</h2>
    ${mismatch}
    <div class="cards">
      ${row("新增", diff.added.length, "#c0392b")}
      ${row("已修復", diff.fixed.length, "#1e8449")}
      ${row("惡化", escalated.length, "#d35400")}
      ${row("減輕", improved.length, "#2471a3")}
      ${row("持續", diff.unchanged.length, "#6b7280")}
    </div>
    ${list("新增", diff.added)}
    ${changedList}
    ${list("已修復（本次不再出現）", diff.fixed)}`;
}

/** 被抑制的發現。抑制是一種有期限、要具名的決定，所以它永遠留在報告上。 */
function suppressedBlock(report: RunReport): string {
  const suppressed = report.suppressed ?? [];
  if (suppressed.length === 0) return "";
  const rows = suppressed
    .map(
      (s) => `<tr>
        <td><span class="pill" style="background:${SEVERITY_META[s.finding.severity].color}">${SEVERITY_META[s.finding.severity].label}</span></td>
        <td>${esc(s.finding.title)}<br><code>${esc(s.finding.id)}</code></td>
        <td class="note">${esc(s.reason)}</td>
        <td class="note">${s.expires ? esc(s.expires) : "<b>永久</b>"}</td>
        <td class="note">${esc(s.owner ?? "—")}</td>
      </tr>`,
    )
    .join("");
  return `<h2>已抑制（${suppressed.length}）</h2>
    <div class="banner warn">這些發現<b>依然存在</b>，只是依抑制清單移出主清單。抑制不等於修好。</div>
    <div class="tablewrap"><table>
      <thead><tr><th>嚴重度</th><th>問題</th><th>抑制理由</th><th>到期</th><th>負責人</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>`;
}

export function renderHtml(report: RunReport): string {
  const findings = sortFindings(allFindings(report));
  const { summary } = report;
  const incomplete = report.results.filter((r) => !r.completed);

  const cards = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => {
      const meta = SEVERITY_META[s];
      const count = summary.findings[s];
      return `<div class="card" data-empty="${count === 0}">
        <div class="dot" style="background:${meta.color}"></div>
        <div class="num">${count}</div>
        <div class="lbl">${meta.label}</div>
      </div>`;
    })
    .join("");

  // 新增的發現要一眼看得出來：一份 40 筆的報告裡，該先處理的是這次才冒出來的那幾筆。
  const newKeys = new Set((report.diff?.added ?? []).map(findingKey));

  const findingRows = findings
    .map((f, i) => {
      const meta = SEVERITY_META[f.severity];
      const isNew = newKeys.has(findingKey(f));
      return `<details class="finding" data-sev="${f.severity}" data-cat="${f.category}" data-surface="${f.surface}" data-new="${isNew}">
      <summary>
        <span class="pill" style="background:${meta.color}">${meta.label}</span>
        ${isNew ? '<span class="pill new">新增</span>' : ""}
        <span class="ftitle">${esc(f.title)}</span>
        <span class="meta">${CATEGORY_LABEL[f.category] ?? f.category} · ${esc(String(f.surface))}</span>
      </summary>
      <div class="body">
        <p class="detail">${esc(f.detail).replace(/\n/g, "<br>")}</p>
        ${f.where ? `<p class="where"><b>位置</b><code>${esc(f.where)}</code></p>` : ""}
        ${f.evidence ? `<pre class="evidence">${esc(f.evidence.slice(0, 1500))}</pre>` : ""}
        <p class="fix"><b>建議修法</b>${esc(f.remediation ?? "（未提供）")}</p>
        <p class="fid">id: <code>${esc(f.id)}</code>${i === 0 ? "" : ""}</p>
      </div>
    </details>`;
    })
    .join("\n");

  const checkRows = report.results
    .map((r) => {
      const status = r.error
        ? `<span class="st err">執行錯誤</span>`
        : r.completed
          ? `<span class="st ok">完成</span>`
          : `<span class="st skip">跳過</span>`;
      const note = r.error ?? r.skippedReason ?? "";
      return `<tr>
        <td>${esc(r.check)}</td>
        <td>${esc(String(r.surface))}</td>
        <td>${status}</td>
        <td class="n">${r.findings.length}</td>
        <td class="n">${(r.durationMs / 1000).toFixed(1)}s</td>
        <td class="note">${esc(note)}</td>
      </tr>`;
    })
    .join("\n");

  return `<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aios Sentinel 檢測報告 — ${esc(report.target)}</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #f7f6f3; --fg: #1c1917; --muted: #6b7280; --panel: #ffffff; --line: #e5e2dc;
    --code: #f3f0e8;
  }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #16161a; --fg: #ecebe8; --muted: #9ca3af; --panel: #1f1f24; --line: #2f2f37; --code: #26262c; }
  }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
    font-family: "Noto Sans TC", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.65; }
  .wrap { max-width: 68rem; margin: 0 auto; }
  h1 { font-size: 1.6rem; margin: 0 0 .35rem; }
  .sub { color: var(--muted); font-size: .9rem; margin: 0 0 1.5rem; }
  .sub code { background: var(--code); padding: .1rem .35rem; border-radius: .25rem; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(7rem, 1fr)); gap: .75rem; margin-bottom: 1.5rem; }
  .card { background: var(--panel); border: 1px solid var(--line); border-radius: .6rem; padding: .9rem; text-align: center; }
  .card[data-empty="true"] { opacity: .45; }
  .card .dot { width: .6rem; height: .6rem; border-radius: 50%; margin: 0 auto .4rem; }
  .card .num { font-size: 1.7rem; font-weight: 700; line-height: 1; }
  .card .lbl { font-size: .8rem; color: var(--muted); margin-top: .25rem; }
  .banner { border-radius: .6rem; padding: .9rem 1rem; margin-bottom: 1.5rem; border: 1px solid var(--line); background: var(--panel); }
  .banner.warn { border-left: .3rem solid #b7950b; }
  .banner.good { border-left: .3rem solid #1e8449; }
  .banner ul { margin: .5rem 0 0; padding-left: 1.2rem; }
  h2 { font-size: 1.15rem; margin: 2rem 0 .75rem; }
  .filters { display: flex; flex-wrap: wrap; gap: .4rem; margin-bottom: 1rem; }
  .filters button { border: 1px solid var(--line); background: var(--panel); color: var(--fg);
    border-radius: 999px; padding: .3rem .8rem; font-size: .85rem; cursor: pointer; font-family: inherit; }
  .filters button[aria-pressed="true"] { background: var(--fg); color: var(--bg); border-color: var(--fg); }
  .finding { background: var(--panel); border: 1px solid var(--line); border-radius: .6rem; margin-bottom: .5rem; }
  .finding[hidden] { display: none; }
  .finding > summary { cursor: pointer; padding: .75rem .9rem; display: flex; gap: .6rem; align-items: baseline; flex-wrap: wrap; }
  .finding > summary::-webkit-details-marker { display: none; }
  .pill { color: #fff; font-size: .72rem; padding: .1rem .5rem; border-radius: 999px; white-space: nowrap; }
  .pill.new { background: #7d3c98; }
  .dh { font-size: .95rem; margin: 1.25rem 0 .4rem; color: var(--muted); }
  .dlist { margin: 0; padding-left: 1.1rem; font-size: .88rem; }
  .dlist li { margin-bottom: .3rem; }
  .dlist code { background: var(--code); padding: .05rem .3rem; border-radius: .25rem; font-size: .78rem; }
  .ftitle { font-weight: 600; flex: 1 1 20rem; }
  .meta { color: var(--muted); font-size: .8rem; }
  .body { padding: 0 .9rem .9rem; border-top: 1px solid var(--line); }
  .detail { margin: .75rem 0; }
  .where code, .fid code { background: var(--code); padding: .1rem .35rem; border-radius: .25rem; font-size: .82rem; word-break: break-all; }
  .where b, .fix b { display: block; font-size: .78rem; color: var(--muted); margin-bottom: .15rem; }
  .evidence { background: var(--code); padding: .7rem; border-radius: .4rem; overflow-x: auto;
    font-size: .8rem; white-space: pre-wrap; word-break: break-all; }
  .fix { background: var(--code); padding: .7rem; border-radius: .4rem; margin: .75rem 0 0; }
  .fid { font-size: .75rem; color: var(--muted); margin: .6rem 0 0; }
  table { width: 100%; border-collapse: collapse; font-size: .87rem; }
  .tablewrap { overflow-x: auto; border: 1px solid var(--line); border-radius: .6rem; background: var(--panel); }
  th, td { text-align: left; padding: .5rem .7rem; border-bottom: 1px solid var(--line); }
  th { font-size: .78rem; color: var(--muted); font-weight: 600; }
  tr:last-child td { border-bottom: none; }
  td.n { text-align: right; font-variant-numeric: tabular-nums; }
  td.note { color: var(--muted); font-size: .8rem; }
  .st { font-size: .78rem; padding: .1rem .45rem; border-radius: .25rem; }
  .st.ok { background: rgba(30,132,73,.15); color: #1e8449; }
  .st.skip { background: rgba(183,149,11,.15); color: #b7950b; }
  .st.err { background: rgba(192,57,43,.15); color: #c0392b; }
  footer { margin-top: 2.5rem; color: var(--muted); font-size: .8rem; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Aios Sentinel 檢測報告</h1>
  <p class="sub">
    受測目標 <code>${esc(report.target)}</code> ·
    檢測端 ${esc(report.surfaces.join("、"))} ·
    ${esc(report.startedAt)} · 耗時 ${(report.durationMs / 1000).toFixed(1)} 秒
  </p>

  <div class="cards">${cards}</div>

  ${coverageBanner(report)}

  ${
    incomplete.length > 0
      ? `<div class="banner warn">
      <b>有 ${incomplete.length} 項檢查沒有完成——未完成不等於通過。</b>
      <ul>${incomplete.map((r) => `<li><code>${esc(r.check)}</code>（${esc(String(r.surface))}）：${esc(r.error ?? r.skippedReason ?? "")}</li>`).join("")}</ul>
    </div>`
      : `<div class="banner good">所有檢查皆已完成執行。</div>`
  }

  ${diffBlock(report)}

  <h2>發現（${findings.length}）</h2>
  <div class="filters" id="filters">
    <button data-filter="all" aria-pressed="true">全部</button>
    <button data-filter="critical">極嚴重</button>
    <button data-filter="high">高</button>
    <button data-filter="medium">中</button>
    <button data-filter="low">低</button>
    <button data-filter="info">參考</button>
    ${report.diff ? '<button data-filter="new">只看新增</button>' : ""}
  </div>
  ${findings.length > 0 ? findingRows : `<div class="banner good">本次檢測沒有發現任何問題。</div>`}

  ${suppressedBlock(report)}

  <h2>檢查明細</h2>
  <div class="tablewrap">
    <table>
      <thead><tr><th>檢查</th><th>端</th><th>狀態</th><th>發現</th><th>耗時</th><th>備註</th></tr></thead>
      <tbody>${checkRows}</tbody>
    </table>
  </div>

  <footer>由 Aios Sentinel 產生。這份報告涵蓋自動化可判定的項目；業務邏輯授權、資料隔離等仍需人工審查。</footer>
</div>
<script>
  const filters = document.getElementById("filters");
  filters?.addEventListener("click", (event) => {
    const button = event.target.closest("button[data-filter]");
    if (!button) return;
    for (const b of filters.querySelectorAll("button")) b.setAttribute("aria-pressed", String(b === button));
    const want = button.dataset.filter;
    for (const el of document.querySelectorAll(".finding")) {
      el.hidden = want === "all" ? false : want === "new" ? el.dataset.new !== "true" : el.dataset.sev !== want;
    }
  });
</script>
</body>
</html>`;
}
