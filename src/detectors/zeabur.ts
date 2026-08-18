/**
 * 平台層錯誤監測（Zeabur）。
 *
 * ai_os 部署在 Zeabur：App 服務 + PostgreSQL + 掛在 /data 的 Volume，前面有反向代理終止 TLS。
 * 這組檢查專門抓「不是應用寫壞、而是平台層出事」的錯誤——那些錯誤在應用日誌裡看不到，
 * 但使用者照樣連不上：
 *
 * - 邊緣 5xx（502/504）＝反向代理連不到後端／後端還在冷啟動；
 * - 503＝服務被平台停用或健康檢查未過；
 * - 素材存在容器本地磁碟而非 Zeabur Volume＝重新部署即遺失（ai_os 啟動時會擲此錯）。
 *
 * 深度（需 Zeabur API token）：拉近期部署與執行狀態。沒 token 時誠實標記跳過。
 */
import { finding, stopwatch } from "../core/findings.js";
import { isProbeFailure, join, looksLikeGatewayInterception, parseJson, tryProbe } from "../core/http.js";
import type { CheckResult, Finding, Surface } from "../core/types.js";

const base = { check: "zeabur", category: "monitoring" as const };

export type PlatformErrorKind = "ok" | "app-error" | "edge-5xx" | "gateway";

export interface ResponseSignal {
  status: number;
  body: string;
  contentType: string;
  server: string | null;
}

/**
 * 判定一個回應是「應用自己回的」還是「平台／邊緣層回的」。
 *
 * 關鍵區別：應用的 5xx 帶得出 SPA 外殼或應用 JSON（值得查應用碼）；
 * 邊緣層的 5xx 是代理的裸錯誤頁（要查平台，不是查應用）。把兩者混為一談，
 * 會讓人拿著「應用壞了」的假設去查一個其實是平台冷啟動的問題。
 */
export function classifyPlatformError(signal: ResponseSignal): PlatformErrorKind {
  if (signal.status < 400) return "ok";
  const appShaped =
    /<div\s+id=["']root["']|<script[^>]+type=["']module["']/i.test(signal.body) ||
    (/application\/json/i.test(signal.contentType) && /"(error|ok|code|message)"\s*:/.test(signal.body));
  if (appShaped) return "app-error";
  if (signal.status === 502 || signal.status === 503 || signal.status === 504) return "edge-5xx";
  if (looksLikeGatewayInterception({ status: signal.status, body: signal.body, contentType: signal.contentType })) {
    return "gateway";
  }
  return "app-error";
}

export interface ZeaburAssessment {
  /** 根路徑的回應訊號。 */
  root: ResponseSignal;
  /** /api/ready 的 storage 分項說明（若取得）。 */
  storageNote?: string | null;
}

export function analyzeZeabur(input: ZeaburAssessment, surface: Surface): Finding[] {
  const out: Finding[] = [];
  const kind = classifyPlatformError(input.root);

  if (kind === "edge-5xx") {
    out.push(
      finding({
        ...base,
        surface: surface.id,
        id: "zeabur.edge-5xx",
        severity: "high",
        title: `${surface.label}：平台邊緣回應 ${input.root.status}（非應用錯誤）`,
        detail:
          "反向代理回了 5xx 且內容不是應用頁面——代表代理連不到後端，通常是實例當掉、還在冷啟動、或被平台重啟。使用者此刻整站打不開。",
        remediation: "查 Zeabur 該服務的執行狀態與資源用量；若剛部署，確認新實例是否通過健康檢查後才切流量。",
        evidence: `HTTP ${input.root.status}　server=${input.root.server ?? "?"}`,
        where: surface.origin,
      }),
    );
  } else if (kind === "gateway") {
    out.push(
      finding({
        ...base,
        surface: surface.id,
        id: "zeabur.gateway-intercept",
        severity: "medium",
        title: `${surface.label}：請求被中介層攔截（HTTP ${input.root.status}）`,
        detail:
          "回應不像應用送出的（可能是出口代理、WAF 或平台閘道）。本輪對這一端的監測其實沒有真正觸及站台。",
        remediation: "從能直連 Zeabur 的網路環境重跑；若是刻意的存取控制，將該來源加入允許清單。",
        evidence: `HTTP ${input.root.status}　server=${input.root.server ?? "?"}`,
        where: surface.origin,
      }),
    );
  }

  // 素材儲存在非持久磁碟：ai_os 啟動時會擲錯，就緒分項的 note 也會帶線索。
  const note = input.storageNote ?? "";
  if (/非持久|本地磁碟|重新部署會遺失|Volume|ASSET_DIR/.test(note) && /(非持久|本地|遺失)/.test(note)) {
    out.push(
      finding({
        ...base,
        surface: surface.id,
        id: "zeabur.ephemeral-storage",
        severity: "high",
        title: `${surface.label}：素材疑似存在非持久磁碟`,
        detail:
          "就緒檢查回報素材存於容器本地磁碟而非持久 Volume。Zeabur 每次重新部署都會換掉容器檔案系統，屆時所有既有素材（圖／旁白／成片）全數遺失。",
        remediation: "在 Zeabur 掛載 Volume 到 /data（或設 ASSET_DIR 指向持久磁碟，或設 S3_ENDPOINT 改用物件儲存）。",
        evidence: note.slice(0, 300),
        where: join(surface.origin, "/api/ready"),
      }),
    );
  }

  return out;
}

// ── 深度：Zeabur API（需 token）───────────────────────────────────────────────

export interface ZeaburDeployment {
  status: string;
  createdAt?: string;
}

export function analyzeZeaburDeployments(deployments: ZeaburDeployment[]): Finding[] {
  const out: Finding[] = [];
  const latest = deployments[0];
  if (latest && /FAILED|ERROR|CRASH/i.test(latest.status)) {
    out.push(
      finding({
        ...base,
        surface: "all",
        id: "zeabur.deploy-failed",
        severity: "high",
        title: `Zeabur 最近一次部署狀態為 ${latest.status}`,
        detail: "最新部署未成功，線上跑的可能仍是舊版，或服務處於降級狀態。",
        remediation: "到 Zeabur 後台看該部署的建置與執行日誌，修正後重新部署。",
        evidence: JSON.stringify(latest),
      }),
    );
  }
  return out;
}

// ── 執行 ──────────────────────────────────────────────────────────────────────

export async function checkZeabur(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const findings: Finding[] = [];
  const facts: Record<string, unknown> = {};
  const meta = { ...base, surface: surface.id };

  const root = await tryProbe(surface.origin, { surface, timeoutMs, followRedirects: 2 });
  if (isProbeFailure(root)) {
    return {
      ...meta,
      completed: false,
      skippedReason: `${surface.label}：無法連線（${root.error}），平台層錯誤無從判定。`,
      durationMs: elapsed(),
      findings,
      facts,
    };
  }

  const signal: ResponseSignal = {
    status: root.status,
    body: root.body,
    contentType: root.headers.get("content-type") ?? "",
    server: root.headers.get("server"),
  };
  facts.rootStatus = root.status;
  facts.server = signal.server;
  facts.classification = classifyPlatformError(signal);

  // 取就緒的 storage 分項說明（供非持久磁碟判定）。
  let storageNote: string | null = null;
  const ready = await tryProbe(join(surface.origin, "/api/ready"), { surface, timeoutMs, followRedirects: 2 });
  if (!isProbeFailure(ready)) {
    const body = parseJson<{ components?: Record<string, { note?: string }> }>(ready.body);
    storageNote = body?.components?.storage?.note ?? null;
    facts.storageNote = storageNote;
  }

  findings.push(...analyzeZeabur({ root: signal, storageNote }, surface));

  // 深度：Zeabur API（需 token + service id）。
  const token = process.env.ZEABUR_API_TOKEN;
  const serviceId = process.env.ZEABUR_SERVICE_ID;
  if (token && serviceId) {
    const res = await tryProbe("https://api.zeabur.com/graphql", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        query: `query($id:ObjectID!){ deployments(serviceID:$id, first:5){ edges{ node{ status createdAt } } } }`,
        variables: { id: serviceId },
      }),
      timeoutMs,
    });
    if (!isProbeFailure(res) && res.status === 200) {
      const parsed = parseJson<{ data?: { deployments?: { edges?: Array<{ node: ZeaburDeployment }> } } }>(res.body);
      const deployments = (parsed?.data?.deployments?.edges ?? []).map((e) => e.node);
      if (deployments.length > 0) {
        facts.deployments = deployments;
        findings.push(...analyzeZeaburDeployments(deployments));
      }
    }
  } else {
    facts.deploymentsSkipped = "未設定 ZEABUR_API_TOKEN／ZEABUR_SERVICE_ID，略過部署狀態深度拉取。";
  }

  return { ...meta, completed: true, durationMs: elapsed(), findings, facts };
}
