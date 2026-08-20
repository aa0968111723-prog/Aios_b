/**
 * TLS 憑證檢測。
 *
 * 為什麼值得獨立成一項：憑證過期是少數會讓三端**同時**全掛的問題——網站、App 的 Capacitor
 * WebView、桌面的 Tauri WebView 全都靠同一張憑證，沒有任何一端能倖免，也沒有任何一端能先示警。
 * 而且它的失效方式極其突然：前一天全綠，隔天早上全站白畫面，中間沒有漸進的徵兆可以觀察。
 *
 * 既有檢查全部走 HTTP 層，看不到憑證本身；等到 HTTP 探針開始失敗時，使用者已經先撞上了。
 * 所以這一項刻意下沉到 TLS 交握層，直接把憑證撈出來看，把「還有幾天」變成可以排進待辦的數字，
 * 而不是某個星期六早上的意外。
 */
import { isIP } from "node:net";
import { connect } from "node:tls";
import type { DetailedPeerCertificate } from "node:tls";
import { finding, stopwatch } from "../core/findings.js";
import type { CheckResult, Finding, Surface, SurfaceId } from "../core/types.js";

const DAY_MS = 86_400_000;

/** 到期分級門檻（天）。分級的意義是「這件事該多快處理」，不是「問題有多大」。 */
const EXPIRY_CRITICAL_DAYS = 7;
const EXPIRY_HIGH_DAYS = 14;
const EXPIRY_NOTICE_DAYS = 30;

/** CA/Browser Forum 自 2020 年 9 月起對公開信任憑證的效期上限（天）。 */
const MAX_VALIDITY_DAYS = 398;

/** RSA 金鑰長度下限。低於這個長度的憑證已被主流 CA 與瀏覽器淘汰。 */
const MIN_RSA_BITS = 2048;

/**
 * 常見橢圓曲線的金鑰位元數。
 *
 * 存在的理由是避免誤報：ECDSA 的 256 bits 強度遠高於 RSA 的 2048 bits，兩者的數字不能互相比較。
 * 憑證上沒有直接寫「這把公鑰是什麼演算法」，只能從簽章演算法推測，而簽章演算法屬於**簽發者**的
 * 金鑰——RSA 的中介 CA 簽一張 ECDSA 葉憑證是完全合法的組合。所以只要位元數落在這些曲線長度上，
 * 就當作判斷不了而不報。
 */
const EC_KEY_BITS = new Set([192, 224, 233, 239, 256, 283, 320, 384, 409, 512, 521, 571]);

/**
 * 從憑證取得的原始事實。
 *
 * 全部是純資料：判定邏輯只看這個結構，不碰 socket，測試才能離線重現「憑證剩三天」這種
 * 現實中很難湊出來的情境。
 */
export interface CertificateInfo {
  /** subject DN，例如 `CN=aios.example, O=Aios`。 */
  subject: string;
  /** issuer DN。自簽時會與 subject 相同。 */
  issuer: string;
  /** SAN 名稱清單。可帶 `DNS:` / `IP Address:` 前綴，比對前會剝掉。 */
  subjectAltNames: string[];
  /** 生效時間（OpenSSL 格式字串，例如 `Sep 24 13:28:30 2027 GMT`）。 */
  validFrom: string;
  validTo: string;
  selfSigned: boolean;
  /** 簽章演算法名稱；解析不出來時為 null（不可據此判定，只能據此排除）。 */
  signatureAlgorithm: string | null;
  /** 本次交握實際協商到的協定與加密套件。 */
  protocol: string | null;
  cipher: string | null;
  /** 公鑰位元數。單位語意隨演算法而異，見 `EC_KEY_BITS`。 */
  keyBits: number | null;
}

export interface CertificateContext {
  surface: SurfaceId | "all";
  /** 實際連線的主機名，用來比對 CN／SAN。 */
  host: string;
  where: string;
  /** 判定基準時間。由呼叫端注入，測試才能把到期邊界釘死。 */
  now: Date;
}

/** OpenSSL 時間字串轉 Date；轉不出來回 null（格式怪異時寧可不判，也不要用 NaN 去比大小）。 */
function parseCertificateDate(value: string): Date | null {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** 剝掉 SAN 的型別前綴。來源不同時前綴留不留並不一致，容錯比要求格式划算。 */
function stripSanPrefix(entry: string): string {
  return entry.trim().replace(/^(?:DNS|IP Address|IP|URI|email|othername)\s*:\s*/i, "").trim();
}

/** 從 DN 字串抓 CN。DN 的分隔符在不同來源可能是逗號或斜線，兩種都吃。 */
function subjectCommonName(dn: string): string | null {
  return /(?:^|[,/;])\s*CN\s*=\s*([^,/;]+)/i.exec(dn)?.[1]?.trim() ?? null;
}

/** 憑證上所有可用於主機名比對的名稱：SAN 全部，外加 subject 的 CN。 */
function certificateNames(info: CertificateInfo): string[] {
  const names = info.subjectAltNames.map(stripSanPrefix);
  const cn = subjectCommonName(info.subject);
  if (cn) names.push(cn);
  return names.filter((n) => n.length > 0);
}

/**
 * 主機名是否符合憑證上的某個名稱（含萬用字元）。
 *
 * 萬用字元的規則寫錯會往兩邊壞：放寬了就發不出真正的不符警告（假綠燈），
 * 收緊了就對正常憑證整排噴紅（假警報）。RFC 6125 的規則是——
 * `*` 只能出現在**最左邊那一個標籤**，而且只吃**一層**：
 *   `*.example.com` 匹配 `a.example.com`，
 *   但不匹配 `example.com`（少一層），也不匹配 `a.b.example.com`（多一層）。
 */
function matchesHostPattern(host: string, pattern: string): boolean {
  const target = host.trim().toLowerCase().replace(/\.$/, "");
  const name = pattern.trim().toLowerCase().replace(/\.$/, "");
  if (!target || !name) return false;
  if (!name.startsWith("*.")) return target === name;

  const suffix = name.slice(1); // "*.example.com" → ".example.com"
  if (!target.endsWith(suffix)) return false;
  const leftmost = target.slice(0, target.length - suffix.length);
  // 剩下的部分必須恰好是一個非空標籤：空字串代表少一層，含點代表多一層。
  return leftmost.length > 0 && !leftmost.includes(".");
}

/** 簽章演算法是否用了已被證實可製造碰撞的雜湊。 */
function usesBrokenHash(signatureAlgorithm: string | null): boolean {
  if (!signatureAlgorithm) return false;
  // 結尾的否定前瞻是為了讓 `sha1` 不會誤咬 `sha1x`／數字延伸；`sha256`、`sha384` 本來就不會進來。
  return /(?:md5|sha-?1)(?!\d)/i.test(signatureAlgorithm);
}

/** 這張憑證的公鑰有沒有把握是 RSA。沒把握就回 false——不報，好過報錯。 */
function looksLikeRsaKey(info: CertificateInfo): boolean {
  if (!info.signatureAlgorithm || !/rsa/i.test(info.signatureAlgorithm)) return false;
  if (info.keyBits === null) return false;
  return !EC_KEY_BITS.has(info.keyBits);
}

/**
 * 從 DER 位元組找出簽章演算法。
 *
 * 為什麼要自己翻位元組：Node 的 `getPeerCertificate()` 給了主體、效期、金鑰長度，唯獨沒有
 * 簽章演算法，而 sha1／md5 憑證正是要靠它才看得出來。這裡不做完整的 ASN.1 解析，只在整段 DER 裡
 * 找已知的 OID TLV（`06 <長度> <OID 位元組>`）——TBSCertificate 與外層的簽章演算法規格上必須相同，
 * 所以在哪個位置命中都是同一個答案。帶上標籤與長度一起比對，是為了不讓 OID 位元組意外撞進
 * 其他欄位（例如公鑰演算法的 `rsaEncryption`）。
 */
const SIGNATURE_OIDS: ReadonlyArray<readonly [string, string]> = [
  ["06092a864886f70d010104", "md5WithRSAEncryption"],
  ["06092a864886f70d010105", "sha1WithRSAEncryption"],
  ["06092a864886f70d01010b", "sha256WithRSAEncryption"],
  ["06092a864886f70d01010c", "sha384WithRSAEncryption"],
  ["06092a864886f70d01010d", "sha512WithRSAEncryption"],
  ["06092a864886f70d01010a", "rsassaPss"],
  ["06072a8648ce3d0401", "ecdsa-with-SHA1"],
  ["06082a8648ce3d040302", "ecdsa-with-SHA256"],
  ["06082a8648ce3d040303", "ecdsa-with-SHA384"],
  ["06082a8648ce3d040304", "ecdsa-with-SHA512"],
  ["06032b6570", "Ed25519"],
  ["06032b6571", "Ed448"],
];

export function signatureAlgorithmFromDer(der: Uint8Array): string | null {
  const hex = Array.from(der, (b) => b.toString(16).padStart(2, "0")).join("");
  for (const [pattern, name] of SIGNATURE_OIDS) {
    if (hex.includes(pattern)) return name;
  }
  return null;
}

/**
 * 憑證判定。純函式：進來的是事實，出去的是發現，中間不碰任何 IO。
 *
 * 判不出來的一律不報。這一項的價值建立在「它說快到期就是真的快到期」，
 * 一次假警報就足以讓維運者把整份報告降級成雜訊。
 */
export function analyzeCertificate(info: CertificateInfo, ctx: CertificateContext): Finding[] {
  const base = { check: "tls", category: "security" as const, surface: ctx.surface, where: ctx.where };
  const out: Finding[] = [];

  const validFrom = parseCertificateDate(info.validFrom);
  const validTo = parseCertificateDate(info.validTo);
  const identity = `subject: ${info.subject || "（無）"}\nissuer: ${info.issuer || "（無）"}`;

  // ── 效期 ────────────────────────────────────────────────────────────────
  if (validTo) {
    const msLeft = validTo.getTime() - ctx.now.getTime();
    const daysLeft = msLeft / DAY_MS;

    if (msLeft <= 0) {
      out.push(
        finding({
          ...base,
          id: "tls.cert.expired",
          severity: "critical",
          title: `憑證已於 ${info.validTo} 過期`,
          detail:
            "憑證過期的當下，網站、App 的 Capacitor WebView、桌面的 Tauri WebView 會同時停在瀏覽器的錯誤攔截頁——" +
            "三端共用同一張憑證，所以不會有任何一端還能用。使用者看到的是安全警告，不是 Aios。",
          remediation:
            "立刻簽發並佈署新憑證，然後回頭查為什麼自動續期沒有生效（ACME 續期失敗、平台代管憑證未綁上網域、或憑證根本是手動上傳的）。",
          evidence: `${identity}\nvalidTo: ${info.validTo}（已過期 ${Math.abs(Math.floor(daysLeft))} 天）`,
        }),
      );
    } else if (daysLeft < EXPIRY_NOTICE_DAYS) {
      const severity = daysLeft < EXPIRY_CRITICAL_DAYS ? "critical" : daysLeft < EXPIRY_HIGH_DAYS ? "high" : "medium";
      const detail =
        daysLeft < EXPIRY_CRITICAL_DAYS
          ? "剩不到 7 天：這個週末就可能全站掛掉，而週末沒有人盯著看板。憑證不是漸進劣化，是到點瞬間全滅，三端同時。"
          : daysLeft < EXPIRY_HIGH_DAYS
            ? "剩不到 14 天：已經短到禁不起一次連假、一次續期失敗重試，或一次「等下週再處理」。這週就要確認續期機制真的會動。"
            : "剩不到 30 天：現在還不緊急，但這是能從容處理的最後時機——把換證排進待辦，並確認自動續期真的有在跑。";

      out.push(
        finding({
          ...base,
          id: "tls.cert.expiring",
          severity,
          title: `憑證將在 ${Math.floor(daysLeft)} 天後到期`,
          detail,
          remediation:
            "確認自動續期（ACME／平台代管憑證）確實執行成功，而不是只確認「有設定」；並在到期前 30 天設一個會吵人的提醒，別依賴這份報告有人讀。",
          evidence: `${identity}\nvalidTo: ${info.validTo}`,
        }),
      );
    }
  }

  if (validFrom && validFrom.getTime() > ctx.now.getTime()) {
    out.push(
      finding({
        ...base,
        id: "tls.cert.not-yet-valid",
        severity: "critical",
        title: `憑證尚未生效（${info.validFrom} 才開始）`,
        detail:
          "生效時間在未來，瀏覽器一律直接擋下，效果與過期完全相同。常見成因有兩個：換證時把還沒到啟用日的新憑證提早貼上去，" +
          "或伺服器時鐘飄掉了。後者更危險——時鐘不對會同時影響簽章驗證、權杖效期與日誌時序。",
        remediation: "比對憑證的 validFrom 與伺服器時間（`date -u`）：時鐘錯就修 NTP，貼錯憑證就先回滾到目前有效的那張。",
        evidence: `${identity}\nvalidFrom: ${info.validFrom}\n檢測時間: ${ctx.now.toISOString()}`,
      }),
    );
  }

  if (validFrom && validTo) {
    const lifetimeDays = (validTo.getTime() - validFrom.getTime()) / DAY_MS;
    if (lifetimeDays > MAX_VALIDITY_DAYS) {
      out.push(
        finding({
          ...base,
          id: "tls.cert.long-validity",
          severity: "low",
          title: `憑證效期 ${Math.round(lifetimeDays)} 天，超過 398 天上限`,
          detail:
            "CA/Browser Forum 自 2020 年 9 月起把公開信任憑證的效期壓在 398 天內，公開 CA 不會簽出更長的。" +
            "超過上限代表這張憑證來自自簽、內部 CA 或不遵守規範的簽發者，部分用戶端會直接拒絕；" +
            "附帶的問題是效期越長，私鑰一旦外洩，可被冒用的時間窗也越長。",
          remediation: "改用公開 CA 搭配自動續期（90 天以內的短效期反而更安全，因為它逼出一套會自己運作的續期流程）。",
          evidence: `${identity}\nvalidFrom: ${info.validFrom}\nvalidTo: ${info.validTo}`,
        }),
      );
    }
  }

  // ── 主機名比對 ──────────────────────────────────────────────────────────
  // 名稱完全取不到時不判定：那是解析失敗，不是憑證不符，硬報只會製造無法追查的紅燈。
  const names = certificateNames(info);
  if (names.length > 0 && !names.some((name) => matchesHostPattern(ctx.host, name))) {
    out.push(
      finding({
        ...base,
        id: "tls.cert.hostname-mismatch",
        severity: "critical",
        title: `憑證不含連線主機名 ${ctx.host}`,
        detail:
          "憑證上的名稱與實際連線的網域對不起來，瀏覽器會判定為身分不符並擋下連線，三端一起。" +
          "常見成因是網域搬家或新增子網域後忘了把它加進 SAN，於是新網域從第一天起就是連不上的狀態。",
        remediation: "重新簽發憑證並把這個主機名列入 SAN；若是多網域部署，確認反向代理有依 SNI 選到對的那一張。",
        evidence: `連線主機: ${ctx.host}\n憑證名稱: ${names.join(", ")}`,
      }),
    );
  }

  // ── 信任鏈 ──────────────────────────────────────────────────────────────
  if (info.selfSigned) {
    out.push(
      finding({
        ...base,
        id: "tls.cert.self-signed",
        severity: "high",
        title: "憑證為自簽",
        detail:
          "自簽憑證不在任何信任根裡，瀏覽器會擋下；App 與桌面的 WebView 甚至不一定提供「繼續前往」的選項，" +
          "等於這兩端直接不可用。就算這是內部測試站，長期讓人按過警告也有代價：使用者被訓練成看到憑證警告就略過，" +
          "真正的中間人攻擊來時就攔不住了。",
        remediation:
          "換成公開 CA 簽發的憑證（Let's Encrypt 或平台代管）；內部環境請把自建 CA 的根憑證佈到裝置信任庫，而不是教使用者略過警告。",
        evidence: identity,
      }),
    );
  }

  if (usesBrokenHash(info.signatureAlgorithm)) {
    out.push(
      finding({
        ...base,
        id: "tls.cert.weak-signature",
        severity: "high",
        title: `憑證簽章使用已破解的雜湊（${info.signatureAlgorithm}）`,
        detail:
          "SHA-1 與 MD5 的碰撞攻擊早已是實作等級而非理論等級，攻擊者有機會偽造一張「驗得過」的憑證來冒充本站。" +
          "現實面的影響更直接：主流瀏覽器已全面拒收這類憑證，使用者根本連不進來。",
        remediation: "重新簽發為 SHA-256 以上的簽章；若簽發者只給得出 SHA-1，代表該 CA 已經不該再用。",
        evidence: `${identity}\nsignatureAlgorithm: ${info.signatureAlgorithm}`,
      }),
    );
  }

  // ── 金鑰強度 ────────────────────────────────────────────────────────────
  if (looksLikeRsaKey(info) && (info.keyBits ?? 0) < MIN_RSA_BITS) {
    out.push(
      finding({
        ...base,
        id: "tls.key.weak",
        severity: "high",
        title: `RSA 金鑰僅 ${info.keyBits} bits`,
        detail:
          "低於 2048 bits 的 RSA 已不足以抵抗現有的分解能力，私鑰被還原後，攻擊者可以完整冒充本站並解開被側錄的流量。" +
          "公開 CA 早已停止簽發這種長度，用戶端也陸續拒絕。",
        remediation: "以 2048 bits 以上的 RSA（或 P-256 以上的 ECDSA）重新產生金鑰對並重簽憑證——換憑證不換金鑰沒有意義。",
        evidence: `${identity}\nkeyBits: ${info.keyBits}\nsignatureAlgorithm: ${info.signatureAlgorithm ?? "（未知）"}`,
      }),
    );
  }

  // ── 協定版本 ────────────────────────────────────────────────────────────
  if (info.protocol) {
    // SSLv2／SSLv3 一併算在這條裡：它們比 TLSv1 更糟，沒有理由讓它們從縫隙溜過去。
    if (/^(?:SSLv[23]|TLSv1(?:\.1)?)$/i.test(info.protocol)) {
      out.push(
        finding({
          ...base,
          id: "tls.protocol.legacy",
          severity: "high",
          title: `協商到過時的協定 ${info.protocol}`,
          detail:
            "這些版本缺少現代的加密與完整性保護（BEAST、POODLE 一脈的攻擊都打在這一層），主流瀏覽器自 2020 年起全數停用。" +
            "還能協商到它，代表反向代理的設定停留在很舊的年代；對使用者來說結果就是連線直接失敗。",
          remediation: "在反向代理／負載平衡器把最低版本設為 TLSv1.2，並開啟 TLSv1.3。",
          evidence: `protocol: ${info.protocol}\ncipher: ${info.cipher ?? "（未知）"}`,
        }),
      );
    }

    out.push(
      finding({
        ...base,
        id: "tls.protocol.version",
        severity: "info",
        title: `TLS 協定 ${info.protocol}`,
        detail:
          "記錄本次交握實際協商到的協定與加密套件。日後出現「某些舊裝置連不上」或「換了代理之後怪怪的」時，" +
          "這一行是唯一能回答「當時到底談成什麼」的證據。",
        remediation: "無須處理。若長期停在 TLSv1.2，可評估在反向代理開啟 TLSv1.3 以取得更短的交握與更好的前向保密。",
        evidence: `protocol: ${info.protocol}\ncipher: ${info.cipher ?? "（未知）"}`,
      }),
    );
  }

  return out;
}

/** 把 Node 的 DN 物件攤成 `CN=…, O=…` 字串。值可能是陣列（同一個屬性出現多次）。 */
function formatDn(dn: Record<string, string | string[]> | undefined): string {
  if (!dn) return "";
  return Object.entries(dn)
    .map(([key, value]) => `${key}=${Array.isArray(value) ? value.join("+") : value}`)
    .join(", ");
}

/**
 * 葉憑證是不是自己簽自己。
 *
 * 判準用 subject／issuer DN 相等：內部 CA 簽出來的葉憑證 issuer 會是那個 CA，DN 不會相同，
 * 所以不會被誤判成自簽。指紋比對是保險——鏈的頂端在 Node 裡會指回自己。
 */
function isSelfSigned(cert: DetailedPeerCertificate): boolean {
  const subject = formatDn(cert.subject as unknown as Record<string, string | string[]>);
  const issuer = formatDn(cert.issuer as unknown as Record<string, string | string[]>);
  if (!subject || !issuer) return false;
  if (subject !== issuer) return false;
  const issuerCert = cert.issuerCertificate;
  return !issuerCert || issuerCert === cert || issuerCert.fingerprint256 === cert.fingerprint256;
}

interface TlsHandshake {
  info: CertificateInfo;
}

/**
 * 建立一次 TLS 交握，把憑證與協商結果撈回來。
 *
 * 兩個關鍵設定：
 * - `servername`（SNI）：現代平台一個 IP 上放幾十個站，不帶 SNI 會拿到預設站的憑證，
 *   接著我們就會煞有介事地報一筆「主機名不符」——測錯對象比沒測更糟。
 *   目標是 IP 字面值時反而不能帶：RFC 6066 不允許，Node 會發棄用警告且未來版本會直接忽略，
 *   而 IP 直連本來就沒有「同一個 IP 上多個站」的歧義。
 * - `rejectUnauthorized: false`：這裡是**刻意**不驗證。憑證有問題的時候，正是最需要看清楚它的時候；
 *   若讓 Node 直接拒絕連線，我們手上只會剩一個「連不上」，過期、自簽、名稱不符全部變成同一句話。
 *   驗證由我們自己在 `analyzeCertificate` 做，而且做完會說出是哪一種問題。
 */
function readCertificate(options: { host: string; port: number; timeoutMs: number }): Promise<TlsHandshake | { error: string }> {
  return new Promise((resolve) => {
    let settled = false;
    const socket = connect({
      host: options.host,
      port: options.port,
      ...(isIP(options.host) === 0 ? { servername: options.host } : {}),
      rejectUnauthorized: false,
    });

    const finish = (result: TlsHandshake | { error: string }): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      // 一定要主動收線：逾時的 socket 若放著不管，整輪掃描會被吊在事件迴圈上不結束。
      socket.destroy();
      resolve(result);
    };

    // 逾時自己算並自己 destroy：連線層的 timeout 選項只管「連上之前」，
    // 對方接了 TCP 卻不完成 TLS 交握（企業代理最常見的樣子）時不會觸發。
    const timer = setTimeout(() => finish({ error: `TLS 交握逾時（${options.timeoutMs} ms）` }), options.timeoutMs);

    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate(true);
      if (!cert || Object.keys(cert).length === 0) {
        finish({ error: "交握完成但未取得對端憑證" });
        return;
      }
      const cipher = socket.getCipher();
      finish({
        info: {
          subject: formatDn(cert.subject as unknown as Record<string, string | string[]>),
          issuer: formatDn(cert.issuer as unknown as Record<string, string | string[]>),
          subjectAltNames: (cert.subjectaltname ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0),
          validFrom: cert.valid_from ?? "",
          validTo: cert.valid_to ?? "",
          selfSigned: isSelfSigned(cert),
          signatureAlgorithm: cert.raw ? signatureAlgorithmFromDer(cert.raw) : null,
          protocol: socket.getProtocol(),
          cipher: cipher?.name ?? null,
          keyBits: typeof cert.bits === "number" ? cert.bits : null,
        },
      });
    });

    socket.once("error", (err: Error) => finish({ error: err.message }));
    socket.once("close", () => finish({ error: "連線在 TLS 交握完成前被關閉" }));
  });
}

export async function checkTls(surface: Surface, timeoutMs: number): Promise<CheckResult> {
  const elapsed = stopwatch();
  const base = { check: "tls", category: "security" as const, surface: surface.id };

  let origin: URL;
  try {
    origin = new URL(surface.origin);
  } catch {
    return {
      ...base,
      completed: false,
      skippedReason: `無法解析目標位址：${surface.origin}`,
      durationMs: elapsed(),
      findings: [],
    };
  }

  // http 目標沒有憑證可驗。這是「不適用」，不是「通過」——回 completed: true 加空發現，
  // 會在報告上長成一個綠勾，讀者則以為憑證被檢查過了。
  if (origin.protocol !== "https:") {
    return {
      ...base,
      completed: false,
      skippedReason: `目標為 ${origin.protocol}//${origin.host}，沒有 TLS 憑證可驗（本機開發常見）。這不代表憑證沒問題，只代表這項檢查不適用。`,
      durationMs: elapsed(),
      findings: [],
    };
  }

  // URL 會把 IPv6 主機保留成 `[::1]` 的形式，但 socket 要的是不含方括號的位址。
  const host = origin.hostname.replace(/^\[|\]$/g, "");
  const port = origin.port ? Number(origin.port) : 443;
  const where = `${origin.protocol}//${origin.host}`;

  const handshake = await readCertificate({ host, port, timeoutMs });
  if ("error" in handshake) {
    // 連不上就是連不上。這個環境常有出口代理擋掉 443 直連，把代理造成的失敗說成「憑證有問題」
    // 是這類檢查最嚴重的誤判方式——它會讓人在半夜去改一張其實好好的憑證。
    return {
      ...base,
      completed: false,
      skippedReason:
        `無法與 ${host}:${port} 完成 TLS 交握（${handshake.error}）。` +
        "可能是出口代理／防火牆擋掉 443 直連、DNS 解析不到，或對端根本沒開這個埠。" +
        "連線失敗不足以推論憑證有問題，因此不轉成發現；請從能直連目標的網路環境重跑。",
      durationMs: elapsed(),
      findings: [],
      facts: { host, port },
    };
  }

  const info = handshake.info;
  const now = new Date();
  const findings = analyzeCertificate(info, { surface: surface.id, host, where, now });

  const validTo = parseCertificateDate(info.validTo);
  const facts: Record<string, unknown> = {
    host,
    port,
    subject: info.subject,
    issuer: info.issuer,
    subjectAltNames: info.subjectAltNames,
    validFrom: info.validFrom,
    validTo: info.validTo,
    // 這一個數字是整項檢查最常被回頭查的東西：報告要能回答「當時還剩幾天」。
    daysRemaining: validTo ? Math.round(((validTo.getTime() - now.getTime()) / DAY_MS) * 10) / 10 : null,
    selfSigned: info.selfSigned,
    signatureAlgorithm: info.signatureAlgorithm,
    keyBits: info.keyBits,
    protocol: info.protocol,
    cipher: info.cipher,
  };

  return { ...base, completed: true, durationMs: elapsed(), findings, facts };
}
