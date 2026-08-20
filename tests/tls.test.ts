import { describe, expect, it } from "vitest";
import {
  analyzeCertificate,
  checkTls,
  expiryCheckBlocker,
  signatureAlgorithmFromDer,
  type CertificateInfo,
} from "../src/detectors/tls.js";
import { buildSurfaces } from "../src/core/surfaces.js";
import type { Finding } from "../src/core/types.js";

const DAY = 86_400_000;
/** 判定基準時間由測試注入，「剩幾天」才有辦法釘死；真實時鐘會讓邊界測試隔天就變色。 */
const NOW = new Date("2026-06-01T00:00:00.000Z");

/** 以 NOW 為基準推算憑證上的時間字串（OpenSSL 也是 GMT 格式）。 */
const at = (days: number): string => new Date(NOW.getTime() + days * DAY).toUTCString();

/** 一張健康的憑證，測試只覆寫要驗的那一項。 */
function cert(overrides: Partial<CertificateInfo> = {}): CertificateInfo {
  return {
    subject: "CN=aios.example, O=Aios",
    issuer: "CN=R3, O=Let's Encrypt",
    subjectAltNames: ["DNS:aios.example"],
    validFrom: at(-30),
    validTo: at(60),
    selfSigned: false,
    signatureAlgorithm: "sha256WithRSAEncryption",
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    keyBits: 2048,
    ...overrides,
  };
}

const ctx = { surface: "web" as const, host: "aios.example", where: "https://aios.example", now: NOW };
const ids = (findings: Finding[]): string[] => findings.map((f) => f.id);
const severityOf = (findings: Finding[], id: string): string | undefined => findings.find((f) => f.id === id)?.severity;

describe("analyzeCertificate", () => {
  it("健康的憑證只留下協定紀錄，不製造任何告警", () => {
    const findings = analyzeCertificate(cert(), ctx);
    expect(ids(findings)).toEqual(["tls.protocol.version"]);
    expect(severityOf(findings, "tls.protocol.version")).toBe("info");
  });

  it("已過期的憑證是 critical——三端會同時停在瀏覽器的錯誤頁", () => {
    const findings = analyzeCertificate(cert({ validTo: at(-1) }), ctx);
    expect(severityOf(findings, "tls.cert.expired")).toBe("critical");
  });

  it("已過期時不再重複報「即將到期」，同一件事只留一筆", () => {
    const findings = analyzeCertificate(cert({ validTo: at(-1) }), ctx);
    expect(ids(findings)).not.toContain("tls.cert.expiring");
  });

  it("剩 3 天是 critical（這個週末就會全站掛掉）", () => {
    const findings = analyzeCertificate(cert({ validTo: at(3) }), ctx);
    expect(severityOf(findings, "tls.cert.expiring")).toBe("critical");
  });

  it("剩 10 天是 high", () => {
    expect(severityOf(analyzeCertificate(cert({ validTo: at(10) }), ctx), "tls.cert.expiring")).toBe("high");
  });

  it("剩 20 天是 medium（該排進待辦，還不必半夜處理）", () => {
    expect(severityOf(analyzeCertificate(cert({ validTo: at(20) }), ctx), "tls.cert.expiring")).toBe("medium");
  });

  it("剩 45 天完全不報——正常續期節奏不該產生噪音", () => {
    expect(ids(analyzeCertificate(cert({ validTo: at(45) }), ctx))).not.toContain("tls.cert.expiring");
  });

  it("邊界：恰好 7 天算 high，不是 critical", () => {
    expect(severityOf(analyzeCertificate(cert({ validTo: at(7) }), ctx), "tls.cert.expiring")).toBe("high");
  });

  it("邊界：恰好 14 天算 medium", () => {
    expect(severityOf(analyzeCertificate(cert({ validTo: at(14) }), ctx), "tls.cert.expiring")).toBe("medium");
  });

  it("邊界：恰好 30 天不報，29 天才報", () => {
    expect(ids(analyzeCertificate(cert({ validTo: at(30) }), ctx))).not.toContain("tls.cert.expiring");
    expect(severityOf(analyzeCertificate(cert({ validTo: at(29) }), ctx), "tls.cert.expiring")).toBe("medium");
  });

  it("生效時間在未來是 critical（換錯憑證或伺服器時鐘飄掉）", () => {
    const findings = analyzeCertificate(cert({ validFrom: at(2) }), ctx);
    expect(severityOf(findings, "tls.cert.not-yet-valid")).toBe("critical");
  });

  it("萬用字元 SAN 匹配同一層的子網域", () => {
    const findings = analyzeCertificate(
      cert({ subject: "CN=*.aios.example", subjectAltNames: ["DNS:*.aios.example"] }),
      { ...ctx, host: "app.aios.example" },
    );
    expect(ids(findings)).not.toContain("tls.cert.hostname-mismatch");
  });

  it("萬用字元 SAN 不匹配根網域——*.aios.example 蓋不到 aios.example", () => {
    const findings = analyzeCertificate(
      cert({ subject: "CN=*.aios.example", subjectAltNames: ["DNS:*.aios.example"] }),
      { ...ctx, host: "aios.example" },
    );
    expect(severityOf(findings, "tls.cert.hostname-mismatch")).toBe("critical");
  });

  it("萬用字元 SAN 只吃一層，不匹配多層子網域", () => {
    const findings = analyzeCertificate(
      cert({ subject: "CN=*.aios.example", subjectAltNames: ["DNS:*.aios.example"] }),
      { ...ctx, host: "a.b.aios.example" },
    );
    expect(severityOf(findings, "tls.cert.hostname-mismatch")).toBe("critical");
  });

  it("名稱完全對不上時報 critical", () => {
    const findings = analyzeCertificate(
      cert({ subject: "CN=other.example", subjectAltNames: ["DNS:other.example", "DNS:*.other.example"] }),
      ctx,
    );
    expect(severityOf(findings, "tls.cert.hostname-mismatch")).toBe("critical");
  });

  it("CN 命中但 SAN 不含時不報不符——舊式憑證不該整排紅燈", () => {
    const findings = analyzeCertificate(
      cert({ subject: "CN=aios.example", subjectAltNames: ["DNS:www.aios.example"] }),
      ctx,
    );
    expect(ids(findings)).not.toContain("tls.cert.hostname-mismatch");
  });

  it("憑證上完全取不到名稱時不判定——那是解析失敗，不是憑證不符", () => {
    const findings = analyzeCertificate(cert({ subject: "O=Aios", subjectAltNames: [] }), ctx);
    expect(ids(findings)).not.toContain("tls.cert.hostname-mismatch");
  });

  it("SAN 的 IP Address 前綴會被正確剝除後比對", () => {
    const findings = analyzeCertificate(
      cert({ subject: "O=Aios", subjectAltNames: ["IP Address:10.0.0.5"] }),
      { ...ctx, host: "10.0.0.5" },
    );
    expect(ids(findings)).not.toContain("tls.cert.hostname-mismatch");
  });

  it("自簽憑證是 high（App 與桌面 WebView 可能連略過的選項都沒有）", () => {
    expect(severityOf(analyzeCertificate(cert({ selfSigned: true }), ctx), "tls.cert.self-signed")).toBe("high");
  });

  it("sha1 簽章是 high，sha256 不報", () => {
    const weak = analyzeCertificate(cert({ signatureAlgorithm: "sha1WithRSAEncryption" }), ctx);
    expect(severityOf(weak, "tls.cert.weak-signature")).toBe("high");
    expect(ids(analyzeCertificate(cert(), ctx))).not.toContain("tls.cert.weak-signature");
  });

  it("md5 簽章同樣是 high，ecdsa-with-SHA256 不誤報", () => {
    expect(severityOf(analyzeCertificate(cert({ signatureAlgorithm: "md5WithRSAEncryption" }), ctx), "tls.cert.weak-signature")).toBe("high");
    expect(ids(analyzeCertificate(cert({ signatureAlgorithm: "ecdsa-with-SHA256" }), ctx))).not.toContain(
      "tls.cert.weak-signature",
    );
  });

  it("效期超過 398 天報 low（公開 CA 簽不出這種憑證）", () => {
    const findings = analyzeCertificate(cert({ validFrom: at(-30), validTo: at(400) }), ctx);
    expect(severityOf(findings, "tls.cert.long-validity")).toBe("low");
  });

  it("效期 397 天在上限內，不報", () => {
    const findings = analyzeCertificate(cert({ validFrom: at(-30), validTo: at(367) }), ctx);
    expect(ids(findings)).not.toContain("tls.cert.long-validity");
  });

  it("協商到 TLSv1.1 報 high", () => {
    const findings = analyzeCertificate(cert({ protocol: "TLSv1.1" }), ctx);
    expect(severityOf(findings, "tls.protocol.legacy")).toBe("high");
  });

  it("協商到 TLSv1 一樣報 high", () => {
    expect(severityOf(analyzeCertificate(cert({ protocol: "TLSv1" }), ctx), "tls.protocol.legacy")).toBe("high");
  });

  it("TLSv1.3 只留 info 紀錄，不報過時協定", () => {
    const findings = analyzeCertificate(cert({ protocol: "TLSv1.3" }), ctx);
    expect(ids(findings)).not.toContain("tls.protocol.legacy");
    expect(severityOf(findings, "tls.protocol.version")).toBe("info");
  });

  it("RSA 1024 bits 報弱金鑰", () => {
    const findings = analyzeCertificate(cert({ keyBits: 1024, signatureAlgorithm: "sha256WithRSAEncryption" }), ctx);
    expect(severityOf(findings, "tls.key.weak")).toBe("high");
  });

  it("ECDSA 256 bits 不報弱金鑰——曲線的位元數與 RSA 不能相提並論", () => {
    const findings = analyzeCertificate(cert({ keyBits: 256, signatureAlgorithm: "ecdsa-with-SHA256" }), ctx);
    expect(ids(findings)).not.toContain("tls.key.weak");
  });

  it("RSA 中介 CA 簽的 EC 葉憑證不誤報弱金鑰——判斷不了就不報", () => {
    const findings = analyzeCertificate(cert({ keyBits: 256, signatureAlgorithm: "sha256WithRSAEncryption" }), ctx);
    expect(ids(findings)).not.toContain("tls.key.weak");
  });

  it("簽章演算法未知時不對金鑰長度下判斷", () => {
    const findings = analyzeCertificate(cert({ keyBits: 1024, signatureAlgorithm: null }), ctx);
    expect(ids(findings)).not.toContain("tls.key.weak");
  });

  // 這一條只保證「不亂報」。解析不出來**不等於憑證沒事**，那一半由 expiryCheckBlocker 負責——
  // 少了那一半，一張讀不出效期的憑證會拿到一份完全乾淨的報告。
  it("時間字串解析不出來時不崩潰、也不亂報效期問題", () => {
    const findings = analyzeCertificate(cert({ validFrom: "not a date", validTo: "still not a date" }), ctx);
    expect(ids(findings)).toEqual(["tls.protocol.version"]);
  });

  // 邊界值要釘在門檻本身。只測 -1 天與 430 天的話，把 `<=` 寫成 `<`、把 `>` 寫成 `>=`
  // 兩種寫錯都照樣全綠，而它們各自對應一次假綠燈與一次假警報。
  it("邊界：到期時間正好等於檢測當下，算已過期而不是即將到期", () => {
    const findings = analyzeCertificate(cert({ validTo: at(0) }), ctx);
    expect(severityOf(findings, "tls.cert.expired")).toBe("critical");
    expect(ids(findings)).not.toContain("tls.cert.expiring");
  });

  it("邊界：效期正好 398 天不報，399 天才報", () => {
    expect(ids(analyzeCertificate(cert({ validFrom: at(-30), validTo: at(368) }), ctx))).not.toContain(
      "tls.cert.long-validity",
    );
    expect(severityOf(analyzeCertificate(cert({ validFrom: at(-30), validTo: at(369) }), ctx), "tls.cert.long-validity")).toBe(
      "low",
    );
  });

  // 最緊急的那一格不能是最難懂的一句話：剩 12 小時被取整印成「0 天後到期」，
  // 讀者第一個反應是「這數字壞了」，而不是「今天就得換憑證」。
  it("剩不到一天時標題講「不到 1 天」，不會被取整成 0 天", () => {
    const hit = analyzeCertificate(cert({ validTo: at(0.5) }), ctx).find((f) => f.id === "tls.cert.expiring");
    expect(hit?.severity).toBe("critical");
    expect(hit?.title).toContain("不到 1 天");
    expect(hit?.title).not.toContain("0 天");
  });

  it("剛過期幾小時不會被講成「已過期 1 天」——證據欄一旦說錯數字，旁邊的判定也跟著不被信任", () => {
    const hit = analyzeCertificate(cert({ validTo: at(-0.25) }), ctx).find((f) => f.id === "tls.cert.expired");
    expect(hit?.evidence).toContain("距今不到 1 天");
  });

  // Node 的 getPeerCertificate 給的是 `Jun  1 00:00:00 2026 GMT` 這種格式（個位數日期補兩個空白）。
  // 測試若只餵 toUTCString() 的格式，一個看不懂真實輸入的解析器照樣全綠，
  // 線上跑起來卻是「效期完全沒被判定」——最該抓的那件事永遠不會被抓到。
  it("OpenSSL 原生格式的時間字串要解析得出來", () => {
    const findings = analyzeCertificate(
      cert({ validFrom: "May  2 08:30:00 2026 GMT", validTo: "Jun 21 08:30:00 2026 GMT" }),
      ctx,
    );
    expect(severityOf(findings, "tls.cert.expiring")).toBe("medium");
  });

  it("主機名比對忽略大小寫與尾端的點——在 DNS 上那是同一個名字", () => {
    expect(ids(analyzeCertificate(cert(), { ...ctx, host: "AIOS.Example." }))).not.toContain("tls.cert.hostname-mismatch");
  });

  // 512 同時是 brainpoolP512r1 的長度與 RSA 的長度。把它當成曲線而放行，等於對
  // 「幾小時就能分解的私鑰」發綠燈；而 brainpool 不在任何公開 CA 的簽發清單上，
  // 主流瀏覽器交握時也不接受。兩種誤判都罕見，代價卻差了好幾個數量級。
  it("RSA 512 bits 要報弱金鑰，不能因為和 P-512 撞號就放過", () => {
    const findings = analyzeCertificate(cert({ keyBits: 512, signatureAlgorithm: "sha256WithRSAEncryption" }), ctx);
    expect(severityOf(findings, "tls.key.weak")).toBe("high");
  });

  it("RSA CA 簽的 P-256／P-384／P-521 葉憑證一律不報弱金鑰", () => {
    for (const bits of [256, 384, 521]) {
      const findings = analyzeCertificate(cert({ keyBits: bits, signatureAlgorithm: "sha256WithRSAEncryption" }), ctx);
      expect(ids(findings), `${bits} bits`).not.toContain("tls.key.weak");
    }
  });

  // 這條誤報的殺傷力特別大：TLSv1.2 是目前最普遍的協定，判錯會讓幾乎每個正常站台變紅。
  it("TLSv1.2 不是過時協定", () => {
    const findings = analyzeCertificate(cert({ protocol: "TLSv1.2" }), ctx);
    expect(ids(findings)).not.toContain("tls.protocol.legacy");
    expect(severityOf(findings, "tls.protocol.version")).toBe("info");
  });

  it("SSLv3 比 TLSv1 更糟，一樣要報過時協定", () => {
    expect(severityOf(analyzeCertificate(cert({ protocol: "SSLv3" }), ctx), "tls.protocol.legacy")).toBe("high");
  });

  it("協定取不到時不硬生出協定紀錄，也不誤判成過時", () => {
    expect(ids(analyzeCertificate(cert({ protocol: null, cipher: null }), ctx))).toEqual([]);
  });

  it("每一筆發現都有 remediation，id 也都掛在 tls. 命名空間下", () => {
    const findings = analyzeCertificate(
      cert({ validTo: at(3), selfSigned: true, signatureAlgorithm: "sha1WithRSAEncryption", keyBits: 1024, protocol: "TLSv1.1" }),
      { ...ctx, host: "nope.example" },
    );
    expect(findings.length).toBeGreaterThan(5);
    for (const f of findings) {
      expect(f.remediation, f.id).toBeTruthy();
      expect(f.id.startsWith("tls.")).toBe(true);
      expect(f.check).toBe("tls");
      expect(f.where).toBe(ctx.where);
    }
  });
});

describe("expiryCheckBlocker", () => {
  it("正常憑證沒有阻礙，回 null", () => {
    expect(expiryCheckBlocker(cert())).toBeNull();
  });

  it("憑證沒帶到期時間時要說得出原因——這一輪就不能算檢查過", () => {
    expect(expiryCheckBlocker(cert({ validTo: "" }))).toContain("空");
  });

  it("原因裡要帶上實際觀測到的值，人才有辦法接手追下去", () => {
    expect(expiryCheckBlocker(cert({ validTo: "20260601000000Z" }))).toContain("20260601000000Z");
  });
});

describe("signatureAlgorithmFromDer", () => {
  it("認得 DER 裡的 sha1WithRSAEncryption OID", () => {
    const der = new Uint8Array([0x30, 0x82, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00]);
    expect(signatureAlgorithmFromDer(der)).toBe("sha1WithRSAEncryption");
  });

  it("認得 ecdsa-with-SHA256", () => {
    const der = new Uint8Array([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    expect(signatureAlgorithmFromDer(der)).toBe("ecdsa-with-SHA256");
  });

  it("公鑰的 rsaEncryption OID 不會被誤認成簽章演算法", () => {
    const der = new Uint8Array([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
    expect(signatureAlgorithmFromDer(der)).toBeNull();
  });

  // 這串位元組的十六進位表示裡確實「含有」sha1 的 OID 樣板，但它從半個位元組的位置開始，
  // 根本不是一個 OID TLV。憑證裡有幾百個亂數位元組（公鑰模數、簽章值），
  // 只要比對不看位元組邊界，這種巧合就會變成一筆 high 等級的「憑證簽章已破解」——對一張好憑證。
  it("錯開半個位元組的巧合不算命中", () => {
    const der = new Uint8Array([0xf0, 0x60, 0x92, 0xa8, 0x64, 0x88, 0x6f, 0x70, 0xd0, 0x10, 0x10, 0x5f]);
    expect(signatureAlgorithmFromDer(der)).toBeNull();
  });
});

// checkTls 是唯一碰 IO 的進入點，但這兩條路徑在送出任何連線之前就返回了，
// 所以測得起來也不會發出真實請求。它們驗的是本專案最硬的一條規則：
// 檢查不適用時要說「跳過」，絕不可以回一個完成的空結果——那在報告上長成綠勾。
describe("checkTls：不適用的目標一律標記為未完成", () => {
  it("http 目標沒有憑證可驗，回 completed: false 並說明為什麼", async () => {
    const result = await checkTls(buildSurfaces("http://localhost:3000")[0]!, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("TLS 憑證");
    expect(result.findings).toEqual([]);
  });

  it("origin 解析不出來時同樣是跳過，不是通過", async () => {
    const surface = { ...buildSurfaces("https://aios.example")[0]!, origin: "這不是網址" };
    const result = await checkTls(surface, 1000);
    expect(result.completed).toBe(false);
    expect(result.skippedReason).toContain("這不是網址");
  });
});
