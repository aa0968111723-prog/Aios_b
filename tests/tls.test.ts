import { describe, expect, it } from "vitest";
import { analyzeCertificate, signatureAlgorithmFromDer, type CertificateInfo } from "../src/detectors/tls.js";
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

  it("時間字串解析不出來時不崩潰、也不亂報效期問題", () => {
    const findings = analyzeCertificate(cert({ validFrom: "not a date", validTo: "still not a date" }), ctx);
    expect(ids(findings)).toEqual(["tls.protocol.version"]);
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
});
