import { describe, expect, it } from "vitest";
import { scanFileForSecrets } from "../src/core/secretsScanner.js";
import type { WalkedFile } from "../src/core/fileWalker.js";

function makeFile(content: string, relativePath = "app.js"): WalkedFile {
  return { absolutePath: relativePath, relativePath, content };
}

describe("scanFileForSecrets", () => {
  it("detects an AWS access key", () => {
    const findings = scanFileForSecrets(makeFile('const key = "AKIAABCDEFGHIJKLMNOP";'));
    expect(findings.some((f) => f.ruleId === "secret-aws-access-key")).toBe(true);
    expect(findings[0].severity).toBe("critical");
  });

  it("redacts the secret value in the snippet", () => {
    const findings = scanFileForSecrets(makeFile('const key = "AKIAABCDEFGHIJKLMNOP";'));
    expect(findings[0].snippet).not.toContain("AKIAABCDEFGHIJKLMNOP");
    expect(findings[0].snippet).toContain("*");
  });

  it("detects a live Stripe key", () => {
    // Built via concatenation so this fixture doesn't read as a literal
    // live credential to secret-scanning tools (it's fake either way).
    const fakeStripeKey = "sk_live_" + "abcdefghijklmnopqrstuvwx";
    const findings = scanFileForSecrets(makeFile(`const sk = "${fakeStripeKey}";`));
    expect(findings.some((f) => f.ruleId === "secret-stripe-key")).toBe(true);
  });

  it("detects a database connection string with embedded credentials", () => {
    const findings = scanFileForSecrets(
      makeFile('const url = "postgres://admin:hunter2@db.example.com:5432/prod";'),
    );
    expect(findings.some((f) => f.ruleId === "secret-connection-string-creds")).toBe(true);
  });

  it("detects a private key block", () => {
    const findings = scanFileForSecrets(makeFile("-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"));
    expect(findings.some((f) => f.ruleId === "secret-private-key-block")).toBe(true);
  });

  it("flags a high-entropy generic assignment as a possible secret", () => {
    const findings = scanFileForSecrets(makeFile('const token = "aZ9!kQ2#mP7xR4vL8wB1nC6";'));
    expect(findings.some((f) => f.ruleId === "secret-generic-high-entropy")).toBe(true);
  });

  it("does not flag an obvious placeholder value", () => {
    const findings = scanFileForSecrets(makeFile('const apiKey = "YOUR_API_KEY_HERE";'));
    expect(findings.some((f) => f.ruleId === "secret-generic-high-entropy")).toBe(false);
  });

  it("does not flag a reference to an environment variable", () => {
    const findings = scanFileForSecrets(makeFile('const password = "process.env.DB_PASSWORD";'));
    expect(findings.some((f) => f.ruleId === "secret-generic-high-entropy")).toBe(false);
  });

  it("returns no findings for clean code", () => {
    const findings = scanFileForSecrets(makeFile('function add(a, b) { return a + b; }'));
    expect(findings).toHaveLength(0);
  });
});
