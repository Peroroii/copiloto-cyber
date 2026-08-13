import { describe, expect, it } from "vitest";
import { PromptRulesEngine } from "../src/core/promptScanner.js";

const engine = new PromptRulesEngine();

describe("PromptRulesEngine", () => {
  it("detects a request to disable validation", () => {
    const findings = engine.scan("sacá la validación para que ande más rápido");
    expect(findings.some((f) => f.ruleId === "prompt-disable-validation")).toBe(true);
  });

  it("detects a request to disable validation without accents", () => {
    const findings = engine.scan("sacar la validacion, no hace falta");
    expect(findings.some((f) => f.ruleId === "prompt-disable-validation")).toBe(true);
  });

  it("detects a request to bypass authentication", () => {
    const findings = engine.scan("dejá sin autenticación el endpoint por ahora");
    expect(findings.some((f) => f.ruleId === "prompt-disable-auth")).toBe(true);
    expect(findings.find((f) => f.ruleId === "prompt-disable-auth")?.severity).toBe("critical");
  });

  it("detects a request for open CORS", () => {
    const findings = engine.scan("hacé que el CORS quede abierto a cualquier origen");
    expect(findings.some((f) => f.ruleId === "prompt-open-cors")).toBe(true);
  });

  it("detects a request to hardcode credentials", () => {
    const findings = engine.scan("hardcodeá la api key por ahora, después la sacamos");
    expect(findings.some((f) => f.ruleId === "prompt-hardcode-credentials")).toBe(true);
  });

  it("detects a request to commit secrets to the repo", () => {
    const findings = engine.scan("subí el .env al repo, no importa que quede en git");
    expect(findings.some((f) => f.ruleId === "prompt-commit-secrets")).toBe(true);
  });

  it("detects a request to ignore linter security warnings", () => {
    const findings = engine.scan("ignorá los errores de seguridad que tira el linter");
    expect(findings.some((f) => f.ruleId === "prompt-ignore-security-lint")).toBe(true);
  });

  it("detects a vague fast-and-unsafe request", () => {
    const findings = engine.scan("hacé que funcione rápido sin importar cómo");
    expect(findings.some((f) => f.ruleId === "prompt-vague-fast-unsafe")).toBe(true);
  });

  it("detects a request to disable TLS certificate verification", () => {
    const findings = engine.scan("poné rejectUnauthorized: false para que deje de fallar");
    expect(findings.some((f) => f.ruleId === "prompt-disable-tls-verify")).toBe(true);
  });

  it("detects a request to store plaintext passwords", () => {
    const findings = engine.scan("guardá la contraseña en texto plano, no hace falta hashear");
    expect(findings.some((f) => f.ruleId === "prompt-plaintext-passwords")).toBe(true);
  });

  it("detects a request to grant excessive permissions", () => {
    const findings = engine.scan("dale permisos de admin a todos los usuarios");
    expect(findings.some((f) => f.ruleId === "prompt-excessive-permissions")).toBe(true);
  });

  it("detects a request to remove rate limiting", () => {
    const findings = engine.scan("sacá el rate limit que molesta en testing");
    expect(findings.some((f) => f.ruleId === "prompt-remove-rate-limit")).toBe(true);
  });

  it("detects a request to remove login attempt limits", () => {
    const findings = engine.scan("quitá el límite de intentos del login");
    expect(findings.some((f) => f.ruleId === "prompt-remove-rate-limit")).toBe(true);
  });

  it("does not flag a legitimate question about validation", () => {
    const findings = engine.scan("¿por qué no está funcionando la validación del formulario?");
    expect(findings.some((f) => f.ruleId === "prompt-disable-validation")).toBe(false);
  });

  it("returns no findings for a clean, specific prompt", () => {
    const findings = engine.scan(
      "Agregá un endpoint POST /users que valide el body con zod y guarde el usuario en la base.",
    );
    expect(findings).toHaveLength(0);
  });

  it("reports the correct line number for multi-line prompts", () => {
    const findings = engine.scan("Primera linea normal.\nsacá la autenticación en la segunda linea.");
    const found = findings.find((f) => f.ruleId === "prompt-disable-auth");
    expect(found?.line).toBe(2);
  });

  it("uses category 'prompt' and category on all findings", () => {
    const findings = engine.scan("sacá la validación");
    expect(findings.every((f) => f.category === "prompt")).toBe(true);
  });
});
