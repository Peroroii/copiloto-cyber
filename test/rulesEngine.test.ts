import { describe, expect, it } from "vitest";
import { RulesEngine } from "../src/core/rulesEngine.js";
import type { WalkedFile } from "../src/core/fileWalker.js";

function makeFile(content: string, relativePath: string): WalkedFile {
  return { absolutePath: relativePath, relativePath, content };
}

const engine = new RulesEngine();

describe("RulesEngine", () => {
  it("detects SQL injection via template literal", () => {
    const findings = engine.scanFile(
      makeFile("db.query(`SELECT * FROM users WHERE id = ${id}`);", "app.js"),
    );
    expect(findings.some((f) => f.ruleId === "injection-sql-template-literal")).toBe(true);
  });

  it("detects SQL injection via python f-string", () => {
    const findings = engine.scanFile(
      makeFile('cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")', "app.py"),
    );
    expect(findings.some((f) => f.ruleId === "injection-sql-fstring-python")).toBe(true);
  });

  it("detects eval usage", () => {
    const findings = engine.scanFile(makeFile("eval(userInput);", "app.js"));
    expect(findings.some((f) => f.ruleId === "injection-eval-usage")).toBe(true);
  });

  it("detects command injection via child_process.exec", () => {
    const findings = engine.scanFile(makeFile("exec(`ls ${dir}`);", "app.js"));
    expect(findings.some((f) => f.ruleId === "injection-child-process-exec")).toBe(true);
  });

  it("detects command injection via python subprocess shell=True", () => {
    const findings = engine.scanFile(
      makeFile("subprocess.run(cmd, shell=True)", "app.py"),
    );
    expect(findings.some((f) => f.ruleId === "injection-os-system-python")).toBe(true);
  });

  it("detects dangerouslySetInnerHTML with dynamic data", () => {
    const findings = engine.scanFile(
      makeFile("<div dangerouslySetInnerHTML={{ __html: `<p>${bio}</p>` }} />", "Profile.jsx"),
    );
    expect(findings.some((f) => f.ruleId === "injection-dangerous-html")).toBe(true);
  });

  it("detects wildcard CORS", () => {
    const findings = engine.scanFile(makeFile("app.use(cors({ origin: '*' }));", "server.js"));
    expect(findings.some((f) => f.ruleId === "auth-cors-wildcard-credentials")).toBe(true);
  });

  it("detects JWT verification disabled", () => {
    const findings = engine.scanFile(
      makeFile("jwt.decode(token, verify=False)", "auth.py"),
    );
    expect(findings.some((f) => f.ruleId === "auth-jwt-verify-disabled")).toBe(true);
  });

  it("detects plaintext password comparison", () => {
    const findings = engine.scanFile(
      makeFile("if (user.password === input.password) { login(user); }", "auth.js"),
    );
    expect(findings.some((f) => f.ruleId === "auth-plaintext-password-compare")).toBe(true);
  });

  it("does not run JS rules against unrelated extensions", () => {
    const findings = engine.scanFile(makeFile("eval(x)", "notes.md"));
    expect(findings).toHaveLength(0);
  });

  it("returns no findings for clean code", () => {
    const findings = engine.scanFile(
      makeFile("db.query('SELECT * FROM users WHERE id = ?', [id]);", "app.js"),
    );
    expect(findings).toHaveLength(0);
  });
});
