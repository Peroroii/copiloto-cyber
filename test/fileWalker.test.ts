import { describe, expect, it, afterEach } from "vitest";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { walkFiles } from "../src/core/fileWalker.js";

let dir: string;

afterEach(() => {
  if (dir) rmSync(dir, { recursive: true, force: true });
});

describe("walkFiles", () => {
  it("finds text files and skips ignored directories", () => {
    dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-test-"));
    writeFileSync(join(dir, "app.js"), "console.log('hi');");
    mkdirSync(join(dir, "node_modules"));
    writeFileSync(join(dir, "node_modules", "lib.js"), "should be ignored");
    mkdirSync(join(dir, "src"));
    writeFileSync(join(dir, "src", "index.js"), "export default 1;");

    const files = walkFiles(dir);
    const relativePaths = files.map((f) => f.relativePath.replace(/\\/g, "/"));

    expect(relativePaths).toContain("app.js");
    expect(relativePaths).toContain("src/index.js");
    expect(relativePaths.some((p) => p.includes("node_modules"))).toBe(false);
  });

  it("scans a single file when given a file path", () => {
    dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-test-"));
    const filePath = join(dir, "app.js");
    writeFileSync(filePath, "console.log('hi');");

    const files = walkFiles(filePath);
    expect(files).toHaveLength(1);
    expect(files[0].content).toContain("console.log");
  });

  it("respects .copilotoignore patterns", () => {
    dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-test-"));
    writeFileSync(join(dir, ".copilotoignore"), "fixtures/\n*.secret.js\n");
    writeFileSync(join(dir, "app.js"), "console.log('hi');");
    writeFileSync(join(dir, "creds.secret.js"), "const x = 1;");
    mkdirSync(join(dir, "fixtures"));
    writeFileSync(join(dir, "fixtures", "vuln.js"), "eval(x)");

    const files = walkFiles(dir);
    const relativePaths = files.map((f) => f.relativePath.replace(/\\/g, "/"));

    expect(relativePaths).toContain("app.js");
    expect(relativePaths).not.toContain("creds.secret.js");
    expect(relativePaths.some((p) => p.startsWith("fixtures/"))).toBe(false);
  });
});
