import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { applyFixes, ensureCleanGitTree } from "../src/core/fixer.js";
import type { Finding } from "../src/core/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: "test-rule",
    category: "dependency",
    severity: "high",
    title: "test finding",
    description: "test",
    fixSuggestion: "test",
    file: "package.json",
    line: 1,
    snippet: "",
    ...overrides,
  };
}

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-fixer-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("applyFixes", () => {
  it("applies a text-based fix and writes the file", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "package.json"), '{\n  "dependencies": { "yaml": "~2.5.1" }\n}\n', "utf-8");

    const finding = makeFinding({
      fix: {
        strategy: "bump-dependency-manifest",
        instructions: "bump it",
        search: '"yaml": "~2.5.1"',
        replace: '"yaml": "~2.8.3"',
      },
    });

    const outcomes = applyFixes([finding], dir, { dryRun: false });

    expect(outcomes).toHaveLength(1);
    expect(outcomes[0].fixStatus).toBe("applied");
    const written = readFileSync(join(dir, "package.json"), "utf-8");
    expect(written).toContain('"yaml": "~2.8.3"');
    expect(written).not.toContain("~2.5.1");
  });

  it("does not write anything in dry-run mode", () => {
    const dir = makeTempDir();
    const original = '{\n  "dependencies": { "yaml": "~2.5.1" }\n}\n';
    writeFileSync(join(dir, "package.json"), original, "utf-8");

    const finding = makeFinding({
      fix: {
        strategy: "bump-dependency-manifest",
        instructions: "bump it",
        search: '"yaml": "~2.5.1"',
        replace: '"yaml": "~2.8.3"',
      },
    });

    const outcomes = applyFixes([finding], dir, { dryRun: true });

    expect(outcomes[0].fixStatus).toBe("would-apply");
    expect(readFileSync(join(dir, "package.json"), "utf-8")).toBe(original);
  });

  it("marks findings without a fix as not-auto-fixable", () => {
    const outcomes = applyFixes([makeFinding()], makeTempDir(), { dryRun: false });
    expect(outcomes[0].fixStatus).toBe("not-auto-fixable");
  });

  it("marks reinstall-dependency findings as a manual step, without touching files", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "package.json"), "{}", "utf-8");

    const finding = makeFinding({
      fix: { strategy: "reinstall-dependency", instructions: "run npm install" },
    });
    const outcomes = applyFixes([finding], dir, { dryRun: false });

    expect(outcomes[0].fixStatus).toBe("manual-step");
    expect(readFileSync(join(dir, "package.json"), "utf-8")).toBe("{}");
  });

  it("marks blocked-major-bump findings as such", () => {
    const outcomes = applyFixes(
      [makeFinding({ fix: { strategy: "blocked-major-bump", instructions: "review changelog" } })],
      makeTempDir(),
      { dryRun: false },
    );
    expect(outcomes[0].fixStatus).toBe("blocked-major-bump");
  });

  it("marks as not-auto-fixable when the search text is no longer present", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "package.json"), '{ "dependencies": { "yaml": "^2.9.0" } }', "utf-8");

    const finding = makeFinding({
      fix: {
        strategy: "bump-dependency-manifest",
        instructions: "bump it",
        search: '"yaml": "~2.5.1"',
        replace: '"yaml": "~2.8.3"',
      },
    });
    const outcomes = applyFixes([finding], dir, { dryRun: false });

    expect(outcomes[0].fixStatus).toBe("not-auto-fixable");
  });

  it("applies the CORS wildcard placeholder fix", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "server.js"), "app.use(cors({ origin: '*' }));\n", "utf-8");

    const finding = makeFinding({
      file: "server.js",
      fix: {
        strategy: "replace-cors-wildcard",
        instructions: "restrict origin",
        search: "origin: '*'",
        replace: "origin: 'REPLACE_WITH_ALLOWED_ORIGIN'",
      },
    });
    const outcomes = applyFixes([finding], dir, { dryRun: false });

    expect(outcomes[0].fixStatus).toBe("applied");
    expect(readFileSync(join(dir, "server.js"), "utf-8")).toContain("origin: 'REPLACE_WITH_ALLOWED_ORIGIN'");
  });
});

function initGitRepo(dir: string): void {
  execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir, stdio: "ignore" });
}

describe("ensureCleanGitTree", () => {
  it("returns ok for a clean git repo", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    writeFileSync(join(dir, "file.txt"), "hello\n", "utf-8");
    execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: dir, stdio: "ignore" });

    expect(ensureCleanGitTree(dir).ok).toBe(true);
  });

  it("returns not-ok when there are uncommitted changes", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    writeFileSync(join(dir, "file.txt"), "hello\n", "utf-8");
    execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: dir, stdio: "ignore" });
    writeFileSync(join(dir, "file.txt"), "changed\n", "utf-8");

    const result = ensureCleanGitTree(dir);
    expect(result.ok).toBe(false);
    expect(result.reason).toContain("sin commitear");
  });

  it("returns not-ok when the directory isn't a git repo", () => {
    const dir = makeTempDir();
    writeFileSync(join(dir, "file.txt"), "hello\n", "utf-8");

    expect(ensureCleanGitTree(dir).ok).toBe(false);
  });
});
