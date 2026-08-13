import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { installHook, uninstallHook } from "../src/core/gitHook.js";

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-hook-test-"));
  tempDirs.push(dir);
  return dir;
}

function initGitRepo(dir: string): void {
  execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir, stdio: "ignore" });
}

function hooksDirOf(dir: string): string {
  return join(dir, ".git", "hooks");
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("installHook", () => {
  it("creates a fresh pre-commit hook when none exists", () => {
    const dir = makeTempDir();
    initGitRepo(dir);

    const result = installHook(dir);

    expect(result.ok).toBe(true);
    const hookPath = join(hooksDirOf(dir), "pre-commit");
    expect(existsSync(hookPath)).toBe(true);
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("copiloto-cyber");
    expect(content).toContain("scan --staged");
    expect(content).toContain("COPILOTO_CYBER_SKIP");
    expect(content.startsWith("#!/bin/sh")).toBe(true);
  });

  it("is idempotent: reinstalling doesn't duplicate the block", () => {
    const dir = makeTempDir();
    initGitRepo(dir);

    installHook(dir);
    const result = installHook(dir);

    expect(result.ok).toBe(true);
    const content = readFileSync(join(hooksDirOf(dir), "pre-commit"), "utf-8");
    expect(content.match(/copiloto-cyber >>>/g)).toHaveLength(1);
  });

  it("appends to an existing hook without touching its content", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    const hookPath = join(hooksDirOf(dir), "pre-commit");
    writeFileSync(hookPath, "#!/bin/sh\necho 'running husky'\nnpx lint-staged\n", "utf-8");

    const result = installHook(dir);

    expect(result.ok).toBe(true);
    expect(result.message).toContain("hook pre-commit existente");
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("echo 'running husky'");
    expect(content).toContain("npx lint-staged");
    expect(content).toContain("copiloto-cyber");
  });

  it("respects core.hooksPath when set (e.g. Husky-style setups)", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    execFileSync("git", ["config", "core.hooksPath", ".husky"], { cwd: dir, stdio: "ignore" });

    const result = installHook(dir);

    expect(result.ok).toBe(true);
    const hookPath = join(dir, ".husky", "pre-commit");
    expect(existsSync(hookPath)).toBe(true);
    expect(existsSync(join(hooksDirOf(dir), "pre-commit"))).toBe(false);
  });
});

describe("uninstallHook", () => {
  it("removes the whole file if nothing else was in it", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    installHook(dir);

    const result = uninstallHook(dir);

    expect(result.ok).toBe(true);
    expect(existsSync(join(hooksDirOf(dir), "pre-commit"))).toBe(false);
  });

  it("removes only our block, preserving pre-existing hook content", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    const hookPath = join(hooksDirOf(dir), "pre-commit");
    writeFileSync(hookPath, "#!/bin/sh\necho 'running husky'\nnpx lint-staged\n", "utf-8");
    installHook(dir);

    const result = uninstallHook(dir);

    expect(result.ok).toBe(true);
    const content = readFileSync(hookPath, "utf-8");
    expect(content).toContain("echo 'running husky'");
    expect(content).toContain("npx lint-staged");
    expect(content).not.toContain("copiloto-cyber");
  });

  it("is a no-op when there is no hook installed", () => {
    const dir = makeTempDir();
    initGitRepo(dir);

    const result = uninstallHook(dir);

    expect(result.ok).toBe(true);
  });
});
