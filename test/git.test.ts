import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { getRepoRoot, getStagedFiles, readStagedBlob } from "../src/core/git.js";

let tempDirs: string[] = [];

function makeTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "copiloto-cyber-git-test-"));
  tempDirs.push(dir);
  return dir;
}

function initGitRepo(dir: string): void {
  execFileSync("git", ["init"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: dir, stdio: "ignore" });
  execFileSync("git", ["config", "user.name", "Test"], { cwd: dir, stdio: "ignore" });
}

afterEach(() => {
  for (const dir of tempDirs) {
    rmSync(dir, { recursive: true, force: true });
  }
  tempDirs = [];
});

describe("getRepoRoot", () => {
  it("returns the repo root for a git repo", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    expect(getRepoRoot(dir)).not.toBeNull();
  });

  it("returns null for a non-git directory", () => {
    const dir = makeTempDir();
    expect(getRepoRoot(dir)).toBeNull();
  });
});

describe("getStagedFiles / readStagedBlob", () => {
  it("lists only staged files and reads their staged content, not the working tree", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    writeFileSync(join(dir, "committed.js"), "console.log('v1');", "utf-8");
    execFileSync("git", ["add", "."], { cwd: dir, stdio: "ignore" });
    execFileSync("git", ["commit", "-m", "init"], { cwd: dir, stdio: "ignore" });

    writeFileSync(join(dir, "staged.js"), "console.log('staged');", "utf-8");
    execFileSync("git", ["add", "staged.js"], { cwd: dir, stdio: "ignore" });

    writeFileSync(join(dir, "unstaged.js"), "console.log('unstaged');", "utf-8");

    const staged = getStagedFiles(dir);
    expect(staged).toEqual(["staged.js"]);
    expect(staged).not.toContain("unstaged.js");
    expect(staged).not.toContain("committed.js");
  });

  it("reads the staged blob, ignoring later unstaged edits to the same file", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    writeFileSync(join(dir, "app.js"), "const secret = 'old';", "utf-8");
    execFileSync("git", ["add", "app.js"], { cwd: dir, stdio: "ignore" });

    writeFileSync(join(dir, "app.js"), "const secret = 'new-but-unstaged';", "utf-8");

    const blob = readStagedBlob(dir, "app.js");
    expect(blob).toContain("old");
    expect(blob).not.toContain("new-but-unstaged");
  });

  it("returns null for a path that isn't staged", () => {
    const dir = makeTempDir();
    initGitRepo(dir);
    expect(readStagedBlob(dir, "nope.js")).toBeNull();
  });
});
