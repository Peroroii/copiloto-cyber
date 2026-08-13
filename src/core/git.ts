import { execFileSync } from "node:child_process";

/** Absolute repo root for the git worktree containing `cwd`, or null if not a git repo. */
export function getRepoRoot(cwd: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Paths (repo-root-relative, POSIX separators) staged in the git index,
 * limited to added/copied/modified/renamed entries — deleted files have no
 * content to scan.
 */
export function getStagedFiles(repoRoot: string): string[] {
  try {
    const output = execFileSync(
      "git",
      ["diff", "--cached", "--name-only", "--diff-filter=ACMR"],
      { cwd: repoRoot, encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] },
    );
    return output.split(/\r?\n/).filter((line) => line.trim() !== "");
  } catch {
    return [];
  }
}

/**
 * Content of `relativePath` as staged in the index (not the working-tree
 * copy), so scanning reflects exactly what a commit would capture.
 */
export function readStagedBlob(repoRoot: string, relativePath: string): string | null {
  try {
    return execFileSync("git", ["show", `:${relativePath}`], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 10 * 1024 * 1024,
    });
  } catch {
    return null;
  }
}
