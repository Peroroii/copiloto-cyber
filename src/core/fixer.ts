import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { Finding, FixStatus } from "./types.js";

export interface FixOutcome {
  finding: Finding;
  fixStatus: FixStatus;
}

export interface GitCleanCheck {
  ok: boolean;
  reason: string;
}

/**
 * `--fix` (without --dry-run) refuses to run unless the target is a git
 * repo with a clean working tree, so a bad fix is always one
 * `git checkout -- .` / `git reset --hard` away from being undone.
 */
export function ensureCleanGitTree(rootPath: string): GitCleanCheck {
  try {
    const output = execFileSync("git", ["status", "--porcelain"], {
      cwd: rootPath,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    if (output.trim() !== "") {
      return {
        ok: false,
        reason:
          "Hay cambios sin commitear en el repo. Commiteá o hacé stash antes de correr --fix, así podés revertir facil si algo sale mal (git checkout -- . / git reset --hard).",
      };
    }
    return { ok: true, reason: "" };
  } catch {
    return {
      ok: false,
      reason:
        "No se pudo verificar el estado de git (¿no es un repo git, o git no esta instalado?). --fix necesita un repo git limpio para ser reversible; usa --dry-run para ver los cambios sin aplicarlos.",
    };
  }
}

/**
 * Applies every fixable finding's text-based fix in memory, then writes
 * each touched file once (skipped entirely in dry-run). Findings without
 * a `fix`, or whose strategy needs a manual step, are categorized but
 * never touch the filesystem.
 */
export function applyFixes(findings: Finding[], rootPath: string, options: { dryRun: boolean }): FixOutcome[] {
  const fileContents = new Map<string, string>();
  const modifiedFiles = new Set<string>();
  const outcomes: FixOutcome[] = [];

  const readContent = (relativePath: string): string => {
    if (!fileContents.has(relativePath)) {
      fileContents.set(relativePath, readFileSync(join(rootPath, relativePath), "utf-8"));
    }
    return fileContents.get(relativePath)!;
  };

  for (const finding of findings) {
    const fix = finding.fix;

    if (!fix) {
      outcomes.push({ finding, fixStatus: "not-auto-fixable" });
      continue;
    }
    if (fix.strategy === "reinstall-dependency") {
      outcomes.push({ finding, fixStatus: "manual-step" });
      continue;
    }
    if (fix.strategy === "blocked-major-bump") {
      outcomes.push({ finding, fixStatus: "blocked-major-bump" });
      continue;
    }
    if (!fix.search || fix.replace === undefined) {
      outcomes.push({ finding, fixStatus: "not-auto-fixable" });
      continue;
    }

    const current = readContent(finding.file);
    if (!current.includes(fix.search)) {
      // Already fixed, or the file changed since the scan — don't guess.
      outcomes.push({ finding, fixStatus: "not-auto-fixable" });
      continue;
    }

    fileContents.set(finding.file, current.replace(fix.search, fix.replace));
    modifiedFiles.add(finding.file);
    outcomes.push({ finding, fixStatus: options.dryRun ? "would-apply" : "applied" });
  }

  if (!options.dryRun) {
    for (const relativePath of modifiedFiles) {
      writeFileSync(join(rootPath, relativePath), fileContents.get(relativePath)!, "utf-8");
    }
  }

  return outcomes;
}
