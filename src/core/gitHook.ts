import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

const MARKER_START = "# >>> copiloto-cyber >>>";
const MARKER_END = "# <<< copiloto-cyber <<<";

const HOOK_BODY = `if [ "$COPILOTO_CYBER_SKIP" = "1" ]; then
  echo "copiloto-cyber: chequeo omitido para este commit (COPILOTO_CYBER_SKIP=1)"
else
  npx --no-install copiloto-cyber scan --staged --fail-on high
  status=$?
  if [ $status -ne 0 ]; then
    echo "copiloto-cyber encontro hallazgos bloqueantes. Corregilos, o usa 'git commit --no-verify' / COPILOTO_CYBER_SKIP=1 para saltear este chequeo puntualmente."
    exit $status
  fi
fi`;

const HOOK_BLOCK = `${MARKER_START}\n${HOOK_BODY}\n${MARKER_END}`;

const BLOCK_PATTERN = new RegExp(`\\n?${escapeRegExp(MARKER_START)}[\\s\\S]*?${escapeRegExp(MARKER_END)}\\n?`);

export interface HookResult {
  ok: boolean;
  message: string;
  hookPath?: string;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function resolveHooksDir(repoRoot: string): string {
  let hooksPath: string | null = null;
  try {
    const output = execFileSync("git", ["config", "core.hooksPath"], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
    hooksPath = output || null;
  } catch {
    hooksPath = null;
  }

  if (hooksPath) return resolve(repoRoot, hooksPath);

  const gitDir = execFileSync("git", ["rev-parse", "--git-dir"], {
    cwd: repoRoot,
    encoding: "utf-8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  return resolve(repoRoot, gitDir, "hooks");
}

export function installHook(repoRoot: string): HookResult {
  let hooksDir: string;
  try {
    hooksDir = resolveHooksDir(repoRoot);
  } catch {
    return { ok: false, message: "No se pudo resolver el repo git (¿estas dentro de un repo?)." };
  }

  mkdirSync(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, "pre-commit");

  if (!existsSync(hookPath)) {
    writeFileSync(hookPath, `#!/bin/sh\n${HOOK_BLOCK}\n`, "utf-8");
    chmodSync(hookPath, 0o755);
    return { ok: true, message: `Hook instalado en ${hookPath}`, hookPath };
  }

  const existing = readFileSync(hookPath, "utf-8");

  if (BLOCK_PATTERN.test(existing)) {
    const updated = existing.replace(BLOCK_PATTERN, `\n${HOOK_BLOCK}\n`);
    writeFileSync(hookPath, updated, "utf-8");
    chmodSync(hookPath, 0o755);
    return { ok: true, message: `Hook actualizado en ${hookPath}`, hookPath };
  }

  const appended = `${existing.replace(/\s*$/, "")}\n\n${HOOK_BLOCK}\n`;
  writeFileSync(hookPath, appended, "utf-8");
  chmodSync(hookPath, 0o755);
  return {
    ok: true,
    message: `Se encontro un hook pre-commit existente en ${hookPath}; se agrego copiloto-cyber al final sin tocar lo que ya tenias.`,
    hookPath,
  };
}

export function uninstallHook(repoRoot: string): HookResult {
  let hooksDir: string;
  try {
    hooksDir = resolveHooksDir(repoRoot);
  } catch {
    return { ok: false, message: "No se pudo resolver el repo git (¿estas dentro de un repo?)." };
  }

  const hookPath = join(hooksDir, "pre-commit");
  if (!existsSync(hookPath)) {
    return { ok: true, message: "No habia ningun hook instalado." };
  }

  const existing = readFileSync(hookPath, "utf-8");
  if (!BLOCK_PATTERN.test(existing)) {
    return { ok: true, message: `No se encontro un bloque de copiloto-cyber en ${hookPath}.`, hookPath };
  }

  const withoutBlock = existing.replace(BLOCK_PATTERN, "\n");
  const remainderIsEmpty = withoutBlock.replace(/^#!.*(\r?\n)?/, "").trim() === "";

  if (remainderIsEmpty) {
    rmSync(hookPath);
    return { ok: true, message: `Hook eliminado (${hookPath}), no quedaba nada mas en el archivo.`, hookPath };
  }

  writeFileSync(hookPath, withoutBlock, "utf-8");
  return { ok: true, message: `Bloque de copiloto-cyber removido de ${hookPath}.`, hookPath };
}
