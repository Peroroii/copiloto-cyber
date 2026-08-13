#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { runScan } from "../core/scanner.js";
import { PromptRulesEngine } from "../core/promptScanner.js";
import { applyFixes, ensureCleanGitTree } from "../core/fixer.js";
import { getRepoRoot, getStagedFiles, readStagedBlob } from "../core/git.js";
import { installHook, uninstallHook } from "../core/gitHook.js";
import {
  hasIgnoredExtension,
  isIgnored,
  loadIgnorePatterns,
  prepareContent,
} from "../core/fileWalker.js";
import type { WalkedFile } from "../core/fileWalker.js";
import {
  printFixSummary,
  printJsonReport,
  printPromptJsonReport,
  printPromptReport,
  printTextReport,
} from "./reporter.js";
import type { Severity } from "../core/types.js";

function collectStagedFiles(repoRoot: string): WalkedFile[] {
  const ignorePatterns = loadIgnorePatterns(repoRoot);
  const files: WalkedFile[] = [];

  for (const relativePath of getStagedFiles(repoRoot)) {
    if (hasIgnoredExtension(relativePath)) continue;
    if (isIgnored(relativePath, ignorePatterns)) continue;

    const blob = readStagedBlob(repoRoot, relativePath);
    if (blob === null) continue;
    const content = prepareContent(blob);
    if (content === null) continue;

    files.push({ absolutePath: join(repoRoot, relativePath), relativePath, content });
  }

  return files;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_VALUES = Object.keys(SEVERITY_RANK) as Severity[];

const program = new Command();

program
  .name("copiloto-cyber")
  .description("Copiloto de ciberseguridad: escanea tu codigo en busca de secrets, inyecciones, malas practicas de auth y dependencias vulnerables.")
  .version("0.1.0");

program
  .command("scan")
  .description("Escanea un archivo o carpeta")
  .argument("[path]", "ruta a escanear", ".")
  .option("--json", "salida en JSON en vez de texto", false)
  .option("--no-deps", "no chequear dependencias vulnerables (evita llamadas de red)")
  .option(
    "--staged",
    "escanea solo los archivos en el git index (staged), pensado para hooks de pre-commit",
    false,
  )
  .option(
    "--fail-on <severity>",
    `severidad minima que hace fallar el comando (${SEVERITY_VALUES.join("|")})`,
    "high",
  )
  .option("--fix", "aplica automaticamente los fixes seguros disponibles (bump de dependencias, CORS wildcard)", false)
  .option("--dry-run", "con --fix, muestra los cambios sin aplicarlos", false)
  .action(
    async (
      path: string,
      opts: { json: boolean; deps: boolean; staged: boolean; failOn: string; fix: boolean; dryRun: boolean },
    ) => {
      const failOn = opts.failOn as Severity;
      if (!SEVERITY_VALUES.includes(failOn)) {
        console.error(`Valor invalido para --fail-on: "${opts.failOn}". Usa uno de: ${SEVERITY_VALUES.join(", ")}`);
        process.exitCode = 2;
        return;
      }

      let scanTarget = path;
      let stagedFiles: WalkedFile[] | undefined;
      if (opts.staged) {
        const repoRoot = getRepoRoot(path);
        if (!repoRoot) {
          console.error(`No se encontro un repo git en "${path}".`);
          process.exitCode = 2;
          return;
        }
        scanTarget = repoRoot;
        stagedFiles = collectStagedFiles(repoRoot);
      }

      const result = await runScan({
        targetPath: scanTarget,
        skipDependencyCheck: !opts.deps,
        files: stagedFiles,
      });

      if (!opts.fix) {
        if (opts.json) {
          printJsonReport(result);
        } else {
          printTextReport(result);
        }
        const hasBlockingFinding = result.findings.some(
          (finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn],
        );
        process.exitCode = hasBlockingFinding ? 1 : 0;
        return;
      }

      if (!opts.dryRun) {
        const gitCheck = ensureCleanGitTree(scanTarget);
        if (!gitCheck.ok) {
          console.error(gitCheck.reason);
          process.exitCode = 2;
          return;
        }
      }

      const outcomes = applyFixes(result.findings, scanTarget, { dryRun: opts.dryRun });
      for (const outcome of outcomes) {
        outcome.finding.fixStatus = outcome.fixStatus;
      }

      if (opts.json) {
        printJsonReport(result);
      } else {
        printTextReport(result);
        printFixSummary(outcomes, opts.dryRun);
      }

      const hasBlockingFinding = result.findings.some(
        (finding) => finding.fixStatus !== "applied" && SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn],
      );
      process.exitCode = hasBlockingFinding ? 1 : 0;
    },
  );

program
  .command("check-prompt")
  .description("Analiza un prompt en busca de patrones de riesgo antes de mandarlo a una IA de codigo")
  .argument("[texto]", "prompt a analizar (si se omite, usa --file o stdin)")
  .option("--file <path>", "leer el prompt desde un archivo en vez de un argumento")
  .option("--json", "salida en JSON en vez de texto", false)
  .option(
    "--fail-on <severity>",
    `severidad minima que hace fallar el comando (${SEVERITY_VALUES.join("|")})`,
    "high",
  )
  .action((texto: string | undefined, opts: { file?: string; json: boolean; failOn: string }) => {
    const failOn = opts.failOn as Severity;
    if (!SEVERITY_VALUES.includes(failOn)) {
      console.error(`Valor invalido para --fail-on: "${opts.failOn}". Usa uno de: ${SEVERITY_VALUES.join(", ")}`);
      process.exitCode = 2;
      return;
    }

    let promptText: string;
    if (texto !== undefined) {
      promptText = texto;
    } else if (opts.file) {
      try {
        promptText = readFileSync(opts.file, "utf-8");
      } catch (error) {
        console.error(`No se pudo leer el archivo "${opts.file}": ${(error as Error).message}`);
        process.exitCode = 2;
        return;
      }
    } else if (!process.stdin.isTTY) {
      promptText = readFileSync(0, "utf-8");
    } else {
      console.error("Falta el prompt a analizar. Pasalo como argumento, con --file <path>, o por stdin.");
      process.exitCode = 2;
      return;
    }

    if (promptText.trim() === "") {
      console.error("El prompt esta vacio.");
      process.exitCode = 2;
      return;
    }

    const engine = new PromptRulesEngine();
    const findings = engine.scan(promptText);

    if (opts.json) {
      printPromptJsonReport(findings);
    } else {
      printPromptReport(findings);
    }

    const hasBlockingFinding = findings.some(
      (finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn],
    );
    process.exitCode = hasBlockingFinding ? 1 : 0;
  });

program
  .command("install-hook")
  .description("Instala un pre-commit hook de git que corre 'scan --staged --fail-on high' antes de cada commit")
  .option("--uninstall", "remueve el hook instalado por copiloto-cyber", false)
  .action((opts: { uninstall: boolean }) => {
    const repoRoot = getRepoRoot(process.cwd());
    if (!repoRoot) {
      console.error("No se encontro un repo git en el directorio actual.");
      process.exitCode = 2;
      return;
    }

    const result = opts.uninstall ? uninstallHook(repoRoot) : installHook(repoRoot);
    if (result.ok) {
      console.log(result.message);
    } else {
      console.error(result.message);
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv).catch((error) => {
  console.error("Error inesperado corriendo el scan:", error);
  process.exitCode = 1;
});
