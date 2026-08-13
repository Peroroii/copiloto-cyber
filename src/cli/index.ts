#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { Command } from "commander";
import { runScan } from "../core/scanner.js";
import { PromptRulesEngine } from "../core/promptScanner.js";
import { applyFixes, ensureCleanGitTree } from "../core/fixer.js";
import {
  printFixSummary,
  printJsonReport,
  printPromptJsonReport,
  printPromptReport,
  printTextReport,
} from "./reporter.js";
import type { Severity } from "../core/types.js";

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
    "--fail-on <severity>",
    `severidad minima que hace fallar el comando (${SEVERITY_VALUES.join("|")})`,
    "high",
  )
  .option("--fix", "aplica automaticamente los fixes seguros disponibles (bump de dependencias, CORS wildcard)", false)
  .option("--dry-run", "con --fix, muestra los cambios sin aplicarlos", false)
  .action(
    async (path: string, opts: { json: boolean; deps: boolean; failOn: string; fix: boolean; dryRun: boolean }) => {
      const failOn = opts.failOn as Severity;
      if (!SEVERITY_VALUES.includes(failOn)) {
        console.error(`Valor invalido para --fail-on: "${opts.failOn}". Usa uno de: ${SEVERITY_VALUES.join(", ")}`);
        process.exitCode = 2;
        return;
      }

      const result = await runScan({ targetPath: path, skipDependencyCheck: !opts.deps });

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
        const gitCheck = ensureCleanGitTree(path);
        if (!gitCheck.ok) {
          console.error(gitCheck.reason);
          process.exitCode = 2;
          return;
        }
      }

      const outcomes = applyFixes(result.findings, path, { dryRun: opts.dryRun });
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

program.parseAsync(process.argv).catch((error) => {
  console.error("Error inesperado corriendo el scan:", error);
  process.exitCode = 1;
});
