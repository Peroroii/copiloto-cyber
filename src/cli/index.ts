#!/usr/bin/env node
import { Command } from "commander";
import { runScan } from "../core/scanner.js";
import { printJsonReport, printTextReport } from "./reporter.js";
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
  .action(async (path: string, opts: { json: boolean; deps: boolean; failOn: string }) => {
    const failOn = opts.failOn as Severity;
    if (!SEVERITY_VALUES.includes(failOn)) {
      console.error(`Valor invalido para --fail-on: "${opts.failOn}". Usa uno de: ${SEVERITY_VALUES.join(", ")}`);
      process.exitCode = 2;
      return;
    }

    const result = await runScan({ targetPath: path, skipDependencyCheck: !opts.deps });

    if (opts.json) {
      printJsonReport(result);
    } else {
      printTextReport(result);
    }

    const hasBlockingFinding = result.findings.some(
      (finding) => SEVERITY_RANK[finding.severity] <= SEVERITY_RANK[failOn],
    );
    process.exitCode = hasBlockingFinding ? 1 : 0;
  });

program.parseAsync(process.argv).catch((error) => {
  console.error("Error inesperado corriendo el scan:", error);
  process.exitCode = 1;
});
