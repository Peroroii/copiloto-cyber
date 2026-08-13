import pc from "picocolors";
import type { Finding, FixStatus, ScanResult, Severity } from "../core/types.js";
import type { FixOutcome } from "../core/fixer.js";

const SEVERITY_EMOJI: Record<Severity, string> = {
  critical: "🔴",
  high: "🔴",
  medium: "🟡",
  low: "🟢",
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: pc.bold(pc.red("CRITICA")),
  high: pc.red("ALTA"),
  medium: pc.yellow("MEDIA"),
  low: pc.green("BAJA"),
};

const CATEGORY_LABEL: Record<Finding["category"], string> = {
  secret: "secreto expuesto",
  injection: "inyeccion",
  auth: "autenticacion",
  dependency: "dependencia vulnerable",
  prompt: "riesgo en el prompt",
};

const FIX_STATUS_LABEL: Record<FixStatus, string> = {
  applied: pc.green("✅ fix aplicado"),
  "would-apply": pc.cyan("🔧 se aplicaria (dry-run)"),
  "manual-step": pc.cyan("↻ accion manual"),
  "blocked-major-bump": pc.yellow("⚠ requiere revision manual (version mayor)"),
  "not-auto-fixable": pc.dim("— sin fix automatico disponible"),
};

function printFixStatusLine(finding: Finding): void {
  if (!finding.fixStatus) return;
  const label = FIX_STATUS_LABEL[finding.fixStatus];

  if ((finding.fixStatus === "applied" || finding.fixStatus === "would-apply") && finding.fix?.search && finding.fix.replace) {
    console.log(`   ${label}: ${pc.dim(finding.fix.search)} → ${pc.dim(finding.fix.replace)}`);
    return;
  }
  if (finding.fix?.instructions) {
    console.log(`   ${label}: ${finding.fix.instructions}`);
    return;
  }
  console.log(`   ${label}`);
}

function printFinding(finding: Finding): void {
  const location = pc.dim(`${finding.file}:${finding.line}`);
  console.log(
    `${SEVERITY_EMOJI[finding.severity]} ${SEVERITY_LABEL[finding.severity]}  ${pc.bold(finding.title)}  ${pc.dim(
      `[${CATEGORY_LABEL[finding.category]}]`,
    )}`,
  );
  console.log(`   ${location}`);
  if (finding.snippet) {
    console.log(`   ${pc.dim("│")} ${pc.dim(finding.snippet)}`);
  }
  console.log(`   ${finding.description}`);
  console.log(`   ${pc.cyan("→ fix:")} ${finding.fixSuggestion}`);
  printFixStatusLine(finding);
  console.log("");
}

export function printTextReport(result: ScanResult): void {
  console.log("");
  console.log(pc.bold(`Copiloto Cyber — escaneo de seguridad`));
  console.log(pc.dim(`${result.filesScanned} archivo(s) analizados`));
  console.log("");

  if (result.findings.length === 0) {
    console.log(pc.green("✅ No encontramos problemas conocidos. Buen trabajo."));
    console.log(
      pc.dim("(Esto no es una garantia de seguridad total: cubrimos secrets, patrones de inyeccion, auth basica y dependencias con CVEs conocidos.)"),
    );
    console.log("");
    return;
  }

  for (const finding of result.findings) {
    printFinding(finding);
  }

  const counts = countBySeverity(result.findings);
  console.log(pc.bold("Resumen:"));
  console.log(
    `  🔴 criticas: ${counts.critical}   🔴 altas: ${counts.high}   🟡 medias: ${counts.medium}   🟢 bajas: ${counts.low}`,
  );
  console.log("");
}

export function printJsonReport(result: ScanResult): void {
  console.log(JSON.stringify(result, null, 2));
}

export function printFixSummary(outcomes: FixOutcome[], dryRun: boolean): void {
  const countOf = (status: FixStatus): number => outcomes.filter((o) => o.fixStatus === status).length;

  console.log(pc.bold("Resumen de --fix:"));
  if (dryRun) {
    console.log(
      `  🔧 se aplicarian: ${countOf("would-apply")}   ↻ accion manual: ${countOf("manual-step")}   ⚠ revision manual: ${countOf("blocked-major-bump")}   — sin fix: ${countOf("not-auto-fixable")}`,
    );
  } else {
    console.log(
      `  ✅ aplicados: ${countOf("applied")}   ↻ accion manual: ${countOf("manual-step")}   ⚠ revision manual: ${countOf("blocked-major-bump")}   — sin fix: ${countOf("not-auto-fixable")}`,
    );
  }
  console.log("");
}

function printPromptFinding(finding: Finding): void {
  console.log(
    `${SEVERITY_EMOJI[finding.severity]} ${SEVERITY_LABEL[finding.severity]}  ${pc.bold(finding.title)}`,
  );
  if (finding.snippet) {
    console.log(`   ${pc.dim("│")} ${pc.dim(finding.snippet)}`);
  }
  console.log(`   ${finding.description}`);
  console.log(`   ${pc.cyan("→ en vez de eso:")} ${finding.fixSuggestion}`);
  console.log("");
}

export function printPromptReport(findings: Finding[]): void {
  console.log("");
  console.log(pc.bold("Copiloto Cyber — analisis de prompt"));
  console.log("");

  if (findings.length === 0) {
    console.log(pc.green("✅ No encontramos patrones de riesgo conocidos en este prompt."));
    console.log(
      pc.dim("(Esto es un chequeo heuristico, no una garantia: el codigo que se termine generando igual puede tener problemas.)"),
    );
    console.log("");
    return;
  }

  for (const finding of findings) {
    printPromptFinding(finding);
  }

  const counts = countBySeverity(findings);
  console.log(pc.bold("Resumen:"));
  console.log(
    `  🔴 criticas: ${counts.critical}   🔴 altas: ${counts.high}   🟡 medias: ${counts.medium}   🟢 bajas: ${counts.low}`,
  );
  console.log("");
}

export function printPromptJsonReport(findings: Finding[]): void {
  console.log(JSON.stringify({ findings }, null, 2));
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    counts[finding.severity]++;
  }
  return counts;
}
