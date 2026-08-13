import pc from "picocolors";
import type { Finding, ScanResult, Severity } from "../core/types.js";

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
};

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

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    counts[finding.severity]++;
  }
  return counts;
}
