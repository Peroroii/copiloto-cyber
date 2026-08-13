import { walkFiles } from "./fileWalker.js";
import { scanFileForSecrets } from "./secretsScanner.js";
import { RulesEngine } from "./rulesEngine.js";
import { scanDependencies } from "./dependencyScanner.js";
import type { Finding, ScanResult } from "./types.js";

export interface RunScanOptions {
  targetPath: string;
  skipDependencyCheck?: boolean;
}

const SEVERITY_ORDER: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export async function runScan(options: RunScanOptions): Promise<ScanResult> {
  const files = walkFiles(options.targetPath);
  const rulesEngine = new RulesEngine();

  const findings: Finding[] = [];
  for (const file of files) {
    findings.push(...scanFileForSecrets(file));
    findings.push(...rulesEngine.scanFile(file));
  }

  if (!options.skipDependencyCheck) {
    findings.push(...(await scanDependencies(files)));
  }

  findings.sort((a, b) => {
    const severityDiff = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return a.file.localeCompare(b.file) || a.line - b.line;
  });

  return { findings, filesScanned: files.length };
}

export * from "./types.js";
