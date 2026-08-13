export type Severity = "critical" | "high" | "medium" | "low";

export type FindingCategory = "secret" | "injection" | "auth" | "dependency" | "prompt";

export interface Finding {
  ruleId: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  fixSuggestion: string;
  file: string;
  line: number;
  column?: number;
  snippet: string;
}

export interface ScanOptions {
  targetPath: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
}
