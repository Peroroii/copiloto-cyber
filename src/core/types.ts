export type Severity = "critical" | "high" | "medium" | "low";

export type FindingCategory = "secret" | "injection" | "auth" | "dependency" | "prompt";

/**
 * How a finding's fix would be carried out. Only a narrow set of findings
 * get one of these at all (dependency version bumps, and the open-origin
 * CORS shape) — everything else (secrets, injection, plaintext password
 * compare, JWT verification) has no safe generic auto-fix and is left
 * undefined here, always reported manually via `fixSuggestion`.
 */
export type FixStrategy =
  | "bump-dependency-manifest"
  | "reinstall-dependency"
  | "blocked-major-bump"
  | "replace-cors-wildcard";

/**
 * Outcome of attempting a fix, set only when `scan --fix`/`--dry-run` ran.
 * Absent on a plain `scan`.
 */
export type FixStatus = "applied" | "would-apply" | "manual-step" | "blocked-major-bump" | "not-auto-fixable";

export interface FixDescriptor {
  strategy: FixStrategy;
  instructions: string;
  /** Exact substring to find/replace, for text-based strategies only. */
  search?: string;
  replace?: string;
}

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
  fix?: FixDescriptor;
  fixStatus?: FixStatus;
}

export interface ScanOptions {
  targetPath: string;
}

export interface ScanResult {
  findings: Finding[];
  filesScanned: number;
}
