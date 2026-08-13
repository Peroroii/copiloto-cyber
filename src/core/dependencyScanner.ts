import type { Finding, Severity } from "./types.js";
import type { WalkedFile } from "./fileWalker.js";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const MAX_DEPENDENCIES_PER_MANIFEST = 300;
const CONCURRENCY = 8;
const REQUEST_TIMEOUT_MS = 10_000;

export type FetchLike = (url: string, init?: RequestInit) => Promise<{
  ok: boolean;
  status: number;
  json: () => Promise<unknown>;
}>;

interface DependencyRef {
  name: string;
  versionSpec: string;
  resolvedVersion?: string;
  ecosystem: "npm" | "PyPI";
  manifestFile: string;
}

interface OsvSeverityEntry {
  type: string;
  score: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  severity?: OsvSeverityEntry[];
  database_specific?: { severity?: string };
  references?: { url: string }[];
}

interface OsvQueryResponse {
  vulns?: OsvVuln[];
}

function extractConcreteVersion(spec: string): string | null {
  const cleaned = spec.trim();
  if (cleaned === "" || cleaned === "*" || cleaned === "latest") return null;
  if (/^(git|file|https?|workspace):/i.test(cleaned) || cleaned.startsWith("link:")) return null;

  const match = cleaned.match(/(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)/);
  return match ? match[1] : null;
}

function parsePackageJsonDeps(
  content: string,
  manifestFile: string,
  lockVersions?: Map<string, string>,
): DependencyRef[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content);
  } catch {
    return [];
  }

  const deps: DependencyRef[] = [];
  const sections = ["dependencies", "devDependencies"] as const;
  for (const section of sections) {
    const entries = parsed[section];
    if (!entries || typeof entries !== "object") continue;
    for (const [name, versionSpec] of Object.entries(entries as Record<string, string>)) {
      deps.push({ name, versionSpec, resolvedVersion: lockVersions?.get(name), ecosystem: "npm", manifestFile });
    }
  }
  return deps;
}

/**
 * Extracts the top-level (hoisted) resolved version for each direct
 * dependency from a package-lock.json, so we check what's actually
 * installed instead of guessing from the manifest's semver range (e.g.
 * "^2.5.1" is not a concrete version — npm may have resolved it to 2.9.0).
 * Only top-level entries are read; nested/duplicated transitive
 * resolutions are intentionally ignored to keep this a direct-dependency
 * check, consistent with what package.json declares.
 */
function parsePackageLockVersions(content: string): Map<string, string> {
  const versions = new Map<string, string>();
  let parsed: {
    packages?: Record<string, { version?: string }>;
    dependencies?: Record<string, { version?: string }>;
  };
  try {
    parsed = JSON.parse(content);
  } catch {
    return versions;
  }

  if (parsed.packages) {
    for (const [pkgPath, pkg] of Object.entries(parsed.packages)) {
      if (!pkg.version) continue;
      const match = pkgPath.match(/^node_modules\/(@[^/]+\/[^/]+|[^/]+)$/);
      if (!match) continue;
      versions.set(match[1], pkg.version);
    }
  } else if (parsed.dependencies) {
    for (const [name, info] of Object.entries(parsed.dependencies)) {
      if (info.version) versions.set(name, info.version);
    }
  }

  return versions;
}

function parseRequirementsTxt(content: string, manifestFile: string): DependencyRef[] {
  const deps: DependencyRef[] = [];
  const lines = content.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.split("#")[0].trim();
    if (!line || line.startsWith("-")) continue;
    const match = line.match(/^([A-Za-z0-9_.\-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.\-]*)/);
    if (!match) continue;
    const [, name, , version] = match;
    deps.push({ name, versionSpec: version ?? "", ecosystem: "PyPI", manifestFile });
  }
  return deps;
}

function dirOf(normalizedPath: string, base: string): string {
  return normalizedPath.slice(0, normalizedPath.length - base.length);
}

export function findDependencyManifests(files: WalkedFile[]): DependencyRef[] {
  const lockVersionsByDir = new Map<string, Map<string, string>>();
  for (const file of files) {
    const normalizedPath = file.relativePath.replace(/\\/g, "/");
    const base = normalizedPath.split("/").pop() ?? "";
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
      lockVersionsByDir.set(dirOf(normalizedPath, base), parsePackageLockVersions(file.content));
    }
  }

  const deps: DependencyRef[] = [];
  for (const file of files) {
    const normalizedPath = file.relativePath.replace(/\\/g, "/");
    const base = normalizedPath.split("/").pop() ?? "";
    if (base === "package.json") {
      const lockVersions = lockVersionsByDir.get(dirOf(normalizedPath, base));
      deps.push(...parsePackageJsonDeps(file.content, file.relativePath, lockVersions));
    } else if (base === "requirements.txt") {
      deps.push(...parseRequirementsTxt(file.content, file.relativePath));
    }
  }

  return deps.slice(0, MAX_DEPENDENCIES_PER_MANIFEST);
}

function mapSeverity(vuln: OsvVuln): Severity {
  const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
  if (dbSeverity === "CRITICAL") return "critical";
  if (dbSeverity === "HIGH") return "high";
  if (dbSeverity === "MODERATE" || dbSeverity === "MEDIUM") return "medium";
  if (dbSeverity === "LOW") return "low";

  const cvssEntry = vuln.severity?.find((entry) => entry.type === "CVSS_V3");
  if (cvssEntry) {
    const scoreMatch = cvssEntry.score.match(/(\d+\.\d+)$/);
    const score = scoreMatch ? Number.parseFloat(scoreMatch[1]) : null;
    if (score !== null) {
      if (score >= 9) return "critical";
      if (score >= 7) return "high";
      if (score >= 4) return "medium";
      return "low";
    }
  }

  return "medium";
}

async function queryOsvWithTimeout(
  fetchImpl: FetchLike,
  dep: DependencyRef,
  version: string,
): Promise<OsvVuln[]> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetchImpl(OSV_QUERY_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        version,
        package: { name: dep.name, ecosystem: dep.ecosystem },
      }),
      signal: controller.signal,
    } as RequestInit);

    if (!response.ok) return [];
    const data = (await response.json()) as OsvQueryResponse;
    return data.vulns ?? [];
  } catch {
    return [];
  } finally {
    clearTimeout(timeout);
  }
}

async function runWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;

  async function runNext(): Promise<void> {
    while (cursor < items.length) {
      const currentIndex = cursor++;
      results[currentIndex] = await worker(items[currentIndex]);
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, () => runNext());
  await Promise.all(workers);
  return results;
}

function vulnToFinding(dep: DependencyRef, version: string, vuln: OsvVuln): Finding {
  const severity = mapSeverity(vuln);
  const summary = vuln.summary ?? vuln.details?.slice(0, 200) ?? "Vulnerabilidad conocida sin resumen disponible.";
  const referenceUrl = vuln.references?.[0]?.url ?? `https://osv.dev/vulnerability/${vuln.id}`;

  return {
    ruleId: `dependency-${vuln.id}`,
    category: "dependency",
    severity,
    title: `Dependencia vulnerable: ${dep.name}@${version} (${vuln.id})`,
    description: `${summary} Mas info: ${referenceUrl}`,
    fixSuggestion: `Actualiza "${dep.name}" a una version que no este afectada por ${vuln.id} (revisa el changelog/advisory) y corre tu gestor de paquetes de nuevo.`,
    file: dep.manifestFile,
    line: 1,
    snippet: `"${dep.name}": "${dep.versionSpec}"`,
  };
}

export async function scanDependencies(
  files: WalkedFile[],
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
): Promise<Finding[]> {
  const deps = findDependencyManifests(files);
  const resolvable = deps
    .map((dep) => ({ dep, version: dep.resolvedVersion ?? extractConcreteVersion(dep.versionSpec) }))
    .filter((entry): entry is { dep: DependencyRef; version: string } => Boolean(entry.version));

  const results = await runWithConcurrency(resolvable, CONCURRENCY, async ({ dep, version }) => {
    const vulns = await queryOsvWithTimeout(fetchImpl, dep, version);
    return vulns.map((vuln) => vulnToFinding(dep, version, vuln));
  });

  return results.flat();
}
