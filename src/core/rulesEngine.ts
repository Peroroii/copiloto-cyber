import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Finding, FindingCategory, Severity } from "./types.js";
import type { WalkedFile } from "./fileWalker.js";

interface RawRule {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  extensions: string[];
  pattern: string;
  description: string;
  fixSuggestion: string;
}

interface CompiledRule extends Omit<RawRule, "pattern" | "extensions"> {
  regex: RegExp;
  extensions: Set<string>;
}

const SNIPPET_MAX_LENGTH = 160;

function defaultRulesPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "..", "rules", "patterns.yaml");
}

function loadRawRules(rulesPath: string): RawRule[] {
  const raw = readFileSync(rulesPath, "utf-8");
  const parsed = parseYaml(raw) as { rules: RawRule[] };
  return parsed.rules ?? [];
}

function compileRule(rule: RawRule): CompiledRule {
  return {
    ...rule,
    extensions: new Set(rule.extensions.map((ext) => ext.toLowerCase())),
    regex: new RegExp(rule.pattern, "g"),
  };
}

function extensionOf(fileName: string): string {
  const dot = fileName.lastIndexOf(".");
  if (dot === -1) return "";
  return fileName.slice(dot + 1).toLowerCase();
}

function buildSnippet(line: string, matchStart: number, matchEnd: number): string {
  const trimmed = line.trim();
  if (trimmed.length <= SNIPPET_MAX_LENGTH) return trimmed;
  const start = Math.max(0, matchStart - 40);
  const end = Math.min(line.length, matchEnd + 40);
  return `…${line.slice(start, end).trim()}…`;
}

export class RulesEngine {
  private rules: CompiledRule[];

  constructor(rulesPath: string = defaultRulesPath()) {
    this.rules = loadRawRules(rulesPath).map(compileRule);
  }

  scanFile(file: WalkedFile): Finding[] {
    const findings: Finding[] = [];
    const ext = extensionOf(file.relativePath);
    const applicableRules = this.rules.filter((rule) => rule.extensions.has(ext));
    if (applicableRules.length === 0) return findings;

    const lines = file.content.split(/\r?\n/);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      for (const rule of applicableRules) {
        rule.regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.regex.exec(line)) !== null) {
          findings.push({
            ruleId: rule.id,
            category: rule.category,
            severity: rule.severity,
            title: rule.title,
            description: rule.description.trim(),
            fixSuggestion: rule.fixSuggestion.trim(),
            file: file.relativePath,
            line: lineNumber,
            column: match.index + 1,
            snippet: buildSnippet(line, match.index, match.index + match[0].length),
          });
          if (match[0].length === 0) {
            rule.regex.lastIndex++;
          }
        }
      }
    });

    return findings;
  }
}
