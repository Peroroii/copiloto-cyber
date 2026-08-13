import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { Finding, Severity } from "./types.js";

interface RawPromptRule {
  id: string;
  title: string;
  severity: Severity;
  pattern: string;
  description: string;
  fixSuggestion: string;
}

interface CompiledPromptRule extends Omit<RawPromptRule, "pattern"> {
  regex: RegExp;
}

const SNIPPET_MAX_LENGTH = 160;
const PROMPT_PSEUDO_FILE = "<prompt>";

function defaultRulesPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "..", "rules", "prompt-patterns.yaml");
}

function loadRawRules(rulesPath: string): RawPromptRule[] {
  const raw = readFileSync(rulesPath, "utf-8");
  const parsed = parseYaml(raw) as { rules: RawPromptRule[] };
  return parsed.rules ?? [];
}

function compileRule(rule: RawPromptRule): CompiledPromptRule {
  return { ...rule, regex: new RegExp(rule.pattern, "g") };
}

/**
 * Prompts se escriben en espanol casual, muchas veces sin tildes. Sacamos
 * mayusculas y diacriticos antes de matchear para que "validación" y
 * "validacion" disparen la misma regla (que se escribe sin tilde).
 */
function normalizeForMatch(text: string): string {
  return text
    .normalize("NFD")
    .replace(/[̀-ͯ]/g, "")
    .toLowerCase();
}

function buildSnippet(line: string, matchStart: number, matchEnd: number): string {
  const trimmed = line.trim();
  if (trimmed.length <= SNIPPET_MAX_LENGTH) return trimmed;
  const start = Math.max(0, matchStart - 40);
  const end = Math.min(line.length, matchEnd + 40);
  return `…${line.slice(start, end).trim()}…`;
}

export class PromptRulesEngine {
  private rules: CompiledPromptRule[];

  constructor(rulesPath: string = defaultRulesPath()) {
    this.rules = loadRawRules(rulesPath).map(compileRule);
  }

  scan(promptText: string): Finding[] {
    const findings: Finding[] = [];
    const lines = promptText.split(/\r?\n/);

    lines.forEach((line, index) => {
      const lineNumber = index + 1;
      const normalizedLine = normalizeForMatch(line);

      for (const rule of this.rules) {
        rule.regex.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.regex.exec(normalizedLine)) !== null) {
          findings.push({
            ruleId: rule.id,
            category: "prompt",
            severity: rule.severity,
            title: rule.title,
            description: rule.description.trim(),
            fixSuggestion: rule.fixSuggestion.trim(),
            file: PROMPT_PSEUDO_FILE,
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
