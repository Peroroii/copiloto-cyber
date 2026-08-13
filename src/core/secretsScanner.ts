import type { Finding, Severity } from "./types.js";
import type { WalkedFile } from "./fileWalker.js";
import { shannonEntropy } from "./entropy.js";

interface KnownSecretPattern {
  id: string;
  title: string;
  severity: Severity;
  regex: RegExp;
  description: string;
  fixSuggestion: string;
}

const KNOWN_SECRET_PATTERNS: KnownSecretPattern[] = [
  {
    id: "secret-aws-access-key",
    title: "AWS Access Key ID hardcodeada",
    severity: "critical",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    description: "Encontramos lo que parece ser una AWS Access Key ID escrita directamente en el codigo.",
    fixSuggestion: "Movela a variables de entorno o a un secret manager (AWS Secrets Manager, SSM Parameter Store) y rotala ya, porque si este codigo se subio a un repo publico esta comprometida.",
  },
  {
    id: "secret-github-token",
    title: "Token de GitHub hardcodeado",
    severity: "critical",
    regex: /\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,
    description: "Hay un token de GitHub (personal access token o similar) escrito directamente en el codigo.",
    fixSuggestion: "Revocalo en GitHub Settings > Developer settings > Tokens, y usa una variable de entorno o un secret del CI en su lugar.",
  },
  {
    id: "secret-slack-token",
    title: "Token de Slack hardcodeado",
    severity: "critical",
    regex: /\bxox[baprs]-[0-9A-Za-z-]{10,48}\b/g,
    description: "Hay un token de Slack escrito directamente en el codigo.",
    fixSuggestion: "Revocalo desde la app de Slack y movelo a una variable de entorno.",
  },
  {
    id: "secret-stripe-key",
    title: "API key de Stripe hardcodeada",
    severity: "critical",
    regex: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/g,
    description: "Hay una API key de Stripe en modo LIVE escrita directamente en el codigo.",
    fixSuggestion: "Revocala en el dashboard de Stripe y movela a una variable de entorno. Una key live filtrada puede permitir mover dinero real.",
  },
  {
    id: "secret-google-api-key",
    title: "API key de Google hardcodeada",
    severity: "high",
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    description: "Hay una API key de Google escrita directamente en el codigo.",
    fixSuggestion: "Restringila por dominio/IP en Google Cloud Console y movela a una variable de entorno.",
  },
  {
    id: "secret-private-key-block",
    title: "Bloque de clave privada en el repo",
    severity: "critical",
    regex: /-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)?\s?PRIVATE KEY-----/g,
    description: "Encontramos un bloque de clave privada (PEM) dentro del codigo o del repo.",
    fixSuggestion: "Sacala del repo, agregala a .gitignore, y si ya se subio a git, considerala comprometida: generá una clave nueva.",
  },
  {
    id: "secret-connection-string-creds",
    title: "Connection string con credenciales embebidas",
    severity: "high",
    regex: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s'"]+:[^@\s'"]+@[^\s'"]+/g,
    description: "Hay una cadena de conexion a una base de datos con usuario y contrasena escritos directamente en el codigo.",
    fixSuggestion: "Movela a una variable de entorno (por ejemplo DATABASE_URL) y no la commitees.",
  },
  {
    id: "secret-jwt",
    title: "JSON Web Token hardcodeado",
    severity: "medium",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    description: "Hay un JWT (token de sesion/autenticacion) escrito directamente en el codigo.",
    fixSuggestion: "Si es un token real (no un ejemplo/fixture de test), sacalo del codigo: los JWT pueden dar acceso autenticado a quien los lea.",
  },
];

const GENERIC_ASSIGNMENT_REGEX =
  /(api[_-]?key|apikey|secret|token|password|passwd|pwd|client[_-]?secret)\s*[:=]\s*["']([^"'\s]{8,})["']/gi;

const PLACEHOLDER_PATTERNS = [
  /^(changeme|change_me|your[_-]?(api[_-]?key|token|secret|password)|xxx+|placeholder|example|sample|test|dummy|fake|todo|fixme)/i,
  /^\$\{.*\}$/,
  /^<.*>$/,
];

const MIN_ENTROPY_FOR_GENERIC_SECRET = 3.5;
const SNIPPET_MAX_LENGTH = 160;

function isLikelyPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value));
}

function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  return `${value.slice(0, 4)}${"*".repeat(Math.min(value.length - 8, 20))}${value.slice(-4)}`;
}

function buildSnippet(line: string, matchStart: number, matchEnd: number, redactedMatch: string): string {
  const before = line.slice(0, matchStart);
  const after = line.slice(matchEnd);
  const snippet = `${before}${redactedMatch}${after}`.trim();
  if (snippet.length <= SNIPPET_MAX_LENGTH) return snippet;
  return `${snippet.slice(0, SNIPPET_MAX_LENGTH)}…`;
}

export function scanFileForSecrets(file: WalkedFile): Finding[] {
  const findings: Finding[] = [];
  const lines = file.content.split(/\r?\n/);

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    for (const pattern of KNOWN_SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      let match: RegExpExecArray | null;
      while ((match = pattern.regex.exec(line)) !== null) {
        const redacted = redact(match[0]);
        findings.push({
          ruleId: pattern.id,
          category: "secret",
          severity: pattern.severity,
          title: pattern.title,
          description: pattern.description,
          fixSuggestion: pattern.fixSuggestion,
          file: file.relativePath,
          line: lineNumber,
          column: match.index + 1,
          snippet: buildSnippet(line, match.index, match.index + match[0].length, redacted),
        });
        if (!pattern.regex.global) break;
      }
    }

    GENERIC_ASSIGNMENT_REGEX.lastIndex = 0;
    let genericMatch: RegExpExecArray | null;
    while ((genericMatch = GENERIC_ASSIGNMENT_REGEX.exec(line)) !== null) {
      const value = genericMatch[2];
      if (isLikelyPlaceholder(value)) continue;
      if (value.startsWith("process.env") || value.includes("import.meta.env")) continue;

      const entropy = shannonEntropy(value);
      if (entropy < MIN_ENTROPY_FOR_GENERIC_SECRET) continue;

      const redacted = redact(value);
      const valueStart = line.indexOf(value, genericMatch.index);
      const valueEnd = valueStart + value.length;
      findings.push({
        ruleId: "secret-generic-high-entropy",
        category: "secret",
        severity: "medium",
        title: "Posible secreto hardcodeado",
        description: `Encontramos un valor de alta entropia (${entropy.toFixed(1)} bits/char) asignado a una variable con nombre "${genericMatch[1]}", lo que suele indicar una API key, password o token pegado directamente en el codigo.`,
        fixSuggestion: "Si es un valor real, movelo a una variable de entorno (.env, no commiteado) o a un secret manager. Si es un placeholder de ejemplo, ignora este hallazgo o renombralo para que quede claro (ej. 'YOUR_API_KEY_HERE').",
        file: file.relativePath,
        line: lineNumber,
        column: genericMatch.index + 1,
        snippet: buildSnippet(line, valueStart, valueEnd, redacted),
      });
    }
  });

  return findings;
}
