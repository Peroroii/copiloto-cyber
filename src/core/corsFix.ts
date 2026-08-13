import type { FixDescriptor } from "./types.js";

/**
 * Deliberately narrow: only the `origin` config-object wildcard shape (the
 * `cors` npm package / Express convention). The other shape the
 * auth-cors-wildcard-credentials rule also detects — a raw
 * "Access-Control-Allow-Origin" header string — isn't touched, since
 * rewriting that safely needs more context than a single-line regex can
 * responsibly guess.
 */
const CORS_ORIGIN_WILDCARD = /(origin\s*:\s*)(['"])\*\2/i;
const CORS_PLACEHOLDER = "REPLACE_WITH_ALLOWED_ORIGIN";

export function computeCorsFix(line: string): FixDescriptor | null {
  const match = CORS_ORIGIN_WILDCARD.exec(line);
  if (!match) return null;

  const [search, prefix, quote] = match;
  const replace = `${prefix}${quote}${CORS_PLACEHOLDER}${quote}`;

  return {
    strategy: "replace-cors-wildcard",
    instructions:
      'Se reemplaza el origen abierto ("*") por un placeholder que bloquea todo hasta que definas el/los dominios reales permitidos.',
    search,
    replace,
  };
}
