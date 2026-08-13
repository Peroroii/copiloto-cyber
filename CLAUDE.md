# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Copiloto Cyber is a CLI security scanner aimed at "vibecoding" (AI-assisted, low-security-experience) developers. It statically scans a target path for hardcoded secrets, injection/XSS patterns, weak auth practices, and vulnerable dependencies, and reports findings in plain Spanish. All user-facing strings (descriptions, fix suggestions, CLI output) are in Spanish — keep new rules and messages consistent with that.

It explicitly favors few false positives and clear explanations over exhaustive SAST coverage.

## Commands

```bash
npm install
npm run build          # tsc -> dist/
npm run dev -- scan .  # run CLI directly from TS via tsx, no build needed
npm test               # vitest run (single run)
npm run test:watch     # vitest watch mode
npx tsc --noEmit        # type-check only
```

Run a single test file: `npx vitest run test/secretsScanner.test.ts`

Run the built CLI directly:
```bash
node dist/cli/index.js scan .                 # scan a path
node dist/cli/index.js scan ./src --no-deps   # skip OSV dependency lookups (no network)
node dist/cli/index.js scan . --json          # JSON output
node dist/cli/index.js scan . --fail-on critical  # change exit-code threshold (default: high)

node dist/cli/index.js check-prompt "<texto>"          # analyze a prompt before sending it to an AI coder
node dist/cli/index.js check-prompt --file prompt.txt   # read prompt from a file (multi-line)
echo "<texto>" | node dist/cli/index.js check-prompt    # or from stdin
```

CI (`.github/workflows/ci.yml`) runs type-check → test → build → dogfoods the built CLI against this repo itself (`scan . --fail-on high`), so a scan-breaking change to `rules/patterns.yaml` or the scanners can fail CI on its own output, not just on tests.

## Architecture

Pipeline, orchestrated by `runScan` in `src/core/scanner.ts`:

1. **`fileWalker.ts`** — walks the target path into `WalkedFile[]` (absolute path, relative path, content). Skips default-ignored dirs (`node_modules`, `.git`, `dist`, etc. and anything dotfile-prefixed), binary extensions, files >2MB, and anything matching a `.copilotoignore` file at the scan root (gitignore-style globs, `*` and `**`, basename-only patterns match anywhere).
2. **`secretsScanner.ts`** — two passes per file: (a) a fixed list of known secret signatures (AWS keys, GitHub/Slack/Stripe tokens, Google API keys, PEM blocks, DB connection strings with embedded creds, JWTs), each with its own severity/description/fix; (b) a generic pass that flags high-entropy string literals (Shannon entropy via `entropy.ts`, threshold 3.5 bits/char) assigned to suspiciously-named variables (`apiKey`, `secret`, `token`, `password`, etc.), filtering out obvious placeholders (`changeme`, `${...}`, `<...>`, etc.) and `process.env`/`import.meta.env` references. All matched secret values are redacted (`redact()`) before being included in a finding's snippet — never surface raw matched secrets.
3. **`rulesEngine.ts`** — loads declarative regex rules from `rules/patterns.yaml`, compiled once per `RulesEngine` instance. Rules are filtered by file extension, then applied line-by-line. This covers `injection` (SQLi, eval/Function, command injection, unsanitized HTML) and `auth` (CORS wildcard, JWT verification disabled, plaintext password comparison) categories. **Adding a new pattern rule = editing `rules/patterns.yaml` only**, no engine code changes needed — see existing entries for the `id/title/category/severity/extensions/pattern/description/fixSuggestion` shape.
4. **`dependencyScanner.ts`** — parses `package.json` (`dependencies`/`devDependencies`) and `requirements.txt` found among walked files, extracts a concrete version per dependency (skips ranges/`latest`/git/workspace refs it can't resolve to a single version), and queries the OSV.dev API (`POST https://api.osv.dev/v1/query`, no API key) with bounded concurrency (8) and a 10s per-request timeout. Network failures degrade silently to "no vuln found" rather than failing the scan. `fetchImpl` is injectable for testing (see `test/dependencyScanner.test.ts` for the mock-fetch pattern).

All findings share the `Finding` shape (`src/core/types.ts`): `ruleId`, `category` (`secret | injection | auth | dependency | prompt`), `severity` (`critical | high | medium | low`), `title`, `description`, `fixSuggestion`, `file`, `line`, `column?`, `snippet`. `runScan` merges findings from all scanners and sorts by severity, then file, then line.

`src/cli/index.ts` (Commander-based) wires flags to `runScan`/`RunScanOptions` and sets `process.exitCode = 1` when any finding's severity is at or above `--fail-on` (default `high`) — this is what makes the tool usable as a pre-commit hook or CI gate. `src/cli/reporter.ts` renders either colored text (`printTextReport`) or raw JSON (`printJsonReport`) from a `ScanResult`.

### Prompt scanning (`check-prompt`)

Separate pipeline from the `scan` command, for analyzing natural-language prompts *before* they're sent to an AI coding assistant — catching requests that tend to produce insecure code ("disable validation to keep it simple", "hardcode the API key for now") before any code exists.

- **`promptScanner.ts`** — `PromptRulesEngine`, structurally parallel to `rulesEngine.ts` but deliberately not the same engine: it loads `rules/prompt-patterns.yaml` (no `extensions` field — prompts aren't files) and, critically, normalizes each line (NFD-decompose + strip diacritics + lowercase via `normalizeForMatch`) before matching, so "validación" and "validacion" hit the same rule. Rule patterns in `prompt-patterns.yaml` are therefore written *without* accents. This normalization is prompt-specific and intentionally not applied to source-code scanning (it would be semantically wrong there). All findings get `category: "prompt"` and `file: "<prompt>"`.
- Patterns combine an action verb (sacar/deshabilitar/desactivar/ignorar/bypass...) with a security concept, rather than matching a bare keyword — this avoids flagging legitimate questions like "¿por qué no anda la validación?".
- `check-prompt` in `src/cli/index.ts` accepts the prompt as a positional arg, `--file <path>`, or stdin (in that priority order), and reuses the same `--fail-on`/exit-code convention as `scan` (default `high`). `printPromptReport`/`printPromptJsonReport` in `reporter.ts` render it (no file/line noise, since there's no real file).

### Adding a new rule type

- **New regex-based pattern over source code** (injection/auth/secret-like-but-generic): add an entry to `rules/patterns.yaml`. No TypeScript changes required.
- **New regex-based pattern over prompt text**: add an entry to `rules/prompt-patterns.yaml`, written without accents (see above). No TypeScript changes required.
- **New scanner category or logic that can't be expressed as a single-line regex** (e.g. a new known-secret signature with custom redaction, or a new dependency manifest format): add it in the relevant `src/core/*.ts` file, following the existing pattern of a typed list of signatures/rules plus a `scanFile`-style function returning `Finding[]`.

### Test fixtures

`test/` contains fixtures with real-looking secrets and vulnerable patterns *on purpose*, to verify the scanners detect them — this is why `test/` is excluded from the repo's own dogfooding scan via `.copilotoignore`, not because it's exempt from normal review.
