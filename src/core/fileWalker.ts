import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const IGNORE_FILE_NAME = ".copilotoignore";

const DEFAULT_IGNORED_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
  "coverage",
  ".turbo",
]);

const BINARY_EXTENSIONS = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
  ".woff", ".woff2", ".ttf", ".eot", ".zip", ".gz", ".lock",
  ".exe", ".dll", ".so", ".dylib", ".map",
]);

const MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024;
const NUL_CHAR_CODE = 0;

export interface WalkedFile {
  absolutePath: string;
  relativePath: string;
  content: string;
}

export function hasIgnoredExtension(fileName: string): boolean {
  const dot = fileName.lastIndexOf(".");
  if (dot === -1) return false;
  return BINARY_EXTENSIONS.has(fileName.slice(dot).toLowerCase());
}

function looksBinary(content: string): boolean {
  const sampleLength = Math.min(content.length, 8000);
  for (let i = 0; i < sampleLength; i++) {
    if (content.charCodeAt(i) === NUL_CHAR_CODE) return true;
  }
  return false;
}

/**
 * Applies the same size/binary gate `walkFiles` uses when reading from disk,
 * for callers (e.g. staged-file scanning) that already have content in hand
 * from somewhere other than a direct file read.
 */
export function prepareContent(content: string): string | null {
  if (Buffer.byteLength(content, "utf-8") > MAX_FILE_SIZE_BYTES) return null;
  if (looksBinary(content)) return null;
  return content;
}

function globToRegExp(pattern: string): RegExp {
  let source = "";
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "*") {
      if (pattern[i + 1] === "*") {
        source += ".*";
        i++;
      } else {
        source += "[^/]*";
      }
    } else if (".+^${}()|[]\\".includes(char)) {
      source += `\\${char}`;
    } else {
      source += char;
    }
  }
  return new RegExp(`^${source}$`);
}

export interface IgnorePattern {
  regex: RegExp;
  matchesBasenameOnly: boolean;
}

export function loadIgnorePatterns(rootPath: string): IgnorePattern[] {
  const ignoreFilePath = join(rootPath, IGNORE_FILE_NAME);
  if (!existsSync(ignoreFilePath)) return [];

  const lines = readFileSync(ignoreFilePath, "utf-8").split(/\r?\n/);
  const patterns: IgnorePattern[] = [];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const withoutTrailingSlash = line.endsWith("/") ? line.slice(0, -1) : line;
    const matchesBasenameOnly = !withoutTrailingSlash.includes("/");
    patterns.push({ regex: globToRegExp(withoutTrailingSlash), matchesBasenameOnly });
  }

  return patterns;
}

export function isIgnored(relativePathPosix: string, patterns: IgnorePattern[]): boolean {
  const basename = relativePathPosix.split("/").pop() ?? relativePathPosix;
  return patterns.some((pattern) =>
    pattern.matchesBasenameOnly ? pattern.regex.test(basename) : pattern.regex.test(relativePathPosix),
  );
}

export function walkFiles(rootPath: string): WalkedFile[] {
  const rootStat = statSync(rootPath);
  const results: WalkedFile[] = [];

  if (rootStat.isFile()) {
    const content = safeReadFile(rootPath);
    if (content !== null) {
      results.push({ absolutePath: rootPath, relativePath: rootPath, content });
    }
    return results;
  }

  const ignorePatterns = loadIgnorePatterns(rootPath);
  const stack: string[] = [rootPath];

  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const absolutePath = join(dir, entry.name);
      const relativePathPosix = relative(rootPath, absolutePath).replace(/\\/g, "/");

      if (entry.isDirectory()) {
        if (DEFAULT_IGNORED_DIRS.has(entry.name) || entry.name.startsWith(".")) {
          continue;
        }
        if (isIgnored(relativePathPosix, ignorePatterns)) continue;
        stack.push(absolutePath);
        continue;
      }

      if (!entry.isFile()) continue;
      if (hasIgnoredExtension(entry.name)) continue;
      if (isIgnored(relativePathPosix, ignorePatterns)) continue;

      const content = safeReadFile(absolutePath);
      if (content === null) continue;

      results.push({
        absolutePath,
        relativePath: relative(rootPath, absolutePath),
        content,
      });
    }
  }

  return results;
}

function safeReadFile(path: string): string | null {
  try {
    const stat = statSync(path);
    if (stat.size > MAX_FILE_SIZE_BYTES) return null;
    const content = readFileSync(path, "utf-8");
    if (looksBinary(content)) return null;
    return content;
  } catch {
    return null;
  }
}
