import { describe, expect, it, vi } from "vitest";
import { scanDependencies, findDependencyManifests } from "../src/core/dependencyScanner.js";
import type { WalkedFile } from "../src/core/fileWalker.js";
import type { FetchLike } from "../src/core/dependencyScanner.js";

function makeFile(content: string, relativePath: string): WalkedFile {
  return { absolutePath: relativePath, relativePath, content };
}

describe("findDependencyManifests", () => {
  it("parses dependencies and devDependencies from package.json", () => {
    const file = makeFile(
      JSON.stringify({
        dependencies: { lodash: "^4.17.15" },
        devDependencies: { vitest: "^2.0.0" },
      }),
      "package.json",
    );
    const deps = findDependencyManifests([file]);
    expect(deps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "lodash", ecosystem: "npm" }),
        expect.objectContaining({ name: "vitest", ecosystem: "npm" }),
      ]),
    );
  });

  it("parses requirements.txt", () => {
    const file = makeFile("flask==2.0.1\n# a comment\nrequests>=2.25.0\n", "requirements.txt");
    const deps = findDependencyManifests([file]);
    expect(deps).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "flask", ecosystem: "PyPI" }),
        expect.objectContaining({ name: "requests", ecosystem: "PyPI" }),
      ]),
    );
  });
});

describe("scanDependencies", () => {
  it("reports a finding when OSV returns a known vulnerability", async () => {
    const file = makeFile(JSON.stringify({ dependencies: { lodash: "4.17.15" } }), "package.json");

    const fetchMock: FetchLike = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        vulns: [
          {
            id: "GHSA-test-1234",
            summary: "Prototype pollution in lodash",
            database_specific: { severity: "HIGH" },
            references: [{ url: "https://example.com/advisory" }],
          },
        ],
      }),
    }));

    const findings = await scanDependencies([file], fetchMock);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("high");
    expect(findings[0].ruleId).toBe("dependency-GHSA-test-1234");
  });

  it("returns no findings when OSV reports nothing", async () => {
    const file = makeFile(JSON.stringify({ dependencies: { lodash: "4.17.21" } }), "package.json");
    const fetchMock: FetchLike = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ vulns: [] }),
    }));

    const findings = await scanDependencies([file], fetchMock);
    expect(findings).toHaveLength(0);
  });

  it("fails gracefully when the network request errors", async () => {
    const file = makeFile(JSON.stringify({ dependencies: { lodash: "4.17.21" } }), "package.json");
    const fetchMock: FetchLike = vi.fn(async () => {
      throw new Error("network down");
    });

    const findings = await scanDependencies([file], fetchMock);
    expect(findings).toHaveLength(0);
  });

  it("skips dependencies without a resolvable concrete version", async () => {
    const file = makeFile(JSON.stringify({ dependencies: { lodash: "*" } }), "package.json");
    const fetchMock: FetchLike = vi.fn();

    const findings = await scanDependencies([file], fetchMock);
    expect(findings).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
