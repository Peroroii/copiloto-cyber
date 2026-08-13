import { describe, expect, it } from "vitest";
import { runScan } from "../src/core/scanner.js";

describe("runScan with an explicit files list", () => {
  it("scans only the provided files instead of walking targetPath", async () => {
    const result = await runScan({
      targetPath: "/does/not/exist",
      skipDependencyCheck: true,
      files: [
        {
          absolutePath: "/repo/app.js",
          relativePath: "app.js",
          content: "eval(userInput);",
        },
      ],
    });

    expect(result.filesScanned).toBe(1);
    expect(result.findings.some((f) => f.file === "app.js")).toBe(true);
  });

  it("returns no findings for an empty files list", async () => {
    const result = await runScan({ targetPath: "/does/not/exist", skipDependencyCheck: true, files: [] });
    expect(result.filesScanned).toBe(0);
    expect(result.findings).toEqual([]);
  });
});
