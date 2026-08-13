import { describe, expect, it } from "vitest";
import { computeCorsFix } from "../src/core/corsFix.js";

describe("computeCorsFix", () => {
  it("computes a replacement for a single-quoted origin wildcard", () => {
    const fix = computeCorsFix("app.use(cors({ origin: '*' }));");
    expect(fix).toEqual(
      expect.objectContaining({
        strategy: "replace-cors-wildcard",
        search: "origin: '*'",
        replace: "origin: 'REPLACE_WITH_ALLOWED_ORIGIN'",
      }),
    );
  });

  it("computes a replacement for a double-quoted origin wildcard", () => {
    const fix = computeCorsFix('app.use(cors({ origin: "*" }));');
    expect(fix?.search).toBe('origin: "*"');
    expect(fix?.replace).toBe('origin: "REPLACE_WITH_ALLOWED_ORIGIN"');
  });

  it("returns null for the raw header-string shape (out of scope)", () => {
    const fix = computeCorsFix("res.setHeader('Access-Control-Allow-Origin', '*');");
    expect(fix).toBeNull();
  });

  it("returns null when there's no wildcard origin on the line", () => {
    const fix = computeCorsFix("app.use(cors({ origin: 'https://example.com' }));");
    expect(fix).toBeNull();
  });
});
