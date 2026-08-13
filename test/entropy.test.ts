import { describe, expect, it } from "vitest";
import { shannonEntropy } from "../src/core/entropy.js";

describe("shannonEntropy", () => {
  it("returns 0 for an empty string", () => {
    expect(shannonEntropy("")).toBe(0);
  });

  it("returns 0 for a string of a single repeated character", () => {
    expect(shannonEntropy("aaaaaaaa")).toBe(0);
  });

  it("returns a higher value for random-looking strings than for words", () => {
    const word = shannonEntropy("password");
    const random = shannonEntropy("k3F!9zQwXm2#pLr8");
    expect(random).toBeGreaterThan(word);
  });
});
