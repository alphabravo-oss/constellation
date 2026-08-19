import { describe, expect, it } from "vitest";
import { severityBg, severityOrder } from "./severity";

describe("severityOrder", () => {
  it("ranks critical above info", () => {
    expect(severityOrder("critical")).toBeGreaterThan(severityOrder("info"));
  });

  it("totally orders the five canonical severities", () => {
    const ranks = (["info", "low", "medium", "high", "critical"] as const).map(severityOrder);
    expect(ranks).toEqual([0, 1, 2, 3, 4]);
  });
});

describe("severityBg", () => {
  it("provides a class string for every canonical severity", () => {
    for (const s of ["info", "low", "medium", "high", "critical"] as const) {
      expect(severityBg[s]).toMatch(/bg-\[/);
    }
  });
});
