import { describe, expect, it } from "vitest";
import { artifactIssue, scanEngineEvidence } from "./scan-evidence";

describe("scanner evidence", () => {
  it("never presents absent or unknown outcomes as successful coverage", () => {
    const cases: Array<Record<string, string> | undefined> = [undefined, {}, { trivy: "succeeded" }, { syft: "succeeded", trivy: "succeeded", grype: "unexpected" }];
    for (const status of cases) {
      const evidence = scanEngineEvidence(status);
      expect(evidence.engines.some((engine) => engine.status === "not reported")).toBe(true);
      expect(evidence.message).not.toContain("completed successfully");
    }
  });
  it("shows failure even with successful scanners and zero findings", () => {
    expect(scanEngineEvidence({ syft: "succeeded", trivy: "succeeded", grype: "failed" }).message).toContain("Findings may be incomplete");
  });
  it("reports successful engines without claiming the image is safe", () => {
    const evidence = scanEngineEvidence({ syft: "succeeded", trivy: "succeeded", grype: "succeeded" });
    expect(evidence.message).toContain("Review findings");
    expect(evidence.engines.every((engine) => engine.status === "succeeded")).toBe(true);
  });
  it("distinguishes failed inspections and request errors from missing historical evidence", () => {
    expect(artifactIssue({ status: "error", reason: "image config unavailable" })).toContain("Inspection failed");
    expect(artifactIssue({ status: "skipped" })).toContain("Inspection unavailable");
    expect(artifactIssue(undefined, { response: { status: 503 } })).toContain("could not be loaded");
    expect(artifactIssue(undefined, { response: { status: 404 } })).toBeNull();
    expect(artifactIssue({ status: "observed" })).toBeNull();
  });
});
