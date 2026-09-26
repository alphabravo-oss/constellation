import { describe, expect, it } from "vitest";

import {
  isPlatformNamespace,
  isPlatformWorkloadID,
  namespaceFromWorkloadID,
} from "./platform-components";

describe("platform component classification", () => {
  it.each([
    "kube-system",
    "constellation",
    "constellation-system",
    "astronomer",
    "astronomer-system",
    "astronomer-monitoring",
    "astronomer-ingress-nginx",
  ])("classifies %s as a platform namespace", (namespace) => {
    expect(isPlatformNamespace(namespace)).toBe(true);
  });

  it("normalizes whitespace and case", () => {
    expect(isPlatformNamespace("  ASTRONOMER-SYSTEM ")).toBe(true);
  });

  it.each([
    "default",
    "payments",
    "astronomer-screenshot-demo",
    "constellation-api",
    "kube-system-test",
  ])("does not hide similarly named application namespace %s", (namespace) => {
    expect(isPlatformNamespace(namespace)).toBe(false);
  });

  it("extracts and classifies namespace-qualified workload ids", () => {
    expect(namespaceFromWorkloadID("astronomer-system/houston")).toBe("astronomer-system");
    expect(isPlatformWorkloadID("astronomer-system/houston")).toBe(true);
    expect(isPlatformWorkloadID("payments/api")).toBe(false);
    expect(isPlatformWorkloadID("external/8.8.8.8")).toBe(false);
  });
});
