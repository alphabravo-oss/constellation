import { describe, expect, it } from "vitest";
import { activeClusterItem, CLUSTER_NAV, CLUSTER_NAV_ITEMS, ORG_NAV, segmentLabel } from "./shell/nav-model";

describe("C1 navigation model", () => {
  const reachable = CLUSTER_NAV_ITEMS.flatMap((item) => [item.path, ...(item.also ?? [])]);

  it("keeps every policy surface reachable through the Policies hub", () => {
    for (const path of ["admission", "policies", "runtime-policies", "groups", "response-rules", "response"]) {
      expect(reachable).toContain(path);
      expect(activeClusterItem(`/clusters/c1/${path}`, "c1")?.label).toBe("Policies");
    }
  });

  it("has six labelled groups plus flat Overview/Policies/Compliance/Agents and no reused icons", () => {
    expect(CLUSTER_NAV.filter((group) => group.label).map((group) => group.label)).toEqual(["Inventory", "Vulnerabilities", "Runtime", "Network"]);
    expect(CLUSTER_NAV_ITEMS.map((item) => item.label)).toEqual([
      "Overview", "Nodes", "Workloads", "Containers", "Images", "Registries", "Serverless",
      "Findings", "Vulnerability profiles", "Exceptions",
      "Activity", "Process baselines", "File monitor", "Signatures",
      "Map", "Rules", "Incidents", "Policies", "Compliance", "Agents",
    ]);
    const icons = [...ORG_NAV, ...CLUSTER_NAV_ITEMS].map((item) => item.icon);
    expect(new Set(icons).size).toBe(icons.length);
  });

  it("maps agents and sensor health to Agents and the longest match wins", () => {
    expect(activeClusterItem("/clusters/c1/health", "c1")?.label).toBe("Agents");
    expect(activeClusterItem("/clusters/c1/runtime/baselines/abc", "c1")?.label).toBe("Process baselines");
    expect(activeClusterItem("/clusters/c1/runtime", "c1")?.label).toBe("Activity");
  });

  it("never renders ids as breadcrumb labels", () => {
    expect(segmentLabel("236ca601-becb-4197-b8f5-0a1b2c3d4e5f", "findings")).toBe("Finding");
    expect(segmentLabel("4db624d8-8f00-4c1d-9a00-000000000000", "assets")).toBe("Asset");
    expect(segmentLabel("CVE-2026-5450", "cve")).toBe("CVE-2026-5450");
    expect(segmentLabel("vuln-profiles")).toBe("Vulnerability profiles");
  });
});
