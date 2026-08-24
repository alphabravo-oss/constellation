import { describe, expect, it } from "vitest";

import { componentDiagnosticsHref, normalizeNVRole, nvRoleAlias } from "./component-roles";

describe("component role helpers", () => {
  it("maps component names to NeuVector operator role aliases", () => {
    expect(nvRoleAlias({ component: "constellation-controller" })).toMatchObject({ id: "controller" });
    expect(nvRoleAlias({ component: "runtime-agent", kind: "DaemonSet" })).toMatchObject({ id: "enforcer" });
    expect(nvRoleAlias({ component: "scan-worker" })).toMatchObject({ id: "scanner" });
    expect(nvRoleAlias({ component: "admission-webhook" })).toMatchObject({ id: "admission" });
    expect(nvRoleAlias({ component: "inventory-importer" })).toMatchObject({ id: "discoverer" });
  });

  it("builds cluster-scoped diagnostics links with normalized role and search query", () => {
    expect(normalizeNVRole("SCANNER")).toBe("scanner");
    expect(normalizeNVRole("invalid")).toBe("all");
    expect(componentDiagnosticsHref({
      clusterId: "cluster-1",
      component: "scan-worker",
      role: "scanner",
    })).toBe("/clusters/cluster-1/components?role=scanner&q=scan-worker");
  });
});
