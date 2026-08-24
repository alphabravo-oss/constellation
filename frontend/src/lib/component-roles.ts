export const NV_COMPONENT_ROLES = [
  { id: "all", label: "All Roles" },
  { id: "controller", label: "Controllers" },
  { id: "enforcer", label: "Enforcers" },
  { id: "scanner", label: "Scanners" },
  { id: "admission", label: "Admission" },
  { id: "discoverer", label: "Import / Discovery" },
  { id: "other", label: "Other" },
] as const;

type ComponentRoleSource = {
  component?: string;
  display_name?: string;
  name?: string;
  role?: string;
  kind?: string;
};

export function nvRoleAlias(item: ComponentRoleSource): { id: string; label: string } {
  const text = [item.component, item.display_name, item.name, item.role, item.kind].join(" ").toLowerCase();
  if (/\b(scanner|scan-worker|vuln|cve)\b/.test(text)) {
    return { id: "scanner", label: "Scanner" };
  }
  if (/\b(admission|webhook)\b/.test(text)) {
    return { id: "admission", label: "Admission" };
  }
  if (/\b(enforcer|runtime-agent|agent|sensor|node-agent)\b/.test(text)) {
    return { id: "enforcer", label: "Enforcer" };
  }
  if (/\b(discoverer|discovery|importer|collector|inventory)\b/.test(text)) {
    return { id: "discoverer", label: "Import / Discovery" };
  }
  if (/\b(controller|control-plane|api)\b/.test(text)) {
    return { id: "controller", label: "Controller" };
  }
  return { id: "other", label: "Other" };
}

export function normalizeNVRole(value: string | null): string {
  const role = value?.trim().toLowerCase() ?? "";
  return NV_COMPONENT_ROLES.some((item) => item.id === role) ? role : "all";
}

export function componentDiagnosticsHref({
  clusterId,
  component,
  role,
}: {
  clusterId?: string;
  component?: string;
  role?: string;
}) {
  const params = new URLSearchParams();
  const normalizedRole = normalizeNVRole(role ?? null);
  if (normalizedRole !== "all") {
    params.set("role", normalizedRole);
  }
  const q = component?.trim();
  if (q) {
    params.set("q", q);
  }
  const query = params.toString();
  return `${clusterId ? `/clusters/${clusterId}/components` : "/components"}${query ? `?${query}` : ""}`;
}
