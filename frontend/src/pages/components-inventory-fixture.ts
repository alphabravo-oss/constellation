import type { ComponentInventoryResponse, ComponentsInventoryParams } from "@/api/client";
import { nvRoleAlias } from "@/lib/component-roles";
// Server-response fixtures for meaningful scope/filter/continuation tests.
export function componentFixture(data: ComponentInventoryResponse, params: ComponentsInventoryParams = { cluster_id: "cluster", sort: "component", order: "asc", limit: 100, offset: 0 }): ComponentInventoryResponse {
 const counts: Record<string, number> = { all: data.summary.total_instances, controller: 0, enforcer: 0, scanner: 0, admission: 0, discoverer: 0, other: 0 };
 for (const item of data.components) counts[nvRoleAlias(item).id]++;
 const rows = data.components.filter(item => (!params.status || item.status === params.status) && (!params.role || nvRoleAlias(item).id === params.role) && (!params.q || [item.component, item.display_name, item.role, nvRoleAlias(item).label, item.scope, item.kind, item.hostname, item.version || "", item.commit || "", item.cluster_name || "", item.status_reason || ""].some(value => value.toLowerCase().includes(params.q!.toLowerCase()))));
 const offset = params.offset || 0;
 return { ...data, components: rows.slice(offset, offset + 100), cluster_id: params.cluster_id, component: params.component || "", q: params.q || "", status: params.status || "", role: params.role || "", sort: params.sort || "component", order: params.order || "asc", limit: params.limit || 100, offset, total: rows.length, has_more: rows.length > offset + 100, role_counts: counts, source_window_hours: 24 };
}
