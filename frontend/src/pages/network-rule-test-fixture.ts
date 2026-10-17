import type {
  NetworkRuleInventoryParams,
  NetworkRuleInventoryResponse,
  NetworkRuleInventoryRow,
} from "@/api/client";
export function ruleRow(
  id: number,
  from = `team/app-${id}`,
  patch: Partial<NetworkRuleInventoryRow> = {},
): NetworkRuleInventoryRow {
  const to = patch.to ?? "team/db";
  return {
    id,
    from,
    to,
    row_id: JSON.stringify([from, to]),
    priority: id,
    match_counter: id,
    last_match_timestamp: 0,
    comment: "",
    ports: "any",
    action: "allow",
    applications: [],
    learned: false,
    disable: false,
    cfg_type: "user_created",
    from_platform_role: "",
    to_platform_role: "",
    ...patch,
  };
}
export function ruleInventory(
  cluster: string,
  source: NetworkRuleInventoryRow[],
  request: NetworkRuleInventoryParams = {},
): NetworkRuleInventoryResponse {
  const filters = {
    q: request.q ?? "",
    from: request.from ?? "",
    to: request.to ?? "",
    action: request.action ?? "",
    status: request.status ?? "",
    cfg_type: request.cfg_type ?? "",
    hide_platform: request.hide_platform ?? false,
  };
  const matches = source.filter(
    (row) =>
      (!filters.q ||
        [row.from, row.to, row.ports, row.applications.join(","), row.comment]
          .join(" ")
          .toLowerCase()
          .includes(filters.q.toLowerCase())) &&
      (!filters.from || row.from === filters.from) &&
      (!filters.to || row.to === filters.to) &&
      (!filters.action || row.action === filters.action) &&
      (!filters.status || row.disable === (filters.status === "disabled")) &&
      (!filters.cfg_type || row.cfg_type === filters.cfg_type) &&
      (!filters.hide_platform ||
        (!row.from_platform_role && !row.to_platform_role)),
  );
  const sort = request.sort ?? "evaluation",
    order = request.order ?? "asc",
    limit = request.limit ?? 100,
    offset = request.offset ?? 0;
  const field = (row: NetworkRuleInventoryRow) =>
    (({
      evaluation: row.priority,
      matches: row.match_counter,
      last_match: row.last_match_timestamp,
      type: row.cfg_type,
      status: Number(row.disable),
      apps: row.applications.join(","),
    })[sort] ?? row[sort as keyof NetworkRuleInventoryRow]) as string | number;
  const sorted = [...matches].sort((a, b) => {
    const av = field(a),
      bv = field(b);
    return (
      (typeof av === "number" && typeof bv === "number"
        ? av - bv
        : String(av).localeCompare(String(bv))) * (order === "desc" ? -1 : 1) ||
      a.row_id.localeCompare(b.row_id)
    );
  });
  return {
    cluster_id: cluster,
    rules: sorted.slice(offset, offset + limit),
    total: matches.length,
    has_more: matches.length > offset + limit,
    summary: {
      total: matches.length,
      allow: matches.filter((row) => row.action === "allow").length,
      deny: matches.filter((row) => row.action === "deny").length,
      learned: matches.filter((row) => row.learned).length,
      disabled: matches.filter((row) => row.disable).length,
    },
    sort,
    order,
    limit,
    offset,
    filters,
    source: "retained_flow_rollups_and_authored_overrides",
    source_complete: true,
    summary_scope: "matching_rules",
  };
}
