import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import {
  Network as NetworkIcon,
  Check,
  Ban,
  Plus,
  Power,
  PowerOff,
  Trash2,
  Pencil,
  ArrowUpToLine,
} from "lucide-react";
import {
  networkRules,
  type NetworkRuleInventoryRow,
  type NetworkRuleInventoryParams,
} from "@/api/client";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { Pager } from "@/components/ui/pager";
import { fmtRelative } from "@/lib/format";
import { INVENTORY_MAX_PAGE } from "@/lib/inventory-pagination";
import { exportQueryReady, useExportGuard } from "@/hooks/useExportGuard";
import { useInventoryRoute, ScanInventoryExport } from "./inventory-workspace";
import {
  useNetworkRuleScope,
  NETWORK_RULE_SORTS,
  networkRuleInventoryMatches,
  networkRuleFingerprint,
} from "./network-rule-inventory";
import { Select } from "@/components/ui/form";

const RULE_METADATA_MIGRATION = {
  id: "network-rule-metadata-v1",
  hideColumnIds: ["from-role", "to-role", "comment"],
};

export function NetworkRulesPage() {
  const scope = useNetworkRuleScope(),
    route = useInventoryRoute(INVENTORY_MAX_PAGE),
    navigate = useNavigate();
  const cluster = scope.clusterId ?? "",
    params = route.params;
  const filter = (key: string) =>
    params.get(key)?.trim() === "all" ? "" : (params.get(key)?.trim() ?? "");
  const sort = params.get("sort") ?? "evaluation",
    order = params.get("order") ?? "asc";
  const request: NetworkRuleInventoryParams = {
    q: route.debouncedQuery.trim(),
    from: filter("from"),
    to: filter("to"),
    action: filter("action"),
    status: filter("status"),
    cfg_type: filter("cfg_type"),
    hide_platform: params.get("hide_platform") === "true",
    sort,
    order: order as "asc" | "desc",
    limit: 100,
    offset: route.offset,
  };
  const validRoute =
    [...new Set(params.keys())].every(
      (key) => params.getAll(key).length === 1,
    ) &&
    (!params.has("page") ||
      (/^[1-9]\d*$/.test(params.get("page")!) &&
        Number(params.get("page")) <= INVENTORY_MAX_PAGE)) &&
    NETWORK_RULE_SORTS.includes(sort) &&
    ["asc", "desc"].includes(order) &&
    ["", "allow", "deny"].includes(request.action!) &&
    ["", "enabled", "disabled"].includes(request.status!) &&
    ["", "learned", "learned_override", "user_created"].includes(
      request.cfg_type!,
    ) &&
    (!params.has("hide_platform") ||
      ["true", "false"].includes(params.get("hide_platform")!));
  const key = ["network-rules-inventory", scope.owner, cluster, request];
  const context = JSON.stringify([scope.owner, cluster, request]);
  const q = useQuery({
    queryKey: key,
    enabled: scope.ready && validRoute && !route.debouncing,
    queryFn: async () => {
      const data = await networkRules.inventory(cluster, request);
      if (!networkRuleInventoryMatches(data, cluster, request))
        throw new Error("Network rule response does not match its request");
      return data;
    },
  });
  const available =
    scope.ready &&
    validRoute &&
    !route.debouncing &&
    q.isSuccess &&
    !q.isFetching &&
    exportQueryReady(scope.client, key) &&
    networkRuleInventoryMatches(q.data, cluster, request);
  const fresh = (row?: NetworkRuleInventoryRow) =>
    available &&
    scope.recheck() &&
    exportQueryReady(scope.client, key, q.data) &&
    (!row ||
      q.data!.rules.some(
        (current) =>
          networkRuleFingerprint(current) === networkRuleFingerprint(row),
      ));
  const [uncertainContext, setUncertain] = useState<string | null>(null);
  const uncertain = uncertainContext === context;
  const captureCurrent = useExportGuard(
    context,
    !available || uncertain,
    fresh,
  );
  const invalidate = () =>
    scope.client.invalidateQueries({
      queryKey: ["network-rules-inventory", scope.owner, cluster],
    });
  const action = useMutation({
    mutationFn: async ({
      row,
      kind,
    }: {
      row: NetworkRuleInventoryRow;
      kind: "move" | "toggle" | "status" | "remove";
    }) => {
      if (uncertain || !fresh(row))
        throw new Error("Refresh rule evidence first");
      const current = captureCurrent();
      let receipt: { ok?: boolean; id?: number; priority?: number };
      if (kind === "remove")
        receipt = await networkRules.remove(cluster, row.from, row.to);
      else if (kind === "move")
        receipt = await networkRules.moveTop(cluster, row.from, row.to);
      else
        receipt = await networkRules.upsert(cluster, {
          from: row.from,
          to: row.to,
          ports: row.ports,
          applications: row.applications,
          action:
            kind === "toggle"
              ? row.action === "deny"
                ? "allow"
                : "deny"
              : row.action,
          disable: kind === "status" ? !row.disable : row.disable,
          comment: row.comment,
          priority: row.priority,
        });
      if (
        !current() ||
        receipt?.ok !== true ||
        ((kind === "toggle" || kind === "status") && receipt.id !== row.id) ||
        (kind === "move" && !Number.isSafeInteger(receipt.priority))
      ) {
        setUncertain(context);
        throw new Error("Action response could not be confirmed");
      }
      await invalidate();
    },
  });
  const listPath = `/clusters/${cluster}/network-rules`;
  const returnTo = `${listPath}${params.size ? `?${params}` : ""}${typeof window !== "undefined" ? window.location.hash : ""}`;
  const editHref = (row: NetworkRuleInventoryRow) =>
    `${listPath}/${row.id}/edit?${new URLSearchParams({ from: row.from, to: row.to, return_to: returnTo })}`;
  const rows = available ? q.data!.rules : [],
    summary = available ? q.data!.summary : undefined;
  const busy = !available || uncertain || action.isPending;
  const fullEvaluation =
    sort === "evaluation" &&
    order === "asc" &&
    route.page === 0 &&
    !request.q &&
    !request.from &&
    !request.to &&
    !request.action &&
    !request.status &&
    !request.cfg_type &&
    !request.hide_platform;
  const columns: Column<NetworkRuleInventoryRow>[] = [
    {
      id: "id",
      header: "ID",
      kind: "count",
      numeric: true,
      sort: () => 0,
      cell: (row) => row.id,
    },
    {
      id: "priority",
      header: "Priority",
      kind: "count",
      numeric: true,
      sort: () => 0,
      cell: (row) => row.priority,
    },
    {
      id: "from",
      header: "From",
      kind: "name",
      code: true,
      sort: () => 0,
      cell: (row) => row.from,
    },
    {
      id: "to",
      header: "To",
      kind: "name",
      code: true,
      sort: () => 0,
      cell: (row) => row.to,
    },
    {
      id: "apps",
      header: "Applications",
      kind: "text",
      wrap: true,
      sort: () => 0,
      cell: (row) => row.applications.join(", ") || "any",
    },
    {
      id: "ports",
      header: "Ports",
      kind: "text",
      code: true,
      size: 128,
      sort: () => 0,
      cell: (row) => row.ports,
    },
    {
      id: "action",
      header: "Action",
      kind: "status",
      sort: () => 0,
      cell: (row) => (
        <span className="inline-flex items-center gap-1">
          {row.action === "deny" ? (
            <Ban className="h-3 w-3" />
          ) : (
            <Check className="h-3 w-3" />
          )}
          {row.action}
        </span>
      ),
      exportValue: (row) => row.action,
    },
    {
      id: "status",
      header: "Status",
      kind: "status",
      sort: () => 0,
      cell: (row) => (row.disable ? "Disabled" : "Enabled"),
    },
    {
      id: "learned",
      header: "Type",
      kind: "status",
      sort: () => 0,
      cell: (row) => row.cfg_type,
    },
    {
      id: "matches",
      header: "Matches",
      kind: "count",
      numeric: true,
      sort: () => 0,
      cell: (row) => row.match_counter.toLocaleString(),
      exportValue: (row) => row.match_counter,
    },
    {
      id: "last",
      header: "Last match",
      kind: "date",
      sort: () => 0,
      cell: (row) =>
        row.last_match_timestamp
          ? fmtRelative(new Date(row.last_match_timestamp * 1000).toISOString())
          : "Not observed",
      exportValue: (row) =>
        row.last_match_timestamp
          ? new Date(row.last_match_timestamp * 1000).toISOString()
          : "",
    },
    {
      id: "from-role",
      header: "From platform role",
      kind: "status",
      cell: (row) => row.from_platform_role || "Unclassified",
      exportValue: (row) => row.from_platform_role,
    },
    {
      id: "to-role",
      header: "To platform role",
      kind: "status",
      cell: (row) => row.to_platform_role || "Unclassified",
      exportValue: (row) => row.to_platform_role,
    },
    {
      id: "comment",
      header: "Comment",
      kind: "text",
      wrap: true,
      cell: (row) => row.comment,
    },
    {
      id: "actions",
      header: "",
      kind: "actions",
      size: 176,
      minSize: 176,
      maxSize: 208,
      hideable: false,
      exportable: false,
      cell: (row) => {
        const top = fullEvaluation && rows[0]?.row_id === row.row_id;
        return (
          <div className="flex items-center justify-end gap-1">
            <button
              type="button"
              aria-label={`Move rule from ${row.from} to ${row.to} to top`}
              title={
                top
                  ? "Already highest precedence"
                  : "Move to top (evaluate first)"
              }
              disabled={busy || top}
              onClick={() => action.mutate({ row, kind: "move" })}
            >
              <ArrowUpToLine className="h-3.5 w-3.5" />
            </button>
            <button
              type="button"
              title={row.action === "deny" ? "Set to allow" : "Set to deny"}
              aria-label={`Set rule from ${row.from} to ${row.to} to ${row.action === "deny" ? "allow" : "deny"}`}
              disabled={busy}
              onClick={() => action.mutate({ row, kind: "toggle" })}
            >
              {row.action === "deny" ? (
                <Check className="h-3.5 w-3.5" />
              ) : (
                <Ban className="h-3.5 w-3.5" />
              )}
            </button>
            <button
              type="button"
              title={row.disable ? "Enable rule" : "Disable rule"}
              aria-label={`${row.disable ? "Enable" : "Disable"} rule from ${row.from} to ${row.to}`}
              disabled={busy}
              onClick={() => action.mutate({ row, kind: "status" })}
            >
              {row.disable ? (
                <Power className="h-3.5 w-3.5" />
              ) : (
                <PowerOff className="h-3.5 w-3.5" />
              )}
            </button>
            {busy ? (
              <span aria-label="Edit unavailable">
                <Pencil className="h-3.5 w-3.5 text-muted-foreground" />
              </span>
            ) : (
              <a
                href={editHref(row)}
                title="Edit"
                aria-label={`Edit rule from ${row.from} to ${row.to}`}
              >
                <Pencil className="h-3.5 w-3.5" />
              </a>
            )}
            {row.cfg_type !== "learned" && (
              <button
                type="button"
                title={row.learned ? "Revert to learned" : "Delete rule"}
                aria-label={`${row.learned ? "Revert" : "Delete"} rule from ${row.from} to ${row.to}`}
                disabled={busy}
                onClick={() => {
                  if (
                    fresh(row) &&
                    window.confirm(
                      `${row.learned ? "Revert" : "Delete"} rule from ${row.from} to ${row.to}?`,
                    )
                  )
                    action.mutate({ row, kind: "remove" });
                }}
              >
                <Trash2 className="h-3.5 w-3.5 text-status-error" />
              </button>
            )}
          </div>
        );
      },
    },
  ];
  const sortColumns: Record<string, string> = {
    type: "learned",
    last_match: "last",
  };
  const sortFields: Record<string, string> = {
    learned: "type",
    last: "last_match",
  };
  const setFilter = (key: string, value: string) =>
    route.update({ [key]: value }, true, ["from", "to"].includes(key));
  return (
    <div
      className="space-y-4"
      data-testid="network-rules-page"
      data-cluster-id={cluster}
    >
      <PageHeader
        title="Network Rules"
        description="Review learned traffic and configured allow or deny rules."
        actions={
          <div className="flex items-center gap-2">
            {available && !uncertain && (
              <ImportExportButtons
                filename="constellation-network-rules.yaml"
                label="network rules"
                exportYaml={async () => {
                  const current = captureCurrent();
                  if (!current()) throw new Error("Scope unavailable");
                  const text = await networkRules.exportYaml(cluster);
                  if (!current()) throw new Error("Scope changed");
                  return text;
                }}
                importYaml={async (text) => {
                  const current = captureCurrent();
                  if (!current()) throw new Error("Scope unavailable");
                  const result = await networkRules.importYaml(cluster, text);
                  if (!current()) {
                    setUncertain(context);
                    throw new Error("Import could not be confirmed");
                  }
                  return result;
                }}
                onImported={() => void invalidate()}
              />
            )}
            <Button
              disabled={!available || uncertain}
              onClick={() => {
                if (fresh())
                  void navigate({
                    href: `${listPath}/new?${new URLSearchParams({ return_to: returnTo })}`,
                  });
              }}
            >
              <Plus className="h-4 w-4" />
              Add rule
            </Button>
          </div>
        }
      />
      {!scope.ready ? (
        <ErrorState
          title="Resolve the selected cluster and operator before reviewing network rules."
          action={<Button onClick={scope.retry}>Retry cluster</Button>}
        />
      ) : !validRoute ? (
        <ErrorState
          title="These network rule filters or page are invalid."
          action={<a href={listPath}>Reset filters</a>}
        />
      ) : (
        <>
          <VerdictBanner
            status={q.isError ? "degraded" : "info"}
            title={
              q.isError
                ? "Network rules could not be refreshed"
                : !available
                  ? "Loading network rules"
                  : `${q.data!.total.toLocaleString()} matching network rules`
            }
          />
          <StatGrid>
            {(["total", "allow", "deny", "learned", "disabled"] as const).map(
              (name) => (
                <StatCard
                  key={name}
                  label={
                    name === "total"
                      ? "Rules"
                      : name[0].toUpperCase() + name.slice(1)
                  }
                  value={summary?.[name] ?? "—"}
                  icon={
                    name === "total" ? (
                      <NetworkIcon className="h-3.5 w-3.5" />
                    ) : undefined
                  }
                />
              ),
            )}
          </StatGrid>
          <div className="flex flex-wrap items-end gap-3">
            <label className="min-w-52 flex-1 text-xs">
              Search network rules
              <input
                aria-label="Search network rules"
                value={route.query}
                onChange={(event) => route.setQuery(event.target.value)}
                placeholder="Search from, to, application, port, comment…"
                className="mt-1 w-full rounded border border-border bg-background px-3 py-2"
              />
            </label>
            {(
              [
                ["action", "Action", ["allow", "deny"]],
                ["status", "Status", ["enabled", "disabled"]],
                [
                  "cfg_type",
                  "Type",
                  ["learned", "learned_override", "user_created"],
                ],
              ] as const
            ).map(([name, label, values]) => (
              <label className="text-xs" key={name}>
                {label}
                <Select
                  aria-label={label}
                  className="mt-1 block rounded border border-border bg-background p-2"
                  value={filter(name)}
                  onChange={(event) => setFilter(name, event.target.value)}
                >
                  <option value="">All</option>
                  {values.map((value) => (
                    <option key={value} value={value}>
                      {value}
                    </option>
                  ))}
                </Select>
              </label>
            ))}
            <label className="text-xs">
              Sort
              <Select
                aria-label="Sort network rules"
                className="mt-1 block rounded border border-border bg-background p-2"
                value={sort}
                onChange={(event) => route.update({ sort: event.target.value })}
              >
                {NETWORK_RULE_SORTS.map((value) => (
                  <option value={value} key={value}>
                    {value === "evaluation" ? "Evaluation order" : value}
                  </option>
                ))}
              </Select>
            </label>
            <label className="text-xs">
              Order
              <Select
                aria-label="Sort direction"
                className="mt-1 block rounded border border-border bg-background p-2"
                value={order}
                onChange={(event) =>
                  route.update({ order: event.target.value })
                }
              >
                <option value="asc">Ascending</option>
                <option value="desc">Descending</option>
              </Select>
            </label>
            <label className="flex items-center gap-2 text-xs">
              <input
                type="checkbox"
                checked={request.hide_platform}
                onChange={(event) =>
                  route.update({ hide_platform: String(event.target.checked) })
                }
              />
              Hide platform components
            </label>
            <Button
              variant="outline"
              disabled={q.isFetching}
              onClick={() => void q.refetch()}
            >
              Refresh
            </Button>
          </div>
          <Collapse label="Advanced: exact endpoints">
            <div className="flex flex-wrap gap-3">
              {["from", "to"].map((name) => (
                <label key={name} className="text-xs">
                  Exact {name}
                  <input
                    aria-label={`Exact ${name}`}
                    className="ml-2 rounded border border-border bg-background p-2"
                    value={filter(name)}
                    onChange={(event) => setFilter(name, event.target.value)}
                  />
                </label>
              ))}
            </div>
          </Collapse>
          {uncertain && (
            <ErrorState title="The last write could not be confirmed in this workspace. Reload before another write." />
          )}
          {action.isError && (
            <p role="alert" className="text-sm text-status-error">
              The rule action failed or could not be confirmed. Refresh and
              review before retrying.
            </p>
          )}
          {q.isError ? (
            <ErrorState
              title="Could not load network rules."
              action={<Button onClick={() => void q.refetch()}>Retry</Button>}
            />
          ) : !available ? (
            <LoadingState label="Loading network rules…" />
          ) : (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
                <span>{q.data!.total.toLocaleString()} matching rules</span>
                <ScanInventoryExport
                  context={context}
                  disabled={!available || uncertain}
                  isCurrent={fresh}
                  download={(guard) =>
                    networkRules.inventoryCSV(cluster, request, guard)
                  }
                />
              </div>
              <DataTable
                rows={rows}
                columns={columns}
                rowKey={(row) => row.row_id}
                testId="network-rules-table"
                preferencesKey="network-rules"
                preferenceMigration={RULE_METADATA_MIGRATION}
                defaultHiddenColumnIds={[
                  "id",
                  "from-role",
                  "to-role",
                  "comment",
                ]}
                manualSorting
                sort={
                  sort === "evaluation"
                    ? null
                    : {
                        id: sortColumns[sort] ?? sort,
                        dir: order as "asc" | "desc",
                      }
                }
                onSortChange={(next) =>
                  route.update({
                    sort: next
                      ? (sortFields[next.id] ?? next.id)
                      : "evaluation",
                    order: next?.dir ?? "asc",
                  })
                }
                pagination={false}
                canExport={fresh}
                exportFileName="network-rules-page"
                exportLabel="Export page CSV"
                emptyState={
                  <p className="p-4 text-sm">
                    No matching network rules on this page.
                  </p>
                }
              />
              <Pager
                page={route.page}
                pageSize={100}
                total={q.data!.total}
                rowsOnPage={rows.length}
                onPage={route.setPage}
              />
              {!rows.length && route.page > 0 && (
                <Button onClick={() => route.setPage(0)}>First page</Button>
              )}
            </>
          )}
          <Collapse label="Rule evidence details">
            <p className="text-xs text-muted-foreground">
              Metrics cover every matching retained observed pair and configured
              override. Display sorting applies across server pages; Move to top
              changes configured evaluation priority. Page CSV includes selected
              columns from this page. Matching CSV exports up to 100,000
              matches. Portable YAML exports all authored overrides and ignores
              inventory filters. Configuration and observed traffic do not
              confirm agent enforcement.
            </p>
          </Collapse>
        </>
      )}
    </div>
  );
}
