import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { Pencil, RefreshCw } from "lucide-react";
import { responseRules, type ResponseRule } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";

export function ResponsePage() {
  const { clusterId, cluster, isLoading } = useCluster();
  if (isLoading) return <LoadingState label="Loading cluster…" />;
  if (!clusterId || !cluster) return <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />;
  return <ResponseCatalog key={clusterId} clusterId={clusterId} />;
}

function ResponseCatalog({ clusterId }: { clusterId: string }) {
  const navigate = useNavigate();
  const [search, setSearch] = useRouteSearchParams();
  const eventType = search.get("event") ?? "all";
  const filter = search.get("q") ?? "";
  // This API manages organization-wide built-in overrides, separate from V2
  // cluster-authored rules. Its global cache and unscoped request are intentional.
  const q = useQuery({ queryKey: ["response-rules"], queryFn: () => responseRules.list() });
  const rules = useMemo(() => q.data?.rules ?? [], [q.data?.rules]);
  const eventTypes = useMemo(() => [...new Set(rules.map((r) => r.event_type))].sort(), [rules]);
  const filtered = useMemo(() => rules.filter((rule) =>
    (eventType === "all" || rule.event_type === eventType) &&
    `${rule.name} ${rule.description} ${rule.match} ${rule.actions.join(" ")}`.toLowerCase().includes(filter.toLowerCase()),
  ), [rules, eventType, filter]);
  const setFilter = (key: string, value: string) => setSearch((current) => { if (!value || value === "all") current.delete(key); else current.set(key, value); return current; }, { replace: true });
  const openEditor = (rule: ResponseRule) => void navigate({ href: `/clusters/${clusterId}/response/${encodeURIComponent(rule.id)}/edit${search.size ? `?${search}` : ""}` });
  const columns: Column<ResponseRule>[] = [
    { id: "name", kind: "name", grow: true, minSize: 220, wrap: true, header: "Built-in rule", hideable: false, cell: (rule) => <div><span className="font-medium">{rule.name}</span><p className="mt-1 text-xs text-muted-foreground">{rule.description}</p></div>, exportValue: (r) => r.name, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "event", kind: "status", size: 112, minSize: 88, header: "Event type", cell: (r) => r.event_type, sort: (a, b) => a.event_type.localeCompare(b.event_type) },
    { id: "mode", kind: "status", size: 104, minSize: 88, header: "Mode", cell: (r) => r.mode, sort: (a, b) => a.mode.localeCompare(b.mode) },
    { id: "enabled", kind: "status", size: 112, minSize: 96, header: "Status", cell: (r) => r.enabled ? "Enabled" : "Disabled", exportValue: (r) => r.enabled, sort: (a, b) => Number(a.enabled) - Number(b.enabled) },
    { id: "actions", kind: "text", size: 176, minSize: 160, wrap: true, header: "Response actions", cell: (r) => r.actions.join(", "), exportValue: (r) => r.actions.join(", ") },
    { id: "override", kind: "status", size: 160, minSize: 144, wrap: true, header: "Source", cell: (r) => r.managed ? "Organization override" : "Built-in default" },
    { id: "edit", kind: "actions", size: 176, minSize: 160, maxSize: 192, header: "Manage", hideable: false, exportable: false, cell: (r) => <Button variant="ghost" disabled={q.isError || q.isFetching} onClick={() => openEditor(r)} aria-label={`Edit override for ${r.name}`}><Pencil className="h-4 w-4" /> Edit override</Button> },
  ];
  return <div className="space-y-6" data-testid="response-catalog-page" data-cluster-id={clusterId}>
    <PageHeader title="Response Catalog" description="Review built-in response rules and their organization-wide overrides. These settings are shared across clusters; authored response rules have a separate configuration."
      actions={<><Button onClick={() => void navigate({ href: `/clusters/${clusterId}/response-rules` })}>Authored response rules</Button><Button disabled={q.isFetching} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" /> Refresh</Button></>} />
    {q.isPending ? <LoadingState label="Loading response catalog…" /> : !q.data ? <ErrorState title="Could not load the organization response catalog." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : <>
      <VerdictBanner status={q.isError ? "degraded" : "info"} title={q.isError ? "Response catalog could not be refreshed" : `${rules.filter((r) => r.enabled).length} built-in rules are enabled across the organization`} detail={q.isError ? "Showing the last loaded settings. Refresh before editing an override." : "Configured modes and actions describe response settings. Actual enforcement depends on the runtime agents and action delivery."} />
      <StatGrid>
        <StatCard label="Built-in rules" value={rules.length} />
        <StatCard label="Enabled" value={rules.filter((r) => r.enabled).length} />
        <StatCard label="Enabled · monitor" value={rules.filter((r) => r.enabled && r.mode === "monitor").length} />
        <StatCard label="Enabled · enforce" value={rules.filter((r) => r.enabled && r.mode === "enforce").length} />
        <StatCard label="Organization overrides" value={rules.filter((r) => r.managed).length} />
      </StatGrid>
      <div className="grid gap-4 sm:grid-cols-2" data-testid="response-rule-filters">
        <label className="block space-y-2 text-sm"><span className="font-medium">Search built-in rules</span><input value={filter} onChange={(e) => setFilter("q", e.target.value)} className="h-10 w-full rounded-md border border-border bg-card px-3" placeholder="Rule name, match or action" /></label>
        <label className="block space-y-2 text-sm"><span className="font-medium">Event type</span><select value={eventType} onChange={(e) => setFilter("event", e.target.value)} className="h-10 w-full rounded-md border border-border bg-card px-3"><option value="all">All event types</option>{eventType !== "all" && !eventTypes.includes(eventType) && <option value={eventType}>Unknown event type: {eventType}</option>}{eventTypes.map((type) => <option key={type} value={type}>{type}</option>)}</select></label>
      </div>
      <p className="text-xs text-muted-foreground">{filtered.length} matching rules out of {rules.length} loaded organization rules.</p>
      <DataTable rows={filtered} columns={columns} rowKey={(r) => r.id} onRowClick={q.isError || q.isFetching ? undefined : openEditor} preferencesKey="response-catalog" exportFileName="response-catalog.csv" testId="response-rules-table" rowTestId={() => "response-rule-row"} emptyState={<EmptyState title={rules.length ? "No matching rules" : "No built-in response rules"} hint={rules.length ? "Change the search or event type filter." : "No rules were returned by the organization catalog."} />} />
    </>}
  </div>;
}
