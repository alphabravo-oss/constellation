import { Link, useParams } from "@tanstack/react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowUp, ChevronLeft, Pencil, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { groupsApi, type Group, type GroupUsage } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Collapse } from "@/components/ui/collapse";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { fmtRelative } from "@/lib/format";

const NEXT_MODE: Record<string, Group["policy_mode"]> = { discover: "monitor", monitor: "protect" };

export function GroupDetailPage() {
  const { groupId } = useParams({ strict: false });
  const { clusterId, isLoading, cluster, error } = useCluster();
  const qc = useQueryClient();
  const [tab, setTab] = useTabParam("tab", "members");
  const canLoad = Boolean(clusterId && groupId) && !isLoading && !(error && !cluster);
  const q = useQuery({ queryKey: ["groups", clusterId], queryFn: () => groupsApi.list({ cluster_id: clusterId }), enabled: canLoad });
  const matches = q.data?.groups.filter((group) => group.id === groupId) ?? [];
  const group = matches.length === 1 ? matches[0] : undefined;
  const usageQ = useQuery({ queryKey: ["group-usage", clusterId, groupId], queryFn: () => groupsApi.usage(groupId!, { cluster_id: clusterId }), enabled: canLoad && q.isSuccess && Boolean(group) });
  const listPath = clusterId ? `/clusters/${clusterId}/groups` : "/groups";
  const promote = useMutation({
    mutationFn: (dimension: "policy_mode" | "profile_mode") => {
      if (!clusterId || !group || q.isError || group.cfg_type === "fed") throw new Error("Group unavailable");
      const next = NEXT_MODE[group[dimension] ?? "monitor"];
      if (!next) throw new Error("No next mode");
      return groupsApi.update(group.id, { name: group.name, kind: group.kind, comment: group.comment, criteria: group.criteria,
        members: group.members, learned_from: group.learned_from, cfg_type: group.cfg_type,
        policy_mode: dimension === "policy_mode" ? next : group.policy_mode,
        profile_mode: dimension === "profile_mode" ? next : group.profile_mode }, { cluster_id: clusterId });
    },
    onSuccess: (_result, dimension) => {
      toast.success(`Promoted ${dimension === "policy_mode" ? "network" : "process/file"} mode`);
      void qc.invalidateQueries({ queryKey: ["groups", clusterId] });
      void qc.invalidateQueries({ queryKey: ["group-editor", clusterId] });
      void qc.invalidateQueries({ queryKey: ["group-usage", clusterId, groupId] });
      void qc.invalidateQueries({ queryKey: ["dashboard", clusterId] });
    },
  });
  const backLink = <Link to="." href={listPath} className="inline-flex items-center gap-1 hover:text-foreground"><ChevronLeft className="h-3.5 w-3.5" /> Groups</Link>;
  if (!canLoad || q.isPending || q.isError || !group) return <div className="space-y-6">
    <PageHeader title="Group" description="Review workload membership, enforcement modes, and the policies that depend on a group." backLink={backLink} />
    {isLoading || (canLoad && q.isPending) ? <LoadingState label="Loading group…" />
      : !clusterId || (error && !cluster) ? <ErrorState title="Select an available cluster to inspect groups." />
      : q.isError ? <ErrorState title="This group could not be loaded for the selected cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />
      : <ErrorState title="This group was not found in the selected cluster." />}
  </div>;
  const membership = group.membership;
  const learning = group.policy_mode === "discover" || group.profile_mode === "discover";
  const fullyProtected = group.policy_mode === "protect" && group.profile_mode === "protect";
  const usage = !usageQ.isError && usageQ.data?.group_id === groupId ? usageQ.data : undefined;
  const usageError = usageQ.isError || (usageQ.isSuccess && !usage);
  return <div className="space-y-6" data-testid="group-detail-page">
    <PageHeader title={group.name} description={group.comment || "Review matching workloads, adjust enforcement, and inspect the policies that depend on this group."} backLink={backLink}
      badges={<span className="rounded bg-muted px-2 py-1 text-xs capitalize">{group.kind}</span>}
      actions={<div className="flex gap-2"><Button variant="outline" disabled={q.isFetching || usageQ.isFetching} onClick={() => { void q.refetch(); void usageQ.refetch(); }}><RefreshCw className="h-4 w-4" /> Refresh</Button>
        {group.cfg_type !== "fed" && <Button asChild variant="primary"><Link to="." href={`${listPath}/${group.id}/edit`}><Pencil className="h-4 w-4" /> Edit group</Link></Button>}</div>} />
    <VerdictBanner status={learning ? "degraded" : fullyProtected ? "ok" : "info"} title={learning ? "This group is still learning" : fullyProtected ? "Network and process/file protection is enforced" : "This group monitors policy violations"}
      detail={group.cfg_type === "fed" ? "Configuration is managed by the federation master." : "Review matching members before moving from discovery to monitoring or protection."} />
    <StatGrid>
      <StatCard label="Members" value={membership?.member_count ?? group.members?.length ?? 0} />
      <StatCard label="Selectors" value={membership?.criteria_count ?? group.criteria?.length ?? 0} />
      <StatCard label="Network mode" value={group.policy_mode ?? "monitor"} />
      <StatCard label="Process/file mode" value={group.profile_mode ?? "monitor"} />
      <StatCard label="Policy references" value={usage ? usage.summary.total_references : "—"} hint={usageError ? "Usage unavailable" : usageQ.isPending ? "Loading usage" : "All concrete dependencies"} />
    </StatGrid>
    {promote.isError && <p role="alert" className="text-sm text-status-error">Could not change this group's mode. Refresh to verify its current modes, then try again.</p>}
    <Tabs value={["members", "criteria", "usage", "configuration"].includes(tab) ? tab : "members"} onValueChange={setTab} items={[
      { value: "members", label: "Members", count: group.members?.length ?? 0, content: <Card title="Matching workloads" description="Current membership computed from the selectors and observed workloads.">
        <div data-testid="group-membership-preview" className="mb-4 text-sm text-muted-foreground">Last matched {fmtRelative(membership?.last_matched_at)}{membership?.last_matched_member ? ` · ${membership.last_matched_member}` : " · No current deployment evidence"}</div>
        <DataTable rows={(group.members ?? []).map((member) => ({ member }))} rowKey={(row) => row.member} preferencesKey="group-members" exportFileName="group-members.csv" defaultSort={{ id: "member", dir: "asc" }} columns={[
          { id: "member", kind: "name", grow: true, minSize: 240, header: "Workload", hideable: false, code: true, cell: (row) => <Link to="." href={`/clusters/${clusterId}/deployments?q=${encodeURIComponent(row.member.split("/").pop() ?? row.member)}`} className="text-primary hover:underline">{row.member}</Link>, exportValue: (row) => row.member, sort: (a, b) => a.member.localeCompare(b.member) },
        ]} emptyState={<EmptyState title="No matching members" hint="Review the selectors and confirm matching workloads are reporting to this cluster." />} />
      </Card> },
      { value: "criteria", label: "Membership selectors", count: group.criteria?.length ?? 0, content: <Card title="Membership selectors" description="Every selector must match for a workload to belong to this group.">
        <DataTable rows={(group.criteria ?? []).map((criterion, index) => ({ ...criterion, index }))} rowKey={(row) => row.index} preferencesKey="group-selectors" exportFileName="group-selectors.csv" columns={[
          { id: "key", kind: "id", size: 192, minSize: 160, header: "Key", cell: (row) => row.key, sort: (a, b) => a.key.localeCompare(b.key), code: true },
          { id: "op", kind: "status", header: "Operator", cell: (row) => row.op || "eq", sort: (a, b) => (a.op || "eq").localeCompare(b.op || "eq") },
          { id: "value", kind: "text", grow: true, minSize: 240, wrap: true, header: "Value", cell: (row) => row.value, sort: (a, b) => a.value.localeCompare(b.value), code: true },
        ]} emptyState={<EmptyState title="No selectors" hint="This group has no membership selectors and will not match workloads." />} />
      </Card> },
      { value: "usage", label: "Policy usage", count: usage?.summary.total_references, content: <GroupUsagePanel usage={usage} isLoading={usageQ.isPending} isError={usageError} onRetry={() => void usageQ.refetch()} /> },
      { value: "configuration", label: "Enforcement & details", content: <Card title="Enforcement modes" description="Move each mode forward after reviewing member coverage. Protect enforces network or process/file policy.">
        <div className="grid gap-5 sm:grid-cols-2">
          {(["policy_mode", "profile_mode"] as const).map((dimension) => <div key={dimension} className="space-y-3 rounded-md border border-border p-4"><h3 className="text-sm font-semibold">{dimension === "policy_mode" ? "Network" : "Process/file"}</h3><p className="text-sm capitalize">{group[dimension] ?? "monitor"}</p>
            {NEXT_MODE[group[dimension]] && group.cfg_type !== "learned" && group.cfg_type !== "fed" && <Button variant="outline" disabled={promote.isPending || q.isFetching} onClick={() => promote.mutate(dimension)}><ArrowUp className="h-4 w-4" /> Move to {NEXT_MODE[group[dimension]]}</Button>}</div>)}
        </div>
        <Collapse label="Configuration provenance and timestamps" className="mt-4"><dl className="grid gap-4 text-sm sm:grid-cols-2"><div><dt className="text-muted-foreground">Configuration source</dt><dd>{group.cfg_type || "user"}</dd></div><div><dt className="text-muted-foreground">Learned from</dt><dd>{group.learned_from || "Not learned"}</dd></div><div><dt className="text-muted-foreground">Created</dt><dd>{fmtRelative(group.created_at)}</dd></div><div><dt className="text-muted-foreground">Updated</dt><dd>{fmtRelative(group.updated_at)}</dd></div></dl></Collapse>
      </Card> },
    ]} />
  </div>;
}

function GroupUsagePanel({ usage, isLoading, isError, onRetry }: { usage?: GroupUsage; isLoading: boolean; isError: boolean; onRetry: () => void }) {
  return <Card title="Policy usage" description="Concrete policy references that depend on this group, including dependencies that block deletion.">
    <div data-testid="group-usage-panel">
      {isLoading ? <LoadingState label="Loading policy usage…" /> : isError ? <ErrorState title="Policy usage could not be loaded." action={<Button onClick={onRetry}>Retry</Button>} /> : !usage ? <ErrorState title="Policy usage is unavailable." action={<Button onClick={onRetry}>Retry</Button>} /> : <div className="space-y-5">
        <p className="text-sm text-muted-foreground">{usage.summary.delete_blocked ? `Deletion is blocked by ${usage.summary.blocking_references} policy reference${usage.summary.blocking_references === 1 ? "" : "s"}. Remove these dependencies first.` : "No policy references currently block deletion."}</p>
        <DataTable rows={usage.references} rowKey={(row) => `${row.family}:${row.kind}:${row.id}:${row.role ?? ""}`} preferencesKey="group-usage" exportFileName="group-policy-usage.csv" testId="group-usage-references" columns={[
          { id: "name", kind: "name", grow: true, minSize: 200, header: "Reference", hideable: false, cell: (row) => row.route ? <Link to="." href={row.route} className="text-primary hover:underline">{row.name}</Link> : row.name, sort: (a, b) => a.name.localeCompare(b.name), exportValue: (row) => row.name },
          { id: "family", kind: "status", header: "Family", cell: (row) => row.family, sort: (a, b) => a.family.localeCompare(b.family) },
          { id: "kind", kind: "status", size: 160, minSize: 144, header: "Kind", cell: (row) => row.kind, sort: (a, b) => a.kind.localeCompare(b.kind) },
          { id: "role", kind: "text", size: 160, minSize: 144, wrap: true, header: "Role / mode", cell: (row) => [row.role, row.mode].filter(Boolean).join(" · ") || "—" },
          { id: "blocking", kind: "status", size: 144, minSize: 128, header: "Dependency", cell: (row) => row.blocking ? "Blocks deletion" : "Derived", sort: (a, b) => Number(a.blocking) - Number(b.blocking) },
          { id: "detail", kind: "text", grow: true, minSize: 240, wrap: true, header: "Details", cell: (row) => row.detail || "—" },
        ]} emptyState={<EmptyState title="No concrete references" hint="No policies or member profile artifacts currently reference this group." />} />
        <Collapse label="Modeled coverage"><div className="grid gap-4 sm:grid-cols-2" data-testid="group-usage-coverage">{usage.coverage.map((item) => <div key={item.family} className="rounded-md border border-border p-4"><div className="flex justify-between gap-3 text-sm"><span className="font-medium">{item.family}</span><span className="text-muted-foreground">{item.status.replaceAll("_", " ")}</span></div><p className="mt-2 text-xs text-muted-foreground">{item.detail}</p></div>)}</div></Collapse>
      </div>}
    </div>
  </Card>;
}
