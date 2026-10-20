import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { LogOut as LeaveIcon, Plus } from "lucide-react";
import { federation, type FedMember, type FedMembership } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";

const memberColumns: Column<FedMember>[] = [
  { id: "name", header: "Cluster", kind: "name", wrap: true, cell: m => m.name },
  { id: "role", header: "Role", kind: "status", cell: m => m.role },
  { id: "status", header: "Status", kind: "status", cell: m => m.status },
  { id: "revision", header: "Revision", kind: "count", cell: m => m.revision },
];
export function FederationPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const [params, setParams] = useRouteSearchParams();
  const query = params.get("q") ?? "";
  const state = useQuery({ queryKey: ["fed-state", owner], queryFn: () => federation.state() });
  const members = useQuery({ queryKey: ["fed-members", owner], queryFn: () => federation.members() });
  const stateReady = state.isSuccess && !state.isFetching && !state.isError;
  const membersReady = members.isSuccess && !members.isFetching && !members.isError;
  const cur = stateReady ? state.data : undefined;
  const rows = membersReady ? members.data.members : [];
  const memberRows = rows.filter(member => !query.trim() || [member.name, member.cluster_id, member.role, member.status].some(value => value.toLowerCase().includes(query.trim().toLowerCase())));
  const transit = useMutation({
    mutationFn: (action: "promote" | "demote" | "leave") => {
      const latest = qc.getQueryState<FedMembership>(["fed-state", owner]);
      const expected = action === "promote" ? "standalone" : action === "demote" ? "master" : "joint";
      if (latest?.status !== "success" || latest.fetchStatus !== "idle" || latest.data?.state !== expected) throw new Error("Federation state changed; refresh before retrying.");
      return federation.transition(action);
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["fed-state", owner] }); void qc.invalidateQueries({ queryKey: ["fed-members", owner] }); },
  });
  return <PageContainer>
    <PageHeader title="Federation" description="Organization-wide federation membership and policy synchronization. Runtime data remains local to each member cluster." actions={<Button disabled={state.isFetching || members.isFetching} onClick={() => { void state.refetch(); void members.refetch(); }}>Refresh</Button>} />
    <VerdictBanner status={state.isError || members.isError ? "degraded" : "info"} title={state.isError ? "Federation state is unavailable" : members.isError ? "Federation members are unavailable" : !stateReady || !membersReady ? "Loading federation evidence" : `Federation state: ${cur?.state}`} detail="Membership actions require the latest settled federation state. Member counts describe only the loaded organization inventory." numbers={[{ label: "State", value: cur?.state ?? "Unavailable" }, { label: "Master", value: stateReady ? cur?.master_id?.slice(0, 12) ?? "None reported" : "Unavailable", title: cur?.master_id }, { label: "Revision", value: cur?.revision ?? "Unavailable" }, { label: "Loaded members", value: membersReady ? rows.length : "Unavailable" }]} />
    
    {state.isError && <ErrorState title="Federation state could not be loaded or refreshed." action={<Button onClick={() => void state.refetch()}>Retry state</Button>} />}
    <section className="space-y-3">
      <h2 className="text-sm font-semibold">Members</h2>
      <input aria-label="Search loaded federation members" placeholder="Search loaded members" className="w-full rounded border border-input bg-background px-3 py-2" value={query} onChange={event => setParams(current => { const next = new URLSearchParams(current); if (event.target.value) next.set("q", event.target.value); else next.delete("q"); return next; }, { replace: true })} />
      {members.isError ? <ErrorState title="Federation members could not be loaded or refreshed." action={<Button onClick={() => void members.refetch()}>Retry members</Button>} /> : !membersReady ? <LoadingState label="Loading federation members…" /> : <DataTable rows={memberRows} columns={memberColumns} rowKey={member => member.id} preferencesKey="federation-members" exportFileName="constellation-federation-loaded-members" exportLabel="Export loaded matches CSV" emptyState={<p className="p-6 text-sm text-muted-foreground">No federation members match the loaded inventory.</p>} />}
    </section>
    <Collapse label="Membership actions">
      {transit.isError && <ErrorState title="The federation transition failed. refresh state and retry." />}
      <div className="flex flex-wrap gap-2">
        <Button disabled={cur?.state !== "standalone" || transit.isPending} onClick={() => transit.mutate("promote")}>Promote → Master</Button>
        <Button disabled={cur?.state !== "master" || transit.isPending} onClick={() => transit.mutate("demote")}>Demote → Standalone</Button>
        <Button disabled={cur?.state !== "standalone" || transit.isPending} onClick={() => void navigate({ href: "/federation/new" })}><Plus className="h-3.5 w-3.5" />Join federation</Button>
        <Button disabled={cur?.state !== "joint" || transit.isPending} onClick={() => transit.mutate("leave")}><LeaveIcon className="h-3.5 w-3.5" />Leave federation</Button>
      </div>
    </Collapse>
  </PageContainer>;
}
