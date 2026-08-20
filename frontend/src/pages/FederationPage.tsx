import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Crown, GitBranch, Hash, LogOut as LeaveIcon, Plus, Users } from "lucide-react";

import { federation, type FedMember } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";

const memberColumns: Column<FedMember>[] = [
  { id: "name", header: "Cluster", cell: (m) => m.name, className: "text-xs font-medium" },
  { id: "role", header: "Role", cell: (m) => m.role, className: "text-xs" },
  { id: "status", header: "Status", cell: (m) => m.status, className: "text-xs" },
  { id: "revision", header: "Revision", cell: (m) => m.revision, className: "text-xs" },
];

export function FederationPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const state = useQuery({ queryKey: ["fed-state"], queryFn: () => federation.state() });
  const members = useQuery({ queryKey: ["fed-members"], queryFn: () => federation.members() });
  const memberRows = members.data?.members ?? [];

  const transit = useMutation({
    mutationFn: (action: "promote" | "demote" | "leave") =>
      federation.transition(action),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["fed-state"] }),
  });

  const cur = state.data;

  return (
    <PageContainer>
      <PageHeader
        title="Federation"
        description="Share security policies and user groups across multiple Constellation clusters. One cluster is the master; joint clusters receive its synced config. Runtime data stays local to each cluster."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <StatCard label="State" value={cur?.state ?? "unknown"} tone="accent" icon={<Crown className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Master" value={cur?.master_id ? cur.master_id.slice(0, 12) : "—"} hint={cur?.master_id ?? undefined} icon={<GitBranch className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Revision" value={cur?.revision ?? 0} icon={<Hash className="h-3.5 w-3.5" aria-hidden />} />
        <StatCard label="Members" value={memberRows.length} icon={<Users className="h-3.5 w-3.5" aria-hidden />} />
      </section>

      <section className="rounded-lg border border-border bg-card p-4 space-y-3">
        <h2 className="text-sm font-medium">Membership actions</h2>
        <div className="flex flex-wrap gap-2">
          <button
            disabled={cur?.state !== "standalone"}
            onClick={() => transit.mutate("promote")}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            Promote → Master
          </button>
          <button
            disabled={cur?.state !== "master"}
            onClick={() => transit.mutate("demote")}
            className="rounded-md border border-border bg-background px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            Demote → Standalone
          </button>
          <button
            disabled={cur?.state !== "standalone"}
            onClick={() => navigate("/federation/new")}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-primary px-3 py-1.5 text-xs font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            <Plus className="h-3.5 w-3.5" />
            Join federation
          </button>
          <button
            disabled={cur?.state !== "joint"}
            onClick={() => transit.mutate("leave")}
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background px-3 py-1.5 text-xs hover:bg-accent disabled:opacity-50"
          >
            <LeaveIcon className="h-3.5 w-3.5" />
            Leave federation
          </button>
        </div>
      </section>

      <section className="rounded-lg border border-border bg-card">
        <div className="flex items-center justify-between border-b border-border px-3 py-2">
          <div className="flex items-center gap-2">
            <Users className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Members</span>
          </div>
          <span className="text-xs text-muted-foreground">{memberRows.length}</span>
        </div>
        <DataTable<FedMember>
          rows={memberRows}
          columns={memberColumns}
          rowKey={(m) => m.id}
          showDensityToggle={false}
          className="rounded-none border-0"
          emptyState={
            <div className="px-3 py-6 text-center text-xs text-muted-foreground">
              No federation members.
            </div>
          }
        />
      </section>
    </PageContainer>
  );
}
