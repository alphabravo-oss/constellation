// Wave C4: DLP regex rules UI.
//
// One page for the user to author / promote / demote / delete payload
// regex rules. Each rule has a name, severity (1–9), and a list of PCRE
// patterns dp's hyperscan engine compiles. Matches produce runtime_threats
// rows with dlp_name_hash set, which the threat drilldown already
// surfaces via the Wave 5b path.
//
// Layout: full-width stat row + rules table. Authoring/editing happens in a
// right-side Drawer opened by the "New rule" (+) button or a row's pencil —
// browsing the page shows only the verdict + list.
import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  ListChecks,
  Plus,
  Edit3,
  Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { StatCard } from "@/components/ui/stat-card";
import { StatusPill } from "@/components/ui/status-pill";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";

import {
  runtimeDLP,
  type DLPMode,
  type DLPRule,
} from "@/api/client";

const MODE_BADGE: Record<DLPMode, { label: string; tone: "success" | "warning" | "neutral"; icon: React.ReactNode }> = {
  monitor:  { label: "Monitor",  tone: "warning", icon: <ShieldAlert className="h-3 w-3" aria-hidden /> },
  enforce:  { label: "Enforce",  tone: "success", icon: <ShieldCheck className="h-3 w-3" aria-hidden /> },
  disabled: { label: "Disabled", tone: "neutral", icon: <ShieldOff   className="h-3 w-3" aria-hidden /> },
};

export function RuntimeDLPPage() {
  const [search] = useSearchParams();
  const { id: pathClusterID } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const q = useQuery({
    queryKey: ["runtime-dlp-rules", clusterID],
    queryFn: () => runtimeDLP.list(clusterID),
    enabled: !!clusterID,
  });

  // Add/edit now live on dedicated routes (Astronomer pattern; see
  // frontend/CLAUDE.md). Preserve any ?cluster_id= fallback across the nav.
  const openNew = () => navigate({ pathname: "new", search: search.toString() });
  const openEdit = (id: string) => navigate({ pathname: id, search: search.toString() });
  const rules = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = rules.filter((r) => r.mode === "enforce").length;
  const monitorCount = rules.filter((r) => r.mode === "monitor").length;

  const columns: Column<DLPRule>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-mono">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "severity", header: "Sev", numeric: true, cell: (r) => r.severity, sort: (a, b) => a.severity - b.severity },
    {
      id: "mode",
      header: "Mode",
      cell: (r) => {
        const badge = MODE_BADGE[r.mode];
        return <StatusPill label={badge.label} tone={badge.tone} />;
      },
      sort: (a, b) => a.mode.localeCompare(b.mode),
    },
    {
      id: "patterns",
      header: "Patterns",
      numeric: true,
      cell: (r) => (Array.isArray(r.patterns) ? r.patterns.length : 0),
      sort: (a, b) => (Array.isArray(a.patterns) ? a.patterns.length : 0) - (Array.isArray(b.patterns) ? b.patterns.length : 0),
    },
    { id: "actions", header: "Actions", className: "text-right", cell: (r) => <DLPActions r={r} onEdit={() => openEdit(r.id)} /> },
  ];

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-dlp-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-dlp-page">
      <PageHeader
        title="DLP Rules"
        description="Data-loss-prevention patterns dp scans network payloads for. New rules start in monitor mode; promote one to enforce to start blocking matches."
        actions={
          <div className="flex items-center gap-2">
            <ImportExportButtons
              filename="constellation-dlp-rules.yaml"
              label="DLP rules"
              exportYaml={() => runtimeDLP.exportYaml(clusterID)}
              importYaml={(text) => runtimeDLP.importYaml(clusterID, text)}
              onImported={() => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules", clusterID] })}
            />
            <Button size="sm" variant="outline" onClick={openNew} data-testid="runtime-dlp-new">
              <Plus className="mr-1 h-3.5 w-3.5" /> New rule
            </Button>
          </div>
        }
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatCard label="Total rules" value={rules.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={monitorCount} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </section>

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-dlp-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState error={q.error} />}
        {q.data && (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.id}
            showDensityToggle={false}
            emptyState={<EmptyState title="No DLP rules yet" hint="Click New rule to author one." />}
          />
        )}
      </div>
    </div>
  );
}

function DLPActions({ r, onEdit }: { r: DLPRule; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const promote = useMutation({
    mutationFn: () => runtimeDLP.promote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  const demote = useMutation({
    mutationFn: () => runtimeDLP.demote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimeDLP.remove(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-dlp-rules"] }),
  });
  return (
    <div className="inline-flex items-center gap-1" data-testid={`runtime-dlp-row-${r.id}`}>
      {r.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={() => promote.mutate()} disabled={promote.isPending} data-testid={`runtime-dlp-promote-${r.id}`}>
          Promote
        </Button>
      )}
      {r.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => demote.mutate()} disabled={demote.isPending} data-testid={`runtime-dlp-demote-${r.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" onClick={onEdit} data-testid={`runtime-dlp-edit-${r.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (window.confirm(`Delete DLP rule "${r.name}"?`)) remove.mutate();
        }}
        disabled={remove.isPending}
        data-testid={`runtime-dlp-delete-${r.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}
