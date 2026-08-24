// Wave D4: custom DPI signatures UI.
//
// Structurally identical to RuntimeDLPPage but bound to the signatures
// endpoints. Signatures default to bidirectional (apply_dir=3) on
// create; DLP rules default to egress (apply_dir=1).
//
// The shared backing table means a row authored here shows up in the same
// runtime_threats stream as DLP — only the threat row's row-of-origin
// (via the dp_rule_id → rule) tells operators what fired. We surface the
// distinction by giving signatures their own page so attack-pattern
// authoring doesn't collide visually with data-exfiltration authoring.
//
// Layout: full-width stat row + signatures table. Authoring/editing happens
// on a dedicated form page (the Astronomer add/edit-as-a-page pattern): the
// "New signature" (+) button and a row's pencil navigate to
// runtime-signatures/new and runtime-signatures/:sigId respectively.
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
import { DPIGroupBindingsPanel } from "@/components/DPIGroupBindingsPanel";
import { NeuVectorCompatibilityChips } from "@/components/NeuVectorCompatibilityChips";
import { runtimeRuleOrigin } from "@/lib/runtime-rule-provenance";

import {
  runtimeSignatures,
  type DLPMode,
  type DLPRule,
} from "@/api/client";

const MODE_BADGE: Record<DLPMode, { label: string; tone: "success" | "warning" | "neutral"; icon: React.ReactNode }> = {
  monitor:  { label: "Monitor",  tone: "warning", icon: <ShieldAlert className="h-3 w-3" aria-hidden /> },
  enforce:  { label: "Enforce",  tone: "success", icon: <ShieldCheck className="h-3 w-3" aria-hidden /> },
  disabled: { label: "Disabled", tone: "neutral", icon: <ShieldOff   className="h-3 w-3" aria-hidden /> },
};

const APPLY_DIR_LABEL: Record<number, string> = {
  1: "egress",
  2: "ingress",
  3: "both",
};

export function RuntimeSignaturesPage() {
  const [search] = useSearchParams();
  const { id: pathClusterID } = useParams();
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const q = useQuery({
    queryKey: ["runtime-signatures", clusterID],
    queryFn: () => runtimeSignatures.list(clusterID),
    enabled: !!clusterID,
  });

  const rules = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = rules.filter((r) => r.mode === "enforce").length;
  const monitorCount = rules.filter((r) => r.mode === "monitor").length;

  const columns: Column<DLPRule>[] = [
    { id: "name", header: "Name", cell: (r) => <span className="font-mono">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    {
      id: "category",
      header: "Type",
      cell: (r) => <StatusPill label={r.category === "waf" ? "WAF" : "DPI"} tone={r.category === "waf" ? "accent" : "info"} />,
      sort: (a, b) => a.category.localeCompare(b.category),
    },
    { id: "severity", header: "Sev", numeric: true, cell: (r) => r.severity, sort: (a, b) => a.severity - b.severity },
    {
      id: "direction",
      header: "Direction",
      cell: (r) => <span className="text-mono text-[10px] text-muted-foreground">{APPLY_DIR_LABEL[r.apply_dir] ?? "—"}</span>,
      sort: (a, b) => (APPLY_DIR_LABEL[a.apply_dir] ?? "").localeCompare(APPLY_DIR_LABEL[b.apply_dir] ?? ""),
    },
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
      id: "origin",
      header: "Origin",
      cell: (r) => {
        const origin = runtimeRuleOrigin(r);
        return (
          <span title={r.source_path || r.source || r.cfg_type}>
            <StatusPill label={origin.label} tone={origin.tone} />
          </span>
        );
      },
      sort: (a, b) => runtimeRuleOrigin(a).label.localeCompare(runtimeRuleOrigin(b).label),
    },
    {
      id: "patterns",
      header: "Patterns",
      numeric: true,
      cell: (r) => (Array.isArray(r.patterns) ? r.patterns.length : 0),
      sort: (a, b) => (Array.isArray(a.patterns) ? a.patterns.length : 0) - (Array.isArray(b.patterns) ? b.patterns.length : 0),
    },
    { id: "actions", header: "Actions", className: "text-right", cell: (r) => <SignatureActions r={r} onEdit={() => navigate(r.id)} /> },
  ];

  if (!clusterID) {
    return (
      <div className="flex h-[calc(100vh-72px)] items-center justify-center text-sm text-muted-foreground" data-testid="runtime-signatures-empty">
        Select a cluster (the URL needs <code>?cluster_id=&lt;uuid&gt;</code>).
      </div>
    );
  }
  return (
    <div className="space-y-6" data-testid="runtime-signatures-page">
      <PageHeader
        title="DPI Signatures"
        description="Attack-pattern PCRE rules dp matches against packet payloads (bidirectional by default). New signatures start in monitor mode; promote one to enforce to start blocking."
        actions={
          <div className="flex items-center gap-2">
            <ImportExportButtons
              filename="constellation-dpi-signatures.yaml"
              label="WAF/DPI signatures"
              exportYaml={() => runtimeSignatures.exportYaml(clusterID)}
              importYaml={(text) => runtimeSignatures.importYaml(clusterID, text)}
              onImported={() => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] })}
            />
            <Button size="sm" variant="outline" onClick={() => navigate("new")} data-testid="runtime-signatures-new">
              <Plus className="mr-1 h-3.5 w-3.5" /> New signature
            </Button>
          </div>
        }
      />

      <NeuVectorCompatibilityChips
        testId="runtime-signatures-nv-compatibility"
        items={[
          { label: "NV WAF Sensors -> WAF/DPI Signatures" },
          { label: "NV waf_group -> WAF/DPI group scope" },
          { label: "Migration Imports", to: "/settings/migration" },
        ]}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
        <StatCard label="Total signatures" value={rules.length} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitoring" value={monitorCount} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforcing" value={enforceCount} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={enforceCount > 0 ? "accent" : "neutral"} />
      </section>

      <DPIGroupBindingsPanel
        clusterId={clusterID}
        kind="waf"
        title="WAF/DPI signature group scope"
        description="Groups opted into the shared detector used by custom DPI signatures and imported NeuVector WAF rules."
        testId="signature-group-bindings"
      />

      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-signatures-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState error={q.error} />}
        {q.data && (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.id}
            showDensityToggle={false}
            emptyState={<EmptyState title="No signatures yet" hint="Click New signature to author one." />}
          />
        )}
      </div>
    </div>
  );
}

function SignatureActions({ r, onEdit }: { r: DLPRule; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const promote = useMutation({
    mutationFn: () => runtimeSignatures.promote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  const demote = useMutation({
    mutationFn: () => runtimeSignatures.demote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimeSignatures.remove(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures"] }),
  });
  return (
    <div className="inline-flex items-center gap-1" data-testid={`runtime-signature-row-${r.id}`}>
      {r.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={() => promote.mutate()} disabled={promote.isPending} data-testid={`runtime-signature-promote-${r.id}`}>
          Promote
        </Button>
      )}
      {r.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => demote.mutate()} disabled={demote.isPending} data-testid={`runtime-signature-demote-${r.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" onClick={onEdit} data-testid={`runtime-signature-edit-${r.id}`}>
        <Edit3 className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        onClick={() => {
          if (window.confirm(`Delete signature "${r.name}"?`)) remove.mutate();
        }}
        disabled={remove.isPending}
        data-testid={`runtime-signature-delete-${r.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}
