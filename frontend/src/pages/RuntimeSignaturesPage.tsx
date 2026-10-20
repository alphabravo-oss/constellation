import { useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import {
  ShieldAlert,
  ShieldCheck,
  ListChecks,
  Plus,
  PenLine,
  Trash2,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { ImportExportButtons } from "@/components/ImportExportButtons";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Collapse } from "@/components/ui/collapse";
import { VerdictBanner } from "@/components/ui/verdict-banner";
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

const MODE_BADGE: Record<DLPMode, { label: string; tone: "warning" | "neutral" }> = {
  monitor: { label: "Monitor configured", tone: "warning" },
  enforce: { label: "Enforce configured", tone: "neutral" },
  disabled: { label: "Disabled", tone: "neutral" },
};

const APPLY_DIR_LABEL: Record<number, string> = {
  1: "egress",
  2: "ingress",
  3: "both",
};

export function RuntimeSignaturesPage() {
  const [search] = useRouteSearchParams();
  const { id: pathClusterID } = useParams({ strict: false });
  const clusterID = pathClusterID ?? search.get("cluster_id") ?? "";
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const q = useQuery({
    queryKey: ["runtime-signatures", clusterID],
    queryFn: () => runtimeSignatures.list(clusterID),
    enabled: !!clusterID,
  });

  const listPath = `/clusters/${encodeURIComponent(clusterID)}/runtime-signatures`;
  const scopedSearch = search.size ? `?${search}` : "";
  const rules = useMemo(() => q.data ?? [], [q.data]);
  const enforceCount = rules.filter((r) => r.mode === "enforce").length;
  const monitorCount = rules.filter((r) => r.mode === "monitor").length;

  const columns: Column<DLPRule>[] = [
    { id: "name", header: "Name", kind: "name", code: true, hideable: false, exportValue: (r) => r.name, cell: (r) => <span className="font-mono">{r.name}</span>, sort: (a, b) => a.name.localeCompare(b.name) },
    {
      id: "category",
      header: "Type", kind: "badge",
      exportValue: (r) => r.category,
      cell: (r) => <StatusPill label={r.category === "waf" ? "WAF" : "DPI"} tone={r.category === "waf" ? "accent" : "info"} />,
      sort: (a, b) => a.category.localeCompare(b.category),
    },
    { id: "severity", header: "Severity", kind: "count", numeric: true, cell: (r) => r.severity, sort: (a, b) => a.severity - b.severity },
    {
      id: "direction",
      header: "Direction", kind: "status", size: 136, minSize: 112, maxSize: 176,
      exportValue: (r) => APPLY_DIR_LABEL[r.apply_dir] ?? "Unknown",
      cell: (r) => <span className="text-mono text-[10px] text-muted-foreground">{APPLY_DIR_LABEL[r.apply_dir] ?? "—"}</span>,
      sort: (a, b) => (APPLY_DIR_LABEL[a.apply_dir] ?? "").localeCompare(APPLY_DIR_LABEL[b.apply_dir] ?? ""),
    },
    {
      id: "mode",
      header: "Configured mode", kind: "status",
      exportValue: (r) => r.mode,
      cell: (r) => {
        const badge = MODE_BADGE[r.mode] ?? { label: "Unknown", tone: "neutral" as const };
        return <StatusPill label={badge.label} tone={badge.tone} />;
      },
      sort: (a, b) => a.mode.localeCompare(b.mode),
    },
    {
      id: "origin",
      header: "Origin", kind: "status", size: 144, minSize: 112, maxSize: 176,
      exportValue: (r) => runtimeRuleOrigin(r).label,
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
      header: "Patterns", kind: "count",
      numeric: true,
      cell: (r) => (Array.isArray(r.patterns) ? r.patterns.length : 0),
      sort: (a, b) => (Array.isArray(a.patterns) ? a.patterns.length : 0) - (Array.isArray(b.patterns) ? b.patterns.length : 0),
    },
    { id: "actions", header: "Actions", kind: "actions", size: 208, minSize: 192, maxSize: 240, wrap: true, hideable: false, exportable: false, className: "text-right", cell: (r) => <SignatureActions clusterID={clusterID} disabled={q.isError} r={r} onEdit={() => navigate({ href: `${listPath}/${encodeURIComponent(r.id)}${scopedSearch}` })} /> },
  ];

  if (!clusterID) {
    return <div className="space-y-6" data-testid="runtime-signatures-empty">
      <PageHeader title="DPI Signatures" description="Configure patterns for inspecting network traffic in a cluster." />
      <EmptyState title="Select a cluster" hint="Choose a cluster to manage its rules and detector scope." />
    </div>;
  }
  return (
    <div className="space-y-6" data-testid="runtime-signatures-page">
      <PageHeader
        title="DPI Signatures"
        description="Configure attack patterns for network traffic inspection, including imported WAF rules. New signatures start in monitor mode."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => void q.refetch()} disabled={q.isFetching}>{q.isFetching ? "Refreshing…" : "Refresh"}</Button>
            <ImportExportButtons
              filename="constellation-dpi-signatures.yaml"
              label="WAF/DPI signatures"
              exportYaml={() => runtimeSignatures.exportYaml(clusterID)}
              importYaml={(text) => runtimeSignatures.importYaml(clusterID, text)}
              onImported={() => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] })}
            />
            <Button size="sm" variant="outline" onClick={() => navigate({ href: `${listPath}/new${scopedSearch}` })} data-testid="runtime-signatures-new">
              <Plus className="mr-1 h-3.5 w-3.5" /> New signature
            </Button>
          </div>
        }
      />


      <VerdictBanner detailMode={q.isError && q.data ? "inline" : "disclosure"} status={q.isError ? "degraded" : "info"}
        title={q.isError ? "Signatures could not be refreshed" : !q.data ? "Loading signatures configuration" : rules.length === 0 ? "No signatures configured" : `${enforceCount} signatures configured for enforcement`}
        detail={q.isError && q.data ? "Showing the last loaded configuration. Retry to see current settings. Deployment status is not available here." : "Configured modes describe intended behavior. Group scope and successful detector deployment determine what is inspected or blocked."}
      />

      <StatGrid>
        <StatCard label="Configured signatures" value={q.data ? rules.length : "—"} icon={<ListChecks className="h-3.5 w-3.5" />} />
        <StatCard label="Monitor configured" value={q.data ? monitorCount : "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} />
        <StatCard label="Enforce configured" value={q.data ? enforceCount : "—"} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone="neutral" />
      </StatGrid>


      <div className="overflow-x-auto rounded-lg border border-border bg-card" data-testid="runtime-signatures-list">
        {q.isLoading && <LoadingState />}
        {q.isError && <ErrorState title="Could not load current signatures." action={<Button onClick={() => void q.refetch()}>Retry</Button>} />}
        {q.data && (
          <DataTable
            rows={rules}
            columns={columns}
            rowKey={(r) => r.id}
            preferencesKey="runtime-signatures"
            defaultHiddenColumnIds={["origin", "patterns", "direction"]}
            exportFileName="constellation-signatures.csv"
            emptyState={<EmptyState title="No signatures yet" hint="Click New signature to author one." />}
          />
        )}
      </div>
      <Collapse label="Advanced">
        <div className="space-y-5">
          <DPIGroupBindingsPanel
            clusterId={clusterID}
            kind="waf"
            title="WAF/DPI signature group scope"
            description="Groups opted into the shared detector used by custom DPI signatures and imported NeuVector WAF rules."
            testId="signature-group-bindings"
          />
          <NeuVectorCompatibilityChips
            testId="runtime-signatures-nv-compatibility"
            items={[
              { label: "NV WAF Sensors -> WAF/DPI Signatures" },
              { label: "NV waf_group -> WAF/DPI group scope" },
              { label: "Migration Imports", to: "/settings/migration" },
            ]}
          />
        </div>
      </Collapse>
    </div>
  );
}

function SignatureActions({ clusterID, disabled, r, onEdit }: { clusterID: string; disabled: boolean; r: DLPRule; onEdit: () => void }) {
  const queryClient = useQueryClient();
  const promote = useMutation({
    mutationFn: () => runtimeSignatures.promote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] }),
  });
  const demote = useMutation({
    mutationFn: () => runtimeSignatures.demote(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] }),
  });
  const remove = useMutation({
    mutationFn: () => runtimeSignatures.remove(r.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ["runtime-signatures", clusterID] }),
  });
  const busy = disabled || promote.isPending || demote.isPending || remove.isPending;
  const failed = promote.isError || demote.isError || remove.isError;
  const resetErrors = () => { promote.reset(); demote.reset(); remove.reset(); };
  return (
    <div className="flex flex-wrap items-center justify-end gap-2" data-testid={`runtime-signature-row-${r.id}`}>
      {r.mode === "monitor" && (
        <Button size="sm" variant="outline" onClick={() => { resetErrors(); promote.mutate(); }} disabled={busy} data-testid={`runtime-signature-promote-${r.id}`}>
          Promote
        </Button>
      )}
      {r.mode === "enforce" && (
        <Button size="sm" variant="outline" onClick={() => { resetErrors(); demote.mutate(); }} disabled={busy} data-testid={`runtime-signature-demote-${r.id}`}>
          Demote
        </Button>
      )}
      <Button size="sm" variant="ghost" disabled={busy} aria-label={`Edit ${r.name}`} onClick={onEdit} data-testid={`runtime-signature-edit-${r.id}`}>
        <PenLine className="h-3.5 w-3.5" />
      </Button>
      <Button
        size="sm"
        variant="ghost"
        aria-label={`Delete ${r.name}`}
        onClick={() => {
          if (window.confirm(`Delete signature "${r.name}"?`)) { resetErrors(); remove.mutate(); }
        }}
        disabled={busy}
        data-testid={`runtime-signature-delete-${r.id}`}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
      {failed && <p role="alert" className="w-full text-xs text-status-error">Could not update this configuration. Refresh and try again.</p>}
    </div>
  );
}
