// FileMonitorPage — file-monitor (FIM) authoring. Mirrors the DLP sensor
// authoring page in spirit but scoped per workload: file-monitor rules live on
// a workload's file profile, so this page lists the monitored workloads and
// lets you add / delete monitor rules for the selected one.
//
// SAFETY: new rules default to `monitor_change` (observe). `block_access` is an
// explicit opt-in and is never selected by default, so authoring a rule here
// never blocks a live workload.
//
// Layout: full-width stat row, a full-width workload picker, then the selected
// workload's rules. Adding / editing a rule happens on a dedicated form page
// (the Astronomer add/edit-as-a-page pattern): the "Add rule" (+) button and a
// row's pencil navigate to file-monitor/new and file-monitor/:ruleId. Browsing
// shows only the lists. The selected workload is carried in the ?workload= param
// so it survives round-trips to the form page.
import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Edit3, FileText, FolderTree, ListChecks, Plus, Trash2 } from "lucide-react";

import { fileProfiles } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState, ErrorState, EmptyState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

export function FileMonitorPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const selected = params.get("workload");
  const [error, setError] = useState<string | null>(null);

  const listQ = useQuery({
    queryKey: ["file-monitor-profiles", clusterId],
    queryFn: () => fileProfiles.list({ cluster_id: clusterId }),
  });
  const profiles = useMemo(() => listQ.data?.profiles ?? [], [listQ.data]);
  const activeWorkload = selected ?? profiles[0]?.workload_id ?? null;
  const totalRules = useMemo(() => profiles.reduce((n, p) => n + p.rule_count, 0), [profiles]);

  const detailQ = useQuery({
    queryKey: ["file-monitor-detail", clusterId, activeWorkload],
    queryFn: () => fileProfiles.get(activeWorkload!, { cluster_id: clusterId }),
    enabled: !!activeWorkload,
  });

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["file-monitor-detail", clusterId, activeWorkload] });
    void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", clusterId] });
  };

  const gotoForm = (segment: string) =>
    navigate(`${segment}${activeWorkload ? `?workload=${encodeURIComponent(activeWorkload)}` : ""}`);

  const delMut = useMutation({
    mutationFn: (ruleID: string) =>
      fileProfiles.deleteRule(activeWorkload!, ruleID, { reason: "removed via file-monitor console" }, { cluster_id: clusterId }),
    onSuccess: invalidate,
    onError: (e) => setError(e instanceof Error ? e.message : "failed to delete rule"),
  });

  if (clusterLoading) return <LoadingState label="Loading cluster…" />;

  const rules = detailQ.data?.rules ?? [];

  return (
    <div className="space-y-6" data-testid="file-monitor-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="File Monitor"
        description={
          <>
            Watch files on a workload for tampering (file-integrity monitoring). New rules default to{" "}
            <span className="font-mono">monitor_change</span> — they observe and alert, they don't block.
          </>
        }
        actions={
          <Button
            size="sm"
            variant="primary"
            disabled={!activeWorkload}
            onClick={() => { setError(null); gotoForm("new"); }}
            data-testid="file-monitor-add-open"
          >
            <Plus className="h-3 w-3" /> Add rule
          </Button>
        }
      />

      {listQ.isPending ? (
        <LoadingState label="Loading file profiles…" />
      ) : listQ.isError ? (
        <ErrorState title="Failed to load file profiles." error={listQ.error} />
      ) : profiles.length === 0 ? (
        <EmptyState title="No file profiles" hint="No workloads are reporting file monitoring yet." />
      ) : (
        <>
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <StatCard label="Monitored workloads" value={profiles.length} icon={<FolderTree className="h-3.5 w-3.5" />} />
            <StatCard label="Total rules" value={totalRules} icon={<ListChecks className="h-3.5 w-3.5" />} />
            <StatCard label="Rules on selected" value={rules.length} icon={<FileText className="h-3.5 w-3.5" />} />
          </section>

          <section className="space-y-2">
            <h2 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Workloads ({profiles.length})
            </h2>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {profiles.map((p) => (
                <button
                  key={p.workload_id}
                  type="button"
                  onClick={() => setParams({ workload: p.workload_id })}
                  className={`rounded-md border bg-card px-3 py-2 text-left transition-colors hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))] ${
                    p.workload_id === activeWorkload ? "border-[color:var(--color-primary)] ring-1 ring-[color:var(--color-primary)]/30" : "border-border"
                  }`}
                >
                  <div className="truncate font-mono text-xs">{p.name || p.workload_id}</div>
                  <div className="mt-0.5 text-[10px] text-muted-foreground">
                    {p.namespace} · {p.mode} · {p.rule_count} rules
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="space-y-2">
            <div className="rounded-md border border-border bg-card">
              <header className="border-b border-border px-3 py-2 text-xs font-semibold">
                Rules for <span className="font-mono">{activeWorkload}</span>
              </header>
              {detailQ.isPending ? (
                <LoadingState label="Loading rules…" />
              ) : (
                <ul className="divide-y divide-border">
                  {rules.map((r) => (
                    <li key={r.id} className="flex items-center justify-between px-3 py-2 text-xs">
                      <div className="min-w-0">
                        <div className="truncate font-mono">{r.filter}</div>
                        <div className="text-[10px] text-muted-foreground">
                          {r.behavior}{r.recursive ? " · recursive" : ""}{r.enabled ? "" : " · disabled"}
                        </div>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        <button
                          type="button"
                          onClick={() => gotoForm(r.id)}
                          className="text-muted-foreground hover:text-foreground"
                          aria-label="edit rule"
                        >
                          <Edit3 className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => delMut.mutate(r.id)}
                          disabled={delMut.isPending}
                          className="text-muted-foreground hover:text-status-error"
                          aria-label="delete rule"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </li>
                  ))}
                  {rules.length === 0 && (
                    <li className="px-3 py-4 text-[11px] text-muted-foreground">No custom file-monitor rules for this workload.</li>
                  )}
                </ul>
              )}
            </div>
            {error && <p className="text-[11px] text-status-error">{error}</p>}
          </section>
        </>
      )}
    </div>
  );
}
