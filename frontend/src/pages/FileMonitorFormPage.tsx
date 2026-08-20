// Routes: /clusters/:id/file-monitor/new (create) and
// /clusters/:id/file-monitor/:ruleId (edit).
//
// Dedicated form page (the Astronomer add/edit-as-a-page pattern, replacing the
// old right-side Drawer) for authoring / editing a workload's file-monitor (FIM)
// rules. The target workload is threaded in via the `?workload=` query param set
// by the list page.
//
// SAFETY: new rules default to `monitor_change` (observe). `block_access` is an
// explicit opt-in and is never selected by default, so authoring a rule here
// never blocks a live workload.
import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArrowLeft, FileText, Plus, Save } from "lucide-react";

import { fileProfiles, type FileProfileRuleBehavior } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { LoadingState } from "@/components/ui/states";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";

export function FileMonitorFormPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { ruleId } = useParams<{ ruleId: string }>();
  const [search] = useSearchParams();
  const workload = search.get("workload") ?? "";
  const isEdit = Boolean(ruleId);

  const backTo = `/clusters/${clusterId}/file-monitor${workload ? `?workload=${encodeURIComponent(workload)}` : ""}`;

  const [filter, setFilter] = useState("/etc/");
  const [behavior, setBehavior] = useState<FileProfileRuleBehavior>("monitor_change");
  const [recursive, setRecursive] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Edit: load the workload's profile and prefill from the rule being edited.
  const detailQ = useQuery({
    queryKey: ["file-monitor-detail", clusterId, workload],
    queryFn: () => fileProfiles.get(workload, { cluster_id: clusterId }),
    enabled: isEdit && !!workload,
  });
  const editingRule = detailQ.data?.rules?.find((r) => r.id === ruleId) ?? null;

  useEffect(() => {
    if (editingRule) {
      setFilter(editingRule.filter);
      setBehavior(editingRule.behavior);
      setRecursive(editingRule.recursive);
    }
  }, [editingRule]);

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ["file-monitor-detail", clusterId, workload] });
    void qc.invalidateQueries({ queryKey: ["file-monitor-profiles", clusterId] });
  };

  const save = useMutation({
    mutationFn: () =>
      isEdit
        ? fileProfiles.updateRule(
            workload,
            ruleId!,
            { filter, behavior, recursive, reason: "edited via file-monitor console" },
            { cluster_id: clusterId },
          )
        : fileProfiles.createRule(
            workload,
            { filter, behavior, recursive, reason: "authored via file-monitor console" },
            { cluster_id: clusterId },
          ),
    onSuccess: () => {
      setError(null);
      invalidate();
      navigate(backTo);
    },
    onError: (e) => setError(e instanceof Error ? e.message : "failed to save rule"),
  });

  if (clusterLoading) return <LoadingState label="Loading cluster…" />;

  return (
    <div className="space-y-6" data-testid="file-monitor-form-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={backTo} className="inline-flex items-center gap-1 hover:text-foreground">
            <ArrowLeft className="h-3.5 w-3.5" aria-hidden /> File Monitor
          </Link>
        }
        title={
          <span className="flex items-center gap-2">
            <FileText className="h-5 w-5" aria-hidden />
            {isEdit ? "Edit monitor rule" : "Add monitor rule"}
          </span>
        }
        description={
          <>
            Watch a path on <span className="font-mono">{workload || "the selected workload"}</span> for tampering
            (file-integrity monitoring). New rules default to <span className="font-mono">monitor_change</span> — they
            observe and alert, they don't block.
          </>
        }
      />

      <Card title="Rule" description="Which path to watch, and whether to observe or block on change.">
        <form
          className="flex flex-col gap-3"
          onSubmit={(e) => { e.preventDefault(); save.mutate(); }}
        >
          <label className="flex flex-col gap-1 text-[11px]">
            <span className="text-muted-foreground">Path filter</span>
            <input
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full rounded border border-border bg-background px-2 py-1 font-mono text-xs"
              placeholder="/etc/ or /bin/*"
            />
          </label>
          <label className="flex flex-col gap-1 text-[11px]">
            <span className="text-muted-foreground">Behavior</span>
            <select
              value={behavior}
              onChange={(e) => setBehavior(e.target.value as FileProfileRuleBehavior)}
              className="rounded border border-border bg-background px-2 py-1 text-xs"
            >
              <option value="monitor_change">monitor_change (observe)</option>
              <option value="block_access">block_access (enforce)</option>
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-[11px]">
            <input type="checkbox" checked={recursive} onChange={(e) => setRecursive(e.target.checked)} />
            recursive
          </label>
          <div className="flex items-center gap-3">
            <Button
              type="submit"
              variant="primary"
              size="lg"
              disabled={!workload || !filter.trim() || save.isPending}
            >
              {isEdit ? <Save className="h-4 w-4" /> : <Plus className="h-3 w-3" />}
              {isEdit ? (save.isPending ? "Saving…" : "Save changes") : (save.isPending ? "Adding…" : "Add")}
            </Button>
            <Button type="button" variant="ghost" size="lg" onClick={() => navigate(backTo)}>Cancel</Button>
          </div>
          {error && <p className="text-[11px] text-status-error">{error}</p>}
        </form>
      </Card>
    </div>
  );
}
