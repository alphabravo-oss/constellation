import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { systemConfigApi } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput } from "@/components/ui/form";

/**
 * Data Retention — how long the two highest-volume tables (raw network flows and
 * runtime events) are kept before automatic pruning. Bounds storage growth.
 */
export function DataRetentionPage() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  const [flows, setFlows] = useState(0);
  const [events, setEvents] = useState(0);
  const [scanJobs, setScanJobs] = useState(0);

  useEffect(() => {
    const c = q.data?.config;
    if (!c) return;
    setFlows(typeof c.network_flow_retention_days === "number" ? c.network_flow_retention_days : 0);
    setEvents(typeof c.events_retention_days === "number" ? c.events_retention_days : 0);
    setScanJobs(typeof c.scan_job_retention_days === "number" ? c.scan_job_retention_days : 0);
  }, [q.data]);

  const save = useMutation({
    mutationFn: (body: Record<string, unknown>) => systemConfigApi.patch(body),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["system-config"] });
      toast.success("Retention settings saved");
    },
    onError: (error: unknown) => {
      const status = (error as { response?: { status?: number } })?.response?.status;
      if (status === 409) {
        void qc.invalidateQueries({ queryKey: ["system-config"] });
        toast.error("Config changed elsewhere; reloaded latest — please retry.");
        return;
      }
      const msg = (error as { response?: { data?: { error?: string } } })?.response?.data?.error;
      toast.error(msg ? `Save failed: ${msg}` : "Failed to save retention settings");
    },
  });

  const bothOff = flows === 0 && events === 0 && scanJobs === 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Data Retention"
        description="Automatically prune the highest-volume history so storage doesn't grow unbounded. Older rows are deleted in batches by a background job."
      />

      <VerdictBanner
        status={bothOff ? "degraded" : "ok"}
        title={bothOff ? "Retention disabled — history is kept forever" : "Automatic pruning is active"}
        detail={bothOff
          ? "Network flows and events accumulate without limit. Set a horizon to cap storage."
          : "A leader-elected job prunes rows past the horizon every few minutes."}
      />

      <form
        className="space-y-6"
        onSubmit={(e) => { e.preventDefault(); save.mutate({ network_flow_retention_days: flows, events_retention_days: events, scan_job_retention_days: scanJobs }); }}
      >
        <Card title="Network flows" description="Raw per-connection flow records (the largest table). The network map and conversations read from a compact hourly rollup that is unaffected by pruning raw flows.">
          <Field label="Keep raw flows for (days)" hint="0 disables pruning (keep forever). Typical: 7–30 days. The hourly rollup used by dashboards is retained regardless.">
            <div className="flex items-center gap-2">
              <TextInput type="number" min={0} max={3650} value={flows}
                onChange={(e) => setFlows(Number.parseInt(e.target.value, 10) || 0)} className="w-32" />
              <span className="text-xs text-muted-foreground">days</span>
            </div>
          </Field>
        </Card>

        <Card title="Runtime events" description="Process, network, and file events emitted by the runtime agents (the second-largest table).">
          <Field label="Keep events for (days)" hint="0 disables pruning (keep forever). Typical: 30–90 days for forensics.">
            <div className="flex items-center gap-2">
              <TextInput type="number" min={0} max={3650} value={events}
                onChange={(e) => setEvents(Number.parseInt(e.target.value, 10) || 0)} className="w-32" />
              <span className="text-xs text-muted-foreground">days</span>
            </div>
          </Field>
        </Card>

        <Card title="Scan-job history" description="Finished image/host scan jobs (completed, failed, canceled). Live jobs and the actual scan results are always kept.">
          <Field label="Keep finished scan jobs for (days)" hint="0 disables pruning (keep forever). Typical: 7–14 days — the queue turns over fast.">
            <div className="flex items-center gap-2">
              <TextInput type="number" min={0} max={3650} value={scanJobs}
                onChange={(e) => setScanJobs(Number.parseInt(e.target.value, 10) || 0)} className="w-32" />
              <span className="text-xs text-muted-foreground">days</span>
            </div>
          </Field>
        </Card>

        <Button type="submit" variant="primary" size="lg" disabled={save.isPending || q.isLoading}>
          {save.isPending ? "Saving…" : "Save retention settings"}
        </Button>
      </form>
    </div>
  );
}
