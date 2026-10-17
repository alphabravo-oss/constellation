import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { useBlocker } from "@tanstack/react-router";
import { toast } from "sonner";
import { systemConfigApi, type SystemConfigResponse } from "@/api/client";
import { useAppForm, useStore } from "@/lib/form";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

const days = z.number().int("Enter a whole number of days.").min(0).max(3650);
const retentionSchema = z.object({
  network_flow_retention_days: days,
  events_retention_days: days,
  scan_job_retention_days: days,
});

function valuesFrom(data: SystemConfigResponse) {
  const number = (key: string) => typeof data.config[key] === "number" ? data.config[key] as number : 0;
  return {
    network_flow_retention_days: number("network_flow_retention_days"),
    events_retention_days: number("events_retention_days"),
    scan_job_retention_days: number("scan_job_retention_days"),
  };
}

export function DataRetentionPage() {
  const query = useQuery({ queryKey: ["system-config"], queryFn: () => systemConfigApi.get() });
  return <div className="space-y-6">
    <PageHeader title="Data Retention" description="Control how long raw network flows, runtime events, and finished scan jobs are kept." />
    {query.isPending ? <p role="status">Loading retention settings…</p> : query.isError && !query.data ?
      <div role="alert">Could not load retention settings. <Button onClick={() => void query.refetch()}>Retry</Button></div> :
      <RetentionForm data={query.data!} />}
  </div>;
}

function RetentionForm({ data }: { data: SystemConfigResponse }) {
  const qc = useQueryClient();
  const savedValues = useMemo(() => valuesFrom(data), [data]);
  const [loadedRevision, setLoadedRevision] = useState(data.revision);
  const [saveError, setSaveError] = useState("");
  const form = useAppForm({
    defaultValues: savedValues,
    validators: { onChange: retentionSchema, onSubmit: retentionSchema },
    onSubmit: async ({ value }) => {
      if (loadedRevision !== data.revision) {
        setSaveError("Settings changed elsewhere. Your edits are preserved; reload current settings before saving.");
        return;
      }
      setSaveError("");
      try {
        const saved = await systemConfigApi.patch(value, loadedRevision);
        qc.setQueryData(["system-config"], saved);
        form.reset(valuesFrom(saved));
        setLoadedRevision(saved.revision);
        toast.success("Retention settings saved");
      } catch (error) {
        const status = (error as { response?: { status?: number } })?.response?.status;
        if (status === 409 || status === 412) {
          setSaveError("Config changed elsewhere. Your edits are preserved; reload current settings before trying again.");
          void qc.invalidateQueries({ queryKey: ["system-config"] });
        } else {
          setSaveError("Could not save retention settings. Your edits are preserved; please retry.");
        }
      }
    },
  });
  const dirty = useStore(form.store, (state) => state.isDirty);
  useEffect(() => {
    if (!dirty) {
      form.reset(savedValues);
      setLoadedRevision(data.revision);
    }
  }, [data.revision, savedValues, dirty, form]);
  useBlocker({
    shouldBlockFn: () => dirty && !window.confirm("Discard unsaved retention settings?"),
    enableBeforeUnload: dirty,
  });
  const allOff = Object.values(savedValues).every((value) => value === 0);
  return <>
    <VerdictBanner status={allOff ? "degraded" : "ok"}
      title={allOff ? "Retention disabled for this organization" : "Retention windows configured"}
      detail="Shared storage uses the longest window across organizations. A zero value in any organization holds that history indefinitely. Raw flow pruning also waits for successful aggregation." />
    <form className="space-y-6" noValidate onSubmit={(e) => { e.preventDefault(); void form.handleSubmit(); }}>
      {(saveError || (dirty && loadedRevision !== data.revision)) && <div role="alert" className="space-y-2">
        <p>{saveError || "Settings changed elsewhere. Your unsaved edits are preserved."}</p>
        <Button type="button" onClick={() => { form.reset(savedValues); setLoadedRevision(data.revision); setSaveError(""); }}>Reload current settings</Button>
      </div>}
      <Card title="Network flows" description="Raw per-connection records. Historical hourly aggregates are preserved when raw flows expire.">
        <form.AppField name="network_flow_retention_days">{(field) => <field.NumberField label="Keep raw flows for (days)" min={0} max={3650} hint="0 keeps raw flows indefinitely. New organizations default to 14 days." />}</form.AppField>
      </Card>
      <Card title="Runtime events" description="Process, network, and file events emitted by runtime agents.">
        <form.AppField name="events_retention_days">{(field) => <field.NumberField label="Keep events for (days)" min={0} max={3650} hint="0 keeps events indefinitely. New organizations default to 30 days." />}</form.AppField>
      </Card>
      <Card title="Scan-job history" description="Finished scan jobs. Live jobs and scan results are kept.">
        <form.AppField name="scan_job_retention_days">{(field) => <field.NumberField label="Keep finished scan jobs for (days)" min={0} max={3650} hint="0 keeps finished jobs indefinitely. New organizations default to 7 days." />}</form.AppField>
      </Card>
      <form.AppForm><form.SubmitButton>Save retention settings</form.SubmitButton></form.AppForm>
    </form>
  </>;
}
