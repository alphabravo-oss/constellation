import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { ArrowLeft, Plus, Trash2 } from "lucide-react";
import { compliance, type Framework, type ComplianceScheduleDelivery } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";

const CADENCES = [{ label: "Daily at 02:00", cron: "0 2 * * *" }, { label: "Weekly Monday at 02:00", cron: "0 2 * * 1" }, { label: "Monthly on the 1st at 02:00", cron: "0 2 1 * *" }, { label: "Every 5 minutes", cron: "*/5 * * * *" }];

export function ComplianceScheduleFormPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const resolvedScope = !!clusterId && cluster?.id === clusterId;
  const scopeReady = resolvedScope && !clusterLoading && !clusterError;
  const [search] = useRouteSearchParams();
  const queryClient = useQueryClient();
  const retryScope = () => { void queryClient.invalidateQueries({ queryKey: ["clusters"] }); void queryClient.invalidateQueries({ queryKey: ["cluster", clusterId] }); };
  const backSearch = new URLSearchParams(search); backSearch.set("tab", "schedules");
  const backTo = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/compliance?${backSearch}` : "/clusters";
  const frameworks = useQuery({ queryKey: ["compliance", "frameworks"], queryFn: () => compliance.frameworks(), enabled: scopeReady });
  const options = useQuery({ queryKey: ["compliance", "db-schedules", clusterId], queryFn: () => compliance.listDBSchedules(clusterId!), enabled: scopeReady });
  const currentFrameworks = frameworks.data?.frameworks;
  const currentFormats = options.data?.report_formats;
  const currentOptionsAvailable = !!currentFrameworks?.length && !!currentFormats?.length;
  const [snapshot, setSnapshot] = useState<{ scope: string; frameworks: Framework[]; formats: string[] } | null>(null);
  useEffect(() => {
    setSnapshot((previous) => previous?.scope === clusterId ? previous : clusterId && currentFrameworks?.length && currentFormats?.length ? { scope: clusterId, frameworks: currentFrameworks, formats: currentFormats } : null);
  }, [clusterId, currentFrameworks, currentFormats]);
  const savedOptions = snapshot?.scope === clusterId ? snapshot : undefined;
  const loaded = (!!frameworks.data && !!options.data) || !!savedOptions;
  const editorFrameworks = currentFrameworks?.length ? currentFrameworks : savedOptions?.frameworks;
  const editorFormats = currentFormats?.length ? currentFormats : savedOptions?.formats;
  const failed = frameworks.isError || options.isError;
  const retry = () => { void frameworks.refetch(); void options.refetch(); };
  return <div className="space-y-6">
    <PageHeader title="New compliance schedule" description="Configure recurring evidence reports for this cluster. Creating a schedule does not confirm that a report has run or been delivered."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Compliance schedules</Link>} />
    {clusterLoading && !resolvedScope ? <LoadingState label="Loading cluster…" /> : !clusterId ? <ErrorState title="Select a cluster to create a schedule." />
      : !resolvedScope || (clusterError && !loaded) ? <ErrorState title="The selected cluster could not be resolved. Review its registration and retry." action={<Button onClick={retryScope}>Retry cluster</Button>} />
      : !loaded && failed ? <ErrorState title="Schedule options could not be loaded." action={<Button onClick={retry}>Retry</Button>} />
      : !loaded ? <LoadingState label="Loading frameworks and report formats…" />
      : !editorFrameworks?.length || !editorFormats?.length ? <ErrorState title="No frameworks or report formats are available for a new schedule." />
      : <>
        {!scopeReady && <p role="alert" className="text-sm text-status-error">Current cluster scope is unavailable. Your draft is preserved; saving is paused until the cluster resolves. <Button variant="outline" onClick={retryScope}>Retry cluster</Button></p>}
        {failed && <p role="alert" className="text-sm text-status-error">Could not refresh schedule options. Your draft is preserved. Retry before saving. <Button variant="outline" onClick={retry}>Retry</Button></p>}
        {!currentOptionsAvailable && <p role="alert" className="text-sm text-status-error">Current frameworks or report formats are unavailable. Your draft is preserved; saving is paused. <Button variant="outline" onClick={retry}>Retry</Button></p>}
        {(frameworks.isFetching || options.isFetching) && <p role="status" className="text-sm text-muted-foreground">Refreshing schedule options before saving…</p>}
        <ScheduleEditor key={clusterId} clusterId={clusterId} frameworks={editorFrameworks} reportFormats={editorFormats} backTo={backTo} unavailable={failed || !scopeReady || !currentOptionsAvailable || frameworks.isFetching || options.isFetching} />
      </>}
  </div>;
}

function ScheduleEditor({ clusterId, frameworks, reportFormats, backTo, unavailable }: { clusterId: string; frameworks: Framework[]; reportFormats: string[]; backTo: string; unavailable: boolean }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [framework, setFramework] = useState(frameworks[0].id);
  const [cron, setCron] = useState(CADENCES[0].cron);
  const [timezone, setTimezone] = useState("UTC");
  const [delivery, setDelivery] = useState<ComplianceScheduleDelivery[]>([{ kind: "file", target: "file:///tmp/compliance-out/" }]);
  const [format, setFormat] = useState(["html", "json", "csv", "sarif", "pdf"].find(value => reportFormats.includes(value)) ?? reportFormats[0]);
  const [template, setTemplate] = useState("compliance-detailed");
  const [customCadence, setCustomCadence] = useState(false);
  const valid = !unavailable && !!name.trim() && frameworks.some((item) => item.id === framework) && cron.trim().split(/\s+/).length === 5 && !!timezone.trim() && reportFormats.includes(format) && !!template.trim();
  const updateTarget = (index: number, patch: Partial<ComplianceScheduleDelivery>) => setDelivery((current) => current.map((target, i) => i === index ? { ...target, ...patch } : target));
  const save = useMutation({
    mutationFn: () => {
      if (!valid) throw new Error("Invalid schedule");
      return compliance.createSchedule({ name: name.trim(), description, cluster_id: clusterId, framework, cron_expression: cron.trim(), timezone: timezone.trim(), delivery, report_format: format, report_template: template });
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["compliance", "db-schedules", clusterId] }); navigate({ href: backTo }); },
  });
  return <Card title="Schedule" description="Choose the framework, cadence, report format, and delivery targets. New schedules are enabled by the service.">
    <form className="space-y-6" data-testid="compliance-schedule-form" onSubmit={(event) => { event.preventDefault(); if (valid && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Name" htmlFor="schedule-name" required><TextInput id="schedule-name" value={name} onChange={(event) => setName(event.target.value)} required data-testid="wizard-name" /></Field>
          <Field label="Framework" htmlFor="schedule-framework" required><Select id="schedule-framework" value={framework} onChange={(event) => setFramework(event.target.value)} data-testid="wizard-framework">{frameworks.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.id})</option>)}</Select></Field>
          <Field label="Description" htmlFor="schedule-description"><TextInput id="schedule-description" value={description} onChange={(event) => setDescription(event.target.value)} /></Field>
          <Field label="Cadence" htmlFor="schedule-cadence" hint={`Times use ${timezone || "UTC"}.`}><Select id="schedule-cadence" value={customCadence ? "custom" : cron} onChange={(event) => { setCustomCadence(event.target.value === "custom"); if (event.target.value !== "custom") setCron(event.target.value); }}>{CADENCES.map((item) => <option key={item.cron} value={item.cron}>{item.label}</option>)}<option value="custom">Custom (set under Advanced)</option></Select></Field>
          <Field label="Report format" htmlFor="schedule-format"><Select id="schedule-format" value={format} onChange={(event) => setFormat(event.target.value)} data-testid="wizard-format">{reportFormats.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}</Select></Field>
        </div>
        <section className="space-y-4" aria-labelledby="schedule-delivery-title">
          <div className="flex items-center justify-between gap-3"><h2 id="schedule-delivery-title" className="text-sm font-semibold">Delivery targets</h2><Button type="button" variant="outline" onClick={() => setDelivery([...delivery, { kind: "email", target: "" }])}><Plus className="mr-1 h-3.5 w-3.5" /> Add target</Button></div>
          <p className="text-xs text-muted-foreground">Targets configure delivery intent. Review run history to confirm delivery; a schedule may also retain reports without any delivery targets.</p>
          {delivery.map((target, index) => <div key={index} className="space-y-4 rounded-md border border-border p-4" data-testid={`schedule-delivery-${index}`}>
            <div className="flex items-end gap-3"><Field className="flex-1" label="Kind" htmlFor={`delivery-kind-${index}`}><Select id={`delivery-kind-${index}`} value={target.kind} onChange={(event) => updateTarget(index, { kind: event.target.value as ComplianceScheduleDelivery["kind"] })}><option value="email">Email</option><option value="s3">S3</option><option value="webhook">Webhook</option><option value="file">Local file</option></Select></Field><Button type="button" variant="ghost" aria-label={`Remove delivery target ${index + 1}`} onClick={() => setDelivery(delivery.filter((_, i) => i !== index))}><Trash2 className="h-4 w-4" /></Button></div>
            {(target.kind === "email" || target.kind === "file") && <Field label={target.kind === "email" ? "Email address" : "File destination"} htmlFor={`delivery-target-${index}`}><TextInput id={`delivery-target-${index}`} value={target.target ?? ""} onChange={(event) => updateTarget(index, { target: event.target.value })} placeholder={target.kind === "email" ? "auditor@example.com" : "file:///tmp/compliance-out/"} /></Field>}
            {target.kind === "s3" && <div className="grid gap-4 sm:grid-cols-2"><Field label="Bucket" htmlFor={`delivery-bucket-${index}`}><TextInput id={`delivery-bucket-${index}`} value={target.bucket ?? ""} onChange={(event) => updateTarget(index, { bucket: event.target.value })} /></Field><Field label="Prefix" htmlFor={`delivery-prefix-${index}`}><TextInput id={`delivery-prefix-${index}`} value={target.prefix ?? ""} onChange={(event) => updateTarget(index, { prefix: event.target.value })} /></Field></div>}
            {target.kind === "webhook" && <Field label="Webhook URL" htmlFor={`delivery-url-${index}`}><TextInput id={`delivery-url-${index}`} value={target.url ?? ""} onChange={(event) => updateTarget(index, { url: event.target.value })} placeholder="https://example.com/webhook" /></Field>}
          </div>)}
        </section>
        <Collapse label="Advanced" defaultOpen={customCadence}><div className="grid gap-5 sm:grid-cols-2">
          <Field label="Cron expression" htmlFor="schedule-cron" hint="Five fields: minute, hour, day of month, month, day of week. The service validates the expression and its next occurrence."><TextInput id="schedule-cron" value={cron} onChange={(event) => { setCustomCadence(true); setCron(event.target.value); }} data-testid="wizard-cron" /></Field>
          <Field label="Timezone" htmlFor="schedule-timezone" hint="Use an IANA timezone such as UTC or America/New_York. The service determines the next run."><TextInput id="schedule-timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} /></Field>
          <Field label="Report template" htmlFor="schedule-template"><Select id="schedule-template" value={template} onChange={(event) => setTemplate(event.target.value)}><option value="compliance-detailed">compliance-detailed</option></Select></Field>
        </div></Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not create this schedule. Your draft is preserved. Check the cadence, timezone, delivery targets, and your permissions, then try again.</p>}
        <div className="flex items-center gap-3"><Button type="submit" size="lg" disabled={!valid || save.isPending} data-testid="wizard-submit">{save.isPending ? "Saving…" : "Create schedule"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: backTo })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
