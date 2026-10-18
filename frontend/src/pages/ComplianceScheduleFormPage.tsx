import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, Plus, Trash2 } from "lucide-react";
import { compliance, type Framework, type ComplianceScheduleDelivery, type ComplianceScheduleDB, type ComplianceScheduleListDBResponse } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { useEntityClusterScope } from "./entity-detail-scope";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, TextInput, Select } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";

const CADENCES = [{ label: "Daily at 02:00", cron: "0 2 * * *" }, { label: "Weekly Monday at 02:00", cron: "0 2 * * 1" }, { label: "Monthly on the 1st at 02:00", cron: "0 2 1 * *" }, { label: "Every 5 minutes", cron: "*/5 * * * *" }];

type ScheduleConfiguration = Pick<ComplianceScheduleDB, "name" | "description" | "framework" | "cron_expression" | "timezone" | "delivery" | "report_format" | "report_template">;
type SchedulePatch = Partial<ScheduleConfiguration>;
class ScheduleEditConflictError extends Error {}

export function ComplianceScheduleFormPage() {
  const { scheduleId } = useParams({ strict: false });
  return scheduleId ? <EditComplianceScheduleFormPage scheduleId={scheduleId} /> : <NewComplianceScheduleFormPage />;
}

function NewComplianceScheduleFormPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const { visit } = useEditorVisit(["compliance-schedule", clusterId, "new"]);
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
        <ScheduleEditor key={visit.context} editorContext={visit.context} clusterId={clusterId} frameworks={editorFrameworks} reportFormats={editorFormats} backTo={backTo} unavailable={failed || !scopeReady || !currentOptionsAvailable || frameworks.isFetching || options.isFetching} />
      </>}
  </div>;
}

function EditComplianceScheduleFormPage({ scheduleId }: { scheduleId: string }) {
  const scope = useEntityClusterScope();
  const { clusterId } = scope;
  const identity = useTablePreferencesIdentity();
  const qc = useQueryClient();
  const [search] = useRouteSearchParams();
  const { visit, isCurrent } = useEditorVisit(["compliance-schedule", clusterId, scheduleId]);
  const context = visit.context;
  const backSearch = new URLSearchParams(search); backSearch.set("tab", "schedules");
  const backTo = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/compliance?${backSearch}` : "/clusters";
  const listKey = ["compliance", "db-schedules", identity?.org_id, identity?.user_id, clusterId, "edit"];
  const ready = scope.ready && !!identity?.org_id && !!identity.user_id;
  const frameworkKey = ["compliance", "frameworks", identity?.org_id, identity?.user_id, "schedule-edit"];
  const list = useQuery({ queryKey: listKey, queryFn: () => compliance.listDBSchedules(clusterId!), enabled: ready });
  const frameworks = useQuery({ queryKey: frameworkKey, queryFn: () => compliance.frameworks(), enabled: ready });
  // Invalidation alone need not change useQuery's tracked result properties.
  // Observe these two exact owner-scoped flags so Save also pauses visibly.
  const invalidated = useSyncExternalStore(
    callback => qc.getQueryCache().subscribe(callback),
    () => Number(!!qc.getQueryState(listKey)?.isInvalidated) + 2 * Number(!!qc.getQueryState(frameworkKey)?.isInvalidated),
  );
  const current = () => isCurrent() && ready && scope.recheck();
  const currentRow = () => {
    const state = qc.getQueryState<ComplianceScheduleListDBResponse>(listKey);
    if (state?.status !== "success" || state.fetchStatus !== "idle" || state.isInvalidated) return undefined;
    if (!Array.isArray(state.data?.schedules)) return undefined;
    const matches = state.data.schedules.filter(row => row && typeof row === "object" && row.id === scheduleId);
    const row = matches.length === 1 ? matches[0] : undefined;
    return row && row.org_id === identity?.org_id && (!row.cluster_id || row.cluster_id === clusterId) && Array.isArray(row.delivery) && row.delivery.every(target => target && typeof target === "object" && typeof target.kind === "string") ? row : undefined;
  };
  const row = ready ? currentRow() : undefined;
  const [loaded, setLoaded] = useState<{ visit: typeof visit; schedule: ComplianceScheduleDB } | null>(null);
  const initial = loaded?.visit === visit ? loaded.schedule : row;
  // Freeze only the first scoped record. Refetch must never replace a draft.
  if (row && loaded?.visit !== visit) setLoaded({ visit, schedule: { ...row, delivery: row.delivery.map(target => ({ ...target })) } });
  const frameworkState = qc.getQueryState<{ frameworks: Framework[] }>(frameworkKey);
  const availableFrameworks = Array.isArray(frameworks.data?.frameworks) && frameworks.data.frameworks.every(item => item && typeof item.id === "string" && typeof item.name === "string") ? frameworks.data.frameworks : [];
  const availableFormats = Array.isArray(list.data?.report_formats) && list.data.report_formats.every(item => typeof item === "string") ? list.data.report_formats : [];
  const optionsReady = frameworks.isSuccess && !frameworks.isFetching && !frameworkState?.isInvalidated && availableFrameworks.length > 0 && availableFormats.length > 0;
  const unavailable = !ready || !row || !optionsReady || invalidated !== 0;
  const retry = () => { void qc.invalidateQueries({ queryKey: ["clusters"], exact: true }); void qc.invalidateQueries({ queryKey: ["cluster", clusterId], exact: true }); void list.refetch(); void frameworks.refetch(); };
  const assertFresh = (patch: SchedulePatch) => {
    const frameworkState = qc.getQueryState<{ frameworks: Framework[] }>(frameworkKey);
    const state = qc.getQueryState<ComplianceScheduleListDBResponse>(listKey);
    const fresh = currentRow();
    if (!current() || !initial || !fresh || frameworkState?.status !== "success" || frameworkState.fetchStatus !== "idle" || frameworkState.isInvalidated || !Array.isArray(frameworkState.data?.frameworks) || !frameworkState.data.frameworks.length || !frameworkState.data.frameworks.every(item => item && typeof item.id === "string" && typeof item.name === "string") || !Array.isArray(state?.data?.report_formats) || !state.data.report_formats.length || !state.data.report_formats.every(item => typeof item === "string")) throw new Error("Refresh this exact schedule before saving.");
    if (patch.framework !== undefined && !frameworkState.data.frameworks.some(item => item.id === patch.framework)) throw new Error("Selected framework is no longer available");
    if (patch.report_format !== undefined && !state.data.report_formats.includes(patch.report_format)) throw new Error("Selected format is no longer available");
    if (patch.report_template !== undefined && patch.report_template !== "compliance-detailed") throw new Error("Selected template is not an available replacement");
    for (const field of Object.keys(patch) as Array<keyof ScheduleConfiguration>) {
      if (JSON.stringify(fresh[field]) !== JSON.stringify(initial[field])) throw new ScheduleEditConflictError("The saved configuration changed. Reopen this schedule before saving.");
    }
  };
  return <div className="space-y-6">
    <PageHeader title="Edit compliance schedule" description="Edit configuration. Enable or disable this schedule from the schedule list."
      backLink={<Link to="." href={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Compliance schedules</Link>} />
    {!initial ? scope.loading || list.isPending && ready || list.isFetching ? <LoadingState label="Loading schedule…" /> : <ErrorState title="This schedule is unavailable in the current organization and cluster." action={<Button onClick={retry}>Retry</Button>} /> : <>
      <p className="text-sm text-muted-foreground">{initial.cluster_id ? "Cluster schedule" : "Organization schedule · applies across clusters"} · Configured state: {(row?.enabled ?? initial.enabled) ? "Enabled" : "Disabled"}</p>
      {unavailable && <p role="alert" className="text-sm text-status-error">Current schedule or options are unavailable. Your draft is preserved; retry before saving. <Button variant="outline" onClick={retry}>Retry</Button></p>}
      <ScheduleEditor key={context} editorContext={context} clusterId={clusterId!} frameworks={availableFrameworks} reportFormats={availableFormats} backTo={backTo} unavailable={unavailable} initial={initial} assertFresh={assertFresh} isCurrent={current} />
    </>}
  </div>;
}

function ScheduleEditor({ editorContext, clusterId, frameworks, reportFormats, backTo, unavailable, initial, assertFresh, isCurrent }: { editorContext: string; clusterId: string; frameworks: Framework[]; reportFormats: string[]; backTo: string; unavailable: boolean; initial?: ComplianceScheduleDB; assertFresh?: (patch: SchedulePatch) => void; isCurrent?: () => boolean }) {
  const { isCurrent: editorCurrent } = useEditorVisit([editorContext]);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [framework, setFramework] = useState(initial?.framework ?? frameworks[0].id);
  const [cron, setCron] = useState(initial?.cron_expression ?? CADENCES[0].cron);
  const [timezone, setTimezone] = useState(initial?.timezone ?? "UTC");
  const [delivery, setDelivery] = useState<ComplianceScheduleDelivery[]>(() => initial ? initial.delivery.map(target => ({ ...target })) : [{ kind: "file", target: "file:///tmp/compliance-out/" }]);
  const [format, setFormat] = useState(initial?.report_format ?? ["html", "json", "csv", "sarif", "pdf"].find(value => reportFormats.includes(value)) ?? reportFormats[0]);
  const [template, setTemplate] = useState(initial?.report_template ?? "compliance-detailed");
  const [customCadence, setCustomCadence] = useState(!!initial && !CADENCES.some(item => item.cron === initial.cron_expression));
  const frameworkChoices = [...frameworks];
  if (initial) for (const value of [initial.framework, framework]) {
    if (!frameworkChoices.some(item => item.id === value)) frameworkChoices.push({ id: value, name: `${value === initial.framework ? "Configured" : "Unavailable draft"} framework: ${value}`, category: "Configured" });
  }
  const formatChoices = [...reportFormats];
  if (initial) for (const value of [initial.report_format, format]) if (!formatChoices.includes(value)) formatChoices.push(value);
  const frameworkAllowed = frameworks.some(item => item.id === framework) || initial?.framework === framework;
  const formatAllowed = reportFormats.includes(format) || initial?.report_format === format;
  const values: ScheduleConfiguration = { name: initial && name === initial.name ? name : name.trim(), description, framework, cron_expression: initial && cron === initial.cron_expression ? cron : cron.trim(), timezone: initial && timezone === initial.timezone ? timezone : timezone.trim(), delivery, report_format: format, report_template: initial && template === initial.report_template ? template : template.trim() };
  const patch: SchedulePatch = {};
  if (initial) for (const field of Object.keys(values) as Array<keyof ScheduleConfiguration>) {
    if (JSON.stringify(values[field]) !== JSON.stringify(initial[field])) Object.assign(patch, { [field]: values[field] });
  }
  const pending = useRef(false);
  const valid = !unavailable && !!name.trim() && frameworkAllowed && cron.trim().split(/\s+/).length === 5 && !!timezone.trim() && formatAllowed && !!template.trim() && (!initial || template === initial.report_template || template === "compliance-detailed") && (!initial || Object.keys(patch).length > 0);
  const updateTarget = (index: number, patch: Partial<ComplianceScheduleDelivery>) => setDelivery((current) => current.map((target, i) => i === index ? { ...target, ...patch } : target));
  const save = useMutation({
    mutationFn: () => {
      if (!valid) throw new Error("Invalid schedule");
      if (initial) {
        if (!isCurrent?.()) throw new Error("Schedule context changed");
        assertFresh?.(patch);
        return compliance.patchSchedule(initial.id, patch);
      }
      return compliance.createSchedule({ name: name.trim(), description, cluster_id: clusterId, framework, cron_expression: cron.trim(), timezone: timezone.trim(), delivery, report_format: format, report_template: template });
    },
    onSuccess: () => {
      if (initial && (!editorCurrent() || !isCurrent?.())) return;
      void qc.invalidateQueries({ queryKey: initial ? ["compliance", "db-schedules"] : ["compliance", "db-schedules", clusterId] });
      if (editorCurrent()) navigate({ href: backTo });
    },
    onSettled: () => { pending.current = false; },
  });
  return <Card title="Schedule" description={initial ? "Saving updates configuration without requesting a run." : "Choose the framework, cadence, report format, and delivery targets. New schedules are enabled by the service."}>
    <form className="space-y-6" data-testid="compliance-schedule-form" onSubmit={(event) => { event.preventDefault(); if (valid && !save.isPending && !pending.current) { pending.current = true; save.mutate(); } }}>
      <fieldset disabled={save.isPending} className="space-y-6">
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Name" htmlFor="schedule-name" required><TextInput id="schedule-name" value={name} onChange={(event) => setName(event.target.value)} required data-testid="wizard-name" /></Field>
          <Field label="Framework" htmlFor="schedule-framework" required><Select id="schedule-framework" value={framework} onChange={(event) => setFramework(event.target.value)} data-testid="wizard-framework">{frameworkChoices.map((item) => <option key={item.id} value={item.id}>{item.name} ({item.id})</option>)}</Select></Field>
          <Field label="Description" htmlFor="schedule-description"><TextInput id="schedule-description" value={description} onChange={(event) => setDescription(event.target.value)} /></Field>
          <Field label="Cadence" htmlFor="schedule-cadence" hint={`Times use ${timezone || "UTC"}.`}><Select id="schedule-cadence" value={customCadence ? "custom" : cron} onChange={(event) => { setCustomCadence(event.target.value === "custom"); if (event.target.value !== "custom") setCron(event.target.value); }}>{CADENCES.map((item) => <option key={item.cron} value={item.cron}>{item.label}</option>)}<option value="custom">Custom (set under Advanced)</option></Select></Field>
          <Field label="Report format" htmlFor="schedule-format"><Select id="schedule-format" value={format} onChange={(event) => setFormat(event.target.value)} data-testid="wizard-format">{formatChoices.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}</Select></Field>
        </div>
        <section className="space-y-4" aria-labelledby="schedule-delivery-title">
          <div className="flex items-center justify-between gap-3"><h2 id="schedule-delivery-title" className="text-sm font-semibold">Delivery targets</h2><Button type="button" variant="outline" onClick={() => setDelivery([...delivery, { kind: "email", target: "" }])}><Plus className="mr-1 h-3.5 w-3.5" /> Add target</Button></div>
          <p className="text-xs text-muted-foreground">Targets configure delivery intent. Review run history to confirm delivery; a schedule may also retain reports without any delivery targets.</p>
          {delivery.map((target, index) => <div key={index} className="space-y-4 rounded-md border border-border p-4" data-testid={`schedule-delivery-${index}`}>
            <div className="flex items-end gap-3"><Field className="flex-1" label="Kind" htmlFor={`delivery-kind-${index}`}><Select id={`delivery-kind-${index}`} value={target.kind} onChange={(event) => updateTarget(index, { kind: event.target.value as ComplianceScheduleDelivery["kind"] })}>{!["email", "s3", "webhook", "file"].includes(target.kind) && <option value={target.kind}>{target.kind} (retained)</option>}<option value="email">Email</option><option value="s3">S3</option><option value="webhook">Webhook</option><option value="file">Local file</option></Select></Field><Button type="button" variant="ghost" aria-label={`Remove delivery target ${index + 1}`} onClick={() => setDelivery(delivery.filter((_, i) => i !== index))}><Trash2 className="h-4 w-4" /></Button></div>
            {Object.keys(target).some(key => !["kind", "target", "bucket", "prefix", "url"].includes(key)) && <p className="text-xs text-muted-foreground">Additional delivery settings are preserved.</p>}
            {(target.kind === "email" || target.kind === "file") && <Field label={target.kind === "email" ? "Email address" : "File destination"} htmlFor={`delivery-target-${index}`}><TextInput id={`delivery-target-${index}`} value={target.target ?? ""} onChange={(event) => updateTarget(index, { target: event.target.value })} placeholder={target.kind === "email" ? "auditor@example.com" : "file:///tmp/compliance-out/"} /></Field>}
            {target.kind === "s3" && <div className="grid gap-4 sm:grid-cols-2"><Field label="Bucket" htmlFor={`delivery-bucket-${index}`}><TextInput id={`delivery-bucket-${index}`} value={target.bucket ?? ""} onChange={(event) => updateTarget(index, { bucket: event.target.value })} /></Field><Field label="Prefix" htmlFor={`delivery-prefix-${index}`}><TextInput id={`delivery-prefix-${index}`} value={target.prefix ?? ""} onChange={(event) => updateTarget(index, { prefix: event.target.value })} /></Field></div>}
            {target.kind === "webhook" && <Field label="Webhook URL" htmlFor={`delivery-url-${index}`}><TextInput id={`delivery-url-${index}`} value={target.url ?? ""} onChange={(event) => updateTarget(index, { url: event.target.value })} placeholder="https://example.com/webhook" /></Field>}
          </div>)}
        </section>
        <Collapse label="Advanced" defaultOpen={customCadence}><div className="grid gap-5 sm:grid-cols-2">
          <Field label="Cron expression" htmlFor="schedule-cron" hint="Five fields: minute, hour, day of month, month, day of week. The service validates the expression and its next occurrence."><TextInput id="schedule-cron" value={cron} onChange={(event) => { setCustomCadence(true); setCron(event.target.value); }} data-testid="wizard-cron" /></Field>
          <Field label="Timezone" htmlFor="schedule-timezone" hint="Use an IANA timezone such as UTC or America/New_York. The service determines the next run."><TextInput id="schedule-timezone" value={timezone} onChange={(event) => setTimezone(event.target.value)} /></Field>
          <Field label="Report template" htmlFor="schedule-template"><Select id="schedule-template" value={template} onChange={(event) => setTemplate(event.target.value)}>{initial && initial.report_template !== "compliance-detailed" && <option value={initial.report_template}>{initial.report_template} (currently configured)</option>}<option value="compliance-detailed">compliance-detailed</option></Select></Field>
        </div></Collapse>
        {initial && (!frameworkAllowed || !formatAllowed) && <p role="alert" className="text-sm text-status-error">A selected framework or format is no longer available. Your draft selection is retained; choose an available replacement before saving.</p>}
        {save.isError && <p role="alert" className="text-sm text-status-error">{save.error instanceof ScheduleEditConflictError ? "This schedule changed. Your draft is preserved. Copy your edits, then cancel and reopen it." : `Could not ${initial ? "update" : "create"} this schedule. Your draft is preserved. Check the cadence, timezone, delivery targets, and your permissions, then try again.`}</p>}
        <div className="flex items-center gap-3"><Button type="submit" size="lg" disabled={!valid || save.isPending} data-testid="wizard-submit">{save.isPending ? "Saving…" : initial ? "Save changes" : "Create schedule"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: backTo })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
