import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "@tanstack/react-router";
import { ArrowLeft } from "lucide-react";
import { compliance, type ComplianceCheck } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useEditorVisit } from "@/hooks/useEditorVisit";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, Textarea, TextInput } from "@/components/ui/form";
import { Collapse } from "@/components/ui/collapse";
import { ErrorState, LoadingState } from "@/components/ui/states";

export function ComplianceExemptionFormPage() {
  const { clusterId, cluster, isLoading: clusterLoading, error: clusterError } = useCluster();
  const resolvedScope = !!clusterId && cluster?.id === clusterId;
  const scopeReady = resolvedScope && !clusterLoading && !clusterError;
  const [search] = useRouteSearchParams();
  const queryClient = useQueryClient();
  const retryScope = () => { void queryClient.invalidateQueries({ queryKey: ["clusters"] }); void queryClient.invalidateQueries({ queryKey: ["cluster", clusterId] }); };
  const framework = search.get("framework") ?? "";
  const controlID = search.get("control_id") ?? "";
  const { visit } = useEditorVisit(["compliance-exemption", clusterId, framework, controlID]);
  const backSearch = new URLSearchParams(search);
  backSearch.delete("control_id"); backSearch.set("tab", "frameworks");
  const backTo = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/compliance?${backSearch}` : "/clusters";
  const checks = useQuery({
    queryKey: ["compliance", "checks", framework, clusterId, controlID],
    queryFn: () => compliance.checks(framework, clusterId!, { control_id: controlID }),
    enabled: scopeReady && !!framework && !!controlID,
  });
  // Each row represents collected evidence, not a unique control. Exemptions
  // apply to the cluster/framework/control tuple across all matching evidence.
  const currentChecks = useMemo(() => checks.data?.checks.filter((check) => check.framework === framework && check.control_id === controlID) ?? [], [checks.data, framework, controlID]);
  const scopeKey = `${clusterId ?? ""}:${framework}:${controlID}`;
  const [snapshot, setSnapshot] = useState<{ scope: string; checks: ComplianceCheck[] } | null>(null);
  useEffect(() => {
    setSnapshot((previous) => previous?.scope === scopeKey ? previous : scopeReady && checks.isSuccess && !checks.isFetching && currentChecks.length ? { scope: scopeKey, checks: currentChecks } : null);
  }, [scopeKey, currentChecks, scopeReady, checks.isSuccess, checks.isFetching]);
  const controlChecks = currentChecks.length ? currentChecks : snapshot?.scope === scopeKey ? snapshot.checks : [];
  const controlAvailable = controlChecks.length > 0;
  const eligible = (checks.data?.summary?.fail ?? 0) > 0 || currentChecks.some((check) => check.status === "fail" && (check.effective_status ?? check.status) === "fail");
  return <div className="space-y-6">
    <PageHeader title="New compliance exemption" description="Accept a failing control for this cluster until a specific date. The original evidence remains available and the decision is audited."
      backLink={<a href={backTo} className="inline-flex items-center gap-1 hover:text-foreground"><ArrowLeft className="h-3.5 w-3.5" /> Compliance controls</a>} />
    {clusterLoading && !resolvedScope ? <LoadingState label="Loading cluster…" />
      : !clusterId ? <ErrorState title="Select a cluster to create an exemption." />
      : !resolvedScope || (clusterError && !controlAvailable) ? <ErrorState title="The selected cluster could not be resolved. review its registration and retry." action={<Button onClick={retryScope}>Retry cluster</Button>} />
      : !framework || !controlID ? <ErrorState title="Select a failing compliance control before creating an exemption." />
      : checks.isPending && !controlAvailable ? <LoadingState label="Loading compliance control…" />
      : !controlAvailable ? <ErrorState title="This compliance control could not be loaded for the selected cluster." action={<Button onClick={() => void checks.refetch()}>Retry</Button>} />
      : <>
        {!scopeReady && <p role="alert" className="text-sm text-status-error">Current cluster scope is unavailable. Your draft is preserved; saving is paused until the cluster resolves. <Button variant="outline" onClick={retryScope}>Retry cluster</Button></p>}
        {checks.isError && <p role="alert" className="text-sm text-status-error">Could not refresh this control. Your draft is preserved. Retry before saving. <Button variant="outline" onClick={() => void checks.refetch()}>Retry</Button></p>}
        {checks.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing this control before saving…</p>}
        {currentChecks.length === 0 && <p role="alert" className="text-sm text-status-error">This control is no longer available in the current results. Your draft is preserved; saving is paused. <Button variant="outline" onClick={() => void checks.refetch()}>Retry</Button></p>}
        {currentChecks.length > 0 && !eligible && <p role="alert" className="text-sm text-muted-foreground">This control is no longer eligible for a new exemption. Review its current status before proceeding.</p>}
        <ExemptionEditor key={visit.context} editorContext={visit.context} clusterId={clusterId} clusterLabel={cluster?.name || clusterId} framework={framework} controlID={controlID} controlChecks={controlChecks} total={checks.data?.total} fullFailures={checks.data?.summary?.fail} lastLoaded={currentChecks.length === 0 || checks.isError || checks.isFetching || !scopeReady} backTo={backTo} canSave={scopeReady && eligible && !checks.isError && !checks.isFetching} />
      </>}
  </div>;
}

function ExemptionEditor({ editorContext, clusterId, clusterLabel, framework, controlID, controlChecks, total, fullFailures, lastLoaded, backTo, canSave }: { editorContext: string; clusterId: string; clusterLabel: string; framework: string; controlID: string; controlChecks: ComplianceCheck[]; total?: number; fullFailures?: number; lastLoaded: boolean; backTo: string; canSave: boolean }) {
  const { isCurrent } = useEditorVisit([editorContext]);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState(() => {
    const date = new Date(Date.now() + 7 * 86400_000);
    // datetime-local expects the operator's local time, not a UTC wall clock.
    return new Date(date.getTime() - date.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
  });
  const expiry = new Date(expiresAt).getTime();
  const valid = canSave && reason.trim().length >= 12 && Number.isFinite(expiry) && expiry > Date.now();
  const save = useMutation({
    mutationFn: () => {
      if (!canSave || reason.trim().length < 12 || !Number.isFinite(expiry) || expiry <= Date.now()) throw new Error("Invalid exemption");
      return compliance.createExemption({ cluster_id: clusterId, framework, control_id: controlID, reason: reason.trim(), expires_at: new Date(expiry).toISOString() });
    },
    onSuccess: () => {
      for (const family of ["summary", "checks", "evidence", "exemptions"]) void qc.invalidateQueries({ queryKey: ["compliance", family] });
      if (isCurrent()) navigate({ href: backTo });
    },
  });
  const failingCount = controlChecks.filter((check) => check.status === "fail" && (check.effective_status ?? check.status) === "fail").length;
  return <Card title={`${framework} · ${controlID}`} description={controlChecks[0].title}>
    <form className="space-y-5" data-testid="compliance-exemption-form" onSubmit={(event) => { event.preventDefault(); if (valid && !save.isPending) save.mutate(); }}>
      <fieldset disabled={save.isPending} className="space-y-5">
        <section className="space-y-2 rounded-md border border-border bg-muted/30 p-4" data-testid="exemption-control-scope">
          <h2 className="text-sm font-semibold">Entire control in {clusterLabel}</h2>
          <p className="text-sm text-muted-foreground">This exemption covers all matching evidence for {framework} control {controlID} in this cluster, including future results until expiry. It is not limited to a single workload or evidence row.</p>
          <p className="text-xs text-muted-foreground">{lastLoaded ? "Last loaded evidence: " : "Evidence preview: "}{controlChecks.length} loaded evidence {controlChecks.length === 1 ? "row" : "rows"} · {failingCount} unexempted {failingCount === 1 ? "failure" : "failures"}. Counts cover the loaded results; the exemption covers the entire control.</p>
          {total !== undefined && <p className="text-xs text-muted-foreground">Server totals for this exact control: {total.toLocaleString()} evidence rows · {fullFailures?.toLocaleString() ?? "Unavailable"} unexempted failures. The evidence preview is limited to the first 500 rows; eligibility uses the full matching failure count.</p>}
        </section>
        <Field label="Reason" htmlFor="exemption-reason" required hint="Include the owner, compensating control, or approval ticket. At least 12 characters.">
          <Textarea id="exemption-reason" value={reason} onChange={(event) => setReason(event.target.value)} minLength={12} required />
        </Field>
        <Field label="Expires" htmlFor="exemption-expires" required hint="Choose a future date and time in your local timezone.">
          <TextInput id="exemption-expires" type="datetime-local" value={expiresAt} onChange={(event) => setExpiresAt(event.target.value)} required />
        </Field>
        <Collapse label={`Control evidence (${controlChecks.length} loaded rows)`}>
          <ul className="space-y-3" data-testid="exemption-control-evidence">
            {controlChecks.map((check, index) => <li key={index} className="space-y-2 rounded-md border border-border p-3">
              <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-sm font-medium">{check.title}</span><span className="text-xs text-muted-foreground">Recorded: {check.status} · Effective: {check.effective_status ?? check.status}</span></div>
              <p className="whitespace-pre-wrap text-sm text-muted-foreground">{check.evidence || "No evidence text is available."}</p>
              {check.remediation && <p className="text-sm">Remediation: {check.remediation}</p>}
            </li>)}
          </ul>
        </Collapse>
        {save.isError && <p role="alert" className="text-sm text-status-error">Could not create this exemption. Your draft is preserved. Check the reason, expiry, and your permissions, then try again.</p>}
        <div className="flex items-center gap-3"><Button type="submit" size="lg" disabled={!valid || save.isPending}>{save.isPending ? "Saving…" : "Create exemption"}</Button><Button type="button" variant="ghost" size="lg" onClick={() => navigate({ href: backTo })}>Cancel</Button></div>
      </fieldset>
    </form>
  </Card>;
}
