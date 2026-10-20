import { useEffect, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { Pencil, Play, Plus, RefreshCw, CloudUpload } from "lucide-react";
import { policies, type Policy, type PolicySimulation } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { useRouteSearchParams } from "@/lib/route-search";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Button } from "@/components/ui/button";
import { ErrorState, EmptyState, LoadingState } from "@/components/ui/states";
import { StatusPill } from "@/components/ui/status-pill";

const SAMPLE_ADMISSION_MANIFEST = `apiVersion: v1
kind: Pod
metadata:
  name: privileged-debug
  namespace: default
spec:
  containers:
    - name: shell
      image: busybox:latest
      securityContext:
        privileged: true
        runAsUser: 0
`;

export function PoliciesPage() {
  const { clusterId, cluster, isLoading } = useCluster();
  const navigate = useNavigate();
  const [search] = useRouteSearchParams();
  const legacyProfiles = search.get("tab") === "profiles";
  const [redirecting, setRedirecting] = useState(false);
  useEffect(() => {
    if (!legacyProfiles || !clusterId || !cluster || isLoading) return;
    setRedirecting(true);
    const next = new URLSearchParams(search);
    next.delete("tab");
    void navigate({ href: `/clusters/${clusterId}/admission/import${next.size ? `?${next}` : ""}`, replace: true });
  }, [legacyProfiles, clusterId, cluster, isLoading, search, navigate]);
  if (isLoading || redirecting || legacyProfiles && clusterId && cluster) return <LoadingState label={legacyProfiles ? "Opening admission profile import…" : "Loading cluster…"} />;
  if (!clusterId || !cluster) return <ErrorState title="The selected cluster could not be loaded. Return to the cluster list and try again." />;
  return <PolicyCatalog key={clusterId} clusterId={clusterId} />;
}

function PolicyCatalog({ clusterId }: { clusterId: string }) {
  const navigate = useNavigate();
  const [rawTab, setTab] = useTabParam("tab", "catalog");
  const tab = rawTab === "simulator" ? "simulator" : "catalog";
  const q = useQuery({ queryKey: ["policies", clusterId], queryFn: () => policies.list({ cluster_id: clusterId }) });
  const [manifest, setManifest] = useState(SAMPLE_ADMISSION_MANIFEST);
  const simulation = useMutation({ mutationFn: (input: string) => policies.simulate({ manifest: input }, { cluster_id: clusterId }) });
  const result = simulation.variables === manifest ? simulation.data : undefined;
  const list = q.data?.policies ?? [];
  const enabledCount = list.filter((p) => p.enabled).length;
  const enforceCount = list.filter((p) => p.enabled && p.mode === "enforce").length;
  const openEditor = (id: string) => void navigate({ href: `/clusters/${clusterId}/policies/${encodeURIComponent(id)}` });
  const columns: Column<Policy>[] = [
    { id: "name", header: "Policy", kind: "name", wrap: true, hideable: false, cell: (p) => <div><span className="font-medium">{p.name}</span><p className="mt-1 text-xs text-muted-foreground">{p.description}</p></div>, exportValue: (p) => p.name, sort: (a, b) => a.name.localeCompare(b.name) },
    { id: "category", header: "Category", kind: "badge", size: 144, minSize: 112, maxSize: 192, cell: (p) => p.category || "general", sort: (a, b) => a.category.localeCompare(b.category) },
    { id: "engine", header: "Engine", kind: "status", size: 144, minSize: 112, maxSize: 192, cell: (p) => p.engine, sort: (a, b) => a.engine.localeCompare(b.engine) },
    { id: "enabled", header: "Status", kind: "status", cell: (p) => p.enabled ? "Enabled" : "Disabled", exportValue: (p) => p.enabled, sort: (a, b) => Number(a.enabled) - Number(b.enabled) },
    { id: "mode", header: "Configured mode", kind: "status", cell: (p) => p.mode, sort: (a, b) => a.mode.localeCompare(b.mode) },
    { id: "actions", header: "Actions", kind: "actions", hideable: false, exportable: false, cell: (p) => <Button variant="ghost" disabled={q.isError} aria-label={`Edit policy ${p.name}`} onClick={() => openEditor(p.id)}><Pencil className="h-4 w-4" /> Edit</Button> },
  ];
  const simulatorTab = <div className="space-y-5 rounded-md border border-border bg-card p-5" data-testid="policy-simulator">
    <div><h2 className="text-base font-semibold">Admission simulator</h2><p className="mt-1 text-sm text-muted-foreground">Review how enabled policies evaluate a Kubernetes manifest. This dry run does not change the workload.</p></div>
    <label className="block space-y-2 text-sm"><span className="font-medium">Kubernetes manifest</span><textarea value={manifest} disabled={simulation.isPending} onChange={(e) => setManifest(e.target.value)} spellCheck={false} className="h-72 w-full resize-y rounded-md border border-border bg-background p-3 font-mono text-sm" data-testid="policy-simulator-manifest" /></label>
    <Button variant="primary" disabled={simulation.isPending || !manifest.trim() || q.isError} onClick={() => simulation.mutate(manifest)} data-testid="policy-simulator-run"><Play className="h-4 w-4" />{simulation.isPending ? "Reviewing…" : "Run dry-run admission review"}</Button>
    {simulation.isError && simulation.variables === manifest && <p role="alert" className="text-sm text-status-error">Could not run this admission review. Your manifest is preserved. Try again.</p>}
    {result && <div className="space-y-4" data-testid="policy-simulator-results">
      <VerdictBanner status={result.decision === "deny" ? "critical" : result.decision === "warn" ? "degraded" : "info"} title={`Dry-run decision: ${result.decision}`} detail="This result applies to the submitted manifest and current policy configuration." />
      <dl className="grid grid-cols-2 gap-3 sm:grid-cols-3"><Info label="Workload" value={`${result.workload.kind}/${result.workload.name}`} /><Info label="Namespace" value={result.workload.namespace} /><Info label="Mode" value={result.enforcement_mode} /></dl>
      {result.matches.map((match) => <SimulationMatchCard key={match.policy_id} match={match} />)}
      {!result.matches.length && <p className="text-sm text-muted-foreground">No enabled policy matched this manifest.</p>}
      <div className="space-y-3 rounded-md border border-border p-4" data-testid="policy-simulator-guardrails"><h3 className="text-sm font-medium">Guardrails</h3>{result.guardrails.map((guardrail) => <div key={guardrail.id} className="flex justify-between gap-3 text-sm"><span>{guardrail.name}</span><Status value={guardrail.status} /></div>)}</div>
    </div>}
  </div>;
  return <div className="space-y-6" data-testid="policies-page" data-cluster-id={clusterId}>
    <PageHeader title="Policy catalog" description="Review policies available to this cluster, including organization defaults. Open a policy to change its configuration, or test a manifest before enforcing it."
      actions={<><Button disabled={q.isFetching} onClick={() => void q.refetch()}><RefreshCw className="h-4 w-4" /> Refresh</Button><Button onClick={() => void navigate({ href: `/clusters/${clusterId}/admission/import` })}><CloudUpload className="h-4 w-4" /> Import profile</Button><Button variant="primary" disabled={q.isError || !q.data} data-testid="policies-create-cta" onClick={() => void navigate({ href: `/clusters/${clusterId}/policies/new` })}><Plus className="h-4 w-4" /> Create policy</Button></>} />
    {q.isPending ? <LoadingState label="Loading policies…" /> : !q.data ? <ErrorState title="Could not load policies for this cluster." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : <>
      <VerdictBanner detailMode={q.isError ? "inline" : "disclosure"} status={q.isError ? "degraded" : "info"} title={q.isError ? "Policies could not be refreshed" : `${enabledCount} of ${list.length} loaded policies are enabled`} detail={q.isError ? "Showing the last loaded configuration. Refresh before editing." : "These counts describe configuration. They do not confirm enforcement or webhook health."} numbers={[{ label: "Loaded policies", value: list.length }, { label: "Enabled policies", value: enabledCount }, { label: "Enabled · enforce", value: enforceCount }, { label: "Enabled · monitor", value: enabledCount - enforceCount }]} />
      
      <Tabs value={tab} onValueChange={setTab} items={[{ value: "catalog", label: "Policy catalog", count: list.length, content: <DataTable rows={list} columns={columns} rowKey={(p) => p.id} onRowClick={q.isError ? undefined : (p) => openEditor(p.id)} preferencesKey="policy-catalog" exportFileName="policies.csv" testId="policy-catalog-table" rowTestId={(p) => `policy-row-${p.name}`} emptyState={<EmptyState title="No policies" hint="Create a policy or import an admission profile to get started." />} /> }, { value: "simulator", label: "Admission simulator", content: simulatorTab }]} />
    </>}
  </div>;
}

function SimulationMatchCard({ match }: { match: PolicySimulation["matches"][number] }) {
  const details = match.evidence_details ?? [];
  return (
    <article className="rounded-md bg-muted p-3 text-xs">
      <div className="flex items-center justify-between gap-2">
        <div className="font-medium">{match.policy_name}</div>
        <Status value={match.action} />
      </div>
      <p className="mt-1 text-muted-foreground">{match.reason}</p>
      <div className="mt-2 flex flex-wrap gap-1">
        {match.evidence.map((item) => <Badge key={item}>{item}</Badge>)}
      </div>
      {details.length > 0 && (
        <div className="mt-3 space-y-1" data-testid="policy-simulator-evidence-details">
          {details.map((detail, index) => {
            const href = safeInternalHref(detail.href);
            const label = detail.label || detail.finding?.external_id || detail.finding?.title || detail.artifact?.title || detail.scan_result?.id || "Scan evidence";
            const findingPackage = [detail.finding?.package_ecosystem, detail.finding?.package_name, detail.finding?.package_version]
              .filter(Boolean)
              .join(" / ");
            const meta = [
              detail.finding?.severity || detail.artifact?.severity,
              detail.finding?.external_id || detail.artifact?.rule_id,
              detail.finding?.canonical_engine,
              detail.artifact?.type,
              detail.artifact?.status,
              detail.scan_result?.vulndb_bundle_version ? `bundle ${detail.scan_result.vulndb_bundle_version}` : undefined,
            ].filter(Boolean).join(" · ");
            const imageRef = detail.image?.ref || detail.scan_result?.image_ref;
            const scanSource = scanSourceLabel(detail.scan_result?.source_type, detail.scan_result?.source_ref);
            return (
              <div key={`${label}-${index}`} className="rounded-md border border-border bg-background px-2 py-1.5">
                {href ? (
                  <Link to="." href={href} className="font-medium hover:underline" data-testid="policy-simulator-evidence-detail-link">
                    {label}
                  </Link>
                ) : (
                  <span className="font-medium">{label}</span>
                )}
                {meta && <div className="mt-0.5 text-micro text-muted-foreground">{meta}</div>}
                {findingPackage && <div className="mt-0.5 text-micro text-muted-foreground">{findingPackage}</div>}
                {detail.finding?.fixed_version && <div className="mt-0.5 text-micro text-muted-foreground">fixed in {detail.finding.fixed_version}</div>}
                {scanSource && <div className="mt-0.5 break-all text-micro text-muted-foreground">{scanSource}</div>}
                {detail.artifact?.path && <div className="mt-0.5 break-all font-mono text-micro text-muted-foreground">{detail.artifact.path}</div>}
                {imageRef && <div className="mt-0.5 break-all font-mono text-micro text-muted-foreground">{imageRef}</div>}
              </div>
            );
          })}
        </div>
      )}
    </article>
  );
}

function scanSourceLabel(sourceType?: string, sourceRef?: string) {
  if (!sourceType) return undefined;
  const label = sourceLabel(sourceType);
  return sourceRef ? `${label}: ${sourceRef}` : label;
}

function sourceLabel(sourceType: string) {
  switch (sourceType) {
    case "repository":
      return "Repository / CI";
    case "runtime-agent":
      return "Runtime agent";
    case "registry":
      return "Registry";
    case "discoverer":
      return "Discoverer";
    case "platform":
      return "Platform";
    case "host":
      return "Host";
    case "serverless":
      return "Serverless";
    default:
      return sourceType;
  }
}

function safeInternalHref(href?: string) {
  if (!href || !href.startsWith("/") || href.startsWith("//")) return undefined;
  return href;
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md bg-muted p-2">
      <div className="text-micro  text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-medium">{value}</div>
    </div>
  );
}

function Badge({ children }: { children: string }) {
  return <span className="rounded-md bg-background px-1.5 py-0.5 text-micro text-muted-foreground">{children}</span>;
}

function Status({ value }: { value: string }) {
  const tone: "success" | "warning" | "error" | "info" | "pending" | "neutral" = value === "allow" || value === "enforced"
    ? "success"
    : value === "warn"
      ? "warning"
      : value === "deny"
        ? "error"
        : "neutral";
  return <StatusPill label={value} tone={tone} />;
}
