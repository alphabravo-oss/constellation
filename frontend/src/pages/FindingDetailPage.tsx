import { useRouteSearchParams } from "@/lib/route-search";
import { findingHref, findingRevisionValid, sameFindingTimestamp } from "@/lib/finding-instance";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { findings, type AffectedRange, type Finding } from "@/api/client";
import { severityBg } from "@/lib/severity";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { FindingScope } from "./FindingActionFormPage";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { Collapse } from "@/components/ui/collapse";
import { DataTable, type Column } from "@/components/ui/data-table";

type ReconSignal = NonNullable<Finding["reconciliation"]>[number];

export function FindingDetailPage() {
  const { fid } = useParams({ strict: false });
  const { clusterId, cluster, isLoading, error } = useCluster();
  const [params] = useRouteSearchParams();
  const identity = useTablePreferencesIdentity();
  const listPath = clusterId ? `/clusters/${clusterId}/findings` : "/findings";
  return <PageContainer>
    {!clusterId || !fid ? <><PageHeader title="Finding" description="Review this finding and its history." backLink={<a href={listPath}>Findings</a>} /><ErrorState title="Select an available cluster and finding to continue." /></>
      : <FindingScope key={`${identity?.org_id}:${identity?.user_id}:${clusterId}:${fid}:${params.get("first_seen_at")}`} clusterId={clusterId} findingId={fid} resolvedClusterId={cluster?.id} clusterLoading={isLoading} clusterError={Boolean(error)}>
          {(finding, unavailable) => <FindingDetail finding={finding} clusterId={clusterId} listPath={listPath} unavailable={unavailable} />}
        </FindingScope>}
  </PageContainer>;
}

function FindingDetail({ finding: f, clusterId, listPath, unavailable }: { finding: Finding; clusterId: string; listPath: string; unavailable: boolean }) {
  const identity = useTablePreferencesIdentity();
  const comments = useQuery({ queryKey: ["finding-comments", identity?.org_id, identity?.user_id, clusterId, f.id, f.first_seen_at], queryFn: async () => {
    const response = await findings.instanceComments(f.id, { first_seen_at: f.first_seen_at, cluster_id: clusterId });
    const validComment = (row: unknown) => !!row && typeof row === "object" && typeof (row as { id?: unknown }).id === "string" && typeof (row as { author_id?: unknown }).author_id === "string" && typeof (row as { body?: unknown }).body === "string" && typeof (row as { created_at?: unknown }).created_at === "string";
    if (!response || response.row_id !== f.row_id || !sameFindingTimestamp(response.first_seen_at, f.first_seen_at) || !findingRevisionValid(response.revision) || response.legacy_history_scope !== "uuid" || !Array.isArray(response.comments) || !Array.isArray(response.legacy_comments) || !response.comments.every(validComment) || !response.legacy_comments.every(validComment)) throw new Error("Comment evidence does not match the selected observation");
    return response;
  }, enabled: !unavailable });
  const assetCluster = f.source_cluster_id ?? f.cluster_id;
  const score = cvssScore(f);
  const hasVulnerabilityMetadata =
    typeof score === "number" || Boolean(f.cvss_vector) || Boolean(f.kev) || typeof f.epss === "number";

  const reconColumns: Column<ReconSignal>[] = [
    { id: "engine", header: "Engine", kind: "id", size: 160, minSize: 128, maxSize: 192, cell: (s) => <span className="font-mono">{s.engine}</span> },
    { id: "field", header: "Field", kind: "text", code: true, wrap: true, size: 184, minSize: 144, maxSize: 224, cell: (s) => <span className="font-mono">{s.field}</span> },
    { id: "canonical", header: "VulnDB", kind: "text", code: true, wrap: true, size: 280, minSize: 200, maxSize: 480, grow: true, cell: (s) => <span className="font-mono">{s.canonical || "—"}</span> },
    { id: "evidence", header: "Evidence", kind: "text", code: true, wrap: true, size: 280, minSize: 200, maxSize: 480, grow: true, cell: (s) => <span className="font-mono">{s.evidence || "—"}</span> },
  ];

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow={<span className="font-mono font-normal normal-case tracking-normal">{f.external_id}</span>}
        title={f.title}
        backLink={<a href={listPath}>Findings</a>}
        description={
          <span className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`rounded-md px-2 py-0.5 ${severityBg[f.severity]}`}>{f.severity}</span>
            <span>risk {f.risk_score}</span>
            {typeof score === "number" ? <span>· CVSS {score.toFixed(1)}</span> : null}
            <span>· {f.kind}</span>
            <span>· {f.lifecycle}</span>
            {isExceptionLifecycle(f.lifecycle) ? (
              <a
                href={exceptionHref(clusterId, f.lifecycle, f.id, f.first_seen_at)}
                className="rounded-md border border-border px-2 py-0.5 text-foreground hover:bg-accent"
                data-testid="finding-exception-link"
              >
                {exceptionLabel(f)}
              </a>
            ) : null}
          </span>
        }
        actions={!unavailable ? <><a href={findingHref(f, clusterId, "suppress")} className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-accent">Suppress</a><a href={findingHref(f, clusterId, "accept-risk")} className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-accent">Accept risk</a></> : undefined}
      />
      <VerdictBanner status={f.lifecycle === "open" ? "degraded" : "info"} title={`This finding is ${f.lifecycle}`} detail={f.accepted_until ? `Risk acceptance expires ${new Date(f.accepted_until).toLocaleString()}.` : "Review the evidence and recorded history before changing its lifecycle."} />
      <StatGrid><StatCard label="Risk score" value={f.risk_score} /><StatCard label="CVSS base" value={typeof score === "number" ? score.toFixed(1) : "—"} /><StatCard label="Lifecycle" value={f.lifecycle} /></StatGrid>

      <Collapse label="Observation details"><dl className="space-y-2 text-sm"><div><dt>First observed</dt><dd><time dateTime={f.first_seen_at} className="font-mono">{f.first_seen_at}</time></dd></div><div><dt>Reviewed revision</dt><dd>{f.revision}</dd></div><div><dt>Observation identity</dt><dd className="break-all font-mono">{f.row_id}</dd></div><div><dt>Source cluster</dt><dd>{f.source_cluster_id ?? f.cluster_id ?? "Not reported"}</dd></div><div><dt>Target cluster override</dt><dd>{f.target_cluster_id ?? "None reported"}</dd></div></dl></Collapse>
      {f.asset_id && assetCluster ? (
        <section
          className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5 text-xs"
          data-testid="finding-affected-asset"
        >
          <span className="text-micro  text-muted-foreground">Affected asset</span>
          <span className="font-mono">{f.asset_id.slice(0, 24)}</span>
          <div className="ml-auto flex items-center gap-2">
            <a
              href={`/clusters/${assetCluster}/risk/asset/${encodeURIComponent(f.asset_id)}`}
              className="rounded-md border border-border px-2 py-1 text-foreground hover:bg-accent"
              data-testid="finding-affected-asset-risk"
            >
              Risk workspace
            </a>
            <a
              href={`/clusters/${assetCluster}/assets/${encodeURIComponent(f.asset_id)}`}
              className="rounded-md border border-border px-2 py-1 text-foreground hover:bg-accent"
              data-testid="finding-affected-asset-detail"
            >
              Asset detail
            </a>
          </div>
        </section>
      ) : null}

      {f.attack_techniques?.length ? (
        <section>
          <h2 className="mb-2 text-sm font-medium">MITRE ATT&CK Techniques</h2>
          <ul className="flex flex-wrap gap-1.5">
            {f.attack_techniques.map((t) => (
              <li
                key={t}
                className="rounded-md border border-border bg-muted px-2 py-0.5 font-mono text-xs"
              >
                {t}
              </li>
            ))}
          </ul>
        </section>
      ) : null}

      {(f.canonical_engine || f.engines?.length || f.vulndb_bundle || f.affected_range || hasVulnerabilityMetadata) ? (
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-medium">Source Provenance</h2>
          <dl className="grid gap-3 text-xs sm:grid-cols-2">
            <DetailField label="CVSS base" value={formatCVSS(f)} mono />
            <DetailField label="CVSS vector" value={f.cvss_vector ?? "—"} mono wide />
            <DetailField label="KEV" value={f.kev ? "yes" : "no"} />
            <DetailField label="EPSS" value={formatEPSS(f.epss)} />
            <DetailField label="Canonical engine" value={f.canonical_engine ?? "—"} mono />
            <DetailField label="VulnDB bundle" value={f.vulndb_bundle?.bundle_version ?? "—"} mono />
            <DetailField label="Package" value={formatPackage(f)} mono />
            <DetailField label="Fixed version" value={f.fixed_version ?? f.affected_range?.fixed_version ?? "—"} mono />
            <DetailField label="Payload hash" value={shortHash(f.vulndb_bundle?.payload_hash)} mono wide />
            <DetailField label="Exported" value={f.vulndb_bundle?.exported_at ? new Date(f.vulndb_bundle.exported_at).toLocaleString() : "—"} />
            {f.affected_range ? (
              <>
                <DetailField label="Range source" value={f.affected_range.source ?? "—"} mono />
                <DetailField label="Range" value={formatAffectedRange(f.affected_range)} mono wide />
                <DetailField label="Namespace" value={formatRangeNamespace(f.affected_range)} mono />
                <DetailField label="Fix state" value={f.affected_range.fix_state ?? "—"} mono />
              </>
            ) : null}
          </dl>
          {f.engines?.length ? (
            <ul className="mt-3 flex flex-wrap gap-1.5">
              {f.engines.map((engine) => (
                <li
                  key={`${engine.engine}-${engine.role ?? ""}`}
                  className="rounded-md border border-border bg-background px-2 py-1 text-xs"
                >
                  <span className="font-mono">{engine.engine}</span>
                  {engine.role && <span className="ml-1 text-muted-foreground">{engine.role}</span>}
                  <span className="ml-1 text-muted-foreground">{Math.round((engine.confidence ?? 0) * 100)}%</span>
                </li>
              ))}
            </ul>
          ) : null}
        </section>
      ) : null}

      {f.reconciliation?.length ? (
        <section className="rounded-lg border border-border bg-card p-4">
          <h2 className="mb-3 text-sm font-medium">Reconciliation</h2>
          <DataTable
            rows={f.reconciliation}
            columns={reconColumns}
            rowKey={(s) => `${s.engine}-${s.field}-${s.evidence}`}
          />
        </section>
      ) : null}

      <Collapse label="Raw risk inputs">
        <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
{JSON.stringify(f.risk_inputs ?? {}, null, 2)}
        </pre>
      </Collapse>

      <section
        className="rounded-lg border border-border bg-card p-4"
        data-testid="comments-section"
      >
        <div className="mb-3 flex items-center justify-between gap-3"><h2 className="text-sm font-medium">Comment history</h2>{!unavailable && <a href={findingHref(f, clusterId, "comments/new")} className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-accent">Add comment</a>}</div>
        {comments.isError && <ErrorState title="Comment history could not be loaded." action={<Button onClick={() => void comments.refetch()}>Retry comments</Button>} />}
        {comments.isPending && <LoadingState label="Loading comment history…" />}
        {comments.isFetching && !comments.isPending && <p className="mb-3 text-xs text-muted-foreground">Refreshing comment history…</p>}
        <ul className="mb-3 space-y-2" data-testid="comments-list">
          {!unavailable && comments.isSuccess && !comments.isFetching && (comments.data?.comments ?? []).length === 0 && (
            <li className="text-xs text-muted-foreground">No comments yet.</li>
          )}
          {(!unavailable && comments.isSuccess && !comments.isFetching ? comments.data.comments : []).map((c) => (
            <li
              key={c.id}
              className="rounded-md border border-border bg-background p-2 text-sm"
              data-testid="comment-item"
            >
              <div className="mb-0.5 flex items-center justify-between text-xs text-muted-foreground">
                <span className="font-mono">{c.author_id.slice(0, 8)}</span>
                <time dateTime={c.created_at}>{new Date(c.created_at).toLocaleString()}</time>
              </div>
              <p className="whitespace-pre-wrap text-sm">{c.body}</p>
            </li>
          ))}
        </ul>
        {!unavailable && comments.isSuccess && !comments.isFetching && comments.data.legacy_comments?.length > 0 && <Collapse label="Earlier discussion for this finding ID"><p className="mb-2 text-xs text-muted-foreground">These older comments were recorded without an observation timestamp.</p><ul className="space-y-2">{comments.data.legacy_comments.map(comment => <li key={comment.id} className="whitespace-pre-wrap text-sm">{comment.body}</li>)}</ul></Collapse>}
      </section>
    </div>
  );
}

function isExceptionLifecycle(lifecycle: string) {
  return lifecycle === "accepted" || lifecycle === "suppressed";
}

function exceptionHref(clusterId: string, lifecycle: string, query: string, firstSeen: string) {
  const status = lifecycle === "suppressed" ? "suppressed" : "approved";
  const params = new URLSearchParams({ status, target: "finding", finding: query, first_seen_at: firstSeen });
  return `/clusters/${clusterId}/exceptions?${params.toString()}`;
}

function exceptionLabel(f: { lifecycle: string; accepted_until?: string }) {
  if (f.lifecycle === "suppressed") return "Suppressed";
  if (f.accepted_until && new Date(f.accepted_until) < new Date()) return "Expired acceptance";
  return "Accepted";
}

function shortHash(hash?: string) {
  if (!hash) return "—";
  const [algorithm, value] = hash.includes(":") ? hash.split(":", 2) : ["sha256", hash];
  if (!value) return hash;
  return `${algorithm}:${value.slice(0, 12)}`;
}

function formatPackage(f: Finding) {
  const name = f.package_name ?? f.affected_range?.package_name;
  if (!name) return "—";
  const version = f.package_version ? `@${f.package_version}` : "";
  const ecosystem = f.package_ecosystem ? ` (${f.package_ecosystem})` : "";
  return `${name}${version}${ecosystem}`;
}

function cvssScore(f: Pick<Finding, "cvss" | "cvss_base">) {
  return f.cvss_base ?? f.cvss;
}

function formatCVSS(f: Finding) {
  const score = cvssScore(f);
  return typeof score === "number" ? score.toFixed(1) : "—";
}

function formatEPSS(value?: number) {
  return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "—";
}

function formatAffectedRange(range: AffectedRange) {
  if (range.range_expression) return `${range.range_type ?? "range"} ${range.range_expression}`;
  if (range.events?.length) {
    return range.events
      .map((event) => [event.introduced, event.fixed, event.last_affected, event.limit].filter(Boolean).join("/"))
      .join(", ");
  }
  const parts = [
    range.introduced_version ? `introduced=${range.introduced_version}` : "",
    range.fixed_version ? `fixed=${range.fixed_version}` : "",
    range.last_affected_version ? `last_affected=${range.last_affected_version}` : "",
  ].filter(Boolean);
  return parts.length ? `${range.range_type ?? "range"} ${parts.join(", ")}` : (range.range_type ?? "—");
}

function formatRangeNamespace(range: AffectedRange) {
  return [range.namespace_kind, range.namespace_name, range.namespace_version, range.version_scheme]
    .filter(Boolean)
    .join("/") || "—";
}

function DetailField({ label, value, mono, wide }: { label: string; value: string; mono?: boolean; wide?: boolean }) {
  return (
    <div className={wide ? "sm:col-span-2" : undefined}>
      <dt className="text-micro  text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-1 break-all font-mono text-xs" : "mt-1 text-xs"}>{value}</dd>
    </div>
  );
}
