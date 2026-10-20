import { useRouteSearchParams } from "@/lib/route-search";
import { findingHref, findingRevisionValid, sameFindingTimestamp } from "@/lib/finding-instance";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { assets, findings, type AffectedRange, type Finding } from "@/api/client";
import { assetDisplayName } from "@/lib/asset-identity";
import { useCrumbLabel } from "@/lib/page-title";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { RiskScore } from "@/components/ui/risk-score";
import { EpssBadge, KevBadge } from "@/components/ui/kev-badge";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { FindingScope } from "./FindingActionFormPage";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
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
    {!clusterId || !fid ? <><PageHeader title="Finding" /><ErrorState title="Select an available cluster and finding to continue." /></>
      : <FindingScope key={`${identity?.org_id}:${identity?.user_id}:${clusterId}:${fid}:${params.get("first_seen_at")}`} clusterId={clusterId} findingId={fid} resolvedClusterId={cluster?.id} clusterLoading={isLoading} clusterError={Boolean(error)}>
          {(finding, unavailable) => <FindingDetail finding={finding} clusterId={clusterId} listPath={listPath} unavailable={unavailable} />}
        </FindingScope>}
  </PageContainer>;
}

function FindingDetail({ finding: f, clusterId, unavailable }: { finding: Finding; clusterId: string; listPath: string; unavailable: boolean }) {
  const identity = useTablePreferencesIdentity();
  const comments = useQuery({ queryKey: ["finding-comments", identity?.org_id, identity?.user_id, clusterId, f.id, f.first_seen_at], queryFn: async () => {
    const response = await findings.instanceComments(f.id, { first_seen_at: f.first_seen_at, cluster_id: clusterId });
    const validComment = (row: unknown) => !!row && typeof row === "object" && typeof (row as { id?: unknown }).id === "string" && typeof (row as { author_id?: unknown }).author_id === "string" && typeof (row as { body?: unknown }).body === "string" && typeof (row as { created_at?: unknown }).created_at === "string";
    if (!response || response.row_id !== f.row_id || !sameFindingTimestamp(response.first_seen_at, f.first_seen_at) || !findingRevisionValid(response.revision) || response.legacy_history_scope !== "uuid" || !Array.isArray(response.comments) || !Array.isArray(response.legacy_comments) || !response.comments.every(validComment) || !response.legacy_comments.every(validComment)) throw new Error("Comment evidence does not match the selected observation");
    return response;
  }, enabled: !unavailable });
  const assetCluster = f.source_cluster_id ?? f.cluster_id;
  useCrumbLabel(f.external_id || f.title);
  const asset = useQuery({ queryKey: ["finding-asset-name", assetCluster, f.asset_id], queryFn: () => assets.get(f.asset_id), enabled: !!f.asset_id, staleTime: 60_000, retry: false });
  const assetName = asset.data ? assetDisplayName(asset.data.asset, asset.data.image) : undefined;
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
        eyebrow={f.external_id ? <span className="font-mono">{f.external_id}</span> : undefined}
        title={f.title}
        badges={
          <span className="flex flex-wrap items-center gap-2" data-testid="finding-identity">
            <SeverityBadge severity={f.severity} kev={Boolean(f.kev)} />
            {isExceptionLifecycle(f.lifecycle) ? (
              <a href={exceptionHref(clusterId, f.lifecycle, f.id, f.first_seen_at)} className="rounded-full focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring" data-testid="finding-exception-link" title={exceptionLabel(f)}>
                <LifecycleBadge lifecycle={f.lifecycle} />
              </a>
            ) : <LifecycleBadge lifecycle={f.lifecycle} />}
          </span>
        }
        actions={!unavailable ? <><Button asChild><a href={findingHref(f, clusterId, "suppress")}>Suppress</a></Button><Button asChild variant="primary"><a href={findingHref(f, clusterId, "accept-risk")}>Accept risk</a></Button></> : undefined}
      />
      <VerdictBanner
        status={f.lifecycle === "open" ? (f.severity === "critical" || f.severity === "high" ? "critical" : "degraded") : "info"}
        title={f.lifecycle === "open" ? `${sentence(f.kind)} needs triage` : f.accepted_until ? `Risk accepted until ${new Date(f.accepted_until).toLocaleDateString()}` : `${sentence(f.kind)} · ${exceptionLabel(f).toLowerCase()}`}
        numbers={[
          { label: "risk", value: <RiskScore score={f.risk_score} /> },
          { label: "CVSS", value: typeof score === "number" ? score.toFixed(1) : "—", tone: typeof score === "number" && score >= 9 ? "critical" : typeof score === "number" && score >= 7 ? "high" : "default" },
          ...(typeof f.epss === "number" ? [{ label: "EPSS", value: formatEPSS(f.epss) }] : []),
        ]}
        detail={f.accepted_until ? `Risk acceptance expires ${new Date(f.accepted_until).toLocaleString()}.` : "Review the evidence and history below before changing the lifecycle."}
      />
      <Collapse label="Observation details"><dl className="space-y-2 text-sm"><div><dt>First observed</dt><dd><time dateTime={f.first_seen_at} className="font-mono">{f.first_seen_at}</time></dd></div><div><dt>Reviewed revision</dt><dd>{f.revision}</dd></div><div><dt>Observation identity</dt><dd className="break-all font-mono">{f.row_id}</dd></div><div><dt>Source cluster</dt><dd>{f.source_cluster_id ?? f.cluster_id ?? "Not reported"}</dd></div><div><dt>Target cluster override</dt><dd>{f.target_cluster_id ?? "None reported"}</dd></div></dl></Collapse>
      {f.asset_id && assetCluster ? (
        <section
          className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-card px-4 py-3 text-sm"
          data-testid="finding-affected-asset"
        >
          <span className="text-meta font-medium text-muted-foreground">Affected asset</span>
          <a href={`/clusters/${assetCluster}/assets/${encodeURIComponent(f.asset_id)}`} className="text-link font-medium" data-testid="finding-affected-asset-name" title={f.asset_id}>
            {assetName ?? (asset.isPending ? "Loading asset…" : "Asset")}
          </a>
          <div className="ml-auto flex items-center gap-2">
            <Button asChild size="sm"><a href={`/clusters/${assetCluster}/risk/asset/${encodeURIComponent(f.asset_id)}`} data-testid="finding-affected-asset-risk">Risk workspace</a></Button>
            <Button asChild size="sm"><a href={`/clusters/${assetCluster}/assets/${encodeURIComponent(f.asset_id)}`} data-testid="finding-affected-asset-detail">Asset detail</a></Button>
          </div>
        </section>
      ) : null}

      {f.attack_techniques?.length ? (
        <section>
          <h2 className="mb-2 text-section-title font-semibold">MITRE ATT&CK techniques</h2>
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
          <div className="mb-3 flex flex-wrap items-center gap-2"><h2 className="text-section-title font-semibold">Vulnerability evidence</h2>{f.kev ? <KevBadge /> : null}{typeof f.epss === "number" ? <EpssBadge probability={f.epss} /> : null}</div>
          <dl className="grid gap-4 text-sm sm:grid-cols-2 lg:grid-cols-4">
            <DetailField label="CVSS base" value={formatCVSS(f)} mono />
            <DetailField label="CVSS vector" value={f.cvss_vector ?? "—"} mono wide />
            <DetailField label="Known exploited (KEV)" value={f.kev ? "Yes" : "No"} />
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
          <h2 className="mb-3 text-section-title font-semibold">Reconciliation</h2>
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
        <div className="mb-3 flex items-center justify-between gap-3"><h2 className="text-section-title font-semibold">Comments</h2>{!unavailable && <Button asChild size="sm"><a href={findingHref(f, clusterId, "comments/new")}>Add comment</a></Button>}</div>
        {comments.isError && <ErrorState title="Comment history could not be loaded." action={<Button onClick={() => void comments.refetch()}>Retry comments</Button>} />}
        {comments.isPending && <LoadingState label="Loading comments" variant="panel" />}
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

function sentence(value: string) {
  const words = value.replace(/[_-]+/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
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
      <dt className="text-meta font-medium text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-1 break-all font-mono text-13" : "mt-1 text-sm"}>{value}</dd>
    </div>
  );
}
