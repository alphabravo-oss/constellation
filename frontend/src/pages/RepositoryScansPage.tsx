import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Download } from "lucide-react";
import { toast } from "sonner";

import { repositoryScanAttestations, repositoryScans, type RepositoryScan } from "@/api/client";
import { INVENTORY_PAGE_SIZE, scanInventoryResponseValid, InventorySearch, useScanInventoryExport, useInventoryScope, useInventoryRoute, InventoryScopeState, InventoryLoadState, ScanInventoryContinuation } from "./inventory-workspace";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Collapse } from "@/components/ui/collapse";
import { PageHeader } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { cn } from "@/lib/cn";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Select, TextInput } from "@/components/ui/form";
import { sentenceValue } from "@/components/ui/status-pill";

const scanStatuses = ["all", "pending", "running", "completed", "failed", "paused", "canceled", "not-queued"];

const repositoryColumns: Column<RepositoryScan>[] = [
  {
    id: "repository", sort: () => 0, exportValue: item => item.repository_ref,
    header: "Repository", kind: "name", size: 320, minSize: 240, wrap: true,
    cell: (item) => (
      <>
        <div className="flex flex-wrap items-center gap-1.5">
          <Pill tone="accent">{item.source_type || "repository"}</Pill>
          {isStale(item.latest_observed_at || item.last_seen_at) ? <Pill tone="warn">stale evidence</Pill> : null}
          {item.latest_attestation ? <AttestationStatus status={item.latest_attestation.verification_status} trusted={item.latest_attestation.trusted} /> : null}
          {item.critical_findings > 0 ? <Pill tone="danger">critical {item.critical_findings}</Pill> : null}
        </div>
        <div className="mt-2 break-all font-mono text-xs font-medium">{item.repository_ref}</div>
        <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{item.repository_url || item.id}</div>
      </>
    ),
  },
  {
    id: "source", sort: () => 0, exportValue: item => [item.branch, item.commit_sha || item.source_ref, item.workflow].filter(Boolean).join(" · "),
    header: "Source", kind: "text", size: 220, maxSize: 360, wrap: true,
    className: "text-xs",
    cell: (item) => (
      <>
        <div className="font-medium">{item.branch || "branch unknown"}</div>
        <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{shortCommit(item.commit_sha || item.source_ref)}</div>
        <div className="mt-1 text-muted-foreground">{item.workflow || "workflow unknown"}</div>
      </>
    ),
  },
  {
    id: "packages", sort: () => 0, exportValue: item => `${item.package_count} packages; ${item.open_findings} open findings; ${item.inventory_hash || ""}`,
    header: "Packages", kind: "count", size: 180, minSize: 140, maxSize: 240, wrap: true,
    className: "text-xs",
    cell: (item) => (
      <>
        <div className="font-medium">{item.package_count} packages</div>
        <div className="mt-1 text-muted-foreground">{item.open_findings} open findings</div>
        <div className="mt-1 truncate font-mono text-micro text-muted-foreground">{item.inventory_hash || "hash pending"}</div>
      </>
    ),
  },
  {
    id: "scan", sort: () => 0, exportValue: item => [item.latest_job_status, item.latest_observed_at || item.last_seen_at, item.latest_job_id].filter(Boolean).join(" · "),
    header: "Scan", kind: "text", size: 220, minSize: 180, maxSize: 320, wrap: true,
    className: "text-xs",
    cell: (item) => (
      <>
        <ScanStatus status={item.latest_job_status} />
        <div className="mt-1 text-muted-foreground">{formatDate(item.latest_observed_at || item.last_seen_at)}</div>
        <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{item.latest_job_id || "job not queued"}</div>
      </>
    ),
  },
];

export function RepositoryScansPage() {
  const scope = useInventoryScope();
  const { clusterId } = scope;
  const route = useInventoryRoute();
  const { query, setQuery, selectedID, setSelectedID } = route;
  const status = route.params.get("status") || "all";
  const setStatus = (value: string) => route.update({ status: value === "all" ? null : value });
  const sort = route.params.get("sort") || "scan";
  const order = route.params.get("order") || "desc";
  const validFilters = scanStatuses.includes(status) && ['repository', 'source', 'packages', 'scan'].includes(sort) && ["asc", "desc"].includes(order);
  const request = { q: route.debouncedQuery || undefined, branch: route.params.get("branch") || undefined, workflow: route.params.get("workflow") || undefined, limit: INVENTORY_PAGE_SIZE, offset: route.offset, status: status === "all" ? undefined : status, sort, order: order as "asc" | "desc" };
  const q = useQuery({
    queryKey: ["repository-scans", scope.owner, clusterId, request],
    queryFn: () => repositoryScans.list(request),
    enabled: scope.ready && !route.debouncing && validFilters,
  });
  const rawRows = q.data?.repository_scans ?? [];
  const invalid = Boolean(q.data && (!Array.isArray(q.data.repository_scans) || !scanInventoryResponseValid(q.data, rawRows.length, route.offset, sort, order, ['total', 'packages', 'findings', 'critical_high', 'with_evidence', 'active_jobs', 'stale_evidence', 'attestations', 'trusted_attestations', 'unverified_attestations', 'branches', 'workflows'])));
  const available = scope.ready && q.isSuccess && !route.debouncing && validFilters && !invalid;
  const filtered = available ? rawRows : [];
  const hasMore = available && q.data?.has_more === true;
  const selected = filtered.find((item) => item.id === selectedID) ?? null;
  const summary = available ? q.data!.summary! : {};
  const scans = filtered;

  const matching = useScanInventoryExport({ context: JSON.stringify([scope.owner, clusterId, request]), disabled: !available || q.isFetching, download: shouldDownload => repositoryScans.exportCSV(request, shouldDownload) });
  if (!scope.ready) return <div className="space-y-4"><PageHeader title="Repositories" description="Organization-wide repository evidence; the selected cluster provides navigation context only." /><InventoryScopeState scope={scope} /></div>;

  return (
    <div className="space-y-4" data-testid="repository-scans-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Repositories"
        description="Source-repository scans: packages, scan jobs, findings and provenance attestations."
        actions={<Button disabled={q.isFetching || route.debouncing || !scope.ready || !validFilters} onClick={() => void q.refetch()}>Refresh</Button>}
      />

      <VerdictBanner status={q.isError || invalid || !validFilters ? "degraded" : "info"} title={q.isError || invalid || !validFilters ? "Repository scans are unavailable" : !available ? "Loading repository scans" : summary.total ? `${summary.total.toLocaleString()} matching repositories` : "No matching repository scans"}
        numbers={available ? [
          { label: "repositories", value: summary.total.toLocaleString(), title: `${summary.branches} branches · ${summary.workflows} workflows` },
          { label: "open findings", value: summary.findings.toLocaleString(), tone: summary.critical_high > 0 ? "high" : "default", title: `${summary.critical_high} critical or high` },
          { label: "active jobs", value: summary.active_jobs.toLocaleString() },
          { label: "attestations", value: summary.attestations.toLocaleString(), title: `${summary.trusted_attestations} trusted · ${summary.unverified_attestations} unverified` },
        ] : undefined}
        detail={<div className="space-y-1">
          {available && <p data-testid="repository-summary">Matching repositories {summary.total.toLocaleString()} ({summary.branches} branches · {summary.workflows} workflows) · packages {summary.packages.toLocaleString()} ({summary.with_evidence} with evidence) · open findings {summary.findings.toLocaleString()} ({summary.critical_high} critical/high) · active jobs {summary.active_jobs.toLocaleString()} ({summary.stale_evidence} stale evidence) · attestations {summary.attestations.toLocaleString()} ({summary.trusted_attestations} trusted · {summary.unverified_attestations} unverified)</p>}
          <p>Organization-wide repository evidence; the selected cluster provides navigation context only. Matching CSV includes fixed inventory columns across all pages (up to 100,000 records).</p>
        </div>} />
      {q.isFetching && q.isSuccess && <p role="status" className="text-sm text-muted-foreground">Refreshing scan inventory…</p>}
      {matching.status}
      {!validFilters && <ErrorState title="The requested server filter or sort is invalid. Choose a listed value to recover." action={<Button onClick={() => route.update({ sort: null, order: null, status: null })}>Reset filters and sort</Button>} />}
      {available && selectedID && !selected && <ErrorState title="The selected record is unavailable on this page or hidden by its filters." action={<Button onClick={() => setSelectedID(null)}>Clear selection</Button>} />}
      <section className="flex flex-col gap-4">
        <div data-testid={available ? "repository-table" : "repository-table-loading"}>
          {validFilters && (q.isError || invalid) ? <InventoryLoadState label="Repository scans" query={q} invalid={invalid} debouncing={route.debouncing} /> : validFilters ? <DataTable
            rows={filtered}
            pagination={false}
            manualSorting
            sort={{ id: sort, dir: order as "asc" | "desc" }}
            onSortChange={next => route.update({ sort: next?.id ?? null, order: next?.dir ?? null })}
            preferencesKey="repository-scans-inventory"
            toolbar={<>
              <InventorySearch value={query} onChange={setQuery} label="Search repositories" placeholder="Search repository, URL or commit" testId="repository-search" />
              <Select value={status} onChange={(event) => setStatus(event.target.value)} className="h-9" data-testid="repository-status-filter" aria-label="Scan job status filter">
                {scanStatuses.map((item) => <option key={item} value={item}>{item === "all" ? "Any job status" : sentenceValue(item)}</option>)}
              </Select>
              <TextInput aria-label="Branch filter" placeholder="Branch" className="h-9 w-32" value={route.params.get("branch") ?? ""} onChange={event => route.update({ branch: event.target.value }, true, true)} />
              <TextInput aria-label="Workflow filter" placeholder="Workflow" className="h-9 w-32" value={route.params.get("workflow") ?? ""} onChange={event => route.update({ workflow: event.target.value }, true, true)} />
            </>}
            exportOptions={[matching.option]}
            exportFileName="constellation-repository-scans-server-page"
            exportLabel="This page"
            columns={repositoryColumns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={selected ? new Set([selected.id]) : new Set<string>()}
            emptyState={!available ? <InventoryLoadState label="Repository scans" query={q} invalid={invalid} debouncing={route.debouncing} /> : <div className="px-3 py-8 text-center text-sm text-muted-foreground">No repository scans match the current filters.</div>}
          /> : null}
        </div>
        {available && <ScanInventoryContinuation total={q.data?.total} page={route.page} rows={scans.length} matching={filtered.length} hasMore={hasMore} onPage={route.setPage} />}
        {selected && <Collapse label="Selected record summary"><RepositoryPreview item={selected} /></Collapse>}
      </section>
    </div>
  );
}

function RepositoryPreview({ item }: { item: RepositoryScan | null }) {
  if (!item) {
    return (
      <aside className="rounded-lg border border-border bg-card p-4" data-testid="repository-preview">
        <h2 className="text-sm font-semibold">Repository inspection</h2>
        <p className="mt-2 text-xs text-muted-foreground">Select a repository scan to inspect source metadata, package counts, and findings.</p>
      </aside>
    );
  }
  const repoURL = externalURL(item.repository_url);
  return (
    <aside className="space-y-4" data-testid="repository-preview">
      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <ScanStatus status={item.latest_job_status} />
            <h2 className="mt-2 break-all font-mono text-sm font-semibold">{item.repository_ref}</h2>
            <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{item.repository_url || item.source_ref || item.id}</p>
          </div>
          {repoURL ? (
            <a href={repoURL} target="_blank" rel="noreferrer" className="rounded-md border border-border px-2 py-1 text-xs hover:bg-accent">
              Open Repo
            </a>
          ) : null}
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2">
          <MiniMetric label="Critical" value={item.critical_findings} tone={item.critical_findings > 0 ? "danger" : "normal"} />
          <MiniMetric label="High" value={item.high_findings} tone={item.high_findings > 0 ? "warn" : "normal"} />
          <MiniMetric label="Packages" value={item.package_count} tone="normal" />
        </div>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <h3 className="text-sm font-semibold">Source identity</h3>
        <dl className="mt-3 grid gap-2 text-sm">
          <Field label="Branch" value={item.branch || "-"} />
          <Field label="Commit" value={item.commit_sha || item.source_ref || "-"} />
          <Field label="Path" value={item.path || "-"} />
          <Field label="Workflow" value={item.workflow || "-"} />
          <Field label="Run" value={item.run_id || "-"} />
          <Field label="Evidence" value={item.latest_evidence_id || "-"} />
        </dl>
      </div>

      <div className="rounded-lg border border-border bg-card p-4">
        <div className="flex items-center justify-between gap-3">
          <h3 className="text-sm font-semibold">Provenance attestation</h3>
          {item.latest_attestation ? <AttestationStatus status={item.latest_attestation.verification_status} trusted={item.latest_attestation.trusted} /> : null}
        </div>
        {item.latest_attestation ? (
          <dl className="mt-3 grid gap-2 text-sm">
            <Field label="Subject" value={`${item.latest_attestation.subject_kind} · ${shortDigest(item.latest_attestation.subject_digest)}`} />
            <Field label="Predicate" value={item.latest_attestation.predicate_type} />
            <Field label="Payload" value={item.latest_attestation.payload_sha256} />
            <Field label="Policy" value={item.latest_attestation.trust_policy_id || "-"} />
            <Field label="Signer" value={item.latest_attestation.signer_identity || "-"} />
            <Field label="Issuer" value={item.latest_attestation.signer_issuer || "-"} />
            <Field label="Reason" value={item.latest_attestation.verification_reason || "-"} />
            <Field label="Observed" value={formatDate(item.latest_attestation.observed_at)} />
            <Field label="Expires" value={formatDate(item.latest_attestation.expires_at)} />
          </dl>
        ) : (
          <p className="mt-3 text-xs text-muted-foreground">No repository or CI attestation has been reported for this scan.</p>
        )}
        <AttestationHistoryPanel item={item} />
      </div>
    </aside>
  );
}

function AttestationHistoryPanel({ item }: { item: RepositoryScan }) {
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const attestationsQ = useQuery({
    queryKey: ["repository-scan-attestations", owner, item.id],
    queryFn: () => repositoryScans.attestations(item.id),
    enabled: Boolean(item.latest_attestation),
  });
  const latestID = item.latest_attestation?.id ?? "";
  const verificationsQ = useQuery({
    queryKey: ["repository-scan-attestation-verifications", owner, latestID],
    queryFn: () => repositoryScanAttestations.verifications(latestID),
    enabled: Boolean(latestID),
  });
  const attestationMismatch = Boolean(attestationsQ.data?.attestations.some(attestation => attestation.scan_target_id !== item.id));
  const verificationMismatch = Boolean(verificationsQ.data?.verifications.some(verification => verification.attestation_id !== latestID));
  const attestations = !attestationsQ.isFetching && !attestationsQ.isError && !attestationMismatch ? attestationsQ.data?.attestations ?? [] : [];
  const verifications = !verificationsQ.isFetching && !verificationsQ.isError && !verificationMismatch ? verificationsQ.data?.verifications ?? [] : [];
  if (!item.latest_attestation) return null;
  return (
    <div className="mt-4 space-y-3 border-t border-border pt-4" data-testid="repository-attestation-history">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-xs font-semibold">Attestation history</h4>
        {attestationsQ.isFetching ? <span className="text-micro text-muted-foreground">Loading...</span> : null}
      </div>
      {attestationsQ.isError || attestationMismatch ? <ErrorState title="Attestation history is unavailable." action={<Button onClick={() => void attestationsQ.refetch()}>Retry attestations</Button>} /> : attestationsQ.isFetching || attestationsQ.isPending ? <LoadingState label="Loading attestation history…" /> : attestations.length > 0 ? (
        <div className="space-y-2">
          {attestations.slice(0, 5).map((attestation) => (
            <div key={attestation.id} className="rounded-md border border-border p-2 text-xs">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <AttestationStatus status={attestation.verification_status} trusted={attestation.trusted} />
                  <div className="mt-1 break-all font-mono">{shortDigest(attestation.subject_digest)}</div>
                  <div className="mt-1 break-all text-muted-foreground">{attestation.predicate_type}</div>
                </div>
                <button
                  type="button"
                  title="Export attestation JSON"
                  aria-label="Export attestation JSON"
                  className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-border hover:bg-accent"
                  onClick={() => {
                    repositoryScanAttestations.download(attestation.id)
                      .then(() => toast.success("Attestation export downloaded"))
                      .catch((err: Error) => toast.error(`Export failed: ${err.message}`));
                  }}
                >
                  <Download className="h-3.5 w-3.5" aria-hidden />
                </button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <p className="rounded-md border border-border p-2 text-xs text-muted-foreground">No attestation history rows loaded yet.</p>
      )}

      <div>
        <h4 className="text-xs font-semibold">Verification attempts</h4>
        {verificationsQ.isError || verificationMismatch ? <ErrorState title="Verification attempts are unavailable." action={<Button onClick={() => void verificationsQ.refetch()}>Retry verifications</Button>} /> : verifications.length > 0 ? (
          <div className="mt-2 space-y-2">
            {verifications.slice(0, 5).map((verification) => (
              <div key={verification.id} className="rounded-md border border-border p-2 text-xs">
                <div className="flex flex-wrap items-center gap-1.5">
                  <AttestationStatus status={verification.status} trusted={verification.trusted} />
                  {verification.auto_verified ? <Pill tone="accent">auto</Pill> : <Pill tone="neutral">manual</Pill>}
                  {verification.require_rekor ? <Pill tone="neutral">rekor</Pill> : null}
                </div>
                <div className="mt-2 grid gap-1">
                  <Field label="Policy" value={verification.trust_policy_name || verification.trust_policy_id || "-"} />
                  <Field label="Signer" value={verification.signer_identity || "-"} />
                  <Field label="Issuer" value={verification.signer_issuer || "-"} />
                  <Field label="Reason" value={verification.reason || verification.error || "-"} />
                  <Field label="Verified" value={formatDate(verification.verified_at)} />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="mt-2 rounded-md border border-border p-2 text-xs text-muted-foreground">
            {verificationsQ.isFetching ? "Loading verification attempts..." : "No server-side verification attempts recorded yet."}
          </p>
        )}
      </div>
    </div>
  );
}

function ScanStatus({ status }: { status?: string }) {
  const value = status || "not queued";
  let tone: "neutral" | "accent" | "warn" | "danger" = "neutral";
  if (value === "completed") tone = "accent";
  if (value === "pending" || value === "running" || value === "paused") tone = "warn";
  if (value === "failed" || value === "canceled") tone = "danger";
  return <Pill tone={tone}>{value}</Pill>;
}

function AttestationStatus({ status, trusted }: { status: string; trusted: boolean }) {
  let tone: "neutral" | "accent" | "warn" | "danger" = "neutral";
  if (trusted || status === "trusted") tone = "accent";
  if (status === "unverified" || status === "unsigned") tone = "warn";
  if (status === "untrusted" || status === "error") tone = "danger";
  return <Pill tone={tone}>attestation {status}</Pill>;
}

function MiniMetric({ label, value, tone }: { label: string; value: number; tone: "normal" | "warn" | "danger" }) {
  return (
    <div className={cn("rounded-md border border-border p-2", tone === "danger" && "border-destructive/40 bg-destructive/10", tone === "warn" && "border-status-warning/40 bg-status-warning/10")}>
      <div className="text-micro text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border border-border p-2">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function Pill({ children, tone }: { children: ReactNode; tone: "neutral" | "accent" | "warn" | "danger" }) {
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center rounded px-1.5 text-micro font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "accent" && "bg-primary/10 text-primary",
        tone === "warn" && "bg-status-warning/10 text-status-warning",
        tone === "danger" && "bg-destructive/10 text-destructive",
      )}
    >
      {children}
    </span>
  );
}

function shortCommit(value?: string) {
  if (!value) return "source unknown";
  return value.length > 12 ? value.slice(0, 12) : value;
}

function shortDigest(value?: string) {
  if (!value) return "digest unknown";
  if (!value.startsWith("sha256:")) return shortCommit(value);
  return `sha256:${value.slice("sha256:".length, "sha256:".length + 12)}`;
}

function externalURL(value?: string) {
  if (!value) return "";
  return value.startsWith("https://") || value.startsWith("http://") ? value : "";
}

function isStale(value?: string): boolean {
  if (!value) return false;
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t > 7 * 86400 * 1000;
}

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}
