import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { Clock, Download, Fingerprint, GitBranch, PackageSearch, Search, ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import { repositoryScanAttestations, repositoryScans, type RepositoryScan } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { DataTable, type Column } from "@/components/ui/data-table";
import { cn } from "@/lib/cn";

const scanStatuses = ["all", "pending", "running", "completed", "failed", "paused", "canceled"];

const repositoryColumns: Column<RepositoryScan>[] = [
  {
    id: "repository",
    header: "Repository",
    cell: (item) => (
      <>
        <div className="flex flex-wrap items-center gap-1.5">
          <Pill tone="accent">{item.source_type || "repository"}</Pill>
          {isStale(item.latest_observed_at || item.last_seen_at) ? <Pill tone="warn">stale evidence</Pill> : null}
          {item.latest_attestation ? <AttestationStatus status={item.latest_attestation.verification_status} trusted={item.latest_attestation.trusted} /> : null}
          {item.critical_findings > 0 ? <Pill tone="danger">critical {item.critical_findings}</Pill> : null}
        </div>
        <div className="mt-2 break-all font-mono text-xs font-medium">{item.repository_ref}</div>
        <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{item.repository_url || item.id}</div>
      </>
    ),
  },
  {
    id: "source",
    header: "Source",
    className: "text-xs",
    cell: (item) => (
      <>
        <div className="font-medium">{item.branch || "branch unknown"}</div>
        <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{shortCommit(item.commit_sha || item.source_ref)}</div>
        <div className="mt-1 text-muted-foreground">{item.workflow || "workflow unknown"}</div>
      </>
    ),
  },
  {
    id: "packages",
    header: "Packages",
    className: "text-xs",
    cell: (item) => (
      <>
        <div className="font-medium">{item.package_count} packages</div>
        <div className="mt-1 text-muted-foreground">{item.open_findings} open findings</div>
        <div className="mt-1 truncate font-mono text-[10px] text-muted-foreground">{item.inventory_hash || "hash pending"}</div>
      </>
    ),
  },
  {
    id: "scan",
    header: "Scan",
    className: "text-xs",
    cell: (item) => (
      <>
        <ScanStatus status={item.latest_job_status} />
        <div className="mt-1 text-muted-foreground">{formatDate(item.latest_observed_at || item.last_seen_at)}</div>
        <div className="mt-1 break-all font-mono text-[10px] text-muted-foreground">{item.latest_job_id || "job not queued"}</div>
      </>
    ),
  },
];

export function RepositoryScansPage() {
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState("all");
  const [selectedID, setSelectedID] = useState<string | null>(null);

  const q = useQuery({
    queryKey: ["repository-scans"],
    queryFn: () => repositoryScans.list({ limit: 500 }),
  });

  const scans = useMemo(() => q.data?.repository_scans ?? [], [q.data?.repository_scans]);
  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return scans.filter((item) => {
      if (status !== "all" && (item.latest_job_status || "not queued") !== status) return false;
      if (!needle) return true;
      return [
        item.repository_ref,
        item.repository_url ?? "",
        item.source_ref ?? "",
        item.commit_sha ?? "",
        item.branch ?? "",
        item.path ?? "",
        item.workflow ?? "",
        item.run_id ?? "",
        item.latest_job_status ?? "",
      ].some((value) => value.toLowerCase().includes(needle));
    });
  }, [query, scans, status]);
  const selected = filtered.find((item) => item.id === selectedID) ?? filtered[0] ?? null;
  const summary = useMemo(() => summarize(scans), [scans]);

  if (clusterLoading) return <p className="text-sm text-muted-foreground">Loading cluster...</p>;

  return (
    <div className="space-y-4" data-testid="repository-scans-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Repositories"
        description="Source-repository scans — package inventory, scan jobs, findings, and provenance attestations."
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5" data-testid="repository-summary">
        <StatCard label="Repositories" value={summary.total.toLocaleString()} icon={<GitBranch className="h-3.5 w-3.5" />} hint={`${summary.branches} branches · ${summary.workflows} workflows`} />
        <StatCard label="Packages" value={summary.packages.toLocaleString()} icon={<PackageSearch className="h-3.5 w-3.5" />} hint={`${summary.withEvidence} with evidence`} />
        <StatCard label="Open Findings" value={summary.findings.toLocaleString()} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={summary.criticalHigh > 0 ? "high" : "neutral"} hint={`${summary.criticalHigh} critical/high`} />
        <StatCard label="Active Jobs" value={summary.activeJobs.toLocaleString()} icon={<Clock className="h-3.5 w-3.5" />} hint={`${summary.staleEvidence} stale evidence`} />
        <StatCard label="Attestations" value={summary.attestations.toLocaleString()} icon={<Fingerprint className="h-3.5 w-3.5" />} hint={`${summary.trustedAttestations} trusted · ${summary.unverifiedAttestations} unverified`} />
      </section>

      <section className="rounded-lg border border-border bg-card p-3">
        <div className="grid gap-2 lg:grid-cols-[minmax(0,1fr)_170px]">
          <label className="relative block">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" aria-hidden />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search repository, commit, branch, workflow, run"
              className="w-full rounded-md border border-border bg-background py-2 pl-9 pr-3 text-sm"
              data-testid="repository-search"
            />
          </label>
          <select
            value={status}
            onChange={(event) => setStatus(event.target.value)}
            className="rounded-md border border-border bg-background p-2 text-sm"
            data-testid="repository-status-filter"
          >
            {scanStatuses.map((item) => (
              <option key={item} value={item}>{item === "all" ? "All jobs" : item}</option>
            ))}
          </select>
        </div>
      </section>

      <section className="flex flex-col gap-4">
        <div data-testid="repository-table">
          <DataTable
            rows={filtered}
            columns={repositoryColumns}
            rowKey={(item) => item.id}
            onRowClick={(item) => setSelectedID(item.id)}
            selected={selected ? new Set([selected.id]) : new Set<string>()}
            emptyState={
              <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                {q.isPending ? "Loading repository scans..." : "No repository scans match the current filters."}
              </div>
            }
          />
        </div>

        <RepositoryPreview item={selected} />
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
  const attestationsQ = useQuery({
    queryKey: ["repository-scan-attestations", item.id],
    queryFn: () => repositoryScans.attestations(item.id),
    enabled: Boolean(item.latest_attestation),
  });
  const latestID = item.latest_attestation?.id ?? "";
  const verificationsQ = useQuery({
    queryKey: ["repository-scan-attestation-verifications", latestID],
    queryFn: () => repositoryScanAttestations.verifications(latestID),
    enabled: Boolean(latestID),
  });
  const attestations = attestationsQ.data?.attestations ?? [];
  const verifications = verificationsQ.data?.verifications ?? [];
  if (!item.latest_attestation) return null;
  return (
    <div className="mt-4 space-y-3 border-t border-border pt-4" data-testid="repository-attestation-history">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-xs font-semibold">Attestation history</h4>
        {attestationsQ.isFetching ? <span className="text-[10px] text-muted-foreground">Loading...</span> : null}
      </div>
      {attestations.length > 0 ? (
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
        {verifications.length > 0 ? (
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

function summarize(items: RepositoryScan[]) {
  const branches = new Set(items.map((item) => item.branch).filter(Boolean));
  const workflows = new Set(items.map((item) => item.workflow).filter(Boolean));
  return {
    total: items.length,
    branches: branches.size,
    workflows: workflows.size,
    packages: items.reduce((sum, item) => sum + item.package_count, 0),
    withEvidence: items.filter((item) => !!item.latest_evidence_id).length,
    findings: items.reduce((sum, item) => sum + item.open_findings, 0),
    criticalHigh: items.reduce((sum, item) => sum + item.critical_findings + item.high_findings, 0),
    activeJobs: items.filter((item) => item.latest_job_status === "pending" || item.latest_job_status === "running").length,
    staleEvidence: items.filter((item) => isStale(item.latest_observed_at || item.last_seen_at)).length,
    attestations: items.filter((item) => !!item.latest_attestation).length,
    trustedAttestations: items.filter((item) => item.latest_attestation?.trusted).length,
    unverifiedAttestations: items.filter((item) => item.latest_attestation?.verification_status === "unverified").length,
  };
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
      <div className="text-[10px] text-muted-foreground">{label}</div>
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
        "inline-flex h-5 items-center rounded px-1.5 text-[10px] font-medium",
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
