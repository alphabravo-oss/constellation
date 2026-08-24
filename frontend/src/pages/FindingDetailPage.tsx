import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { findings, type AffectedRange, type Finding } from "@/api/client";
import { dateInputDaysFromNow, dateInputEndOfDayWithinDays } from "@/lib/format";
import { severityBg } from "@/lib/severity";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";

type ReconSignal = NonNullable<Finding["reconciliation"]>[number];
const ACCEPT_RISK_MAX_DAYS = 30;

export function FindingDetailPage() {
  // Route param is :fid (see App.tsx). Alias to `id` for the queries below.
  const { fid: id } = useParams<{ fid: string }>();
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["finding", id], queryFn: () => findings.get(id!), enabled: !!id });
  const comments = useQuery({
    queryKey: ["finding-comments", id],
    queryFn: () => findings.listComments(id!),
    enabled: !!id,
  });

  const suppress = useMutation({
    mutationFn: () => findings.suppress(id!, { reason: "manual" }),
    onSuccess: () => {
      toast.success("Suppressed");
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
  });

  const [showAccept, setShowAccept] = useState(false);
  const [rationale, setRationale] = useState("");
  const [acceptedUntil, setAcceptedUntil] = useState(
    () => dateInputDaysFromNow(ACCEPT_RISK_MAX_DAYS),
  );
  const acceptRisk = useMutation({
    mutationFn: () =>
      findings.acceptRisk(id!, {
        reason: rationale,
        accepted_until: dateInputEndOfDayWithinDays(acceptedUntil, ACCEPT_RISK_MAX_DAYS),
      }),
    onSuccess: () => {
      toast.success("Risk accepted");
      setShowAccept(false);
      setRationale("");
      qc.invalidateQueries({ queryKey: ["finding", id] });
    },
    onError: () => toast.error("Accept-risk failed"),
  });

  const [commentBody, setCommentBody] = useState("");
  const addComment = useMutation({
    mutationFn: () => findings.addComment(id!, { body: commentBody }),
    onSuccess: () => {
      setCommentBody("");
      qc.invalidateQueries({ queryKey: ["finding-comments", id] });
    },
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading…</p>;
  if (!q.data) return <p className="text-sm text-destructive">Not found.</p>;
  const f = q.data;
  const score = cvssScore(f);
  const hasVulnerabilityMetadata =
    typeof score === "number" || Boolean(f.cvss_vector) || Boolean(f.kev) || typeof f.epss === "number";

  const reconColumns: Column<ReconSignal>[] = [
    { id: "engine", header: "Engine", cell: (s) => <span className="font-mono">{s.engine}</span> },
    { id: "field", header: "Field", cell: (s) => <span className="font-mono">{s.field}</span> },
    { id: "canonical", header: "VulnDB", cell: (s) => <span className="font-mono">{s.canonical || "—"}</span> },
    { id: "evidence", header: "Evidence", cell: (s) => <span className="font-mono">{s.evidence || "—"}</span> },
  ];

  return (
    <PageContainer>
      <PageHeader
        eyebrow={<span className="font-mono font-normal normal-case tracking-normal">{f.external_id}</span>}
        title={f.title}
        description={
          <span className="flex flex-wrap items-center gap-2 text-xs">
            <span className={`rounded-md px-2 py-0.5 ${severityBg[f.severity]}`}>{f.severity}</span>
            <span>risk {f.risk_score}</span>
            {typeof score === "number" ? <span>· CVSS {score.toFixed(1)}</span> : null}
            <span>· {f.kind}</span>
            <span>· {f.lifecycle}</span>
            {isExceptionLifecycle(f.lifecycle) ? (
              <Link
                to={exceptionHref(f.lifecycle, f.id)}
                className="rounded-md border border-border px-2 py-0.5 text-foreground hover:bg-accent"
                data-testid="finding-exception-link"
              >
                {exceptionLabel(f)}
              </Link>
            ) : null}
          </span>
        }
        actions={
          <>
            <button
              type="button"
              onClick={() => suppress.mutate()}
              className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-accent"
            >
              Suppress
            </button>
            <button
              type="button"
              onClick={() => setShowAccept((s) => !s)}
              className="rounded-md border border-border bg-card px-3 py-1.5 text-sm hover:bg-accent"
            >
              Accept risk
            </button>
          </>
        }
      />

      {f.asset_id ? (
        <section
          className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-card px-4 py-2.5 text-xs"
          data-testid="finding-affected-asset"
        >
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Affected asset</span>
          <span className="font-mono">{f.asset_id.slice(0, 24)}</span>
          <div className="ml-auto flex items-center gap-2">
            <Link
              to={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(f.asset_id)}`}
              className="rounded-md border border-border px-2 py-1 text-foreground hover:bg-accent"
              data-testid="finding-affected-asset-risk"
            >
              Risk workspace
            </Link>
            <Link
              to={`/clusters/${clusterId}/assets/${encodeURIComponent(f.asset_id)}`}
              className="rounded-md border border-border px-2 py-1 text-foreground hover:bg-accent"
              data-testid="finding-affected-asset-detail"
            >
              Asset detail
            </Link>
          </div>
        </section>
      ) : null}

      {showAccept && (
        <section
          className="rounded-lg border border-border bg-card p-4"
          data-testid="accept-risk-modal"
        >
          <h2 className="mb-2 text-sm font-medium">Accept Risk</h2>
          <p className="mb-3 text-xs text-muted-foreground">
            Accepting risk silences this finding org-wide until the expiry date. The action is
            audited with rationale + approver.
          </p>
          <label className="mb-2 block text-xs font-medium">Rationale</label>
          <textarea
            value={rationale}
            onChange={(e) => setRationale(e.target.value)}
            placeholder="Why is this risk acceptable? (e.g. compensating controls)"
            className="mb-3 w-full rounded-md border border-border bg-background p-2 text-sm"
            rows={3}
            data-testid="accept-risk-rationale"
          />
          <label className="mb-2 block text-xs font-medium">Accepted Until</label>
          <input
            type="date"
            value={acceptedUntil}
            max={dateInputDaysFromNow(ACCEPT_RISK_MAX_DAYS)}
            onChange={(e) => setAcceptedUntil(e.target.value)}
            className="mb-3 rounded-md border border-border bg-background p-2 text-sm"
            data-testid="accept-risk-until"
          />
          <div className="flex gap-2">
            <button
              type="button"
              disabled={!rationale.trim() || acceptRisk.isPending}
              onClick={() => acceptRisk.mutate()}
              className="rounded-md bg-foreground px-3 py-1.5 text-sm text-background hover:opacity-90 disabled:opacity-50"
              data-testid="accept-risk-submit"
            >
              Submit
            </button>
            <button
              type="button"
              onClick={() => setShowAccept(false)}
              className="rounded-md border border-border px-3 py-1.5 text-sm hover:bg-accent"
            >
              Cancel
            </button>
          </div>
        </section>
      )}

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

      <section className="rounded-lg border border-border bg-card p-4">
        <h2 className="mb-2 text-sm font-medium">Raw Risk Inputs</h2>
        <pre className="overflow-x-auto rounded-md bg-muted p-3 text-xs">
{JSON.stringify(f.risk_inputs ?? {}, null, 2)}
        </pre>
      </section>

      <section
        className="rounded-lg border border-border bg-card p-4"
        data-testid="comments-section"
      >
        <h2 className="mb-3 text-sm font-medium">Comments</h2>
        <ul className="mb-3 space-y-2" data-testid="comments-list">
          {(comments.data?.comments ?? []).length === 0 && (
            <li className="text-xs text-muted-foreground">No comments yet.</li>
          )}
          {(comments.data?.comments ?? []).map((c) => (
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
        <textarea
          value={commentBody}
          onChange={(e) => setCommentBody(e.target.value)}
          placeholder="Add a comment…"
          className="mb-2 w-full rounded-md border border-border bg-background p-2 text-sm"
          rows={2}
          data-testid="comment-input"
        />
        <button
          type="button"
          disabled={!commentBody.trim() || addComment.isPending}
          onClick={() => addComment.mutate()}
          className="rounded-md bg-foreground px-3 py-1.5 text-sm text-background hover:opacity-90 disabled:opacity-50"
          data-testid="comment-submit"
        >
          Post Comment
        </button>
      </section>
    </PageContainer>
  );
}

function isExceptionLifecycle(lifecycle: string) {
  return lifecycle === "accepted" || lifecycle === "suppressed";
}

function exceptionHref(lifecycle: string, query: string) {
  const status = lifecycle === "suppressed" ? "suppressed" : "approved";
  const params = new URLSearchParams({ status, target: "finding", finding: query });
  return `/exceptions?${params.toString()}`;
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
      <dt className="text-[10px] uppercase tracking-wider text-muted-foreground">{label}</dt>
      <dd className={mono ? "mt-1 break-all font-mono text-xs" : "mt-1 text-xs"}>{value}</dd>
    </div>
  );
}
