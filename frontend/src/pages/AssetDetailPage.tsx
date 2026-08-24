import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { Boxes, FileJson, ShieldAlert, ShieldCheck, Undo2 } from "lucide-react";
import { toast } from "sonner";

import { assets, sbom, type ImageAcceptance } from "@/api/client";
import { dateInputDaysFromNow, dateInputEndOfDayWithinDays } from "@/lib/format";
import { useCluster } from "@/hooks/useCluster";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard } from "@/components/ui/stat-card";

const ACCEPT_RISK_MAX_DAYS = 30;

export function AssetDetailPage() {
  const { aid } = useParams<{ aid: string }>();
  const { clusterId } = useCluster();
  const qc = useQueryClient();
  const [rationale, setRationale] = useState("");
  const [acceptedUntil, setAcceptedUntil] = useState(
    () => dateInputDaysFromNow(14),
  );
  const q = useQuery({
    queryKey: ["asset", aid],
    queryFn: () => assets.get(aid!),
    enabled: !!aid,
  });
  const createAcceptance = useMutation({
    mutationFn: () =>
      assets.createImageAcceptance(aid!, {
        rationale,
        accepted_until: dateInputEndOfDayWithinDays(acceptedUntil, ACCEPT_RISK_MAX_DAYS),
      }),
    onSuccess: () => {
      toast.success("Image risk accepted");
      setRationale("");
      qc.invalidateQueries({ queryKey: ["asset", aid] });
    },
    onError: () => toast.error("Image accept-risk failed"),
  });
  const revokeAcceptance = useMutation({
    mutationFn: (acceptanceID: string) => assets.revokeImageAcceptance(aid!, acceptanceID),
    onSuccess: () => {
      toast.success("Image acceptance revoked");
      qc.invalidateQueries({ queryKey: ["asset", aid] });
    },
    onError: () => toast.error("Revoke failed"),
  });

  if (q.isPending) return <p className="text-sm text-muted-foreground">Loading asset...</p>;
  if (q.isError || !q.data) return <p className="text-sm text-status-error">Asset not found.</p>;

  const { asset, image, image_scan_result, findings, sboms, image_acceptances } = q.data;
  const activeAcceptance = image_acceptances.find((item) => item.status === "active");
  type AssetFinding = (typeof findings)[number];
  const findingColumns: Column<AssetFinding>[] = [
    {
      id: "finding",
      header: "Finding",
      cell: (f) => (
        <>
          {f.image_scan_result_id ? (
            <span className="font-medium">{f.title}</span>
          ) : (
            <Link to={`/clusters/${clusterId}/findings/${f.id}`} className="font-medium hover:underline">{f.title}</Link>
          )}
          <div className="text-xs text-muted-foreground">{f.external_id}</div>
        </>
      ),
    },
    { id: "kind", header: "Kind", cell: (f) => f.kind, className: "text-xs" },
    { id: "severity", header: "Severity", cell: (f) => f.severity, className: "text-xs" },
    { id: "risk", header: "Risk", cell: (f) => f.risk_score, className: "font-semibold" },
  ];
  return (
    <PageContainer>
      <PageHeader
        eyebrow={<Link to={`/clusters/${clusterId}/assets`} className="hover:underline">Assets</Link>}
        title={asset.name}
        description={`${asset.kind} · ${asset.criticality} criticality — image, supply-chain evidence, and accepted-risk history for this asset.`}
      />

      <section className="grid grid-cols-3 gap-3" data-testid="asset-stats">
        <StatCard label="Findings" value={findings.length} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={findings.length > 0 ? "high" : "neutral"} />
        <StatCard label="SBOMs" value={sboms.length} icon={<FileJson className="h-3.5 w-3.5" />} />
        <StatCard label="Layers" value={image?.layers.length ?? 0} icon={<Boxes className="h-3.5 w-3.5" />} />
      </section>

      <div className="space-y-4">
        <div className="rounded-lg border border-border bg-card p-4" data-testid="asset-image-card">
          <h2 className="text-sm font-semibold">Image and supply chain</h2>
          {image ? (
            <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2 lg:grid-cols-4">
              <Field label="Registry" value={image.registry} />
              <Field label="Repository" value={image.repository} />
              <Field label="Tag" value={image.tag || "-"} />
              <Field label="Signed" value={image.signed ? "yes" : "no"} />
              <Field label="Architectures" value={image.architectures.join(", ")} />
              <Field label="Size" value={formatBytes(image.size_bytes ?? 0)} />
              <Field label="Digest" value={image.digest} wide />
            </dl>
          ) : (
            <p className="mt-2 text-xs text-muted-foreground">No image metadata for this asset type.</p>
          )}
        </div>

        <div className="overflow-hidden rounded-lg border border-border bg-card" data-testid="asset-findings">
          {image_scan_result ? (
            <div className="border-b border-border px-3 py-2 text-xs text-muted-foreground">
              Image scan {image_scan_result.image_digest} · {image_scan_result.scanner_profile} · {image_scan_result.finding_count} findings
            </div>
          ) : null}
          <DataTable rows={findings} columns={findingColumns} rowKey={(f) => f.id} />
        </div>

        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <div className="rounded-lg border border-border bg-card p-4" data-testid="image-acceptance-card">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">Image accept-risk</h2>
                <p className="mt-1 text-xs text-muted-foreground">
                  Digest scoped, audited, and expires automatically.
                </p>
              </div>
              <StatusBadge status={activeAcceptance ? "active" : "none"} />
            </div>

            {activeAcceptance ? (
              <AcceptanceSummary
                item={activeAcceptance}
                onRevoke={() => revokeAcceptance.mutate(activeAcceptance.id)}
                disabled={revokeAcceptance.isPending}
              />
            ) : (
              <div className="mt-3 space-y-3">
                <textarea
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  disabled={!image || createAcceptance.isPending}
                  placeholder="Compensating control, ticket, or deployment justification"
                  rows={3}
                  className="w-full rounded-md border border-border bg-background p-2 text-sm"
                  data-testid="image-accept-rationale"
                />
                <div className="flex flex-wrap items-end gap-2">
                  <label className="block text-xs font-medium">
                    Accepted Until
                    <input
                      type="date"
                      value={acceptedUntil}
                      max={dateInputDaysFromNow(ACCEPT_RISK_MAX_DAYS)}
                      onChange={(e) => setAcceptedUntil(e.target.value)}
                      disabled={!image || createAcceptance.isPending}
                      className="mt-1 block rounded-md border border-border bg-background p-2 text-sm"
                      data-testid="image-accept-until"
                    />
                  </label>
                  <button
                    type="button"
                    disabled={!image || createAcceptance.isPending || rationale.trim().length < 12}
                    onClick={() => createAcceptance.mutate()}
                    className="inline-flex items-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                    data-testid="image-accept-submit"
                  >
                    <ShieldCheck className="h-4 w-4" aria-hidden />
                    Accept Image Risk
                  </button>
                </div>
                {image_acceptances.length > 0 ? <AcceptanceHistory items={image_acceptances} /> : null}
              </div>
            )}
          </div>

          <div className="rounded-lg border border-border bg-card p-4" data-testid="asset-sbom-card">
            <h2 className="text-sm font-semibold">SBOM exports</h2>
            <ul className="mt-3 space-y-2">
              {sboms.map((doc) => (
                <li key={doc.id} className="rounded-md border border-border p-3">
                  <div className="text-sm font-medium">{doc.format}</div>
                  <div className="mt-1 truncate font-mono text-xs text-muted-foreground">{doc.sha256}</div>
                </li>
              ))}
            </ul>
            <div className="mt-3 flex flex-wrap gap-2 text-xs">
              <button type="button" className="rounded-md border border-border px-2 py-1 hover:bg-accent" onClick={() => sbom.downloadSpdx(asset.id).catch((e: Error) => toast.error(`SBOM export failed: ${e.message}`))}>SPDX</button>
              <button type="button" className="rounded-md border border-border px-2 py-1 hover:bg-accent" onClick={() => sbom.downloadCyclonedx(asset.id).catch((e: Error) => toast.error(`SBOM export failed: ${e.message}`))}>CycloneDX</button>
              <button type="button" className="rounded-md border border-border px-2 py-1 hover:bg-accent" onClick={() => sbom.downloadMbom(asset.id).catch((e: Error) => toast.error(`SBOM export failed: ${e.message}`))}>MBOM</button>
            </div>
          </div>
        </div>

        <div className="rounded-lg border border-border bg-card p-4">
          <h2 className="text-sm font-semibold">Labels</h2>
          <pre className="mt-3 overflow-x-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(asset.labels, null, 2)}</pre>
        </div>
      </div>
    </PageContainer>
  );
}

function Field({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={`rounded-md border border-border p-2 ${wide ? "sm:col-span-2" : ""}`}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-1 break-all font-medium">{value}</dd>
    </div>
  );
}

function AcceptanceSummary({
  item,
  onRevoke,
  disabled,
}: {
  item: ImageAcceptance;
  onRevoke: () => void;
  disabled: boolean;
}) {
  return (
    <div className="mt-3 rounded-md border border-border p-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <div className="break-all font-mono text-xs text-muted-foreground">{item.image_digest}</div>
          <p className="mt-2 text-sm">{item.rationale}</p>
          <p className="mt-2 text-xs text-muted-foreground">Expires {formatDate(item.accepted_until)}</p>
        </div>
        <button
          type="button"
          onClick={onRevoke}
          disabled={disabled}
          className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 text-xs hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="image-accept-revoke"
        >
          <Undo2 className="h-3.5 w-3.5" aria-hidden />
          Revoke
        </button>
      </div>
    </div>
  );
}

function AcceptanceHistory({ items }: { items: ImageAcceptance[] }) {
  return (
    <div className="space-y-2" data-testid="image-accept-history">
      {items.map((item) => (
        <div key={item.id} className="rounded-md border border-border p-2 text-xs">
          <div className="flex items-center justify-between gap-2">
            <StatusBadge status={item.status} />
            <span className="text-muted-foreground">{formatDate(item.accepted_until)}</span>
          </div>
          <p className="mt-1 text-sm">{item.rationale}</p>
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: ImageAcceptance["status"] | "none" }) {
  const classes = {
    active: "border-status-success/40 bg-status-success/10 text-status-success",
    revoked: "border-muted bg-muted text-muted-foreground",
    expired: "border-status-warning/40 bg-status-warning/10 text-status-warning",
    none: "border-border bg-muted text-muted-foreground",
  };
  return (
    <span className={`rounded-md border px-2 py-0.5 text-xs font-medium ${classes[status]}`}>
      {status}
    </span>
  );
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(new Date(value));
}

function formatBytes(bytes: number) {
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  if (bytes >= 1_000) return `${(bytes / 1_000).toFixed(1)} KB`;
  return `${bytes} B`;
}
