import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Boxes, ChevronLeft, Database, Download, FileJson, FileWarning, KeyRound, Layers, ShieldAlert, ShieldCheck } from "lucide-react";
import { toast } from "sonner";

import {
  imageScanResults,
  type ImageFileRiskFinding,
  type ImageConfigCheck,
  type ImageLayerDescriptor,
  type ImagePackageLayer,
  type ImageScanFinding,
  type ImageScanResult,
  type ImageSecretFinding,
  type ImageSignatureResult,
  type ImpactedWorkload,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";

export function ImageScanDetailPage() {
  const { resultId } = useParams<{ resultId: string }>();
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["image-scan-result", resultId],
    queryFn: () => imageScanResults.get(resultId!),
    enabled: !!resultId,
  });

  const detail = q.data;
  const result = detail?.image_scan_result;
  const clusterWorkloads = useMemo(() => {
    const workloads = detail?.impacted_workloads ?? [];
    return clusterId ? workloads.filter((item) => item.cluster_id === clusterId) : workloads;
  }, [clusterId, detail?.impacted_workloads]);

  if (clusterLoading || q.isPending) return <p className="text-sm text-muted-foreground">Loading image scan...</p>;
  if (q.isError || !result) return <p className="text-sm text-status-error">Image scan not found.</p>;

  return (
    <div className="space-y-4" data-testid="image-scan-detail-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={`/clusters/${clusterId}/images`} className="inline-flex items-center gap-1 hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            Images
          </Link>
        }
        title={displayImage(result)}
        mono
        badges={
          <>
            <ImageKindBadge item={result} />
            {clusterWorkloads.length > 0 ? <Pill tone="accent">running workload</Pill> : null}
            {isStale(result.last_scanned_at) ? <Pill tone="warn">stale scan</Pill> : null}
            <SignaturePill item={result} />
          </>
        }
        description={<span className="break-all font-mono">{result.image_digest}</span>}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-4 xl:grid-cols-7" data-testid="image-scan-stats">
        <StatCard label="Findings" value={result.finding_count} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={result.finding_count > 0 ? "high" : "neutral"} />
        <StatCard label="Packages" value={result.package_count} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Layers" value={result.layer_count} icon={<Layers className="h-3.5 w-3.5" />} />
        <StatCard label="Secrets" value={result.secret_count} icon={<KeyRound className="h-3.5 w-3.5" />} tone={result.secret_count > 0 ? "critical" : "neutral"} />
        <StatCard label="File Risks" value={result.file_risk_count} icon={<FileWarning className="h-3.5 w-3.5" />} tone={result.file_risk_count > 0 ? "medium" : "neutral"} />
        <StatCard label="Workloads" value={clusterWorkloads.length} icon={<Layers className="h-3.5 w-3.5" />} tone={clusterWorkloads.length > 0 ? "accent" : "neutral"} />
        <StatCard label="Risk" value={result.max_risk_score} icon={<Boxes className="h-3.5 w-3.5" />} />
      </section>

      <div className="space-y-4">
        <ScanIdentity result={result} />
        <ArtifactEvidenceSection result={result} />
        <FindingsTable findings={detail.findings} />
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <WorkloadsPanel workloads={clusterWorkloads} />
          <BundlePanel result={result} />
        </div>
      </div>
    </div>
  );
}

function ArtifactEvidenceSection({ result }: { result: ImageScanResult }) {
  const layersQ = useQuery({
    queryKey: ["image-scan-layers", result.id],
    queryFn: () => imageScanResults.layers(result.id),
    enabled: result.layer_count > 0,
  });
  const packagesQ = useQuery({
    queryKey: ["image-scan-packages", result.id],
    queryFn: () => imageScanResults.packages(result.id),
    enabled: result.package_count > 0,
  });
  const secretsQ = useQuery({
    queryKey: ["image-scan-secrets", result.id],
    queryFn: () => imageScanResults.secrets(result.id),
    enabled: result.secret_count > 0,
  });
  const fileRisksQ = useQuery({
    queryKey: ["image-scan-file-risks", result.id],
    queryFn: () => imageScanResults.fileRisks(result.id),
    enabled: result.file_risk_count > 0,
  });
  const signatureQ = useQuery({
    queryKey: ["image-scan-signature", result.id],
    queryFn: () => imageScanResults.signature(result.id),
    enabled: !!result.signature_status,
  });
  // Config checks are computed for every image (no count gate); 404s on older scans.
  const configChecksQ = useQuery({
    queryKey: ["image-scan-config-checks", result.id],
    queryFn: () => imageScanResults.configChecks(result.id),
    retry: false,
  });

  const layers = layersQ.data?.layer_metadata.layers ?? [];
  const packageLayers = packagesQ.data?.package_layers ?? [];
  const secrets = secretsQ.data?.secret_scan.secrets ?? [];
  const fileRisks = fileRisksQ.data?.file_risk.findings ?? [];
  const signature = signatureQ.data?.signature_scan.signature;
  const configChecks = configChecksQ.data?.config_checks.checks ?? [];

  return (
    <section className="grid gap-4 2xl:grid-cols-2" data-testid="image-scan-artifact-evidence">
      <SignatureEvidenceCard
        result={result}
        loading={signatureQ.isPending && !!result.signature_status}
        signature={signature}
        status={signatureQ.data?.signature_scan.status || result.signature_status || ""}
      />
      <PackagesEvidenceCard
        loading={packagesQ.isPending && result.package_count > 0}
        packageLayers={packageLayers}
        layerPackageCount={packagesQ.data?.layer_package_count ?? 0}
        unattributedPackageCount={packagesQ.data?.unattributed_package_count ?? result.package_count}
        totalPackageCount={result.package_count}
      />
      <LayersEvidenceCard loading={layersQ.isPending && result.layer_count > 0} layers={layers} totalSize={layersQ.data?.layer_metadata.total_size_bytes} result={result} />
      <SecretsEvidenceCard loading={secretsQ.isPending && result.secret_count > 0} secrets={secrets} count={result.secret_count} />
      <FileRisksEvidenceCard loading={fileRisksQ.isPending && result.file_risk_count > 0} findings={fileRisks} count={result.file_risk_count} />
      <ConfigChecksEvidenceCard loading={configChecksQ.isPending} checks={configChecks} />
    </section>
  );
}

function PackagesEvidenceCard({
  loading,
  packageLayers,
  layerPackageCount,
  unattributedPackageCount,
  totalPackageCount,
}: {
  loading: boolean;
  packageLayers: ImagePackageLayer[];
  layerPackageCount: number;
  unattributedPackageCount: number;
  totalPackageCount: number;
}) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Package provenance</h2>
        <span className="font-mono text-xs text-muted-foreground">
          {layerPackageCount}/{totalPackageCount} layer-linked
        </span>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading package provenance...</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-muted text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Layer</th>
              <th className="px-3 py-2 text-left">Package</th>
              <th className="px-3 py-2 text-left">Evidence path</th>
            </tr>
          </thead>
          <tbody>
            {packageLayers.flatMap((layer) =>
              layer.packages.slice(0, 4).map((pkg) => {
                const loc = (pkg.locations ?? []).find((item) => item.layer_digest === layer.layer_digest) ?? pkg.locations?.[0];
                return (
                  <tr key={`${layer.layer_digest || layer.layer_index}:${pkg.ecosystem}:${pkg.name}:${pkg.version}`} className="border-t border-border">
                    <td className="max-w-[180px] truncate px-3 py-2 font-mono text-xs" title={layer.layer_digest}>
                      {layer.layer_digest || `${layer.layer_index ?? "-"}`}
                    </td>
                    <td className="px-3 py-2">
                      <div className="font-mono text-xs">{pkg.name || "-"}</div>
                      <div className="mt-1 font-mono text-[11px] text-muted-foreground">{pkg.version || pkg.ecosystem || "-"}</div>
                    </td>
                    <td className="max-w-[260px] truncate px-3 py-2 font-mono text-xs" title={loc?.path || loc?.real_path || loc?.access_path}>
                      {loc?.path || loc?.real_path || loc?.access_path || "-"}
                    </td>
                  </tr>
                );
              }),
            )}
            {packageLayers.length === 0 ? (
              <tr>
                <td colSpan={3} className="px-3 py-6 text-center text-xs text-muted-foreground">
                  {unattributedPackageCount > 0 ? "Package inventory is present, but no layer attribution was captured." : "No package inventory recorded."}
                </td>
              </tr>
            ) : null}
          </tbody>
        </table>
      )}
    </section>
  );
}

function SignatureEvidenceCard({
  result,
  loading,
  signature,
  status,
}: {
  result: ImageScanResult;
  loading: boolean;
  signature?: ImageSignatureResult;
  status: string;
}) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Signature evidence</h2>
        <SignaturePill item={result} />
      </div>
      {loading ? (
        <p className="mt-3 text-xs text-muted-foreground">Loading signature evidence...</p>
      ) : (
        <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
          <Field label="Status" value={status || "-"} />
          <Field label="Trusted" value={signature?.trusted ? "yes" : signature?.signed ? "no" : "-"} />
          <Field label="Identity" value={signature?.identity || "-"} wide />
          <Field label="Issuer" value={signature?.issuer || "-"} wide />
          <Field label="Reason" value={signature?.reason || signature?.error || "-"} wide />
          <Field label="Rekor" value={signature?.rekor_log || "-"} wide />
        </dl>
      )}
    </section>
  );
}

function LayersEvidenceCard({ loading, layers, totalSize, result }: { loading: boolean; layers: ImageLayerDescriptor[]; totalSize?: number; result: ImageScanResult }) {
  // Dockerfile-style reconstruction: one row per layer with the build instruction that
  // created it, base-vs-app attribution, size, and package count. Mirrors NeuVector's
  // layered image view (the scanner already computes command/in_base_image/package_count).
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Image layers · Dockerfile</h2>
        <span className="font-mono text-xs text-muted-foreground">{result.layer_count} layers · {formatBytes(totalSize)}</span>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading layers…</p>
      ) : layers.length === 0 ? (
        <p className="px-3 py-6 text-center text-xs text-muted-foreground">No layer metadata recorded.</p>
      ) : (
        <ol className="divide-y divide-border">
          {layers.map((layer, index) => {
            const cmd = layer.command || layer.created_by || "";
            const instr = cmd.split(/\s+/)[0]?.toUpperCase();
            return (
              <li key={layer.digest || layer.diff_id || index} className="flex items-start gap-3 px-3 py-2">
                <span className="mt-0.5 w-6 shrink-0 text-right font-mono text-[10px] text-muted-foreground">{layer.index ?? index}</span>
                <div className="min-w-0 flex-1">
                  <code className="block whitespace-pre-wrap break-words font-mono text-[11px] leading-snug text-foreground">
                    {cmd
                      ? (["RUN","ADD","COPY","ENV","CMD","ENTRYPOINT","WORKDIR","EXPOSE","USER","LABEL","VOLUME","ARG","FROM"].includes(instr ?? "")
                          ? <><span className="text-[color:var(--color-primary)]">{instr}</span>{cmd.slice(instr!.length)}</>
                          : cmd)
                      : <span className="text-muted-foreground">{layer.media_type || "layer"}</span>}
                  </code>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                    {layer.in_base_image !== undefined && (
                      <span className={cn("rounded px-1 py-px font-medium", layer.in_base_image ? "bg-muted text-muted-foreground" : "bg-[color-mix(in_oklab,var(--color-primary)_14%,transparent)] text-[color:var(--color-primary)]")}>
                        {layer.in_base_image ? "base" : "app"}
                      </span>
                    )}
                    <span className="font-mono">{formatBytes(layer.size_bytes)}</span>
                    {(layer.package_count ?? 0) > 0 && <span>{layer.package_count} pkg{layer.package_count === 1 ? "" : "s"}</span>}
                    {layer.digest && <span className="max-w-[160px] truncate font-mono opacity-70" title={layer.digest}>{layer.digest.replace("sha256:", "").slice(0, 12)}</span>}
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

function SecretsEvidenceCard({ loading, secrets, count }: { loading: boolean; secrets: ImageSecretFinding[]; count: number }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Secret evidence</h2>
        <Pill tone={count > 0 ? "danger" : "neutral"}>{count}</Pill>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading secret evidence...</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-muted text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Rule</th>
              <th className="px-3 py-2 text-left">Severity</th>
              <th className="px-3 py-2 text-left">Path</th>
              <th className="px-3 py-2 text-left">Lines</th>
            </tr>
          </thead>
          <tbody>
            {secrets.slice(0, 6).map((secret, index) => (
              <tr key={`${secret.rule_id || "secret"}:${secret.path || secret.target || index}`} className="border-t border-border">
                <td className="px-3 py-2">
                  <div className="font-mono text-xs">{secret.rule_id || "-"}</div>
                  <div className="mt-1 max-w-[240px] truncate text-xs text-muted-foreground">{secret.title || secret.category || "-"}</div>
                </td>
                <td className="px-3 py-2"><SeverityPill severity={secret.severity || "info"} /></td>
                <td className="max-w-[280px] truncate px-3 py-2 font-mono text-xs" title={secret.path || secret.target}>{secret.path || secret.target || "-"}</td>
                <td className="px-3 py-2 font-mono text-xs">{lineRange(secret.start_line, secret.end_line)}</td>
              </tr>
            ))}
            {secrets.length === 0 ? <tr><td colSpan={4} className="px-3 py-6 text-center text-xs text-muted-foreground">No secret evidence recorded.</td></tr> : null}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ConfigChecksEvidenceCard({ loading, checks }: { loading: boolean; checks: ImageConfigCheck[] }) {
  const fails = checks.filter((c) => c.status === "fail").length;
  const warns = checks.filter((c) => c.status === "warn").length;
  const tone = (s: string): "danger" | "warn" | "accent" => (s === "fail" ? "danger" : s === "warn" ? "warn" : "accent");
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Image config checks</h2>
          <p className="text-[10px] text-muted-foreground">CIS-Docker best-practice controls on the image config</p>
        </div>
        <div className="flex items-center gap-1">
          {fails > 0 && <Pill tone="danger">{fails} fail</Pill>}
          {warns > 0 && <Pill tone="warn">{warns} warn</Pill>}
          {fails === 0 && warns === 0 && checks.length > 0 && <Pill tone="accent">pass</Pill>}
        </div>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading config checks…</p>
      ) : checks.length === 0 ? (
        <p className="px-3 py-6 text-center text-xs text-muted-foreground">No config checks (image predates this scan feature — rescan to populate).</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-muted text-xs uppercase text-muted-foreground">
            <tr><th className="px-3 py-2 text-left">Check</th><th className="px-3 py-2 text-left">Status</th><th className="px-3 py-2 text-left">Detail</th></tr>
          </thead>
          <tbody>
            {checks.map((c) => (
              <tr key={c.id} className="border-t border-border">
                <td className="px-3 py-2">
                  <div className="text-xs font-medium">{c.title}</div>
                  {c.status !== "pass" && c.remediation && <div className="mt-0.5 max-w-[320px] text-[11px] text-muted-foreground">{c.remediation}</div>}
                </td>
                <td className="px-3 py-2"><Pill tone={tone(c.status)}>{c.status}</Pill></td>
                <td className="max-w-[220px] truncate px-3 py-2 font-mono text-[11px] text-muted-foreground" title={c.detail}>{c.detail || "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function FileRisksEvidenceCard({ loading, findings, count }: { loading: boolean; findings: ImageFileRiskFinding[]; count: number }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="flex items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">File risk evidence</h2>
        <Pill tone={count > 0 ? "warn" : "neutral"}>{count}</Pill>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading file risk evidence...</p>
      ) : (
        <table className="w-full text-sm">
          <thead className="bg-muted text-xs uppercase text-muted-foreground">
            <tr>
              <th className="px-3 py-2 text-left">Path</th>
              <th className="px-3 py-2 text-left">Risk</th>
              <th className="px-3 py-2 text-left">Mode</th>
              <th className="px-3 py-2 text-left">Layer</th>
            </tr>
          </thead>
          <tbody>
            {findings.slice(0, 6).map((finding, index) => (
              <tr key={`${finding.path}:${finding.layer_digest || index}`} className="border-t border-border">
                <td className="px-3 py-2">
                  <div className="max-w-[260px] truncate font-mono text-xs" title={finding.path}>{finding.path}</div>
                  <div className="mt-1 text-xs text-muted-foreground">{finding.reason || finding.type || "-"}</div>
                </td>
                <td className="px-3 py-2">
                  <SeverityPill severity={finding.severity || "info"} />
                  <div className="mt-1 max-w-[220px] truncate text-xs text-muted-foreground">{(finding.risk_types ?? []).join(", ") || "-"}</div>
                </td>
                <td className="px-3 py-2 font-mono text-xs">{finding.mode || "-"} · {finding.uid ?? "-"}:{finding.gid ?? "-"}</td>
                <td className="max-w-[180px] truncate px-3 py-2 font-mono text-xs" title={finding.layer_digest}>{finding.layer_digest || `${finding.layer_index ?? "-"}`}</td>
              </tr>
            ))}
            {findings.length === 0 ? <tr><td colSpan={4} className="px-3 py-6 text-center text-xs text-muted-foreground">No file risk evidence recorded.</td></tr> : null}
          </tbody>
        </table>
      )}
    </section>
  );
}

function ScanIdentity({ result }: { result: ImageScanResult }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Image identity</h2>
      <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Reference" value={result.image_ref} wide />
        <Field label="Repository" value={result.image_repository || "-"} />
        <Field label="Tag" value={result.image_tag || "-"} />
        <Field label="Platform" value={result.platform || "-"} />
        <Field label="Scanner Profile" value={result.scanner_profile} />
        <Field label="Source" value={sourceLabel(result)} />
        <Field label="Source Ref" value={result.source_ref || "-"} />
        <Field label="Digest" value={result.image_digest} wide />
      </dl>
    </section>
  );
}

function FindingsTable({ findings }: { findings: ImageScanFinding[] }) {
  const columns: Column<ImageScanFinding>[] = [
    {
      id: "cve",
      header: "CVE",
      cell: (finding) => (
        <>
          <span className="flex items-center gap-1.5">
            {finding.external_id ? (
              <Link to={`/cve/${finding.external_id}`} className="font-mono text-xs font-medium hover:underline">{finding.external_id}</Link>
            ) : (
              <span className="font-mono text-xs">-</span>
            )}
            {finding.kev_listed && <span className="rounded px-1 py-px text-[9px] font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
          </span>
          <div className="mt-1 max-w-[360px] truncate text-xs text-muted-foreground">{finding.title}</div>
        </>
      ),
    },
    {
      id: "package",
      header: "Package",
      cell: (finding) => (
        <>
          <div className="font-mono text-xs">{finding.package_name || "-"}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">{finding.package_version || "-"}</div>
        </>
      ),
    },
    { id: "severity", header: "Severity", cell: (finding) => <SeverityPill severity={finding.severity} /> },
    { id: "cvss", header: "CVSS", numeric: true, cell: (finding) => <span className="font-mono text-xs" style={{ color: (finding.cvss_base ?? 0) >= 9 ? "var(--color-severity-critical)" : (finding.cvss_base ?? 0) >= 7 ? "var(--color-severity-high)" : "var(--color-foreground)" }}>{finding.cvss_base ? finding.cvss_base.toFixed(1) : "—"}</span>, sort: (a, b) => (a.cvss_base ?? 0) - (b.cvss_base ?? 0) },
    { id: "risk", header: "Risk", cell: (finding) => <span className="font-semibold">{finding.risk_score}</span> },
    { id: "fix", header: "Fix", cell: (finding) => <span className="font-mono text-xs">{finding.fixed_version || "-"}</span> },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Vulnerable packages</h2>
        <p className="mt-1 text-xs text-muted-foreground">Vulnerability findings for this image, aggregated across the enabled scanners.</p>
      </header>
      <div data-testid="image-scan-findings">
        <DataTable
          rows={findings}
          columns={columns}
          rowKey={(finding) => finding.id}
          showDensityToggle={false}
          className="rounded-none border-0"
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No vulnerable packages recorded for this scan.</div>}
        />
      </div>
    </section>
  );
}

function WorkloadsPanel({ workloads }: { workloads: ImpactedWorkload[] }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="image-scan-workloads">
      <h2 className="text-sm font-semibold">Affected workloads</h2>
      <div className="mt-3 space-y-2">
        {workloads.map((workload) => (
          <Link
            key={`${workload.cluster_id}:${workload.deployment_id}:${workload.image_ref}`}
            to={`/clusters/${workload.cluster_id}/deployments/${workload.deployment_id}`}
            className="block rounded-md border border-border p-3 hover:bg-accent"
          >
            <div className="flex items-center justify-between gap-2">
              <div className="break-all font-mono text-xs font-medium">{workload.namespace}/{workload.name}</div>
              <Pill tone={workload.critical_count > 0 ? "danger" : workload.high_count > 0 ? "warn" : "neutral"}>{workload.risk_score}</Pill>
            </div>
            <div className="mt-1 text-xs text-muted-foreground">{workload.kind} · {workload.finding_count} finding{workload.finding_count === 1 ? "" : "s"}</div>
          </Link>
        ))}
        {workloads.length === 0 ? (
          <p className="text-xs text-muted-foreground">No active workload exposure in this cluster.</p>
        ) : null}
      </div>
    </section>
  );
}

function BundlePanel({ result }: { result: ImageScanResult }) {
  const metadata = result.bundle_metadata;
  const [downloading, setDownloading] = useState<string | null>(null);
  const download = async (kind: string, fn: () => Promise<void>) => {
    setDownloading(kind);
    try {
      await fn();
    } catch {
      toast.error("Artifact download failed");
    } finally {
      setDownloading(null);
    }
  };
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">VulnDB provenance</h2>
      <dl className="mt-3 grid gap-2 text-sm">
        <Field label="Version" value={result.vulndb_bundle_version || metadata?.bundle_version || "-"} />
        <Field label="Hash" value={result.vulndb_bundle_hash || metadata?.payload_hash || "-"} />
        <Field label="Producer" value={metadata?.producer || "-"} />
        <Field label="Exported" value={metadata?.exported_at ? formatDate(metadata.exported_at) : "-"} />
        <Field label="Records" value={metadata?.record_count != null ? `${metadata.record_count}` : "-"} />
        <Field label="Last scanned" value={formatDate(result.last_scanned_at)} />
      </dl>
      <div className="mt-3 grid gap-2 sm:grid-cols-3 xl:grid-cols-7">
        <ArtifactButton
          icon={Database}
          label="Inventory"
          disabled={downloading !== null}
          onClick={() => void download("inventory", () => imageScanResults.downloadPackages(result.id))}
        />
        <ArtifactButton
          icon={Layers}
          label="Layers"
          disabled={downloading !== null || result.layer_count === 0}
          onClick={() => void download("layers", () => imageScanResults.downloadLayers(result.id))}
        />
        <ArtifactButton
          icon={KeyRound}
          label="Secrets"
          disabled={downloading !== null || result.secret_count === 0}
          onClick={() => void download("secrets", () => imageScanResults.downloadSecrets(result.id))}
        />
        <ArtifactButton
          icon={FileWarning}
          label="File Risks"
          disabled={downloading !== null || result.file_risk_count === 0}
          onClick={() => void download("file-risks", () => imageScanResults.downloadFileRisks(result.id))}
        />
        <ArtifactButton
          icon={ShieldCheck}
          label="Signature"
          disabled={downloading !== null || !result.signature_status}
          onClick={() => void download("signature", () => imageScanResults.downloadSignature(result.id))}
        />
        <ArtifactButton
          icon={FileJson}
          label="SPDX"
          disabled={downloading !== null}
          onClick={() => void download("spdx", () => imageScanResults.downloadSPDX(result.id))}
        />
        <ArtifactButton
          icon={Download}
          label="CycloneDX"
          disabled={downloading !== null}
          onClick={() => void download("cyclonedx", () => imageScanResults.downloadCycloneDX(result.id))}
        />
      </div>
    </section>
  );
}

function ArtifactButton({ icon: Icon, label, disabled, onClick }: { icon: typeof Database; label: string; disabled: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      className="inline-flex h-9 items-center justify-center gap-2 rounded-md border border-border px-2 text-xs font-medium hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
      disabled={disabled}
      onClick={onClick}
      aria-label={`Download ${label}`}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden />
      <span>{label}</span>
    </button>
  );
}

function displayImage(item: ImageScanResult): string {
  if (item.image_repository && item.image_tag) return `${item.image_repository}:${item.image_tag}`;
  if (item.image_repository && item.image_repository !== item.image_digest) return item.image_repository;
  return item.image_ref || item.image_digest;
}

function isLocalImage(item: ImageScanResult): boolean {
  return item.image_ref.startsWith("sha256:") || !item.image_repository || item.image_repository === item.image_digest;
}

function isStale(value: string): boolean {
  const t = new Date(value).getTime();
  if (!Number.isFinite(t)) return false;
  return Date.now() - t > 7 * 86400 * 1000;
}

function ImageKindBadge({ item }: { item: ImageScanResult }) {
  if (item.source_type === "repository") return <Pill tone="accent">repository scan</Pill>;
  return isLocalImage(item) ? <Pill tone="warn">local image</Pill> : <Pill tone="neutral">registry image</Pill>;
}

function SignaturePill({ item }: { item: ImageScanResult }) {
  const status = item.signature_status || "unknown";
  if (status === "trusted") return <Pill tone="accent">signature trusted</Pill>;
  if (status === "untrusted") return <Pill tone="warn">signature untrusted</Pill>;
  if (status === "unsigned") return <Pill tone="danger">unsigned</Pill>;
  if (status === "error") return <Pill tone="warn">signature error</Pill>;
  if (status === "unavailable") return <Pill tone="neutral">signature unavailable</Pill>;
  if (status === "skipped") return <Pill tone="neutral">signature skipped</Pill>;
  return item.image_signed ? <Pill tone="accent">signed</Pill> : <Pill tone="neutral">signature unknown</Pill>;
}

function sourceLabel(item: ImageScanResult): string {
  if (item.source_type === "repository") return "Repository / CI";
  if (item.source_type === "runtime-agent") return "Runtime agent";
  if (item.source_type === "registry") return "Registry";
  return item.source_type || "Manual";
}

function SeverityPill({ severity }: { severity: string }) {
  const tone = severity === "critical" ? "danger" : severity === "high" ? "warn" : "neutral";
  return <Pill tone={tone}>{severity}</Pill>;
}

function Field({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) {
  return (
    <div className={cn("rounded-md border border-border p-2", wide && "sm:col-span-2")}>
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

function formatDate(value?: string) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatBytes(value?: number) {
  if (value == null || !Number.isFinite(value) || value <= 0) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function lineRange(start?: number, end?: number) {
  if (!start && !end) return "-";
  if (start && end && start !== end) return `${start}-${end}`;
  return `${start || end}`;
}
