import { useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useParams } from "@tanstack/react-router";
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
import { useEntityClusterScope } from "./entity-detail-scope";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { imageReferenceName, imageReferenceDisplayName, imageReferenceDigest, imageScanDisplayName } from "@/lib/asset-identity";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Collapse } from "@/components/ui/collapse";
import { artifactIssue, scanEngineEvidence } from "@/lib/scan-evidence";
import { DataTable, type Column } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { StatCard, StatGrid } from "@/components/ui/stat-card";

export function ImageScanDetailPage() {
  const { resultId } = useParams({ strict: false });
  const [requestedTab, setTab] = useTabParam("tab", "findings");
  const tab = ["findings", "evidence", "workloads", "details"].includes(requestedTab) ? requestedTab : "findings";
  const scope = useEntityClusterScope();
  const { clusterId } = scope;
  const identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const q = useQuery({
    queryKey: ["image-scan-result", owner, resultId],
    queryFn: async () => {
      const response = await imageScanResults.get(resultId!);
      if (response.image_scan_result.id !== resultId) throw new Error("Image scan response does not match the requested result.");
      return response;
    },
    enabled: scope.ready && !!resultId,
  });

  const detail = q.data;
  const result = detail?.image_scan_result;
  const clusterWorkloads = useMemo(() => {
    const workloads = detail?.impacted_workloads ?? [];
    return clusterId ? workloads.filter((item) => item.cluster_id === clusterId) : workloads;
  }, [clusterId, detail?.impacted_workloads]);

  if (scope.loading || scope.ready && q.isPending) return <LoadingState label="Loading image scan…" />;
  if (!scope.ready || q.isError || !result || result.id !== resultId) return <ErrorState title="Image scan evidence unavailable." error={q.error ?? scope.error} action={<Button onClick={() => scope.ready ? void q.refetch() : scope.retry()}>Retry</Button>} />;

  return (
    <div className="space-y-4" data-testid="image-scan-detail-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <a href={`/clusters/${clusterId}/images`} className="inline-flex items-center gap-1 hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            Images
          </a>
        }
        title={imageScanDisplayName(result)}
        mono
        badges={
          <>
            <ImageKindBadge item={result} />
            {clusterWorkloads.length > 0 ? <Pill tone="accent">running workload</Pill> : null}
            {isStale(result.last_scanned_at) ? <Pill tone="warn">stale scan</Pill> : null}
            <SignaturePill item={result} />
          </>
        }
        description="Scan evidence is shared across the organization. Affected workload links below are filtered to this cluster."
        actions={<Button onClick={() => void q.refetch()} disabled={q.isFetching}>Refresh</Button>}
      />

      <EngineVerdict result={result} />

      <StatGrid data-testid="image-scan-stats">
        <StatCard label="Findings" value={result.finding_count} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={result.finding_count > 0 ? "high" : "neutral"} />
        <StatCard label="Packages" value={result.package_count} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Secrets" value={result.secret_count} icon={<KeyRound className="h-3.5 w-3.5" />} tone={result.secret_count > 0 ? "critical" : "neutral"} />
        <StatCard label="Workloads" value={clusterWorkloads.length} icon={<Layers className="h-3.5 w-3.5" />} tone={clusterWorkloads.length > 0 ? "accent" : "neutral"} />
        <StatCard label="Risk" value={result.max_risk_score} icon={<Boxes className="h-3.5 w-3.5" />} />
      </StatGrid>

      <Tabs value={tab} onValueChange={setTab} items={[
        { value: "findings", label: "Vulnerabilities", count: result.finding_count, content: <FindingsTable findings={detail.findings} /> },
        { value: "evidence", label: "Scan evidence", content: <div className="space-y-4"><EngineEvidence result={result} /><ArtifactEvidenceSection key={`${owner}:${result.id}`} result={result} owner={owner} /></div> },
        { value: "workloads", label: "Affected workloads", count: clusterWorkloads.length, content: <WorkloadsPanel workloads={clusterWorkloads} /> },
        { value: "details", label: "Identity and exports", content: <div className="space-y-4"><ScanIdentity result={result} /><BundlePanel result={result} /></div> },
      ]} />
    </div>
  );
}

async function checkedArtifact<T extends { image_scan_result_id: string }>(id: string, request: Promise<T>): Promise<T> {
  const response = await request;
  if (response.image_scan_result_id !== id) throw new Error("Artifact does not match the requested image scan.");
  return response;
}

function ArtifactEvidenceSection({ result, owner }: { result: ImageScanResult; owner: string }) {
  const [evidence, setEvidence] = useTabParam("evidence", "packages");
  const layersQ = useQuery({
    queryKey: ["image-scan-layers", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.layers(result.id)),
    retry: false,
  });
  const packagesQ = useQuery({
    queryKey: ["image-scan-packages", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.packages(result.id)),
    enabled: result.package_count > 0,
  });
  const secretsQ = useQuery({
    queryKey: ["image-scan-secrets", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.secrets(result.id)),
    enabled: result.secret_count > 0,
  });
  const fileRisksQ = useQuery({
    queryKey: ["image-scan-file-risks", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.fileRisks(result.id)),
    retry: false,
  });
  const signatureQ = useQuery({
    queryKey: ["image-scan-signature", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.signature(result.id)),
    enabled: !!result.signature_status,
  });
  // Config checks are computed for every image (no count gate); 404s on older scans.
  const configChecksQ = useQuery({
    queryKey: ["image-scan-config-checks", owner, result.id],
    queryFn: () => checkedArtifact(result.id, imageScanResults.configChecks(result.id)),
    retry: false,
  });

  const layers = layersQ.data?.layer_metadata.layers ?? [];
  const packageLayers = packagesQ.data?.package_layers ?? [];
  const secrets = secretsQ.data?.secret_scan.secrets ?? [];
  const fileRisks = fileRisksQ.data?.file_risk.findings ?? [];
  const signature = signatureQ.data?.signature_scan.signature;
  const configChecks = configChecksQ.data?.config_checks.checks ?? [];
  const layerIssue = artifactIssue(layersQ.data?.layer_metadata, layersQ.error);
  const fileRiskIssue = artifactIssue(fileRisksQ.data?.file_risk, fileRisksQ.error);
  const configIssue = artifactIssue(configChecksQ.data?.config_checks, configChecksQ.error);

  const guard = (query: { isError: boolean; error: unknown; data?: { image_scan_result_id: string }; refetch: () => unknown }, title: string, content: ReactNode) =>
    query.isError || query.data && query.data.image_scan_result_id !== result.id
      ? <ErrorState title={`${title} unavailable.`} error={query.error} action={<Button onClick={() => void query.refetch()}>Retry evidence</Button>} /> : content;
  const items = [
    { value: "packages", label: "Packages", content: guard(packagesQ, "Package provenance", <PackagesEvidenceCard loading={packagesQ.isPending && result.package_count > 0} packageLayers={packageLayers} layerPackageCount={packagesQ.data?.layer_package_count ?? 0} unattributedPackageCount={packagesQ.data?.unattributed_package_count ?? result.package_count} totalPackageCount={result.package_count} />) },
    { value: "layers", label: "Layers", content: guard(layersQ, "Image layers", layerIssue ? <EvidenceIssue title="Image layers" message={layerIssue} /> : <LayersEvidenceCard loading={layersQ.isPending} layers={layers} totalSize={layersQ.data?.layer_metadata.total_size_bytes} result={result} />) },
    { value: "secrets", label: "Secrets", content: guard(secretsQ, "Secret evidence", <SecretsEvidenceCard loading={secretsQ.isPending && result.secret_count > 0} secrets={secrets} count={result.secret_count} />) },
    { value: "files", label: "File risks", content: guard(fileRisksQ, "File risk evidence", fileRiskIssue ? <EvidenceIssue title="File risk evidence" message={fileRiskIssue} /> : <FileRisksEvidenceCard loading={fileRisksQ.isPending} findings={fileRisks} count={result.file_risk_count} />) },
    { value: "config", label: "Config checks", content: guard(configChecksQ, "Image config checks", configIssue ? <EvidenceIssue title="Image config checks" message={configIssue} /> : <ConfigChecksEvidenceCard loading={configChecksQ.isPending} checks={configChecks} />) },
    { value: "signature", label: "Signature", content: guard(signatureQ, "Signature evidence", <SignatureEvidenceCard result={result} loading={signatureQ.isPending && !!result.signature_status} signature={signature} status={signatureQ.data?.signature_scan.status || result.signature_status || ""} />) },
  ];
  return <section className="space-y-3" data-testid="image-scan-artifact-evidence">
    <p className="text-sm text-muted-foreground">Tables expose all returned artifact evidence, with local pagination. Full scan artifacts are available under Identity and exports. Package provenance shows layer-linked packages; Inventory also includes unattributed packages.</p>
    <Tabs value={evidence} onValueChange={setEvidence} items={items} />
    {!items.some(item => item.value === evidence) && <ErrorState title="Unknown evidence view." action={<Button onClick={() => setEvidence("packages")}>Show packages</Button>} />}
  </section>;
}

function EvidenceIssue({ title, message }: { title: string; message: string }) {
  return <section className="rounded-lg border border-border bg-card p-4" role="status">
    <h2 className="text-sm font-semibold">{title}</h2>
    <p className="mt-2 text-sm text-status-warning">{message}</p>
  </section>;
}

function EngineVerdict({ result }: { result: ImageScanResult }) {
  const evidence = scanEngineEvidence(result.engine_status);
  const incomplete = evidence.engines.some(({ status }) => status !== "succeeded");
  const stale = isStale(result.last_scanned_at);
  const critical = result.critical_count > 0 || result.secret_count > 0;
  const title = critical ? "This image needs urgent review" : incomplete ? "Scanner coverage is incomplete" : stale ? "This scan needs refreshing" : result.finding_count > 0 ? "Vulnerabilities need review" : "No vulnerabilities reported by the completed scanners";
  return <VerdictBanner status={critical ? "critical" : incomplete || stale || result.finding_count > 0 ? "degraded" : "ok"} title={title} detail={<>{evidence.message}{stale ? " The scan is older than seven days." : ""}</>} />;
}

function EngineEvidence({ result }: { result: ImageScanResult }) {
  const evidence = scanEngineEvidence(result.engine_status);
  return <section className="rounded-lg border border-border bg-card p-4" data-testid="scan-engine-evidence">
    <h2 className="text-sm font-semibold">Scanner results</h2>
    <p className="mt-2 text-sm text-muted-foreground">{evidence.message}</p>
    <dl className="mt-3 flex flex-wrap gap-4 text-sm">
      {evidence.engines.map(({ name, status }) => <div key={name} className="flex items-center gap-2">
        <dt className="font-medium">{name}</dt>
        <dd><Pill tone={status === "succeeded" ? "accent" : status === "failed" ? "danger" : "warn"}>{status}</Pill></dd>
      </div>)}
    </dl>
  </section>;
}

function LayerIdentity({ index, digest }: { index?: number; digest?: string }) {
  return <><span>{index === undefined ? "Layer index not reported" : `Layer ${index}`}</span><DigestDisclosure digest={digest} /></>;
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
  const rows = packageLayers.flatMap((layer, layerIndex) => layer.packages.map((pkg, packageIndex) => ({
    key: `${layerIndex}:${packageIndex}`,
    layer,
    pkg,
    location: (pkg.locations ?? []).find((item) => item.layer_digest === layer.layer_digest) ?? pkg.locations?.[0],
  })));
  return (
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Package provenance</h2>
        <span className="font-mono text-xs text-muted-foreground">
          {layerPackageCount}/{totalPackageCount} layer-linked
        </span>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading package provenance...</p>
      ) : (
        <DataTable
          className="rounded-none border-0"
          preferencesKey="image-package-provenance"
          exportFileName="image-package-provenance"
          rows={rows}
          rowKey={(row) => row.key}
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">{unattributedPackageCount > 0 ? "Package inventory is present, but no layer attribution was captured." : "No package inventory recorded."}</div>}
          columns={[
            { id: "layer", header: "Layer", kind: "text", wrap: true, exportValue: ({ layer }) => layer.layer_digest || `${layer.layer_index ?? "-"}`, cell: ({ layer }) => <LayerIdentity index={layer.layer_index} digest={layer.layer_digest} /> },
            { id: "package", header: "Package", kind: "name", code: true, exportValue: ({ pkg }) => `${pkg.name || "-"} · ${pkg.version || pkg.ecosystem || "-"}`, cell: ({ pkg }) => <><div>{pkg.name || "-"}</div><div className="mt-1 text-xs text-muted-foreground">{pkg.version || pkg.ecosystem || "-"}</div></> },
            { id: "path", header: "Evidence path", kind: "id", size: 260, maxSize: 360, grow: true, cell: ({ location }) => location?.path || location?.real_path || location?.access_path || "-" },
          ]}
        />
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
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
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
                <span className="mt-0.5 w-12 shrink-0 text-right font-mono text-micro text-muted-foreground">Layer {layer.index ?? index}</span>
                <div className="min-w-0 flex-1">
                  <code className="block whitespace-pre-wrap break-words font-mono text-micro leading-snug text-foreground">
                    {cmd
                      ? (["RUN","ADD","COPY","ENV","CMD","ENTRYPOINT","WORKDIR","EXPOSE","USER","LABEL","VOLUME","ARG","FROM"].includes(instr ?? "")
                          ? <><span className="text-[color:var(--color-primary)]">{instr}</span>{cmd.slice(instr!.length)}</>
                          : cmd)
                      : <span className="text-muted-foreground">{layer.media_type || "layer"}</span>}
                  </code>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-micro text-muted-foreground">
                    {layer.in_base_image !== undefined && (
                      <span className={cn("rounded px-1 py-px font-medium", layer.in_base_image ? "bg-muted text-muted-foreground" : "bg-[color-mix(in_oklab,var(--color-primary)_14%,transparent)] text-[color:var(--color-primary)]")}>
                        {layer.in_base_image ? "base" : "app"}
                      </span>
                    )}
                    <span className="font-mono">{formatBytes(layer.size_bytes)}</span>
                    {(layer.package_count ?? 0) > 0 && <span>{layer.package_count} pkg{layer.package_count === 1 ? "" : "s"}</span>}
                    <DigestDisclosure digest={layer.digest} />
                    {layer.diff_id && layer.diff_id !== layer.digest && <div><span>Diff ID</span><DigestDisclosure digest={layer.diff_id} /></div>}
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
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Secret evidence</h2>
        <Pill tone={count > 0 ? "danger" : "neutral"}>{count}</Pill>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading secret evidence...</p>
      ) : (
        <DataTable
          className="rounded-none border-0"
          preferencesKey="image-secret-evidence"
          rows={secrets.map((secret, index) => ({ ...secret, rowKey: `${secret.rule_id || "secret"}:${secret.path || secret.target || ""}:${index}` }))}
          rowKey={(secret) => secret.rowKey}
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No secret evidence recorded.</div>}
          columns={[
            { id: "rule", header: "Rule", kind: "name", cell: (secret) => <><div className="font-mono">{secret.rule_id || "-"}</div><div className="mt-1 truncate text-xs text-muted-foreground" title={secret.title || secret.category}>{secret.title || secret.category || "-"}</div></> },
            { id: "severity", header: "Severity", kind: "status", cell: (secret) => <SeverityPill severity={secret.severity || "info"} /> },
            { id: "path", header: "Path", kind: "id", size: 260, maxSize: 360, grow: true, cell: (secret) => secret.path || secret.target || "-" },
            { id: "lines", header: "Lines", kind: "count", cell: (secret) => lineRange(secret.start_line, secret.end_line) },
          ]}
        />
      )}
    </section>
  );
}

function ConfigChecksEvidenceCard({ loading, checks }: { loading: boolean; checks: ImageConfigCheck[] }) {
  const fails = checks.filter((c) => c.status === "fail").length;
  const warns = checks.filter((c) => c.status === "warn").length;
  const tone = (s: string): "danger" | "warn" | "accent" => (s === "fail" ? "danger" : s === "warn" ? "warn" : "accent");
  return (
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Image config checks</h2>
          <p className="text-micro text-muted-foreground">CIS-Docker best-practice controls on the image config</p>
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
        <DataTable<ImageConfigCheck>
          className="rounded-none border-0"
          preferencesKey="image-config-checks"
          rows={checks}
          rowKey={(check) => check.id}
          columns={[
            { id: "check", header: "Check", kind: "name", wrap: true, cell: (check) => <><div className="font-medium">{check.title}</div>{check.status !== "pass" && check.remediation && <div className="mt-0.5 text-xs text-muted-foreground">{check.remediation}</div>}</> },
            { id: "status", header: "Status", kind: "status", cell: (check) => <Pill tone={tone(check.status)}>{check.status}</Pill> },
            { id: "detail", header: "Detail", kind: "text", code: true, wrap: true, grow: true, cell: (check) => check.detail || "-" },
          ]}
        />
      )}
    </section>
  );
}

function FileRisksEvidenceCard({ loading, findings, count }: { loading: boolean; findings: ImageFileRiskFinding[]; count: number }) {
  return (
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">File risk evidence</h2>
        <Pill tone={count > 0 ? "warn" : "neutral"}>{count}</Pill>
      </header>
      {loading ? (
        <p className="p-3 text-xs text-muted-foreground">Loading file risk evidence...</p>
      ) : (
        <DataTable
          className="rounded-none border-0"
          preferencesKey="image-file-risk-evidence"
          exportFileName="image-file-risk-evidence"
          rows={findings.map((finding, index) => ({ ...finding, rowKey: `${finding.path}:${finding.layer_digest || ""}:${index}` }))}
          rowKey={(finding) => finding.rowKey}
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No file risk evidence recorded.</div>}
          columns={[
            { id: "path", header: "Path", kind: "name", exportValue: (finding) => `${finding.path} · ${finding.reason || finding.type || "-"}`, cell: (finding) => <><div className="truncate font-mono" title={finding.path}>{finding.path}</div><div className="mt-1 text-xs text-muted-foreground">{finding.reason || finding.type || "-"}</div></> },
            { id: "risk", header: "Risk", kind: "text", wrap: true, exportValue: (finding) => `${finding.severity || "info"} · ${(finding.risk_types ?? []).join(", ") || "-"}`, cell: (finding) => <><SeverityPill severity={finding.severity || "info"} /><div className="mt-1 text-xs text-muted-foreground">{(finding.risk_types ?? []).join(", ") || "-"}</div></> },
            { id: "mode", header: "Mode", kind: "id", cell: (finding) => `${finding.mode || "-"} · ${finding.uid ?? "-"}:${finding.gid ?? "-"}` },
            { id: "layer", header: "Layer", kind: "text", wrap: true, exportValue: (finding) => finding.layer_digest || `${finding.layer_index ?? "-"}`, cell: (finding) => <LayerIdentity index={finding.layer_index} digest={finding.layer_digest} /> },
          ]}
        />
      )}
    </section>
  );
}

function ScanIdentity({ result }: { result: ImageScanResult }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <h2 className="text-sm font-semibold">Image identity</h2>
      <dl className="mt-3 grid gap-2 text-sm sm:grid-cols-2">
        <Field label="Reference" value={imageReferenceDisplayName(result.image_ref_normalized, result.image_ref)} wide />
        <Field label="Repository" value={imageReferenceName(result.image_repository) || "-"} />
        <Field label="Tag" value={result.image_tag || "-"} />
        <Field label="Platform" value={result.platform || "-"} />
        <Field label="Scanner Profile" value={result.scanner_profile} />
        <Field label="Source" value={sourceLabel(result)} />
        <Field label="Source Ref" value={<Collapse label="Source reference"><code className="break-all text-xs">{result.source_ref || "-"}</code></Collapse>} />
        <Field label="Digest" value={<DigestDisclosure digest={result.image_digest} />} wide />
        <Field label="Raw reference" value={<Collapse label="Raw image reference"><code className="break-all text-xs">{result.image_ref}</code></Collapse>} wide />
      </dl>
    </section>
  );
}

function FindingsTable({ findings }: { findings: ImageScanFinding[] }) {
  const columns: Column<ImageScanFinding>[] = [
    {
      id: "cve",
      header: "CVE", kind: "name", wrap: true,
      cell: (finding) => (
        <>
          <span className="flex items-center gap-1.5">
            {finding.external_id ? (
              <a href={`/cve/${finding.external_id}`} className="font-mono text-xs font-medium hover:underline">{finding.external_id}</a>
            ) : (
              <span className="font-mono text-xs">-</span>
            )}
            {finding.kev_listed && <span className="rounded px-1 py-px text-micro font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
          </span>
          <div className="mt-1 text-xs text-muted-foreground">{finding.title}</div>
        </>
      ),
    },
    {
      id: "package",
      header: "Package", kind: "text", code: true, wrap: true, size: 200, minSize: 144, maxSize: 280,
      cell: (finding) => (
        <>
          <div className="font-mono text-xs">{finding.package_name || "-"}</div>
          <div className="mt-1 font-mono text-micro text-muted-foreground">{finding.package_version || "-"}</div>
        </>
      ),
    },
    { id: "severity", header: "Severity", kind: "status", cell: (finding) => <SeverityPill severity={finding.severity} /> },
    { id: "cvss", header: "CVSS", kind: "count", numeric: true, cell: (finding) => <span className="font-mono text-xs" style={{ color: (finding.cvss_base ?? 0) >= 9 ? "var(--color-severity-critical)" : (finding.cvss_base ?? 0) >= 7 ? "var(--color-severity-high)" : "var(--color-foreground)" }}>{finding.cvss_base != null ? finding.cvss_base.toFixed(1) : "—"}</span>, sort: (a, b) => (a.cvss_base ?? 0) - (b.cvss_base ?? 0) },
    { id: "risk", header: "Risk", kind: "count", cell: (finding) => <span className="font-semibold">{finding.risk_score}</span> },
    { id: "fix", header: "Fix", kind: "version", size: 160, minSize: 112, maxSize: 224, wrap: true, cell: (finding) => <span className="font-mono text-xs">{finding.fixed_version || "-"}</span> },
  ];
  const [fixableOnly, setFixableOnly] = useState(false);
  const shown = fixableOnly
    ? findings.filter((f) => !["", "false", "not-fixed", "wont-fix", "won't-fix"].includes((f.fixed_version || "").trim().toLowerCase()))
    : findings;
  const hiddenCount = findings.length - shown.length;
  return (
    <section className="min-w-0 rounded-lg border border-border bg-card">
      <header className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Vulnerable packages</h2>
          <p className="mt-1 text-xs text-muted-foreground">All returned vulnerability findings for this image. Fixable only filters this table; the Findings CSV under Identity and exports contains the full scan.</p>
        </div>
        <label className="flex shrink-0 items-center gap-1.5 text-xs text-muted-foreground" title="Hide vulnerabilities with no available fix (won't-fix / not-fixed)">
          <input type="checkbox" checked={fixableOnly} onChange={(e) => setFixableOnly(e.target.checked)} className="h-3.5 w-3.5 accent-[color:var(--color-primary)]" data-testid="image-scan-fixable-toggle" />
          Fixable only{fixableOnly && hiddenCount > 0 ? ` (${hiddenCount} hidden)` : ""}
        </label>
      </header>
      <div data-testid="image-scan-findings">
        <DataTable
          preferencesKey="image-scan-findings"
          rows={shown}
          columns={columns}
          rowKey={(finding) => finding.id}
          className="rounded-none border-0"
          emptyState={<div className="px-3 py-8 text-center text-xs text-muted-foreground">No vulnerable packages recorded for this scan.</div>}
        />
      </div>
    </section>
  );
}

function WorkloadsPanel({ workloads }: { workloads: ImpactedWorkload[] }) {
  const columns: Column<ImpactedWorkload>[] = [
    { id: "workload", header: "Workload", kind: "name", wrap: true, exportValue: item => `${item.namespace}/${item.name}`, cell: item => <a href={`/clusters/${item.cluster_id}/deployments/${item.deployment_id}`} className="font-medium hover:underline">{item.namespace}/{item.name}</a> },
    { id: "kind", header: "Kind", kind: "status", cell: item => item.kind },
    { id: "image", header: "Image", kind: "text", wrap: true, exportValue: item => item.image_ref, cell: item => <><span>{imageScanDisplayName({ ...item, image_repository: item.image_repository ?? "" })}</span><DigestDisclosure digest={item.image_digest || imageReferenceDigest(item.image_ref, item.image_ref_normalized)} /></> },
    { id: "findings", header: "Findings", kind: "count", cell: item => item.finding_count },
    { id: "risk", header: "Risk", kind: "count", cell: item => item.risk_score },
  ];
  return <section className="space-y-3" data-testid="image-scan-workloads">
    <h2 className="text-sm font-semibold">Affected workloads</h2>
    <p className="text-sm text-muted-foreground">All returned workload links in this cluster. No returned links does not establish complete workload coverage.</p>
    <DataTable rows={workloads} columns={columns} rowKey={item => `${item.cluster_id}:${item.workload_id}:${item.image_ref}`} preferencesKey="image-scan-workloads" exportFileName="image-scan-workloads" emptyState={<p className="p-6 text-sm text-muted-foreground">No workload links returned for this cluster.</p>} />
  </section>;
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
      <h2 className="text-sm font-semibold">Scan provenance and exports</h2>
      {metadata || result.vulndb_bundle_version || result.vulndb_bundle_hash ? <dl className="mt-3 grid gap-2 text-sm">
        <Field label="Version" value={result.vulndb_bundle_version || metadata?.bundle_version || "-"} />
        <Field label="Hash" value={result.vulndb_bundle_hash || metadata?.payload_hash ? <DigestDisclosure digest={result.vulndb_bundle_hash || metadata?.payload_hash} /> : "-"} />
        <Field label="Producer" value={metadata?.producer || "-"} />
        <Field label="Exported" value={metadata?.exported_at ? formatDate(metadata.exported_at) : "-"} />
        <Field label="Records" value={metadata?.record_count != null ? `${metadata.record_count}` : "-"} />
      </dl> : null}
      <p className="mt-3 text-sm text-muted-foreground">Exports contain the full stored scan artifact and are independent of table filters.</p>
      <p className="mt-3 text-sm text-muted-foreground">Last scanned {formatDate(result.last_scanned_at)}</p>
      <div className="mt-3 grid gap-2 sm:grid-cols-3 xl:grid-cols-4">
        <ArtifactButton
          icon={ShieldAlert}
          label="Findings CSV"
          disabled={downloading !== null}
          onClick={() => void download("findings-csv", () => imageScanResults.downloadFindingsCSV(result.id))}
        />
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

function Field({ label, value, wide = false }: { label: string; value: ReactNode; wide?: boolean }) {
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
