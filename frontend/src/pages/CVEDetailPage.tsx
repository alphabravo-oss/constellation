import { useParams } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { ExternalLink } from "lucide-react";
import { api, cve as cveApi, type CVEAffectedImage, type CVEAffectedWorkload, type CVEAffectedCluster, type CVEAffectedPackage } from "@/api/client";
import { PageHeader } from "@/components/ui/page";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { DataTable, type Column } from "@/components/ui/data-table";
import { KevBadge, EpssBadge } from "@/components/ui/kev-badge";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { entityDetailError, useEntityClusterScope } from "./entity-detail-scope";

interface CVEDetail {
  cve_id: string;
  title: string;
  description: string;
  cvss_base?: number;
  kev_listed: boolean;
  epss_probability?: number;
  aliases: string[];
}
const WORKSPACES = ["images", "workloads", "clusters", "packages", "details", "remediation"];

export function CVEDetailPage() {
  // Global /cve/$id and cluster /clusters/$id/cve/$cveId intentionally expose
  // different affected-evidence scopes; $cveId never shadows the cluster ID.
  const { id, cveId } = useParams({ strict: false });
  const scoped = cveId !== undefined;
  const scope = useEntityClusterScope(scoped);
  const clusterId = scoped ? scope.clusterId : undefined;
  const cveKey = (cveId ?? id ?? "").trim().toUpperCase();
  const [requestedTab, setTab] = useTabParam("tab", "images");
  const tab = WORKSPACES.includes(requestedTab) ? requestedTab : "images";
  const cveQ = useQuery({
    queryKey: ["cve-detail", clusterId ?? "organization", cveKey],
    queryFn: async () => {
      const { data } = await api.get<CVEDetail>(`/cve/${encodeURIComponent(cveKey)}`);
      if (data.cve_id.toUpperCase() !== cveKey) throw new Error("CVE metadata does not match the requested CVE ID.");
      return data;
    },
    enabled: scope.ready && !!cveKey,
  });
  const relatedQ = useQuery({
    queryKey: ["cve-affected", cveKey, clusterId ?? "organization"],
    queryFn: async () => {
      const data = await cveApi.affected(cveKey, clusterId);
      if (data.cve_id.toUpperCase() !== cveKey || clusterId && (data.workloads.some((item) => item.cluster_id !== clusterId) || data.clusters.some((item) => item.cluster_id !== clusterId))) throw new Error("Affected evidence does not match the requested CVE and cluster scope.");
      return data;
    },
    enabled: scope.ready && !!cveKey,
  });
  const backPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/findings` : "/cve";
  const header = <PageHeader title="CVE evidence" description="Review vulnerability intelligence and the returned images and workloads associated with an exact CVE." backLink={<a href={backPath}>{clusterId ? "Findings" : "CVE database"}</a>} />;
  if (!scope.ready) return <div className="space-y-4">{header}{scope.loading ? <LoadingState label="Resolving CVE evidence cluster…" /> : <ErrorState title="The requested CVE cluster could not be resolved." error={scope.error} action={<Button onClick={scope.retry}>Retry cluster</Button>} />}</div>;
  if (!cveKey) return <div className="space-y-4">{header}<ErrorState title="An exact CVE ID is required." /></div>;
  if (cveQ.isError) return <div className="space-y-4">{header}<VerdictBanner status="degraded" title="CVE intelligence is unavailable" detail="Previously loaded intelligence is hidden after a failed refresh." /><ErrorState title="CVE metadata could not be loaded or refreshed." error={entityDetailError(cveQ.error)} action={<Button onClick={() => void cveQ.refetch()}>Retry CVE</Button>} /></div>;
  if (cveQ.data && cveQ.data.cve_id.toUpperCase() !== cveKey) return <div className="space-y-4">{header}<ErrorState title="CVE metadata does not match the requested CVE ID." action={<Button onClick={() => void cveQ.refetch()}>Retry CVE</Button>} /></div>;
  if (!cveQ.isSuccess || !cveQ.data) return <div className="space-y-4">{header}<LoadingState label="Loading CVE intelligence…" /></div>;
  const cve = cveQ.data;
  const affectedMismatch = !!relatedQ.data && (relatedQ.data.cve_id.toUpperCase() !== cveKey || !!clusterId && (relatedQ.data.workloads.some((item) => item.cluster_id !== clusterId) || relatedQ.data.clusters.some((item) => item.cluster_id !== clusterId)));
  const affectedError = relatedQ.isError || affectedMismatch;
  const affected = relatedQ.isSuccess && !affectedMismatch ? relatedQ.data : undefined;
  const images = affected?.images ?? [];
  const workloads = affected?.workloads ?? [];
  const clusters = affected?.clusters ?? [];
  const findings = affected ? images.reduce((sum, image) => sum + image.finding_count, 0) : undefined;
  const sourceState = affectedError ? <ErrorState title="Affected evidence could not be loaded or refreshed. Previous affected rows are hidden." error={affectedMismatch ? "Affected evidence does not match the requested CVE and cluster scope." : entityDetailError(relatedQ.error)} action={<Button onClick={() => void relatedQ.refetch()}>Retry affected evidence</Button>} /> : !affected ? <LoadingState label="Loading affected evidence…" /> : null;
  const withAffected = (content: ReactNode) => sourceState ?? content;
  const imageCluster = (image: CVEAffectedImage) => clusterId ?? workloads.find((workload) => imageMatchesWorkload(image, workload))?.cluster_id;
  const imageColumns: Column<CVEAffectedImage>[] = [
    { id: "image", header: "Image", kind: "name", code: true, wrap: true, cell: (image) => { const cluster = imageCluster(image); return <div>{cluster ? <a href={`/clusters/${encodeURIComponent(cluster)}/images/${encodeURIComponent(image.image_scan_result_id)}`} className="font-medium hover:underline">{imageName(image)}</a> : <span>{imageName(image)}</span>}<div className="text-xs text-muted-foreground">{image.image_digest}</div></div>; }, exportValue: imageName, sort: (a, b) => imageName(a).localeCompare(imageName(b)) },
    { id: "platform", header: "Platform", kind: "text", size: 144, minSize: 112, maxSize: 192, cell: (image) => image.platform || "Not reported" },
    { id: "scanner", header: "Scanner profile", kind: "text", size: 176, maxSize: 240, wrap: true, cell: (image) => image.scanner_profile },
    { id: "findings", header: "Finding instances", kind: "count", cell: (image) => image.finding_count, sort: (a, b) => a.finding_count - b.finding_count },
    { id: "risk", header: "Max risk", kind: "count", cell: (image) => image.max_risk_score, sort: (a, b) => a.max_risk_score - b.max_risk_score },
    { id: "scanned", header: "Last scanned", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (image) => date(image.last_scanned_at), exportValue: (image) => image.last_scanned_at, sort: (a, b) => a.last_scanned_at.localeCompare(b.last_scanned_at) },
  ];
  const packages = images.flatMap((image) => image.packages.map((item, index) => ({ ...item, image: imageName(image), imageID: image.image_scan_result_id, rowID: `${image.image_scan_result_id}:${item.finding_id}:${index}` })));
  const exportScope = `${cveKey}-${clusterId ?? "organization"}`;
  const scopeLabel = clusterId ? `Affected evidence requested for cluster ${scope.cluster?.name || clusterId}.` : "Affected evidence requested across the organization.";
  return <div className="space-y-5" data-testid="cve-detail-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title={cve.cve_id} mono description={`${cve.title} · ${scopeLabel} Intelligence metadata is global; image scan evidence may be shared by digest.`} backLink={<a href={backPath}>{clusterId ? "Findings" : "CVE database"}</a>}
      badges={<>{cve.kev_listed && <KevBadge />}{cve.epss_probability != null && <EpssBadge probability={cve.epss_probability} />}</>}
      actions={<div className="flex flex-wrap gap-2"><Button onClick={() => { void cveQ.refetch(); void relatedQ.refetch(); }} disabled={cveQ.isFetching || relatedQ.isFetching}>{cveQ.isFetching || relatedQ.isFetching ? "Refreshing…" : "Refresh evidence"}</Button><Button asChild variant="outline"><a href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`} target="_blank" rel="noopener noreferrer">NVD<ExternalLink className="h-3.5 w-3.5" /></a></Button></div>} />
    <VerdictBanner status={affectedError ? "degraded" : cve.kev_listed ? "critical" : images.length ? "degraded" : "info"}
      title={affectedError ? "Affected evidence is unavailable" : !affected ? "Affected evidence is loading" : cve.kev_listed ? "This CVE is listed as known exploited" : images.length ? `${images.length} affected image scans in returned evidence` : "No affected image scans returned in this scope"}
      detail="The affected endpoint returns at most 500 image scans and 1,000 workload associations. Its summary covers those bounded rows; absence does not establish complete coverage." />
    <StatGrid data-testid="cve-detail-stats"><StatCard label="Image scans returned" value={affected ? images.length : "—"} /><StatCard label="Workloads returned" value={affected ? workloads.length : "—"} /><StatCard label="Clusters represented" value={affected ? clusters.length : "—"} /><StatCard label="Image finding instances" value={findings ?? "—"} /></StatGrid>
    {(cveQ.isFetching || relatedQ.isFetching) && <p role="status" className="text-sm text-muted-foreground">Refreshing CVE evidence; previously loaded successful reads remain visible until their requests settle.</p>}
    <Tabs value={tab} onValueChange={setTab} items={[
      { value: "images", label: "Affected images", content: withAffected(<section className="space-y-3" data-testid="cve-affected-images"><p className="text-xs text-muted-foreground">Up to 500 matching image scans. CSV covers matching loaded rows, including digest-shared scan evidence.</p><DataTable rows={images} columns={imageColumns} rowKey={(image) => image.image_scan_result_id} preferencesKey="cve-affected-images" sourceLimit={500} sourceCount={images.length} exportFileName={`${exportScope}-affected-images-loaded`} defaultSort={{ id: "risk", dir: "desc" }} emptyState={<p className="p-6 text-sm text-muted-foreground">No affected image scans returned. Scan coverage may be incomplete.</p>} /></section>) },
      { value: "workloads", label: "Affected workloads", content: withAffected(<section className="space-y-3" data-testid="cve-affected-workloads"><p className="text-xs text-muted-foreground">Up to 1,000 matching workload associations; findings may appear in multiple workloads sharing an image.</p><DataTable rows={workloads} columns={workloadColumns} rowKey={(workload) => `${workload.cluster_id}:${workload.deployment_id}`} preferencesKey="cve-affected-workloads" sourceLimit={1000} sourceCount={workloads.length} exportFileName={`${exportScope}-affected-workloads-loaded`} emptyState={<p className="p-6 text-sm text-muted-foreground">No affected workload associations returned.</p>} /></section>) },
      { value: "clusters", label: "Affected clusters", content: withAffected(<section className="space-y-3" data-testid="cve-affected-clusters"><p className="text-xs text-muted-foreground">Clusters represented by the returned workload associations; this is not a separate full-fleet total.</p><DataTable rows={clusters} columns={clusterColumns} rowKey={(cluster) => cluster.cluster_id} preferencesKey="cve-affected-clusters" exportFileName={`${exportScope}-affected-clusters-loaded`} emptyState={<p className="p-6 text-sm text-muted-foreground">No clusters represented by returned workload evidence.</p>} /></section>) },
      { value: "packages", label: "Package evidence", content: withAffected(<section className="space-y-3" data-testid="cve-package-evidence"><p className="text-xs text-muted-foreground">Package finding instances from the loaded image scans. These scan-finding IDs are not generic finding-detail IDs.</p><DataTable rows={packages} columns={packageColumns} rowKey={(item) => item.rowID} preferencesKey="cve-affected-packages" exportFileName={`${exportScope}-loaded-package-instances`} emptyState={<p className="p-6 text-sm text-muted-foreground">No package instances returned with the loaded images.</p>} /></section>) },
      { value: "details", label: "Intelligence", content: <div className="space-y-4">{sourceState}<section className="space-y-3" data-testid="cve-intelligence"><h2 className="text-sm font-semibold">Vulnerability intelligence</h2><p className="text-sm">{cve.description || "No description reported."}</p><dl className="grid gap-3 text-sm sm:grid-cols-2"><Metadata label="CVSS base" value={cve.cvss_base == null ? "Not reported" : String(cve.cvss_base)} /><Metadata label="Known exploited" value={cve.kev_listed ? "Listed in the CISA KEV catalog" : "Not listed in the returned metadata"} /><Metadata label="EPSS probability" value={cve.epss_probability == null ? "Not reported" : `${(cve.epss_probability * 100).toFixed(2)}%`} /><Metadata label="Aliases" value={cve.aliases.join(", ") || "None returned"} /></dl><p className="text-xs text-muted-foreground">EPSS describes the estimated probability of exploitation in the wild within 30 days. It does not describe observed activity in this cluster.</p>{cve.kev_listed && <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="text-sm underline">CISA known exploited catalog</a>}</section></div> },
      { value: "remediation", label: "Remediation guidance", content: <div className="space-y-4">{sourceState}<section className="space-y-3"><h2 className="text-sm font-semibold">Review remediation evidence</h2><p className="text-sm">Review reported fixed versions in Package evidence, then inspect the exact image or workload before choosing an update. A missing fixed version means the loaded scan has no fix version to report.</p><p className="text-sm text-muted-foreground">Network exposure controls, digest-scoped image risk acceptance and finding suppressions remain distinct actions in their canonical pages. This CVE page does not apply any of those changes.</p><Button onClick={() => setTab("packages")}>Review package evidence</Button></section></div> },
    ]} />
  </div>;
}

const workloadColumns: Column<CVEAffectedWorkload>[] = [
  { id: "name", header: "Workload", kind: "name", code: true, wrap: true, cell: (item) => <a href={`/clusters/${encodeURIComponent(item.cluster_id)}/deployments/${encodeURIComponent(item.deployment_id)}`} className="hover:underline">{item.namespace}/{item.name}</a>, exportValue: (item) => `${item.namespace}/${item.name}`, sort: (a, b) => a.name.localeCompare(b.name) },
  { id: "cluster", header: "Cluster", kind: "text", size: 184, maxSize: 260, wrap: true, cell: (item) => item.cluster_name || item.cluster_id },
  { id: "kind", header: "Kind", kind: "status", cell: (item) => item.kind },
  { id: "image", header: "Image evidence", kind: "text", code: true, size: 280, grow: true, maxSize: 560, wrap: true, cell: (item) => item.image_digest || item.image_ref },
  { id: "findings", header: "Finding instances", kind: "count", cell: (item) => item.finding_count },
  { id: "risk", header: "Max risk", kind: "count", cell: (item) => item.max_risk_score },
];
const clusterColumns: Column<CVEAffectedCluster>[] = [
  { id: "name", header: "Cluster", kind: "name", wrap: true, cell: (item) => <a href={`/clusters/${encodeURIComponent(item.cluster_id)}/dashboard`} className="hover:underline">{item.name || item.cluster_id}</a>, exportValue: (item) => item.name || item.cluster_id },
  { id: "workloads", header: "Workloads represented", kind: "count", cell: (item) => item.workload_count },
  { id: "findings", header: "Finding instances", kind: "count", cell: (item) => item.finding_count },
  { id: "risk", header: "Max risk", kind: "count", cell: (item) => item.max_risk_score },
];
const packageColumns: Column<CVEAffectedPackage & { image: string; imageID: string }>[] = [
  { id: "package", header: "Package", kind: "name", code: true, wrap: true, cell: (item) => item.package_name || "Not reported" },
  { id: "image", header: "Image scan", kind: "text", code: true, wrap: true, size: 240, grow: true, maxSize: 480, cell: (item) => item.image },
  { id: "version", header: "Version", kind: "version", wrap: true, cell: (item) => item.package_version || "Not reported" },
  { id: "fixed", header: "Fixed version", kind: "version", wrap: true, cell: (item) => item.fixed_version || "No fix reported" },
  { id: "severity", header: "Severity", kind: "status", cell: (item) => item.severity },
  { id: "risk", header: "Risk", kind: "count", cell: (item) => item.risk_score },
  { id: "finding", header: "Scan finding ID", kind: "id", wrap: true, size: 224, maxSize: 320, cell: (item) => item.finding_id },
];
function imageMatchesWorkload(image: CVEAffectedImage, workload: CVEAffectedWorkload) { if (image.image_digest && workload.image_digest) return image.image_digest === workload.image_digest; return !!image.image_digest && image.image_digest === workload.image_digest || !!image.image_ref_normalized && image.image_ref_normalized === workload.image_ref_normalized || !!image.image_ref && image.image_ref === workload.image_ref; }
function imageName(image: CVEAffectedImage) { return image.image_tag ? `${image.image_repository}:${image.image_tag}` : image.image_repository || image.image_ref || image.image_digest; }
function Metadata({ label, value }: { label: string; value: string }) { return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-words">{value}</dd></div>; }
function date(value: string) { const parsed = new Date(value); return Number.isNaN(parsed.getTime()) ? "Not reported" : parsed.toLocaleString(); }
