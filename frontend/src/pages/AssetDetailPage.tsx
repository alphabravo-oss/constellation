import { AssetFindingsInventory, useAssetFindingsInventory } from "./AssetFindingsInventory";
import { assetDisplayName } from "@/lib/asset-identity";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { useRef, useState } from "react";
import { Boxes, FileJson, ShieldAlert } from "lucide-react";
import { sbom, type AssetDetail, type AssetSBOM, type ImageAcceptance } from "@/api/client";
import { PageHeader, PageContainer } from "@/components/ui/page";
import { DataTable, type Column } from "@/components/ui/data-table";
import { StatCard, StatGrid } from "@/components/ui/stat-card";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { Collapse } from "@/components/ui/collapse";
import { Button } from "@/components/ui/button";
import { ErrorState, LoadingState } from "@/components/ui/states";
import { assetDate, assetErrorMessage, useAssetDetailScope } from "./asset-detail-scope";

const WORKSPACES = ["findings", "image", "acceptance", "sbom", "labels"];

export function AssetDetailPage() {
  const scope = useAssetDetailScope();
  const inventory = useAssetFindingsInventory(scope);
  const { clusterId, aid, resolved, clusterLoading, clusterError, q } = scope;
  const [requestedTab, setTab] = useTabParam("tab", "findings");
  const tab = WORKSPACES.includes(requestedTab) ? requestedTab : "findings";
  const listPath = clusterId ? `/clusters/${encodeURIComponent(clusterId)}/assets` : "/clusters";
  const header = <PageHeader title="Asset evidence" description="Inspect findings, image metadata, software inventories and digest-scoped risk decisions for this asset." backLink={<a href={listPath}>Assets</a>} />;
  if (!resolved) return <PageContainer>{header}{clusterLoading ? <LoadingState label="Resolving asset cluster…" /> : <ErrorState title="The requested cluster could not be resolved." error={clusterError} action={<Button onClick={scope.retryCluster}>Retry cluster</Button>} />}</PageContainer>;
  if (!aid) return <PageContainer>{header}<ErrorState title="An exact asset ID is required." /></PageContainer>;
  if (q.isError) return <PageContainer>{header}<VerdictBanner status="degraded" title="Asset evidence is unavailable" detail="The asset could not be loaded or refreshed. Previous evidence is hidden until a successful retry." /><ErrorState title="Asset evidence could not be loaded or refreshed." error={assetErrorMessage(q.error)} action={<Button onClick={() => void q.refetch()}>Retry asset</Button>} /></PageContainer>;
  if (!q.isSuccess || !q.data || q.data.asset.id !== aid || q.data.asset.cluster_id !== clusterId) return <PageContainer>{header}<LoadingState label="Loading asset evidence…" /></PageContainer>;
  const data = q.data;
  const { asset, image, sboms, image_acceptances: acceptances } = data;
  const basePath = `${listPath}/${encodeURIComponent(aid)}`;
  const total = inventory.available ? inventory.q.data!.total : undefined;
  const highSeverity = inventory.available ? inventory.q.data!.summary.critical + inventory.q.data!.summary.high : undefined;
  const active = acceptances.filter((item) => item.status === "active");
  const acceptanceColumns: Column<ImageAcceptance>[] = [
    { id: "rationale", header: "Rationale", kind: "name", wrap: true, cell: (item) => item.rationale, sort: (a, b) => a.rationale.localeCompare(b.rationale) },
    { id: "status", header: "Status", kind: "status", cell: (item) => item.status },
    { id: "digest", header: "Image digest", kind: "id", size: 240, maxSize: 480, wrap: true, cell: (item) => item.image_digest },
    { id: "expiry", header: "Accepted until", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (item) => assetDate(item.accepted_until), exportValue: (item) => item.accepted_until, sort: (a, b) => a.accepted_until.localeCompare(b.accepted_until) },
    { id: "action", header: "Actions", kind: "actions", cell: (item) => item.status === "active" && item.image_digest === image?.digest ? <a aria-disabled={q.isFetching} href={q.isFetching ? undefined : `${basePath}/image-acceptance/${encodeURIComponent(item.id)}/revoke`} className="text-xs hover:underline">Revoke</a> : "—", exportValue: () => "" },
  ];
  const findingsView = <AssetFindingsInventory inventory={inventory} />;
  const imageView = <section className="space-y-4" data-testid="asset-image-card"><div><h2 className="text-sm font-semibold">Image and supply chain</h2><p className="text-xs text-muted-foreground">Reported image metadata. Signature presence is not a verification or trust verdict.</p></div>{image ? <>
    <dl className="grid gap-3 text-sm sm:grid-cols-2"><Metadata label="Registry" value={image.registry} /><Metadata label="Repository" value={image.repository} /><Metadata label="Tag" value={image.tag || "Not reported"} /><Metadata label="Signature reported" value={image.signed ? "yes" : "no"} /><Metadata label="Architectures" value={image.architectures.join(", ") || "Not reported"} /><Metadata label="Size" value={image.size_bytes == null ? "Not reported" : formatBytes(image.size_bytes)} /><div className="sm:col-span-2"><DigestDisclosure digest={image.digest} /></div></dl>
    <Collapse label="Image layers and signature metadata"><div className="space-y-4"><DataTable rows={image.layers.map((layer, index) => ({ ...layer, rowId: index }))} columns={layerColumns} rowKey={(layer) => `${layer.digest}:${layer.rowId}`} preferencesKey="asset-image-layers" exportFileName={`asset-${asset.id}-layers`} emptyState={<p className="p-6 text-sm text-muted-foreground">No image layers reported.</p>} /><pre className="overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(image.signature_info, null, 2)}</pre></div></Collapse>
  </> : <p className="text-sm text-muted-foreground">No image metadata reported for this asset type.</p>}</section>;
  const acceptanceView = <section className="space-y-3" data-testid="image-acceptance-card"><div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-sm font-semibold">Image risk acceptance</h2><p className="text-xs text-muted-foreground">{active.length} active acceptance records returned. Decisions apply organization-wide to the exact image digest, including other assets using it; they are audited and expire automatically. Findings remain visible.</p></div>{image?.digest && active.length === 0 && <a href={q.isFetching ? undefined : `${basePath}/image-acceptance/new`} aria-disabled={q.isFetching} className="rounded-md border border-border px-3 py-2 text-sm hover:bg-accent">Accept image risk</a>}</div>{!image && <p className="text-sm text-muted-foreground">Image metadata is required to accept image risk.</p>}<DataTable rows={acceptances} columns={acceptanceColumns} rowKey={(item) => item.id} preferencesKey="asset-image-acceptances" exportFileName={`asset-${asset.id}-image-acceptances`} emptyState={<p className="p-6 text-sm text-muted-foreground">No image acceptance history returned.</p>} /></section>;
  return <PageContainer>
    <PageHeader title={assetDisplayName(asset, image)} backLink={<a href={listPath}>Assets</a>} description={`${asset.kind} · ${asset.criticality} criticality — reported evidence for this exact cluster asset.`} actions={<Button onClick={() => { void q.refetch(); void inventory.q.refetch(); }} disabled={q.isFetching || inventory.q.isFetching}>{q.isFetching ? "Refreshing…" : "Refresh evidence"}</Button>} />
    <VerdictBanner status={highSeverity ? "degraded" : "info"} title={highSeverity === undefined ? "Finding evidence is unavailable" : highSeverity ? `${highSeverity} high or critical matching findings` : "No high or critical matching findings"} detail="Counts cover every finding matching the active filters, across pages. Asset records and the latest shared digest scan are separate evidence sources. A zero count does not establish complete scan coverage." />
    <StatGrid data-testid="asset-stats"><StatCard label="Matching findings" value={total ?? "—"} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={total ? "high" : "neutral"} /><StatCard label="High / critical matching" value={highSeverity ?? "—"} tone={highSeverity ? "high" : "neutral"} /><StatCard label="SBOM formats returned" value={sboms.length} icon={<FileJson className="h-3.5 w-3.5" />} /><StatCard label="Image layers reported" value={image?.layers.length ?? "Not reported"} icon={<Boxes className="h-3.5 w-3.5" />} /></StatGrid>
    {q.isFetching && <p role="status" className="text-xs text-muted-foreground">Refreshing asset evidence. Finding counts and exports are paused until this request settles.</p>}
    <Tabs value={tab} onValueChange={setTab} items={[
      { value: "findings", label: "Findings", content: findingsView },
      { value: "image", label: "Image metadata", content: imageView },
      { value: "acceptance", label: "Risk acceptance", content: acceptanceView },
      { value: "sbom", label: "Software inventories", content: <SBOMView key={`${clusterId}:${aid}`} data={data} canExport={!q.isFetching} recheck={scope.recheck} /> },
      { value: "labels", label: "Asset labels", content: <section className="space-y-3"><h2 className="text-sm font-semibold">Asset labels</h2><pre className="overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(asset.labels, null, 2)}</pre></section> },
    ]} />
  </PageContainer>;
}

function SBOMView({ data, canExport, recheck }: { data: AssetDetail; canExport: boolean; recheck: () => AssetDetail | undefined }) {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const exporting = useRef(false);
  const download = async (format: "spdx" | "cyclonedx" | "mbom") => {
    if (exporting.current || !canExport || !recheck()) return;
    exporting.current = true; setPending(true); setError("");
    try { await ({ spdx: sbom.downloadSpdx, cyclonedx: sbom.downloadCyclonedx, mbom: sbom.downloadMbom })[format](data.asset.id); }
    catch (failure) { setError(assetErrorMessage(failure)); }
    finally { exporting.current = false; setPending(false); }
  };
  return <section className="space-y-3" data-testid="asset-sbom-card"><div><h2 className="text-sm font-semibold">Software inventories and exports</h2><p className="text-xs text-muted-foreground">The API returns the latest inventory per format, preferring image-scan artifacts. These rows are not a complete document history. JSON exports request server-generated formats for this asset; availability is determined by the server.</p></div><DataTable rows={data.sboms} columns={sbomColumns} rowKey={(doc) => doc.id} preferencesKey="asset-sbom-formats" exportFileName={`asset-${data.asset.id}-sbom-metadata`} emptyState={<p className="p-6 text-sm text-muted-foreground">No software inventory documents returned.</p>} /><div className="flex flex-wrap gap-3">{(["spdx", "cyclonedx", "mbom"] as const).map((format) => <Button key={format} disabled={!canExport || pending} onClick={() => void download(format)}>{format === "spdx" ? "SPDX" : format === "cyclonedx" ? "CycloneDX" : "MBOM"}</Button>)}</div>{pending && <p role="status" className="text-sm">Requesting export…</p>}{error && <p role="alert" className="text-sm text-status-error">SBOM export failed: {error}</p>}</section>;
}
const sbomColumns: Column<AssetSBOM>[] = [
  { id: "format", header: "Format", kind: "name", cell: (doc) => doc.format, sort: (a, b) => a.format.localeCompare(b.format) },
  { id: "sha", header: "Document digest", kind: "id", size: 320, maxSize: 640, grow: true, wrap: true, cell: (doc) => doc.sha256 },
  { id: "created", header: "Created", kind: "date", size: 224, minSize: 208, maxSize: 240, cell: (doc) => assetDate(doc.created_at), exportValue: (doc) => doc.created_at, sort: (a, b) => a.created_at.localeCompare(b.created_at) },
];
const layerColumns: Column<NonNullable<AssetDetail["image"]>["layers"][number]>[] = [
  { id: "digest", header: "Layer digest", kind: "name", code: true, wrap: true, cell: (layer) => layer.digest },
  { id: "size", header: "Size", kind: "text", align: "right", size: 160, minSize: 136, maxSize: 192, cell: (layer) => layer.size == null ? "Not reported" : formatBytes(layer.size) },
];
function Metadata({ label, value, wide = false }: { label: string; value: string; wide?: boolean }) { return <div className={`rounded-md border border-border p-3 ${wide ? "sm:col-span-2" : ""}`}><dt className="text-xs text-muted-foreground">{label}</dt><dd className="mt-1 break-all text-sm">{value || "Not reported"}</dd></div>; }
function formatBytes(bytes: number) { return bytes >= 1_000_000 ? `${(bytes / 1_000_000).toFixed(1)} MB` : bytes >= 1_000 ? `${(bytes / 1_000).toFixed(1)} KB` : `${bytes} B`; }
