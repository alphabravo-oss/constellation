import { useMemo, useState, type ReactNode } from "react";
import { useCrumbLabel } from "@/lib/page-title";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Boxes, FileWarning } from "lucide-react";
import { fileProfiles, type DeploymentDetail, type DeploymentComplianceEvidence, type DeploymentFileProfile, type DeploymentFileRisk, type DeploymentImageEvidence, type DeploymentNetworkFlow, type DeploymentPackageEvidence, type DeploymentProcessBaseline, type DeploymentThreatKind, type DeploymentThreatPivot, type FileProfileBundle, type NetworkPolicyLifecycle, type RuntimeEvent, type Violation } from "@/api/client";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { ModePill, StatusPill as SharedStatusPill } from "@/components/ui/status-pill";
import { PageHeader } from "@/components/ui/page";
import { Collapse } from "@/components/ui/collapse";
import { Tabs, useTabParam } from "@/components/ui/tabs";
import { VerdictBanner } from "@/components/ui/verdict-banner";
import { ErrorState, LoadingState, EmptyState } from "@/components/ui/states";
import { cn } from "@/lib/cn";
import { fmtRelative } from "@/lib/format";
import { useDeploymentContext, deploymentKey, currentDeployment, actionURL, profileIsOwned, policyIsCurrent, workloadID, nextMode } from "./deployment-detail/context";
import { DeploymentFindingsInventory } from "./DeploymentFindingsInventory";
import { EvidenceInventory } from "./deployment-detail/EvidenceInventory";

export function DeploymentDetailPage() {
  const context = useDeploymentContext();
  const { detail, clusterId, did, clusterLoading, clusterError, scopeReady, ready, q } = context;
  const [requestedTab, setTab] = useTabParam("tab", "overview");
  const tab = ["overview", "findings", "network", "runtime", "files", "compliance", "packages"].includes(requestedTab) ? requestedTab : "overview";
  const missing = q.isSuccess && !context.matches;
  const openHigh = detail ? detail.critical_count + detail.high_count : undefined;
  useCrumbLabel(detail?.name);
  const root = `/clusters/${encodeURIComponent(clusterId ?? "")}`;
  return <div className="space-y-5" data-testid="deployment-detail-page" data-cluster-id={clusterId ?? ""}>
    <PageHeader title={detail ? detail.name : "Workload"} mono
      eyebrow={detail ? `Namespace ${detail.namespace}` : undefined}
      badges={detail ? <Pill tone="neutral">{detail.kind}</Pill> : undefined}
      actions={scopeReady && did ? <Button disabled={q.isFetching} onClick={() => void q.refetch()}>Refresh</Button> : undefined} />
    <div data-testid="deployment-stats"><VerdictBanner status={clusterError || q.isError || missing ? "degraded" : (detail?.critical_count ?? 0) > 0 || (detail?.risk_score ?? 0) >= 80 ? "critical" : (openHigh ?? 0) > 0 || (detail?.risk_score ?? 0) >= 60 ? "degraded" : "info"}
      title={clusterError ? "Cluster context unavailable" : !scopeReady ? clusterLoading ? "Resolving cluster" : "Select a resolved cluster" : !did ? "Select a deployment" : q.isError ? "Deployment evidence unavailable" : q.isPending ? "Loading deployment evidence" : missing ? "Deployment does not match this cluster" : `Reported workload risk: ${detail?.risk_score}/100`}
      numbers={[
        { label: "risk score", value: detail?.risk_score ?? "—" },
        { label: "findings", value: detail?.finding_count ?? "—" },
        { label: "critical", value: detail?.critical_count ?? "—", tone: detail?.critical_count ? "critical" : "default" },
        { label: "high", value: detail?.high_count ?? "—", tone: detail?.high_count ? "high" : "default" },
      ]}
      detail={<div className="space-y-1"><p>Last observed {detail ? `${fmtRelative(detail.last_seen_at)} (${formatDate(detail.last_seen_at)})` : "—"}.</p><p>Risk and vulnerability totals are reported by workload inventory. Bounded activity samples and configured controls do not establish complete coverage or deployed protection.</p></div>} /></div>
    {!scopeReady ? clusterError ? <ErrorState title="Could not resolve this cluster." action={<Button onClick={() => { void context.qc.invalidateQueries({ queryKey: ["clusters"] }); void context.qc.invalidateQueries({ queryKey: ["cluster", clusterId] }); }}>Retry</Button>} /> : clusterLoading ? <LoadingState label="Resolving cluster…" /> : <p className="text-sm text-muted-foreground">Select a resolved cluster to view deployment evidence.</p> : !did ? <EmptyState title="No deployment selected" /> : q.isPending ? <LoadingState label="Loading deployment…" /> : q.isError ? <ErrorState title="Could not load or refresh deployment evidence." action={<Button onClick={() => void q.refetch()}>Retry</Button>} /> : !detail ? <ErrorState title="This deployment is not in the selected cluster." /> : <>
      {q.isFetching && <p role="status" className="text-sm text-muted-foreground">Refreshing deployment evidence… Authoring is paused until the refresh succeeds.</p>}
      <Tabs key={`${clusterId}/${did}`} value={tab} onValueChange={setTab} items={[
        { value: "overview", label: "Overview", content: <div className="space-y-5"><WorkloadPosture detail={detail} /><Collapse label="Advanced: source coverage and identities"><dl className="grid gap-3 text-sm sm:grid-cols-2"><Field label="Owned workload identities" value={detail.workload_ids.join(" · ") || "Not reported"} wide /><Field label="Returned image links" value={detail.images.length} /><Field label="Returned package reports" value={`${detail.package_evidence.length} · up to 20`} /><Field label="Packages across returned reports" value={sumPackages(detail.package_evidence)} /><Field label="Returned runtime events" value={`${detail.runtime_events.length} · latest 50`} /><Field label="Returned network flows" value={`${detail.network_flows.length} · latest 50`} /><Field label="Returned compliance controls" value={`${detail.compliance_evidence?.length ?? 0} · latest 50`} /></dl><p className="mt-3 text-xs text-muted-foreground">Package counts sum returned reports and can include repeated packages. Activity samples are not aggregate totals.</p></Collapse><a href={`${root}/risk/deployment/${encodeURIComponent(detail.id)}`} className="text-sm text-link">Open deployment risk workspace</a></div> },
        { value: "findings", label: "Findings", content: <div className="space-y-5"><ImageEvidenceTable images={detail.images} clusterId={clusterId} /><DeploymentFindingsInventory deployment={detail} sourceQueryKey={deploymentKey(clusterId, did)} sourceKind="detail" sourceReady={ready} /></div> },
        { value: "network", label: "Network", content: <div className="space-y-5"><DeploymentActionsPanel detail={detail} clusterId={clusterId!} ready={ready} /><NetworkFlowsTable flows={detail.network_flows} clusterId={clusterId!} /></div> },
        { value: "runtime", label: "Runtime", content: <div className="space-y-5"><ProcessBaselinePanel baseline={detail.process_baseline} detail={detail} clusterId={clusterId!} ready={ready} /><ThreatPivotsPanel pivots={detail.threat_pivots ?? []} /><RuntimeEventsPanel events={detail.runtime_events} clusterId={clusterId!} /></div> },
        { value: "files", label: "Files", content: <div className="space-y-5"><FileProfilePanel profile={detail.file_profile} detail={detail} clusterId={clusterId!} ready={ready} /><ImageFileRisksPanel risks={detail.file_risks ?? []} clusterId={clusterId} /></div> },
        { value: "compliance", label: "Compliance", content: <div className="space-y-5"><CompliancePanel evidence={detail.compliance_evidence ?? []} /><ViolationsPanel violations={detail.violations} /></div> },
        { value: "packages", label: "Packages", content: <PackageEvidencePanel evidence={detail.package_evidence} /> },
      ]} />
    </>}
  </div>;
}

function WorkloadPosture({ detail }: { detail: DeploymentDetail }) {
  const labels = Object.entries(detail.labels ?? {});
  const riskFactors = Object.entries(detail.risk_factors ?? {}).filter(([, value]) => Number(value) > 0);
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Workload posture</h2>
          <p className="mt-1 text-xs text-muted-foreground">Risk, identity, labels, and active scan coverage for this workload.</p>
        </div>
        <Boxes className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      <dl className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
        <Field label="Namespace" value={detail.namespace} />
        <Field label="Kind" value={detail.kind} />
        <Field label="Cluster" value={detail.cluster_id || "-"} />
        <Field label="Last seen" value={formatDate(detail.last_seen_at)} />
        <Field label="Image refs" value={`${detail.image_refs.length}`} />
        <Field label="Workload IDs" value={`${detail.workload_ids.length}`} />
      </dl>

      <div className="mt-4 grid gap-3 md:grid-cols-2">
        <div>
          <h3 className="text-xs font-semibold  text-muted-foreground">Risk factors</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {riskFactors.map(([key, value]) => <Pill key={key} tone={Number(value) >= 20 ? "warn" : "neutral"}>{key}: {String(value)}</Pill>)}
            {riskFactors.length === 0 ? <span className="text-xs text-muted-foreground">No positive risk factors.</span> : null}
          </div>
        </div>
        <div>
          <h3 className="text-xs font-semibold  text-muted-foreground">Labels</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {labels.map(([key, value]) => <Pill key={key} tone="neutral">{key}={value}</Pill>)}
            {labels.length === 0 ? <span className="text-xs text-muted-foreground">No labels reported.</span> : null}
          </div>
        </div>
      </div>
    </section>
  );
}

function ThreatPivotsPanel({ pivots }: { pivots: DeploymentThreatPivot[] }) {
  const [filter, setFilter] = useState<DeploymentThreatKind | "all">("all");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = pivots.find(pivot => pivot.id === selectedId);
  const filtered = useMemo(
    () => pivots.filter((pivot) => filter === "all" || pivot.kind === filter),
    [filter, pivots],
  );
  const counts = useMemo(() => ({
    all: pivots.length,
    file: pivots.filter((pivot) => pivot.kind === "file").length,
    dlp: pivots.filter((pivot) => pivot.kind === "dlp").length,
    waf: pivots.filter((pivot) => pivot.kind === "waf").length,
  }), [pivots]);

  const columns: Column<DeploymentThreatPivot>[] = [
    {
      id: "type",
      header: "Type", kind: "badge", size: 160, minSize: 144, maxSize: 192,
      cell: (pivot) => (
        <span data-testid={`deployment-threat-row-${pivot.kind}`}><ThreatKindPill kind={pivot.kind} /></span>
      ),
    },
    {
      id: "signal",
      header: "Signal", kind: "name", wrap: true,
      cell: (pivot) => (
        <>
          <div className="text-xs font-medium">{pivot.title}</div>
          <div className="mt-1 font-mono text-micro text-muted-foreground">{pivot.workload_id}</div>
        </>
      ),
    },
    {
      id: "verdict",
      header: "Verdict", kind: "badge", size: 192, minSize: 160, maxSize: 240, wrap: true,
      cell: (pivot) => (
        <div className="flex flex-wrap gap-1">
          <SeverityPill severity={pivot.severity} />
          <StatusPill status={pivot.verdict} />
        </div>
      ),
    },
    {
      id: "evidence",
      header: "Evidence", kind: "text", wrap: true, size: 280, minSize: 208, maxSize: 400, grow: true,
      cell: (pivot) => pivotEvidenceLabel(pivot),
      className: "text-xs text-muted-foreground",
    },
    {
      id: "at",
      header: "Last Seen", kind: "date", size: 224, minSize: 208, maxSize: 240,
      cell: (pivot) => formatDate(pivot.at),
      className: "text-xs text-muted-foreground",
    },
  ];

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="deployment-threat-pivots">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Runtime threat pivots</h2>
          <p className="mt-1 text-xs text-muted-foreground">Up to 60 returned file, DLP and WAF threat pivots. The source combines the latest 30 file signals and 50 runtime threat signals, then retains 60.</p>
        </div>
        <div className="flex flex-wrap gap-1">
          {(["all", "file", "dlp", "waf"] as const).map((item) => (
            <button
              key={item}
              type="button"
              data-testid={`deployment-threat-filter-${item}`}
              onClick={() => setFilter(item)}
              className={cn(
                "rounded-md border border-border px-2 py-1 text-xs font-medium",
                filter === item ? "bg-foreground text-background" : "bg-background text-muted-foreground hover:text-foreground",
              )}
            >
              {item.toUpperCase()} {counts[item]}
            </button>
          ))}
        </div>
      </header>
      <DataTable<DeploymentThreatPivot>
        rows={filtered}
        columns={columns}
        rowKey={(pivot) => pivot.id}
        onRowClick={(pivot) => setSelectedId(pivot.id)}
                className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground" data-testid="deployment-threat-empty">
            No file, DLP, or WAF threat pivots for this workload.
          </div>
        }
      />
      {selected && <ThreatPivotPanel pivot={selected} onClose={() => setSelectedId(null)} />}
    </section>
  );
}

function ThreatPivotPanel({ pivot, onClose }: { pivot: DeploymentThreatPivot; onClose: () => void }) {
  return (
    <section className="rounded-lg border border-border bg-card shadow-[0_1px_2px_0_rgb(0_0_0/0.04)]" data-testid="deployment-threat-drawer">
      <header className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-foreground">{pivot.title ?? "Threat evidence"}</h2>
          <p className="text-xs text-muted-foreground">{`${pivot.kind.toUpperCase()} · ${pivot.verdict} · ${formatDate(pivot.at)}`}</p>
        </div>
        <Button variant="ghost" size="sm" onClick={onClose}>Close</Button>
      </header>
      <div className="space-y-4 p-5">
          <section className="rounded-md border border-border p-3" data-testid="threat-meta">
            <dl className="grid gap-3 text-sm sm:grid-cols-2">
              <Field label="Workload" value={pivot.workload_id} />
              <Field label="Namespace" value={pivot.namespace || "-"} />
              <Field label="Node" value={pivot.node_id || "-"} />
              <Field label="Severity" value={pivot.severity} />
              <Field label="Verdict" value={pivot.verdict} />
              <Field label="ATT&CK" value={pivot.attack_techniques?.join(", ") || "-"} />
            </dl>
          </section>
          {pivot.kind === "file" && pivot.file ? (
            <section className="rounded-md border border-border p-3" data-testid="deployment-threat-file-evidence">
              <h3 className="text-xs font-semibold  text-muted-foreground">File evidence</h3>
              <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                <Field label="Path" value={pivot.file.path || "-"} wide />
                <Field label="Process" value={pivot.file.comm || "-"} />
                <Field label="PID" value={`${pivot.file.pid ?? "-"}`} />
                <Field label="Flags" value={`${pivot.file.flags ?? "-"}`} />
                <Field label="Mode" value={`${pivot.file.mode ?? "-"}`} />
              </dl>
            </section>
          ) : null}
          {(pivot.kind === "dlp" || pivot.kind === "waf") && (
            <section className="rounded-md border border-border p-3" data-testid={pivot.kind === "dlp" ? "deployment-threat-dlp-evidence" : "deployment-threat-waf-evidence"}>
              <h3 className="text-xs font-semibold  text-muted-foreground">{pivot.kind.toUpperCase()} evidence</h3>
              <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                <Field label="Rule" value={pivot.rule?.name || pivot.rule?.id || "-"} />
                <Field label="DP rule" value={`${pivot.rule?.dp_rule_id ?? "-"}`} />
                <Field label="Direction" value={pivot.network?.direction || "-"} />
                <Field label="Protocol" value={pivot.network?.protocol || "-"} />
                <Field label="Source" value={formatEndpoint(pivot.network?.src_ip, pivot.network?.src_port)} />
                <Field label="Destination" value={formatEndpoint(pivot.network?.dst_ip, pivot.network?.dst_port)} />
              </dl>
              <p className="mt-3 break-words text-xs text-muted-foreground">{pivot.message || "No redacted message recorded."}</p>
              <div className="mt-3" data-testid={pivot.has_packet ? "threat-packet-dump" : "threat-no-packet"}>
                {pivot.has_packet ? <Pill tone="neutral">packet evidence available</Pill> : <Pill tone="neutral">no packet capture</Pill>}
              </div>
            </section>
          )}
      </div>
    </section>
  );
}

function ImageEvidenceTable({ images, clusterId }: { images: DeploymentImageEvidence[]; clusterId?: string }) {
  const columns: Column<DeploymentImageEvidence>[] = [
    {
      id: "image",
      header: "Image", kind: "name", wrap: true, code: true,
      cell: (image) => (
        <>
          {image.image_scan_result_id ? (
            <a href={`/clusters/${clusterId}/images/${image.image_scan_result_id}`} className="break-all font-mono text-xs font-medium hover:underline">
              {displayImage(image)}
            </a>
          ) : (
            <span className="break-all font-mono text-xs font-medium">{displayImage(image)}</span>
          )}
          <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{image.image_digest || image.image_ref_normalized}</div>
        </>
      ),
    },
    {
      id: "scan",
      header: "Scan", kind: "text", wrap: true, size: 224, minSize: 208, maxSize: 240,
      cell: (image) => (
        <>
          <StatusPill status={image.image_scan_result_id ? "scanned" : "missing"} />
          <div className="mt-1 text-muted-foreground">{formatDate(image.last_scanned_at)}</div>
        </>
      ),
      className: "text-xs",
    },
    {
      id: "risk",
      header: "Risk", kind: "text", wrap: true, size: 208, minSize: 160, maxSize: 280, align: "right",
      cell: (image) => (
        <div className="flex flex-wrap justify-end gap-1">
          <Pill tone={image.critical_count > 0 ? "danger" : "neutral"}>C: {image.critical_count}</Pill>
          <Pill tone={image.high_count > 0 ? "warn" : "neutral"}>H: {image.high_count}</Pill>
          <Pill tone={image.finding_count > 0 ? "warn" : "ok"}>{image.finding_count} total</Pill>
        </div>
      ),
    },
    {
      id: "bundle",
      header: "Bundle", kind: "version", size: 192, minSize: 144, maxSize: 256, wrap: true,
      cell: (image) => (
        <>
          <div className="font-mono">{image.vulndb_bundle_version || "-"}</div>
          <div className="mt-1 text-muted-foreground">{image.package_count} packages</div>
        </>
      ),
      className: "text-xs",
    },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Running images</h2>
        <p className="mt-1 text-xs text-muted-foreground">Canonical image scan results joined through active workload exposure.</p>
      </header>
      <DataTable<DeploymentImageEvidence>
        rows={images}
        preferencesKey="deployment-images" exportFileName="deployment-returned-images"
        columns={columns}
        rowKey={(image) => image.image_ref}
                className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No running image exposure recorded for this workload.</div>
        }
      />
    </section>
  );
}

function ImageFileRisksPanel({ risks, clusterId }: { risks: DeploymentFileRisk[]; clusterId?: string }) {
  const fileRiskColumns: Column<DeploymentFileRisk>[] = [
    {
      id: "image",
      header: "Image", kind: "name", wrap: true, code: true,
      cell: (risk) => (
        <>
          {risk.image_scan_result_id ? (
            <a href={`/clusters/${clusterId}/images/${risk.image_scan_result_id}`} className="break-all font-mono text-xs font-medium hover:underline">
              {risk.image_ref || risk.image_digest}
            </a>
          ) : (
            <span className="break-all font-mono text-xs font-medium">{risk.image_ref || risk.image_digest}</span>
          )}
          <div className="mt-1 break-all font-mono text-micro text-muted-foreground">{risk.image_digest || risk.image_ref_normalized}</div>
        </>
      ),
    },
    {
      id: "risk",
      header: "Risk", kind: "text", wrap: true, size: 208, minSize: 160, maxSize: 280, align: "right",
      cell: (risk) => (
        <div className="flex flex-wrap justify-end gap-1">
          <StatusPill status={risk.status || "observed"} />
          <Pill tone={risk.file_risk_count > 0 ? "warn" : "ok"}>{risk.file_risk_count} file risks</Pill>
          {risk.truncated ? <Pill tone="warn">truncated</Pill> : null}
        </div>
      ),
    },
    {
      id: "evidence",
      header: "Evidence", kind: "text", wrap: true, size: 280, minSize: 208, maxSize: 400, grow: true,
      cell: (risk) => (
        <>
          {risk.findings.map((finding) => (
            <div key={`${risk.artifact_id}:${finding.path}`} className="mb-1 last:mb-0">
              <span className="break-all font-mono">{finding.path}</span>
              <span className="ml-2 text-muted-foreground">{finding.risk_types?.join(", ") || finding.reason || ""}</span>
            </div>
          ))}

        </>
      ),
      className: "text-xs",
    },
    {
      id: "observed",
      header: "Observed", kind: "date", size: 224, minSize: 208, maxSize: 240,
      cell: (risk) => formatDate(risk.created_at),
      className: "text-xs text-muted-foreground",
    },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="deployment-file-risks">
      <header className="flex items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Image file risks</h2>
          <p className="mt-1 text-xs text-muted-foreground">Up to 20 linked static filesystem artifacts. All returned findings are visible; artifacts marked truncated may omit source evidence.</p>
        </div>
        <FileWarning className="h-4 w-4 text-muted-foreground" aria-hidden />
      </header>
      <DataTable<DeploymentFileRisk>
        rows={risks}
        preferencesKey="deployment-image-file-risks" exportFileName="deployment-returned-image-file-risks" sourceLimit={20} sourceCount={risks.length}
        columns={fileRiskColumns}
        rowKey={(risk) => risk.artifact_id}
                className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No image file-risk artifacts linked to this workload.</div>
        }
      />
    </section>
  );
}

const networkFlowColumns: Column<DeploymentNetworkFlow>[] = [
  {
    id: "peer",
    header: "Peer", kind: "name", wrap: true, code: true,
    cell: (flow) => (
      <>
        <div className="break-all font-mono text-xs">{flow.src}</div>
        <div className="mt-1 break-all font-mono text-micro text-muted-foreground">to {flow.dst}</div>
      </>
    ),
  },
  { id: "src_platform_role", header: "From role", kind: "status", size: 144, minSize: 128, maxSize: 176, exportHeader: "src_platform_role", exportValue: flow => flow.src_platform_role ?? "", cell: flow => <SharedStatusPill label={flow.src_platform_role || "Not classified"} tone={flow.src_platform_role ? "info" : "neutral"} uppercase={false} /> },
  { id: "dst_platform_role", header: "To role", kind: "status", size: 144, minSize: 128, maxSize: 176, exportHeader: "dst_platform_role", exportValue: flow => flow.dst_platform_role ?? "", cell: flow => <SharedStatusPill label={flow.dst_platform_role || "Not classified"} tone={flow.dst_platform_role ? "info" : "neutral"} uppercase={false} /> },
  {
    id: "protocol",
    header: "Protocol", kind: "text", wrap: true, size: 184, minSize: 144, maxSize: 240,
    cell: (flow) => (
      <>
        <div className="font-medium">{flow.protocol.toUpperCase()} {flow.dst_port || ""}</div>
        <div className="mt-1 text-muted-foreground">{flow.l7_protocol || "l7 unknown"} · {flow.verdict}</div>
      </>
    ),
    className: "text-xs",
  },
  {
    id: "traffic",
    header: "Traffic", kind: "text", wrap: true, align: "right", size: 144, minSize: 112, maxSize: 184,
    cell: (flow) => (
      <>
        <div>{formatBytes(flow.bytes)}</div>
        <div className="mt-1 text-muted-foreground">{flow.packets} packets</div>
      </>
    ),
    className: "text-xs",
  },
  {
    id: "last_seen",
    header: "Last Seen", kind: "date", size: 224, minSize: 208, maxSize: 240,
    cell: (flow) => formatDate(flow.last_seen_at),
    className: "text-xs text-muted-foreground",
  },
];

function NetworkFlowsTable({ flows, clusterId }: { flows: DeploymentNetworkFlow[]; clusterId: string }) {
  if (flows.some(flow => flow.cluster_id && flow.cluster_id !== clusterId)) return <ErrorState title="Embedded network flows do not match this cluster." />;
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Network flows</h2>
        <p className="mt-1 text-xs text-muted-foreground">Latest 50 network flows for owned workloads. Pair links open exact directed endpoints in the cluster’s 24-hour conversation view.</p>
      </header>
      <DataTable<DeploymentNetworkFlow>
        rows={flows}
        preferencesKey="deployment-network-flows" exportFileName="deployment-returned-flows" sourceLimit={50} sourceCount={flows.length}
        columns={[...networkFlowColumns, { id: "pair", header: "Exact pair", kind: "actions", size: 152, minSize: 144, maxSize: 176, cell: flow => <a href={`/clusters/${clusterId}/network?${new URLSearchParams({ tab: "conversations", hours: "24", from: flow.src, to: flow.dst, hide_platform: "false" })}`} className="text-link">View pair · 24h</a>, exportable: false }]}
        rowKey={(flow) => flow.id}
                className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No network flows recorded for this workload.</div>
        }
      />
    </section>
  );
}

function ActionLink({ href, ready, children, testId }: { href: string; ready: boolean; children: ReactNode; testId?: string }) {
  return <a href={ready ? href : undefined} aria-disabled={!ready} data-testid={testId} className={cn("inline-flex items-center gap-2 rounded-md border border-border px-3 py-2 text-sm", ready ? "text-primary hover:bg-accent" : "text-muted-foreground opacity-60")}>{children}</a>;
}

function DeploymentActionsPanel({ detail, clusterId, ready }: { detail: DeploymentDetail; clusterId: string; ready: boolean }) {
  const [reviewOpen, setReviewOpen] = useState(false);
  const workload = workloadID(detail);
  const validPolicy = policyIsCurrent(detail);
  const policy = validPolicy ? detail.network_policy! : undefined;
  const quarantined = detail.quarantine;
  const quarantineValid = !quarantined || quarantined.cluster_id === clusterId && quarantined.scope === "workload" && quarantined.match_key === workload;
  const stale = policy ? deploymentPolicyIsStale(policy) : false;
  const manifests = policy ? deploymentPolicyManifests(policy) : {};
  const currentApply = [...(policy?.apply_statuses ?? [])].sort((a, b) => b.updated_at.localeCompare(a.updated_at))[0];
  const existingForm = (action: string) => `/clusters/${clusterId}/network/actions/${action}?${new URLSearchParams({ workload, back: `tab=rules&workload=${encodeURIComponent(workload)}` })}`;
  return <section className="space-y-4 rounded-md border border-border bg-card p-4" data-testid="deployment-action-controls">
    <h2 className="text-sm font-semibold">Network policy and quarantine</h2>
    <p className="text-sm text-muted-foreground">Approval, configuration and reported applier state are separate. Quarantine blocks re-admission and rescheduling; it does not terminate existing pod traffic.</p>
    {detail.network_policy && !validPolicy ? <ErrorState title="Network policy context does not match this deployment and cluster." /> : <div className="space-y-3" data-testid="deployment-policy-actions">
      {policy ? <><dl className="grid gap-3 text-sm sm:grid-cols-2"><Field label="Reported current mode" value={<ModePill mode={policy.current_mode} />} /><Field label="Target mode" value={policy.target_mode || "Not reported"} /><Field label="Approval" value={policy.approval_status} /><Field label="Candidate hash" value={policy.candidate_hash || "Not reported"} wide /></dl>
        {stale && <p role="alert" className="text-sm text-status-warning" data-testid="deployment-policy-stale-warning">{policy.stale_reason || "The candidate changed since approval. Review it before applying."}</p>}
        <p className="text-sm text-muted-foreground" data-testid="deployment-policy-apply-status">{currentApply ? `Applier reported ${currentApply.last_action}: ${currentApply.status}${currentApply.error ? ` · ${currentApply.error}` : ""}` : "The applier has not reported deployment status for this policy."}</p>
        <div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => setReviewOpen(value => !value)} data-testid="deployment-policy-review-open">Review candidate</Button>
          {policy.target_mode && (policy.approval_status === "pending" || stale) && <ActionLink ready={ready} href={existingForm("approve-policy")} testId="deployment-policy-approve">Approve policy</ActionLink>}
          {policy.target_mode && policy.approval_status === "approved" && !stale && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "apply-policy")} testId="deployment-policy-apply">Apply approved policy</ActionLink>}
          {policy.current_mode !== "discover" && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "demote-policy")} testId="deployment-policy-demote">Demote policy</ActionLink>}
          {policy.rollback_available && policy.rollback_ref && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "rollback-policy")} testId="deployment-policy-rollback">Roll back policy</ActionLink>}
        </div>
        {reviewOpen && <section className="space-y-4 rounded-md border border-border p-4" data-testid="deployment-policy-review-drawer"><h3 className="text-sm font-semibold">Reported candidate · {workload}</h3>{Object.entries(manifests).map(([flavor, yaml]) => <Collapse key={flavor} label={`${flavor} manifest`} defaultOpen><pre className="overflow-auto whitespace-pre-wrap break-all text-xs" data-testid="deployment-policy-preview">{yaml}</pre></Collapse>)}<div data-testid="deployment-policy-diff"><p className="text-sm">{policy.diff.summary}</p><ul className="mt-2 space-y-1 text-xs">{[...policy.diff.added, ...policy.diff.changed, ...policy.diff.removed].map((line, index) => <li key={index}>{line}</li>)}</ul></div><Collapse label="Advanced: returned policy audit trail"><EvidenceInventory rows={policy.audit_trail} fields={[{ key: "at", label: "At", kind: "date" }, { key: "action", label: "Action", kind: "status" }, { key: "actor", label: "Actor", kind: "text" }, { key: "message", label: "Message", kind: "name" }]} testId="deployment-policy-audit-trail" /></Collapse></section>}
      </> : <p className="text-sm text-muted-foreground" data-testid="deployment-policy-empty">No retained policy candidate is reported for this workload. Policy protection is not established.</p>}
      <a href={`/clusters/${clusterId}/network?${new URLSearchParams({ tab: "map", workload, hide_platform: "false" })}`} className="text-sm text-link">Open workload network context</a>
    </div>}
    <div className="space-y-3 border-t border-border pt-4" data-testid="deployment-quarantine-actions">{!quarantineValid ? <ErrorState title="Quarantine context does not match this deployment." /> : quarantined ? <><p className="text-sm" data-testid="deployment-quarantine-active">Active quarantine: {quarantined.reason} · expires {formatDate(quarantined.expires_at)}</p><ActionLink ready={ready} href={actionURL(clusterId, detail.id, "lift-quarantine")} testId="deployment-quarantine-lift">Lift quarantine</ActionLink></> : <><p className="text-sm text-muted-foreground">No active quarantine is reported.</p><ActionLink ready={ready} href={existingForm("quarantine")} testId="deployment-quarantine-create">Quarantine workload</ActionLink></>}</div>
  </section>;
}

function ProcessBaselinePanel({ baseline, detail, clusterId, ready }: { baseline?: DeploymentProcessBaseline | null; detail: DeploymentDetail; clusterId: string; ready: boolean }) {
  if (!baseline) return <EmptyState title="No process baseline evidence reported" />;
  if (!profileIsOwned(detail, baseline)) return <ErrorState title="Process baseline does not match this deployment and cluster." />;
  return <section className="space-y-4" data-testid="deployment-process-baseline"><h2 className="text-sm font-semibold">Reported process baseline</h2><p className="text-sm text-muted-foreground">Reported mode: {baseline.mode}. These observations derive from at most 1,000 retained process events. Configured mode does not prove agent enforcement.</p>
    <dl className="grid gap-3 text-sm sm:grid-cols-2"><Field label="Observed workload" value={baseline.workload_id} /><Field label="Control workload" value={baseline.control_workload_id} /><Field label="Reported learned processes" value={baseline.learned_processes_count} /><Field label="Alerts · 24h within retained source" value={baseline.monitored_alerts_24h} /><Field label="Blocks · 24h within retained source" value={baseline.enforced_blocks_24h} /><Field label="Last new process" value={formatDate(baseline.last_new_process_at)} /></dl>
    <div className="flex flex-wrap gap-2" data-testid="deployment-process-baseline-actions">{nextMode(baseline.mode, false) && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "process-mode", { mode: nextMode(baseline.mode, false)! })} testId="deployment-process-baseline-rollback">Roll back to {nextMode(baseline.mode, false)}</ActionLink>}{nextMode(baseline.mode, true) && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "process-mode", { mode: nextMode(baseline.mode, true)! })} testId="deployment-process-baseline-promote">Promote to {nextMode(baseline.mode, true)}</ActionLink>}<a href={`/clusters/${clusterId}/runtime/baselines/${encodeURIComponent(baseline.control_workload_id)}`} className="text-sm text-link">Open process baseline detail</a></div>
    <EvidenceInventory rows={baseline.processes} fields={[{ key: "name", label: "Process", kind: "name" }, { key: "path", label: "Path", kind: "text" }, { key: "args", label: "Arguments", kind: "text" }, { key: "observed_count", label: "Observations", kind: "count" }, { key: "last_seen", label: "Last observed", kind: "date" }]} testId="deployment-process-baseline-processes" rowTestId={() => "deployment-process-baseline-process-row"} />
    <Collapse label="Advanced: process mode transition history"><EvidenceInventory rows={baseline.transitions ?? []} fields={[{ key: "at", label: "At", kind: "date" }, { key: "from", label: "From", kind: "status" }, { key: "to", label: "To", kind: "status" }, { key: "reason", label: "Reason", kind: "name" }]} testId="deployment-process-baseline-transitions" sourceLimit={50} /></Collapse>
  </section>;
}

function FileProfilePanel({ profile, detail, clusterId, ready }: { profile?: DeploymentFileProfile | null; detail: DeploymentDetail; clusterId: string; ready: boolean }) {
  const qc = useQueryClient();
  const [bundle, setBundle] = useState<FileProfileBundle>();
  const exportBundle = useMutation({ mutationFn: () => {
    const current = currentDeployment(qc, clusterId, detail.id);
    if (!current.file_profile || !profileIsOwned(current, current.file_profile)) throw new Error("Refresh the selected file profile before exporting.");
    return fileProfiles.exportBundle(current.file_profile.control_workload_id, { cluster_id: clusterId });
  }, onSuccess: value => { setBundle(value); const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: "application/json" })); const anchor = document.createElement("a"); anchor.href = url; anchor.download = "deployment-file-profile-bundle.json"; anchor.click(); URL.revokeObjectURL(url); } });
  if (!profile) return <EmptyState title="No file profile evidence reported" />;
  if (!profileIsOwned(detail, profile)) return <ErrorState title="File profile does not match this deployment and cluster." />;
  const control = profile.control_workload_id;
  const ruleURL = (id = "new") => `/clusters/${clusterId}/file-monitor/${encodeURIComponent(id)}?${new URLSearchParams({ workload: control, return_to: `/clusters/${clusterId}/deployments/${detail.id}?tab=files` })}`;
  return <section className="space-y-4" data-testid="deployment-file-profile"><h2 className="text-sm font-semibold">Reported file profile</h2><p className="text-sm text-muted-foreground">Reported mode: {profile.mode}. File observations derive from at most 1,000 retained file-open events. Rules describe configuration; watch snapshots report agent state.</p>
    <dl className="grid gap-3 text-sm sm:grid-cols-2"><Field label="Observed workload" value={profile.workload_id} /><Field label="Control workload" value={control} /><Field label="Reported learned paths" value={profile.learned_paths_count} /><Field label="Alerts · 24h within retained source" value={profile.monitored_alerts_24h} /><Field label="Blocks · 24h within retained source" value={profile.enforced_blocks_24h} /><Field label="Reported sensitive paths" value={profile.sensitive_path_count} /></dl>
    <div className="flex flex-wrap gap-2" data-testid="deployment-file-profile-actions">{nextMode(profile.mode, false) && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-mode", { mode: nextMode(profile.mode, false)! })} testId="deployment-file-profile-rollback">Roll back to {nextMode(profile.mode, false)}</ActionLink>}{nextMode(profile.mode, true) && <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-mode", { mode: nextMode(profile.mode, true)! })} testId="deployment-file-profile-promote">Promote to {nextMode(profile.mode, true)}</ActionLink>}<ActionLink ready={ready} href={ruleURL()} testId="deployment-file-profile-rule-add">Add file monitor rule</ActionLink><ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-exception")} testId="deployment-file-profile-exception-add">Add file exception</ActionLink><ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-bundle-import")}>Import file profile bundle</ActionLink><Button variant="outline" disabled={!ready || exportBundle.isPending} onClick={() => exportBundle.mutate()}>{exportBundle.isPending ? "Exporting bundle…" : "Export bundle"}</Button></div>
    {exportBundle.isError && <ErrorState title="Could not export the file profile bundle." />}
    <EvidenceInventory rows={profile.files} fields={[{ key: "path", label: "Path", kind: "name" }, { key: "operation", label: "Operation", kind: "status" }, { key: "comm", label: "Process", kind: "text" }, { key: "sensitive", label: "Sensitive", kind: "status" }, { key: "observed_count", label: "Observations", kind: "count" }, { key: "last_seen", label: "Last observed", kind: "date" }]} testId="deployment-file-profile-paths" rowTestId={() => "deployment-file-profile-path-row"} />
    <Collapse label="Advanced: monitor rules, exceptions and reported agent watches"><div className="space-y-5">
      <EvidenceInventory rows={profile.rules ?? []} fields={[{ key: "filter", label: "Rule", kind: "name", cell: rule => <ActionLink ready={ready} href={ruleURL(rule.id)}>{rule.filter}</ActionLink> }, { key: "behavior", label: "Behavior", kind: "status" }, { key: "applications", label: "Applications", kind: "text" }, { key: "enabled", label: "Enabled", kind: "status" }, { key: "id", label: "Remove", kind: "actions", cell: rule => <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-rule-delete", { rule: rule.id })} testId="deployment-file-profile-rule-delete">Remove</ActionLink> }]} testId="deployment-file-profile-rules" rowTestId={() => "deployment-file-profile-rule-row"} />
      <EvidenceInventory rows={profile.exceptions ?? []} fields={[{ key: "filter", label: "Exception", kind: "name" }, { key: "rule_id", label: "Rule scope", kind: "id" }, { key: "applications", label: "Applications", kind: "text" }, { key: "enabled", label: "Enabled", kind: "status" }, { key: "id", label: "Remove", kind: "actions", cell: exception => <ActionLink ready={ready} href={actionURL(clusterId, detail.id, "file-exception-delete", { exception: exception.id })} testId="deployment-file-profile-exception-delete">Remove</ActionLink> }]} testId="deployment-file-profile-exceptions" rowTestId={() => "deployment-file-profile-exception-row"} />
      <EvidenceInventory rows={profile.watched_files ?? []} fields={[{ key: "filter", label: "Watch", kind: "name" }, { key: "node", label: "Node", kind: "text" }, { key: "enforcement_state", label: "Reported agent state", kind: "status" }, { key: "desired_protect", label: "Desired protection", kind: "status" }, { key: "protect", label: "Reported protection", kind: "status" }, { key: "files", label: "Returned watched files", kind: "text" }]} testId="deployment-file-profile-watches" sourceLimit={200} rowTestId={() => "deployment-file-profile-watch-row"} />
      <EvidenceInventory rows={profile.transitions ?? []} fields={[{ key: "at", label: "At", kind: "date" }, { key: "from", label: "From", kind: "status" }, { key: "to", label: "To", kind: "status" }, { key: "reason", label: "Reason", kind: "name" }]} testId="deployment-file-profile-transitions" sourceLimit={50} />
      {bundle && <pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs" data-testid="deployment-file-profile-bundle">{JSON.stringify(bundle, null, 2)}</pre>}
    </div></Collapse>
  </section>;
}

function CompliancePanel({ evidence }: { evidence: DeploymentComplianceEvidence[] }) {
  const sorted = [...evidence].sort((a, b) => statusRank(a.effective_status) - statusRank(b.effective_status));
  return <EvidenceInventory rows={sorted} fields={[{ key: "title", label: "Control", kind: "name" }, { key: "framework", label: "Framework", kind: "text" }, { key: "control_id", label: "Control ID", kind: "id" }, { key: "effective_status", label: "Effective result", kind: "status" }, { key: "target", label: "Target", kind: "text" }, { key: "evidence", label: "Evidence", kind: "text" }, { key: "remediation", label: "Remediation", kind: "text" }]} testId="deployment-compliance-evidence" title="Compliance evidence" source="Up to 50 returned workload control rows. Missing checks do not establish compliance." sourceLimit={50} />;
}
function PackageEvidencePanel({ evidence }: { evidence: DeploymentPackageEvidence[] }) {
  const [selectedId, setSelectedId] = useState<string>();
  const selected = selectedId ? evidence.find(item => item.id === selectedId) : evidence[0];
  return <section className="space-y-5"><EvidenceInventory rows={evidence} fields={[{ key: "workload_id", label: "Workload", kind: "name" }, { key: "node", label: "Node", kind: "text" }, { key: "pod_name", label: "Pod", kind: "text" }, { key: "package_count", label: "Packages", kind: "count" }, { key: "container_count", label: "Containers", kind: "count" }, { key: "observed_at", label: "Observed", kind: "date" }]} testId="deployment-package-evidence" title="Package inventory reports" source="Latest 20 inventory reports for owned workloads. Select a report to inspect its full returned payload; package counts may overlap between reports." sourceLimit={20} onRowClick={item => setSelectedId(item.id)} />{selectedId && !selected && <ErrorState title="The selected package report is no longer available." action={<Button onClick={() => setSelectedId(undefined)}>Select the latest report</Button>} />}{selected && <Collapse label={`Advanced: package payload · ${selected.workload_id}`} defaultOpen><dl className="mb-3 grid gap-3 text-sm sm:grid-cols-2"><Field label="Inventory hash" value={selected.inventory_hash} /><Field label="Runtime" value={selected.runtime || "Not reported"} /><Field label="Distro" value={[selected.distro, selected.distro_version].filter(Boolean).join(" ") || "Not reported"} /></dl><pre className="max-h-96 overflow-auto whitespace-pre-wrap break-all text-xs" data-testid="deployment-package-payload">{renderPayload(selected.payload)}</pre></Collapse>}</section>;
}
function RuntimeEventsPanel({ events, clusterId }: { events: RuntimeEvent[]; clusterId: string }) {
  if (events.some(event => event.cluster_id && event.cluster_id !== clusterId)) return <ErrorState title="Embedded runtime events do not match this cluster." />;
  return <EvidenceInventory rows={events} fields={[{ key: "kind", label: "Event", kind: "name" }, { key: "platform_role", label: "Platform role", kind: "status", value: event => event.platform_role ?? "", cell: event => <SharedStatusPill label={event.platform_role || "Not classified"} tone={event.platform_role ? "info" : "neutral"} uppercase={false} /> }, { key: "cluster_id", label: "Cluster", kind: "id" }, { key: "severity", label: "Severity", kind: "status" }, { key: "verdict", label: "Verdict", kind: "status" }, { key: "source", label: "Source", kind: "text" }, { key: "workload_id", label: "Workload", kind: "text" }, { key: "at", label: "Observed", kind: "date" }]} testId="deployment-runtime-events" title="Runtime events" source="Latest 50 returned events for owned workloads. This endpoint applies no 24-hour bound; missing events do not establish runtime coverage." sourceLimit={50} />;
}
function ViolationsPanel({ violations }: { violations: Violation[] }) {
  return <EvidenceInventory rows={violations} fields={[{ key: "policy_name", label: "Policy", kind: "name" }, { key: "kind", label: "Kind", kind: "status" }, { key: "severity", label: "Severity", kind: "status" }, { key: "message", label: "Evidence", kind: "text" }, { key: "at", label: "Observed", kind: "date" }]} testId="deployment-violations" title="Violations" source="Latest 50 returned deployment violation records. A missing record does not prove protection." sourceLimit={50} />;
}

function Field({ label, value, wide }: { label: string; value: ReactNode; wide?: boolean }) {
  return (
    <div className={cn("grid gap-1", wide && "sm:col-span-2")}>
      <dt className="text-micro  text-muted-foreground">{label}</dt>
      <dd className="break-all font-mono text-xs">{value}</dd>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const normalized = (status || "unknown").toLowerCase();
  return (
    <Pill tone={normalized === "protect" || normalized === "scanned" || normalized === "pass" || normalized === "exempted" ? "ok" : normalized === "missing" || normalized === "block" || normalized === "deny" || normalized === "fail" ? "danger" : normalized === "monitor" || normalized === "pending" || normalized === "manual" || normalized === "alert" ? "warn" : "neutral"}>
      {normalized}
    </Pill>
  );
}

function SeverityPill({ severity }: { severity: string }) {
  const normalized = (severity || "unknown").toLowerCase();
  return (
    <Pill tone={normalized === "critical" ? "danger" : normalized === "high" || normalized === "medium" ? "warn" : "neutral"}>
      {normalized}
    </Pill>
  );
}

function Pill({ tone, children }: { tone: "neutral" | "ok" | "warn" | "danger"; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-micro font-medium",
        tone === "neutral" && "bg-muted text-muted-foreground",
        tone === "ok" && "bg-status-ok/10 text-status-ok",
        tone === "warn" && "bg-status-warn/10 text-status-warn",
        tone === "danger" && "bg-status-error/10 text-status-error",
      )}
    >
      {children}
    </span>
  );
}

function ThreatKindPill({ kind }: { kind: DeploymentThreatKind }) {
  return <Pill tone={kind === "file" ? "warn" : kind === "dlp" ? "danger" : "neutral"}>{kind.toUpperCase()}</Pill>;
}

function pivotEvidenceLabel(pivot: DeploymentThreatPivot): string {
  if (pivot.kind === "file") return pivot.file?.path || pivot.message || "file event";
  const src = formatOptionalEndpoint(pivot.network?.src_ip, pivot.network?.src_port);
  const dst = formatOptionalEndpoint(pivot.network?.dst_ip, pivot.network?.dst_port);
  return [pivot.network?.direction, src && dst ? `${src} -> ${dst}` : src || dst].filter(Boolean).join(" · ") || pivot.message || "runtime threat";
}

function formatOptionalEndpoint(ip?: string, port?: number): string {
  if (!ip) return "";
  return port ? `${ip}:${port}` : ip;
}

function formatEndpoint(ip?: string, port?: number): string {
  if (!ip) return "-";
  return port ? `${ip}:${port}` : ip;
}

function deploymentPolicyIsStale(policy: NetworkPolicyLifecycle): boolean {
  return policy.candidate_stale || Boolean(policy.approved_candidate_hash && policy.candidate_hash && policy.approved_candidate_hash !== policy.candidate_hash);
}

function deploymentPolicyManifests(policy: NetworkPolicyLifecycle): Record<string, string> {
  const manifests = policy.preview.manifests && Object.keys(policy.preview.manifests).length > 0
    ? policy.preview.manifests
    : { [policy.preview.engine || "cilium"]: policy.preview.yaml };
  return Object.fromEntries(Object.entries(manifests).filter(([, value]) => value));
}

function displayImage(image: DeploymentImageEvidence): string {
  if (image.image_repository && image.image_tag) return `${image.image_repository}:${image.image_tag}`;
  if (image.image_repository) return image.image_repository;
  return image.image_ref || image.image_digest || "image unknown";
}

function sumPackages(evidence: DeploymentPackageEvidence[]): number {
  return evidence.reduce((sum, item) => sum + item.package_count, 0);
}

function statusRank(status: string): number {
  switch ((status || "").toLowerCase()) {
    case "fail":
      return 0;
    case "manual":
      return 1;
    case "exempted":
      return 2;
    case "pass":
      return 3;
    default:
      return 4;
  }
}

function formatDate(value?: string): string {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let next = value;
  let index = 0;
  while (next >= 1024 && index < units.length - 1) {
    next /= 1024;
    index += 1;
  }
  return `${next.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
}

function renderPayload(payload: Record<string, unknown>): string {
  const rendered = JSON.stringify(payload ?? {}, null, 2);
  if (rendered.length <= 10000) return rendered;
  return `${rendered.slice(0, 10000)}\n... truncated for display`;
}
