import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Ban,
  Boxes,
  CheckCircle2,
  ChevronLeft,
  Database,
  Download,
  FileWarning,
  GitBranch,
  GitMerge,
  Network,
  PackageSearch,
  Plus,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  Upload,
} from "lucide-react";
import {
  baselines,
  deployments,
  fileProfiles,
  network,
  quarantine,
  type BaselineMode,
  type DeploymentComplianceEvidence,
  type DeploymentDetail,
  type DeploymentFileProfile,
  type DeploymentFileRisk,
  type DeploymentFinding,
  type DeploymentImageEvidence,
  type DeploymentNetworkFlow,
  type DeploymentPackageEvidence,
  type DeploymentProcessBaseline,
  type DeploymentThreatKind,
  type DeploymentThreatPivot,
  type FileProfileBundle,
  type FileProfileRuleBehavior,
  type NetworkPolicyLifecycle,
  type QuarantineEntry,
  type RuntimeEvent,
  type Violation,
} from "@/api/client";
import { Button } from "@/components/ui/button";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Drawer } from "@/components/ui/drawer";
import { ModePill } from "@/components/ui/status-pill";
import { PageHeader } from "@/components/ui/page";
import { StatCard } from "@/components/ui/stat-card";
import { useCluster } from "@/hooks/useCluster";
import { cn } from "@/lib/cn";

export function DeploymentDetailPage() {
  const { did } = useParams<{ did: string }>();
  const { clusterId, isLoading: clusterLoading } = useCluster();
  const q = useQuery({
    queryKey: ["deployment", did],
    queryFn: () => deployments.get(did!),
    enabled: !!did,
  });

  const detail = q.data;
  const openHigh = (detail?.critical_count ?? 0) + (detail?.high_count ?? 0);
  const complianceOpen = (detail?.compliance_evidence ?? []).filter((item) => ["fail", "manual"].includes(item.effective_status)).length;

  if (clusterLoading || q.isPending) return <p className="text-sm text-muted-foreground">Loading workload...</p>;
  if (q.isError || !detail) return <p className="text-sm text-status-error">Workload not found.</p>;

  return (
    <div className="space-y-4" data-testid="deployment-detail-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        backLink={
          <Link to={`/clusters/${clusterId}/deployments`} className="inline-flex items-center gap-1 hover:text-foreground">
            <ChevronLeft className="h-3.5 w-3.5" aria-hidden />
            Workloads
          </Link>
        }
        title={`${detail.namespace}/${detail.name}`}
        mono
        badges={
          <>
            <Pill tone={detail.risk_score >= 80 ? "danger" : detail.risk_score >= 60 ? "warn" : "neutral"}>risk {detail.risk_score}</Pill>
            <Pill tone={openHigh > 0 ? "warn" : "ok"}>{openHigh} high+</Pill>
            <Pill tone="neutral">{detail.kind}</Pill>
          </>
        }
        description={detail.workload_ids.join(" · ") || "workload identity pending"}
      />

      <section className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6" data-testid="deployment-stats">
        <StatCard label="Findings" value={detail.finding_count} icon={<ShieldAlert className="h-3.5 w-3.5" />} tone={openHigh > 0 ? "high" : "neutral"} />
        <StatCard label="Images" value={detail.images.length} icon={<PackageSearch className="h-3.5 w-3.5" />} />
        <StatCard label="Packages" value={sumPackages(detail.package_evidence)} icon={<Database className="h-3.5 w-3.5" />} />
        <StatCard label="Events" value={detail.runtime_events.length} icon={<Activity className="h-3.5 w-3.5" />} />
        <StatCard label="Flows" value={detail.network_flows.length} icon={<Network className="h-3.5 w-3.5" />} />
        <StatCard label="Compliance" value={complianceOpen} icon={<ShieldCheck className="h-3.5 w-3.5" />} tone={complianceOpen > 0 ? "medium" : "neutral"} />
      </section>

      <div className="space-y-4">
        <WorkloadPosture detail={detail} />
        <DeploymentActionsPanel detail={detail} clusterId={clusterId} />
        <ThreatPivotsPanel pivots={detail.threat_pivots ?? []} />
        <ImageEvidenceTable images={detail.images} clusterId={clusterId} />
        <ImageFileRisksPanel risks={detail.file_risks ?? []} clusterId={clusterId} />
        <FindingsTable findings={detail.findings} clusterId={clusterId} />
        <NetworkFlowsTable flows={detail.network_flows} />
        <ProcessBaselinePanel baseline={detail.process_baseline} deploymentId={detail.id} clusterId={clusterId} />
        <FileProfilePanel profile={detail.file_profile} deploymentId={detail.id} clusterId={clusterId} />
        <div className="grid gap-4 lg:grid-cols-2 lg:items-start">
          <CompliancePanel evidence={detail.compliance_evidence ?? []} />
          <PackageEvidencePanel evidence={detail.package_evidence} />
          <RuntimeEventsPanel events={detail.runtime_events} />
          <ViolationsPanel violations={detail.violations} />
        </div>
      </div>
    </div>
  );
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
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Risk factors</h3>
          <div className="mt-2 flex flex-wrap gap-2">
            {riskFactors.map(([key, value]) => <Pill key={key} tone={Number(value) >= 20 ? "warn" : "neutral"}>{key}: {String(value)}</Pill>)}
            {riskFactors.length === 0 ? <span className="text-xs text-muted-foreground">No positive risk factors.</span> : null}
          </div>
        </div>
        <div>
          <h3 className="text-xs font-semibold uppercase text-muted-foreground">Labels</h3>
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
  const [selected, setSelected] = useState<DeploymentThreatPivot | null>(null);
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
      header: "Type",
      cell: (pivot) => (
        <span data-testid={`deployment-threat-row-${pivot.kind}`}><ThreatKindPill kind={pivot.kind} /></span>
      ),
    },
    {
      id: "signal",
      header: "Signal",
      cell: (pivot) => (
        <>
          <div className="max-w-[360px] truncate text-xs font-medium">{pivot.title}</div>
          <div className="mt-1 font-mono text-[11px] text-muted-foreground">{pivot.workload_id}</div>
        </>
      ),
    },
    {
      id: "verdict",
      header: "Verdict",
      cell: (pivot) => (
        <div className="flex flex-wrap gap-1">
          <SeverityPill severity={pivot.severity} />
          <StatusPill status={pivot.verdict} />
        </div>
      ),
    },
    {
      id: "evidence",
      header: "Evidence",
      cell: (pivot) => pivotEvidenceLabel(pivot),
      className: "text-xs text-muted-foreground",
    },
    {
      id: "at",
      header: "Last Seen",
      cell: (pivot) => formatDate(pivot.at),
      className: "text-xs text-muted-foreground",
    },
  ];

  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="deployment-threat-pivots">
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Runtime threat pivots</h2>
          <p className="mt-1 text-xs text-muted-foreground">File, DLP, and WAF signals for this workload.</p>
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
        onRowClick={(pivot) => setSelected(pivot)}
        showDensityToggle={false}
        className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground" data-testid="deployment-threat-empty">
            No file, DLP, or WAF threat pivots for this workload.
          </div>
        }
      />
      <ThreatPivotDrawer pivot={selected} onClose={() => setSelected(null)} />
    </section>
  );
}

function ThreatPivotDrawer({ pivot, onClose }: { pivot: DeploymentThreatPivot | null; onClose: () => void }) {
  return (
    <Drawer
      open={!!pivot}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      title={pivot?.title ?? "Threat evidence"}
      description={pivot ? `${pivot.kind.toUpperCase()} · ${pivot.verdict} · ${formatDate(pivot.at)}` : undefined}
      width="lg"
    >
      {pivot ? (
        <div className="space-y-4" data-testid="deployment-threat-drawer">
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
              <h3 className="text-xs font-semibold uppercase text-muted-foreground">File evidence</h3>
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
              <h3 className="text-xs font-semibold uppercase text-muted-foreground">{pivot.kind.toUpperCase()} evidence</h3>
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
      ) : null}
    </Drawer>
  );
}

function ImageEvidenceTable({ images, clusterId }: { images: DeploymentImageEvidence[]; clusterId?: string }) {
  const columns: Column<DeploymentImageEvidence>[] = [
    {
      id: "image",
      header: "Image",
      cell: (image) => (
        <>
          {image.image_scan_result_id ? (
            <Link to={`/clusters/${clusterId}/images/${image.image_scan_result_id}`} className="break-all font-mono text-xs font-medium hover:underline">
              {displayImage(image)}
            </Link>
          ) : (
            <span className="break-all font-mono text-xs font-medium">{displayImage(image)}</span>
          )}
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{image.image_digest || image.image_ref_normalized}</div>
        </>
      ),
    },
    {
      id: "scan",
      header: "Scan",
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
      header: "Risk",
      cell: (image) => (
        <div className="flex flex-wrap gap-1">
          <Pill tone={image.critical_count > 0 ? "danger" : "neutral"}>C: {image.critical_count}</Pill>
          <Pill tone={image.high_count > 0 ? "warn" : "neutral"}>H: {image.high_count}</Pill>
          <Pill tone={image.finding_count > 0 ? "warn" : "ok"}>{image.finding_count} total</Pill>
        </div>
      ),
    },
    {
      id: "bundle",
      header: "Bundle",
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
        columns={columns}
        rowKey={(image) => image.image_ref}
        showDensityToggle={false}
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
      header: "Image",
      cell: (risk) => (
        <>
          {risk.image_scan_result_id ? (
            <Link to={`/clusters/${clusterId}/images/${risk.image_scan_result_id}`} className="break-all font-mono text-xs font-medium hover:underline">
              {risk.image_ref || risk.image_digest}
            </Link>
          ) : (
            <span className="break-all font-mono text-xs font-medium">{risk.image_ref || risk.image_digest}</span>
          )}
          <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{risk.image_digest || risk.image_ref_normalized}</div>
        </>
      ),
    },
    {
      id: "risk",
      header: "Risk",
      cell: (risk) => (
        <div className="flex flex-wrap gap-1">
          <StatusPill status={risk.status || "observed"} />
          <Pill tone={risk.file_risk_count > 0 ? "warn" : "ok"}>{risk.file_risk_count} file risks</Pill>
          {risk.truncated ? <Pill tone="warn">truncated</Pill> : null}
        </div>
      ),
    },
    {
      id: "evidence",
      header: "Evidence",
      cell: (risk) => (
        <>
          {risk.findings.slice(0, 2).map((finding) => (
            <div key={`${risk.artifact_id}:${finding.path}`} className="mb-1 last:mb-0">
              <span className="break-all font-mono">{finding.path}</span>
              <span className="ml-2 text-muted-foreground">{finding.risk_types?.join(", ") || finding.reason || ""}</span>
            </div>
          ))}
          {risk.findings.length > 2 ? <div className="text-[11px] text-muted-foreground">{risk.findings.length - 2} additional file risks</div> : null}
        </>
      ),
      className: "text-xs",
    },
    {
      id: "observed",
      header: "Observed",
      cell: (risk) => formatDate(risk.created_at),
      className: "text-xs text-muted-foreground",
    },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card" data-testid="deployment-file-risks">
      <header className="flex items-start justify-between gap-3 border-b border-border px-3 py-2">
        <div>
          <h2 className="text-sm font-semibold">Image file risks</h2>
          <p className="mt-1 text-xs text-muted-foreground">Static filesystem metadata risks from running image artifacts.</p>
        </div>
        <FileWarning className="h-4 w-4 text-muted-foreground" aria-hidden />
      </header>
      <DataTable<DeploymentFileRisk>
        rows={risks}
        columns={fileRiskColumns}
        rowKey={(risk) => risk.artifact_id}
        showDensityToggle={false}
        className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No image file-risk artifacts linked to this workload.</div>
        }
      />
    </section>
  );
}

function FindingsTable({ findings, clusterId }: { findings: DeploymentFinding[]; clusterId?: string }) {
  const columns: Column<DeploymentFinding>[] = [
    {
      id: "finding",
      header: "Finding",
      cell: (finding) => (
        <>
          {finding.external_id ? (
            <Link to={`/cve/${finding.external_id}`} className="font-mono text-xs font-medium hover:underline">{finding.external_id}</Link>
          ) : (
            <Link to={`/clusters/${clusterId}/findings/${finding.id}`} className="font-mono text-xs font-medium hover:underline">{finding.kind}</Link>
          )}
          <div className="mt-1 max-w-[420px] truncate text-xs text-muted-foreground">{finding.title}</div>
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
    {
      id: "severity",
      header: "Severity",
      cell: (finding) => <SeverityPill severity={finding.severity} />,
    },
    {
      id: "risk",
      header: "Risk",
      cell: (finding) => finding.risk_score,
      className: "font-semibold",
    },
  ];
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Workload findings</h2>
        <p className="mt-1 text-xs text-muted-foreground">Direct workload scan findings and deployment-level findings.</p>
      </header>
      <DataTable<DeploymentFinding>
        rows={findings}
        columns={columns}
        rowKey={(finding) => finding.id}
        showDensityToggle={false}
        className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No direct workload findings recorded.</div>
        }
      />
    </section>
  );
}

const networkFlowColumns: Column<DeploymentNetworkFlow>[] = [
  {
    id: "peer",
    header: "Peer",
    cell: (flow) => (
      <>
        <div className="break-all font-mono text-xs">{flow.src}</div>
        <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">to {flow.dst}</div>
      </>
    ),
  },
  {
    id: "protocol",
    header: "Protocol",
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
    header: "Traffic",
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
    header: "Last Seen",
    cell: (flow) => formatDate(flow.last_seen_at),
    className: "text-xs text-muted-foreground",
  },
];

function NetworkFlowsTable({ flows }: { flows: DeploymentNetworkFlow[] }) {
  return (
    <section className="overflow-hidden rounded-lg border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h2 className="text-sm font-semibold">Network flows</h2>
        <p className="mt-1 text-xs text-muted-foreground">Recent observed conversations for this workload.</p>
      </header>
      <DataTable<DeploymentNetworkFlow>
        rows={flows}
        columns={networkFlowColumns}
        rowKey={(flow) => flow.id}
        showDensityToggle={false}
        className="rounded-none border-0"
        emptyState={
          <div className="px-3 py-8 text-center text-xs text-muted-foreground">No network flows recorded for this workload.</div>
        }
      />
    </section>
  );
}

function DeploymentActionsPanel({ detail, clusterId }: { detail: DeploymentDetail; clusterId?: string }) {
  const queryClient = useQueryClient();
  const workload = deploymentWorkloadID(detail);
  const actionClusterId = detail.cluster_id || clusterId || "";
  const policy = detail.network_policy ?? null;
  const activeQuarantine = detail.quarantine ?? null;
  const [demoteReason, setDemoteReason] = useState("");
  const [rollbackReason, setRollbackReason] = useState("");
  const [quarantineReason, setQuarantineReason] = useState("");
  const [quarantineHours, setQuarantineHours] = useState("24");
  const [liftReason, setLiftReason] = useState("");
  const [actionError, setActionError] = useState("");
  const [reviewOpen, setReviewOpen] = useState(false);
  const [manifestFlavor, setManifestFlavor] = useState("cilium");

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["deployment", detail.id] });
    void queryClient.invalidateQueries({ queryKey: ["network-policy-lifecycle"] });
    void queryClient.invalidateQueries({ queryKey: ["network-map"] });
  };

  const policyAction = useMutation({
    mutationFn: ({ action, reason, candidateHash }: { action: "approve" | "apply" | "demote"; reason?: string; candidateHash?: string }) =>
      network.policyAction(workload, action, {
        reason,
        candidate_hash: candidateHash,
        idempotency_key: deploymentActionIdempotencyKey(workload, action),
      }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setActionError("");
      setDemoteReason("");
      refresh();
    },
    onError: (err) => {
      setActionError(actionErrorMessage(err));
      refresh();
    },
  });

  const rollback = useMutation({
    mutationFn: ({ rollbackRef, reason }: { rollbackRef: string; reason?: string }) =>
      network.rollbackPolicy(workload, {
        rollback_ref: rollbackRef,
        reason,
        idempotency_key: deploymentActionIdempotencyKey(workload, "rollback"),
      }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setActionError("");
      setRollbackReason("");
      refresh();
    },
    onError: (err) => {
      setActionError(actionErrorMessage(err));
      refresh();
    },
  });

  const createQuarantine = useMutation({
    mutationFn: () => quarantine.create({
      cluster_id: actionClusterId,
      scope: "workload",
      match_key: workload,
      reason: quarantineReason.trim(),
      expires_in_hours: positiveInt(quarantineHours),
    }),
    onSuccess: () => {
      setActionError("");
      setQuarantineReason("");
      refresh();
    },
    onError: (err) => setActionError(actionErrorMessage(err)),
  });
  const liftQuarantine = useMutation({
    mutationFn: (entry: QuarantineEntry) => quarantine.lift(entry.id, { reason: liftReason.trim() }),
    onSuccess: () => {
      setLiftReason("");
      refresh();
    },
    onError: (err) => setActionError(actionErrorMessage(err)),
  });

  const isStale = policy ? deploymentPolicyIsStale(policy) : false;
  const canApprove = Boolean(policy?.target_mode) && (policy?.approval_status === "pending" || isStale);
  const canApply = Boolean(policy?.target_mode) && policy?.approval_status === "approved" && !isStale;
  const canDemote = policy !== null && policy.current_mode !== "discover";
  const canRollback = Boolean(policy?.rollback_available && policy.rollback_ref);
  const applyStatuses = policy?.apply_statuses ?? [];
  const latestApplyStatus = [...applyStatuses].sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)))[0];
  const manifests = policy ? deploymentPolicyManifests(policy) : {};
  const manifestFlavors = Object.keys(manifests);
  const activeManifestFlavor = manifests[manifestFlavor] ? manifestFlavor : manifestFlavors[0] ?? "cilium";
  const activeManifest = manifests[activeManifestFlavor] ?? "";
  const actionState = !policy
    ? "No retained flow candidate"
    : canApprove
      ? `Awaiting approval for ${policy.target_mode}`
      : isStale
        ? "Review updated candidate"
        : canApply
          ? `Approved, ready to apply ${policy.target_mode}`
          : canRollback
            ? `Rollback available for ${policy.current_mode}`
            : policy.approval_status;

  return (
    <section className="rounded-lg border border-border bg-card p-4" data-testid="deployment-action-controls">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Action controls</h2>
          <p className="mt-1 break-all font-mono text-xs text-muted-foreground">{workload}</p>
        </div>
        <ShieldAlert className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>

      {actionError ? (
        <div className="mt-3 rounded-md border border-border p-2 text-xs text-status-error" data-testid="deployment-policy-error">
          {actionError}
        </div>
      ) : null}

      <div className="mt-4 space-y-3" data-testid="deployment-policy-actions">
        <div className="flex flex-wrap items-center gap-2">
          <Pill tone="neutral">network policy</Pill>
          {policy ? <ModePill mode={policy.current_mode} /> : <Pill tone="neutral">no candidate</Pill>}
          {policy?.target_mode ? <Pill tone="warn">target {policy.target_mode}</Pill> : null}
          {isStale ? <Pill tone="warn">candidate changed</Pill> : null}
          {policy?.rollback_available ? <Pill tone="neutral">rollback ready</Pill> : null}
        </div>
        {isStale || actionError ? (
          <div className="rounded-md border border-[color:var(--color-status-warning)]/40 bg-muted p-2 text-xs text-muted-foreground" data-testid="deployment-policy-stale-warning">
            {actionError || policy?.stale_reason || "Observed traffic changed since approval. Review the updated candidate before applying."}
          </div>
        ) : null}
        {policy ? (
          <>
            <dl className="grid gap-2 text-xs">
              <div data-testid="deployment-policy-current-mode">
                <Field label="Current mode" value={<ModePill mode={policy.current_mode} />} />
              </div>
              <div data-testid="deployment-policy-target-mode">
                <Field label="Target mode" value={policy.target_mode || "-"} />
              </div>
              <Field label="Approval" value={policy.approval_status} />
              <div data-testid="deployment-policy-candidate-hash">
                <Field label="Candidate" value={policy.candidate_hash ? policy.candidate_hash.slice(0, 12) : "pending"} />
              </div>
              <Field label="Flows" value={`${policy.summary.total_flows}`} />
              <Field label="Alerts" value={`${policy.summary.out_of_policy_alerts}`} />
            </dl>
            <div className="rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="deployment-policy-action-state">
              <div>{actionState}</div>
              <div className="mt-1 font-mono">
                {policy.approved_candidate_hash ? `approved ${policy.approved_candidate_hash.slice(0, 12)}` : "approval pending"}
              </div>
            </div>
            <div className="rounded-md border border-border p-2 text-xs text-muted-foreground" data-testid="deployment-policy-apply-status">
              {latestApplyStatus ? (
                <>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-foreground">Live applier</span>
                    <Pill tone="neutral">{latestApplyStatus.flavor}</Pill>
                    <span className={latestApplyStatus.status === "ok" ? "text-status-ok" : "text-status-error"}>
                      {latestApplyStatus.last_action} {latestApplyStatus.status}
                    </span>
                  </div>
                  {latestApplyStatus.resource_ref ? <div className="mt-1 break-all font-mono">{latestApplyStatus.resource_ref}</div> : null}
                  {latestApplyStatus.error ? <div className="mt-1 text-status-error">{latestApplyStatus.error}</div> : null}
                </>
              ) : (
                <span>Live applier has not reported for this policy.</span>
              )}
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                data-testid="deployment-policy-review-open"
                onClick={() => setReviewOpen(true)}
              >
                <GitBranch className="h-3.5 w-3.5" aria-hidden /> Review
              </Button>
              <Button size="sm" variant="ghost" asChild>
                <Link to={`/network?workload=${encodeURIComponent(workload)}`}>Topology</Link>
              </Button>
              {canApprove ? (
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="deployment-policy-approve"
                  disabled={policyAction.isPending}
                  onClick={() => policyAction.mutate({ action: "approve", candidateHash: policy.candidate_hash })}
                >
                  <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> Approve
                </Button>
              ) : null}
              {canApply ? (
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="deployment-policy-apply"
                  disabled={policyAction.isPending}
                  onClick={() => policyAction.mutate({ action: "apply", candidateHash: policy.candidate_hash })}
                >
                  <GitBranch className="h-3.5 w-3.5" aria-hidden /> Apply
                </Button>
              ) : null}
            </div>
            {canDemote ? (
              <div className="space-y-2">
                <input
                  data-testid="deployment-policy-demote-reason"
                  value={demoteReason}
                  onChange={(e) => setDemoteReason(e.target.value)}
                  placeholder="Demotion reason"
                  className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                />
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="deployment-policy-demote"
                  disabled={policyAction.isPending || demoteReason.trim() === ""}
                  onClick={() => policyAction.mutate({ action: "demote", reason: demoteReason })}
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Demote
                </Button>
              </div>
            ) : null}
            {canRollback && policy.rollback_ref ? (
              <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-policy-rollback-card">
                <Field label="Rollback ref" value={policy.rollback_ref} />
                <input
                  data-testid="deployment-policy-rollback-reason"
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  placeholder="Rollback reason"
                  className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
                />
                <Button
                  size="sm"
                  variant="outline"
                  data-testid="deployment-policy-rollback"
                  disabled={rollback.isPending || rollbackReason.trim() === ""}
                  onClick={() => rollback.mutate({ rollbackRef: policy.rollback_ref ?? "", reason: rollbackReason })}
                >
                  <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Roll back
                </Button>
              </div>
            ) : null}
            <Drawer
              open={reviewOpen}
              onOpenChange={setReviewOpen}
              title="Network policy candidate"
              description={workload}
              width="xl"
              className="z-[60]"
            >
              <div className="space-y-4" data-testid="deployment-policy-review-drawer">
                {manifestFlavors.length > 1 ? (
                  <div className="flex flex-wrap gap-1 rounded-md border border-border p-1" data-testid="deployment-policy-manifest-tabs">
                    {manifestFlavors.map((flavor) => (
                      <button
                        key={flavor}
                        type="button"
                        className={cn(
                          "rounded px-2 py-1 text-xs",
                          activeManifestFlavor === flavor ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground",
                        )}
                        onClick={() => setManifestFlavor(flavor)}
                      >
                        {flavor}
                      </button>
                    ))}
                  </div>
                ) : null}
                <div>
                  <h3 className="text-sm font-medium">Manifest</h3>
                  <pre className="mt-2 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs" data-testid="deployment-policy-preview">
                    {activeManifest || "No generated manifest available."}
                  </pre>
                </div>
                <div className="rounded-md border border-border p-3" data-testid="deployment-policy-diff">
                  <div className="text-xs font-medium">Diff</div>
                  <p className="mt-1 text-xs text-muted-foreground">{policy.diff.summary}</p>
                  <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                    {[...policy.diff.added, ...policy.diff.changed, ...policy.diff.removed].map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </div>
                <div className="rounded-md border border-border p-3" data-testid="deployment-policy-audit-trail">
                  <div className="text-xs font-medium">Audit trail</div>
                  <ul className="mt-2 max-h-36 space-y-1 overflow-auto text-xs text-muted-foreground">
                    {policy.audit_trail.slice(-8).map((event) => (
                      <li key={`${event.at}-${event.action}-${event.actor}-${event.action_id ?? ""}`}>
                        <span className="font-mono">{event.action}</span> · {event.message}
                      </li>
                    ))}
                    {policy.audit_trail.length === 0 ? <li>No audit events recorded.</li> : null}
                  </ul>
                </div>
              </div>
            </Drawer>
          </>
        ) : (
          <p className="text-xs text-muted-foreground" data-testid="deployment-policy-empty">
            No network policy candidate is available for this workload in the retained traffic window.
          </p>
        )}
      </div>

      <div className="mt-4 space-y-3 border-t border-border pt-3" data-testid="deployment-quarantine-actions">
        <div className="flex flex-wrap items-center gap-2">
          <Pill tone={activeQuarantine ? "danger" : "neutral"}>{activeQuarantine ? "quarantined" : "not quarantined"}</Pill>
          {activeQuarantine?.expires_at ? <Pill tone="warn">expires {formatDate(activeQuarantine.expires_at)}</Pill> : null}
        </div>
        {activeQuarantine ? (
          <div className="space-y-2" data-testid="deployment-quarantine-active">
            <Field label="Reason" value={activeQuarantine.reason} />
            <input
              data-testid="deployment-quarantine-lift-reason"
              value={liftReason}
              onChange={(e) => setLiftReason(e.target.value)}
              placeholder="Lift reason"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            />
            <Button
              size="sm"
              variant="outline"
              data-testid="deployment-quarantine-lift"
              disabled={liftQuarantine.isPending || liftReason.trim() === ""}
              onClick={() => liftQuarantine.mutate(activeQuarantine)}
            >
              <RotateCcw className="h-3.5 w-3.5" aria-hidden /> Lift quarantine
            </Button>
          </div>
        ) : (
          <div className="space-y-2">
            <textarea
              data-testid="deployment-quarantine-reason"
              value={quarantineReason}
              onChange={(e) => setQuarantineReason(e.target.value)}
              placeholder="Quarantine reason"
              className="min-h-20 w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            />
            <div className="flex flex-wrap items-center gap-2">
              <input
                data-testid="deployment-quarantine-hours"
                value={quarantineHours}
                onChange={(e) => setQuarantineHours(e.target.value)}
                inputMode="numeric"
                className="h-7 w-20 rounded-md border border-border bg-background px-2 text-xs"
                aria-label="Quarantine duration in hours"
              />
              <Button
                size="sm"
                variant="destructive"
                data-testid="deployment-quarantine-create"
                disabled={createQuarantine.isPending || !actionClusterId || quarantineReason.trim() === ""}
                onClick={() => createQuarantine.mutate()}
              >
                <Ban className="h-3.5 w-3.5" aria-hidden /> Quarantine
              </Button>
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function ProcessBaselinePanel({ baseline, deploymentId, clusterId }: { baseline?: DeploymentProcessBaseline | null; deploymentId: string; clusterId?: string }) {
  const queryClient = useQueryClient();
  const processes = baseline?.processes ?? [];
  const workloadID = baseline?.control_workload_id || baseline?.workload_id || "";
  const actionClusterId = baseline?.cluster_id || clusterId || "";
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const setMode = useMutation({
    mutationFn: (mode: BaselineMode) => baselines.setMode(workloadID, { mode, reason: reason.trim() }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setReason("");
      setError("");
      void queryClient.invalidateQueries({ queryKey: ["deployment", deploymentId] });
      void queryClient.invalidateQueries({ queryKey: ["baseline", workloadID, actionClusterId] });
      void queryClient.invalidateQueries({ queryKey: ["baselines", actionClusterId] });
    },
    onError: (err) => setError(actionErrorMessage(err)),
  });
  const promoteMode = baseline ? nextBaselinePromoteMode(baseline.mode) : null;
  const rollbackMode = baseline ? nextBaselineRollbackMode(baseline.mode) : null;
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Process baseline</h2>
          <p className="mt-1 text-xs text-muted-foreground">Observed exec profile for this workload.</p>
        </div>
        <GitMerge className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      {baseline ? (
        <div className="mt-3 space-y-3" data-testid="deployment-process-baseline">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <Field label="Mode" value={<ModePill mode={baseline.mode} />} />
            <Field label="Workload" value={baseline.workload_id} />
            <Field label="Control" value={workloadID} />
            <Field label="Processes" value={`${baseline.learned_processes_count}`} />
            <Field label="Alerts 24h" value={`${baseline.monitored_alerts_24h}`} />
            <Field label="Blocks 24h" value={`${baseline.enforced_blocks_24h}`} />
            <Field label="Last new" value={formatDate(baseline.last_new_process_at)} />
          </dl>
          <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-process-baseline-actions">
            <input
              data-testid="deployment-process-baseline-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Baseline transition reason"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            />
            {error ? <p className="text-xs text-status-error" data-testid="deployment-process-baseline-error">{error}</p> : null}
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                data-testid="deployment-process-baseline-rollback"
                disabled={!rollbackMode || setMode.isPending || reason.trim() === ""}
                onClick={() => rollbackMode && setMode.mutate(rollbackMode)}
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                {rollbackMode ? `Roll back to ${rollbackMode}` : "Roll back"}
              </Button>
              <Button
                size="sm"
                variant="primary"
                data-testid="deployment-process-baseline-promote"
                disabled={!promoteMode || setMode.isPending || reason.trim() === ""}
                onClick={() => promoteMode && setMode.mutate(promoteMode)}
              >
                {promoteMode ? `Promote to ${promoteMode}` : baseline.mode === "enforce" ? "Already enforcing" : "Promote"}
                {promoteMode ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : null}
              </Button>
            </div>
          </div>
          {baseline.transitions && baseline.transitions.length > 0 ? (
            <ol className="space-y-2" data-testid="deployment-process-baseline-transitions">
              {baseline.transitions.slice(-5).map((transition) => (
                <li key={`${transition.at}-${transition.from}-${transition.to}`} className="rounded-md border border-border p-2 text-xs">
                  <div className="font-medium">{transition.from} to {transition.to}</div>
                  <div className="mt-1 text-muted-foreground">{transition.reason}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{formatDate(transition.at)}</div>
                </li>
              ))}
            </ol>
          ) : null}
          <div className="space-y-2">
            {processes.slice(0, 5).map((process) => (
              <div key={`${process.name}:${process.path}:${process.args.join(" ")}`} className="rounded-md border border-border p-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-mono text-xs font-medium">{process.name}</div>
                  <Pill tone="neutral">{process.observed_count}x</Pill>
                </div>
                <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{process.path || process.args.join(" ") || "path unavailable"}</div>
                <div className="mt-1 text-[11px] text-muted-foreground">last seen {formatDate(process.last_seen)}</div>
              </div>
            ))}
            {processes.length > 5 ? <p className="text-[11px] text-muted-foreground">{processes.length - 5} additional processes observed.</p> : null}
            {processes.length === 0 ? <p className="text-xs text-muted-foreground">No process exec events reported yet.</p> : null}
          </div>
        </div>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground" data-testid="deployment-process-baseline">No process baseline evidence recorded yet.</p>
      )}
    </section>
  );
}

function FileProfilePanel({ profile, deploymentId, clusterId }: { profile?: DeploymentFileProfile | null; deploymentId: string; clusterId?: string }) {
  const queryClient = useQueryClient();
  const files = profile?.files ?? [];
  const rules = profile?.rules ?? [];
  const exceptions = profile?.exceptions ?? [];
  const watches = profile?.watched_files ?? [];
  const workloadID = profile?.control_workload_id || profile?.workload_id || "";
  const actionClusterId = profile?.cluster_id || clusterId || "";
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");
  const [ruleFilter, setRuleFilter] = useState("");
  const [ruleRecursive, setRuleRecursive] = useState(false);
  const [ruleBehavior, setRuleBehavior] = useState<FileProfileRuleBehavior>("monitor_change");
  const [ruleApplications, setRuleApplications] = useState("");
  const [ruleDescription, setRuleDescription] = useState("");
  const [ruleReason, setRuleReason] = useState("");
  const [ruleError, setRuleError] = useState("");
  const [exceptionRuleID, setExceptionRuleID] = useState("");
  const [exceptionFilter, setExceptionFilter] = useState("");
  const [exceptionApplications, setExceptionApplications] = useState("");
  const [exceptionDescription, setExceptionDescription] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [exceptionError, setExceptionError] = useState("");
  const [bundleText, setBundleText] = useState("");
  const [bundleReason, setBundleReason] = useState("");
  const [bundleError, setBundleError] = useState("");
  const setMode = useMutation({
    mutationFn: (mode: BaselineMode) => fileProfiles.setMode(workloadID, { mode, reason: reason.trim() }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setReason("");
      setError("");
      void queryClient.invalidateQueries({ queryKey: ["deployment", deploymentId] });
      void queryClient.invalidateQueries({ queryKey: ["file-profile", workloadID, actionClusterId] });
      void queryClient.invalidateQueries({ queryKey: ["file-profiles", actionClusterId] });
    },
    onError: (err) => setError(actionErrorMessage(err)),
  });
  const refreshRules = () => {
    void queryClient.invalidateQueries({ queryKey: ["deployment", deploymentId] });
    void queryClient.invalidateQueries({ queryKey: ["file-profile", workloadID, actionClusterId] });
    void queryClient.invalidateQueries({ queryKey: ["file-profiles", actionClusterId] });
  };
  const createRule = useMutation({
    mutationFn: () =>
      fileProfiles.createRule(
        workloadID,
        {
          filter: ruleFilter.trim(),
          recursive: ruleRecursive,
          behavior: ruleBehavior,
          applications: splitCSV(ruleApplications),
          description: ruleDescription.trim(),
          reason: ruleReason.trim(),
          enabled: true,
        },
        { cluster_id: actionClusterId || undefined },
      ),
    onSuccess: () => {
      setRuleFilter("");
      setRuleRecursive(false);
      setRuleBehavior("monitor_change");
      setRuleApplications("");
      setRuleDescription("");
      setRuleReason("");
      setRuleError("");
      refreshRules();
    },
    onError: (err) => setRuleError(actionErrorMessage(err)),
  });
  const deleteRule = useMutation({
    mutationFn: (ruleId: string) => fileProfiles.deleteRule(workloadID, ruleId, { reason: ruleReason.trim() }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setRuleReason("");
      setRuleError("");
      refreshRules();
    },
    onError: (err) => setRuleError(actionErrorMessage(err)),
  });
  const createException = useMutation({
    mutationFn: () =>
      fileProfiles.createException(
        workloadID,
        {
          rule_id: exceptionRuleID || undefined,
          filter: exceptionFilter.trim(),
          applications: splitCSV(exceptionApplications),
          description: exceptionDescription.trim(),
          reason: exceptionReason.trim(),
          enabled: true,
        },
        { cluster_id: actionClusterId || undefined },
      ),
    onSuccess: () => {
      setExceptionRuleID("");
      setExceptionFilter("");
      setExceptionApplications("");
      setExceptionDescription("");
      setExceptionReason("");
      setExceptionError("");
      refreshRules();
    },
    onError: (err) => setExceptionError(actionErrorMessage(err)),
  });
  const deleteException = useMutation({
    mutationFn: (exceptionId: string) =>
      fileProfiles.deleteException(workloadID, exceptionId, { reason: exceptionReason.trim() }, { cluster_id: actionClusterId || undefined }),
    onSuccess: () => {
      setExceptionReason("");
      setExceptionError("");
      refreshRules();
    },
    onError: (err) => setExceptionError(actionErrorMessage(err)),
  });
  const exportBundle = useMutation({
    mutationFn: () => fileProfiles.exportBundle(workloadID, { cluster_id: actionClusterId || undefined }),
    onSuccess: (bundle) => {
      setBundleText(JSON.stringify(bundle, null, 2));
      setBundleError("");
    },
    onError: (err) => setBundleError(actionErrorMessage(err)),
  });
  const importBundle = useMutation({
    mutationFn: () => {
      let bundle: FileProfileBundle;
      try {
        bundle = JSON.parse(bundleText) as FileProfileBundle;
      } catch {
        throw new Error("Bundle JSON is invalid");
      }
      return fileProfiles.importBundle(
        workloadID,
        { bundle, reason: bundleReason.trim(), replace: true },
        { cluster_id: actionClusterId || undefined },
      );
    },
    onSuccess: () => {
      setBundleReason("");
      setBundleError("");
      refreshRules();
    },
    onError: (err) => setBundleError(actionErrorMessage(err)),
  });
  const promoteMode = profile ? nextBaselinePromoteMode(profile.mode) : null;
  const rollbackMode = profile ? nextBaselineRollbackMode(profile.mode) : null;
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">File monitor</h2>
          <p className="mt-1 text-xs text-muted-foreground">Observed file access profile for this workload.</p>
        </div>
        <FileWarning className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      {profile ? (
        <div className="mt-3 space-y-3" data-testid="deployment-file-profile">
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            <Field label="Mode" value={<ModePill mode={profile.mode} />} />
            <Field label="Workload" value={profile.workload_id} />
            <Field label="Control" value={workloadID} />
            <Field label="Paths" value={`${profile.learned_paths_count}`} />
	            <Field label="Sensitive" value={`${profile.sensitive_path_count}`} />
	            <Field label="Rules" value={`${profile.rule_count ?? rules.length}`} />
	            <Field label="Exceptions" value={`${exceptions.length}`} />
	            <Field label="Watches" value={`${profile.watched_file_count ?? watches.length}`} />
	            <Field label="Alerts 24h" value={`${profile.monitored_alerts_24h}`} />
	            <Field label="Blocks 24h" value={`${profile.enforced_blocks_24h}`} />
            <Field label="Last new" value={formatDate(profile.last_new_path_at)} />
          </dl>
          <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-file-profile-actions">
            <input
              data-testid="deployment-file-profile-reason"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="File profile transition reason"
              className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
            />
            {error ? <p className="text-xs text-status-error" data-testid="deployment-file-profile-error">{error}</p> : null}
            <div className="flex flex-wrap gap-2">
              <Button
                size="sm"
                variant="outline"
                data-testid="deployment-file-profile-rollback"
                disabled={!rollbackMode || setMode.isPending || reason.trim() === ""}
                onClick={() => rollbackMode && setMode.mutate(rollbackMode)}
              >
                <RotateCcw className="h-3.5 w-3.5" aria-hidden />
                {rollbackMode ? `Roll back to ${rollbackMode}` : "Roll back"}
              </Button>
              <Button
                size="sm"
                variant="primary"
                data-testid="deployment-file-profile-promote"
                disabled={!promoteMode || setMode.isPending || reason.trim() === ""}
                onClick={() => promoteMode && setMode.mutate(promoteMode)}
              >
                {promoteMode ? `Promote to ${promoteMode}` : profile.mode === "enforce" ? "Already enforcing" : "Promote"}
                {promoteMode ? <CheckCircle2 className="h-3.5 w-3.5" aria-hidden /> : null}
              </Button>
            </div>
          </div>
          <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-file-profile-rule-form">
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_140px]">
              <input
                data-testid="deployment-file-profile-rule-filter"
                value={ruleFilter}
                onChange={(e) => setRuleFilter(e.target.value)}
                placeholder="/path/to/watch or /path/*"
                className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-xs"
              />
              <select
                data-testid="deployment-file-profile-rule-behavior"
                value={ruleBehavior}
                onChange={(e) => setRuleBehavior(e.target.value as FileProfileRuleBehavior)}
                className="h-8 rounded-md border border-border bg-background px-2 text-xs"
              >
                <option value="monitor_change">Monitor</option>
                <option value="block_access">Block</option>
              </select>
            </div>
            <div className="grid gap-2 sm:grid-cols-2">
              <input
                data-testid="deployment-file-profile-rule-apps"
                value={ruleApplications}
                onChange={(e) => setRuleApplications(e.target.value)}
                placeholder="apps, comma separated"
                className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              />
              <input
                data-testid="deployment-file-profile-rule-description"
                value={ruleDescription}
                onChange={(e) => setRuleDescription(e.target.value)}
                placeholder="description"
                className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              />
            </div>
            <label className="flex items-center gap-2 text-xs text-muted-foreground">
              <input
                data-testid="deployment-file-profile-rule-recursive"
                type="checkbox"
                checked={ruleRecursive}
                onChange={(e) => setRuleRecursive(e.target.checked)}
                className="h-3.5 w-3.5"
              />
              Recursive match
            </label>
            <div className="flex flex-wrap gap-2">
              <input
                data-testid="deployment-file-profile-rule-reason"
                value={ruleReason}
                onChange={(e) => setRuleReason(e.target.value)}
                placeholder="Rule change reason"
                className="min-w-0 flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
              />
              <Button
                size="sm"
                variant="primary"
                data-testid="deployment-file-profile-rule-add"
                disabled={createRule.isPending || !workloadID || ruleFilter.trim() === "" || ruleReason.trim() === ""}
                onClick={() => createRule.mutate()}
              >
                <Plus className="h-3.5 w-3.5" aria-hidden />
                Add rule
              </Button>
            </div>
            {ruleError ? <p className="text-xs text-status-error" data-testid="deployment-file-profile-rule-error">{ruleError}</p> : null}
          </div>
          <div className="space-y-2" data-testid="deployment-file-profile-rules">
            {rules.map((rule) => (
              <div key={rule.id} className="rounded-md border border-border p-2" data-testid="deployment-file-profile-rule-row">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="break-all font-mono text-xs font-medium">{rule.filter}</div>
                  <div className="flex flex-wrap items-center gap-1">
                    <Pill tone={rule.behavior === "block_access" ? "warn" : "neutral"}>{displayFileRuleBehavior(rule.behavior)}</Pill>
                    {rule.recursive ? <Pill tone="neutral">recursive</Pill> : null}
                    <Button
                      size="sm"
                      variant="ghost"
                      data-testid="deployment-file-profile-rule-delete"
                      disabled={deleteRule.isPending || ruleReason.trim() === ""}
                      onClick={() => deleteRule.mutate(rule.id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" aria-hidden />
                    </Button>
                  </div>
                </div>
                <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
                  path {rule.path}{rule.regex ? ` / ${rule.regex}` : ""}
                </div>
                {rule.applications.length > 0 ? <div className="mt-1 text-[11px] text-muted-foreground">apps {rule.applications.join(", ")}</div> : null}
                {rule.description ? <div className="mt-1 text-[11px] text-muted-foreground">{rule.description}</div> : null}
              </div>
            ))}
	            {rules.length === 0 ? <p className="text-xs text-muted-foreground" data-testid="deployment-file-profile-rules-empty">No file monitor rules defined yet.</p> : null}
	          </div>
	          <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-file-profile-exception-form">
	            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(160px,220px)]">
	              <input
	                data-testid="deployment-file-profile-exception-filter"
	                value={exceptionFilter}
	                onChange={(e) => setExceptionFilter(e.target.value)}
	                placeholder="/path/to/allow or /path/*"
	                className="w-full rounded-md border border-border bg-background px-2 py-1.5 font-mono text-xs"
	              />
	              <select
	                data-testid="deployment-file-profile-exception-rule"
	                value={exceptionRuleID}
	                onChange={(e) => setExceptionRuleID(e.target.value)}
	                className="h-8 rounded-md border border-border bg-background px-2 text-xs"
	              >
	                <option value="">Workload-wide</option>
	                {rules.map((rule) => (
	                  <option key={rule.id} value={rule.id}>{rule.filter}</option>
	                ))}
	              </select>
	            </div>
	            <div className="grid gap-2 sm:grid-cols-2">
	              <input
	                data-testid="deployment-file-profile-exception-apps"
	                value={exceptionApplications}
	                onChange={(e) => setExceptionApplications(e.target.value)}
	                placeholder="apps, comma separated"
	                className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
	              />
	              <input
	                data-testid="deployment-file-profile-exception-description"
	                value={exceptionDescription}
	                onChange={(e) => setExceptionDescription(e.target.value)}
	                placeholder="description"
	                className="w-full rounded-md border border-border bg-background px-2 py-1.5 text-xs"
	              />
	            </div>
	            <div className="flex flex-wrap gap-2">
	              <input
	                data-testid="deployment-file-profile-exception-reason"
	                value={exceptionReason}
	                onChange={(e) => setExceptionReason(e.target.value)}
	                placeholder="Exception change reason"
	                className="min-w-0 flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
	              />
	              <Button
	                size="sm"
	                variant="primary"
	                data-testid="deployment-file-profile-exception-add"
	                disabled={createException.isPending || !workloadID || exceptionFilter.trim() === "" || exceptionReason.trim() === ""}
	                onClick={() => createException.mutate()}
	              >
	                <Plus className="h-3.5 w-3.5" aria-hidden />
	                Add exception
	              </Button>
	            </div>
	            {exceptionError ? <p className="text-xs text-status-error" data-testid="deployment-file-profile-exception-error">{exceptionError}</p> : null}
	          </div>
	          <div className="space-y-2" data-testid="deployment-file-profile-exceptions">
	            {exceptions.map((exception) => (
	              <div key={exception.id} className="rounded-md border border-border p-2" data-testid="deployment-file-profile-exception-row">
	                <div className="flex flex-wrap items-center justify-between gap-2">
	                  <div className="break-all font-mono text-xs font-medium">{exception.filter}</div>
	                  <div className="flex flex-wrap items-center gap-1">
	                    <Pill tone={exception.enabled ? "ok" : "neutral"}>{exception.enabled ? "enabled" : "disabled"}</Pill>
	                    {exception.rule_id ? <Pill tone="neutral">rule scoped</Pill> : <Pill tone="neutral">workload</Pill>}
	                    <Button
	                      size="sm"
	                      variant="ghost"
	                      data-testid="deployment-file-profile-exception-delete"
	                      disabled={deleteException.isPending || exceptionReason.trim() === ""}
	                      onClick={() => deleteException.mutate(exception.id)}
	                    >
	                      <Trash2 className="h-3.5 w-3.5" aria-hidden />
	                    </Button>
	                  </div>
	                </div>
	                <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">
	                  path {exception.path}{exception.regex ? ` / ${exception.regex}` : ""}
	                </div>
	                {exception.applications.length > 0 ? <div className="mt-1 text-[11px] text-muted-foreground">apps {exception.applications.join(", ")}</div> : null}
	                {exception.description ? <div className="mt-1 text-[11px] text-muted-foreground">{exception.description}</div> : null}
	                {exception.expires_at ? <div className="mt-1 text-[11px] text-muted-foreground">expires {formatDate(exception.expires_at)}</div> : null}
	              </div>
	            ))}
	            {exceptions.length === 0 ? <p className="text-xs text-muted-foreground" data-testid="deployment-file-profile-exceptions-empty">No file monitor exceptions defined yet.</p> : null}
	          </div>
	          <div className="space-y-2 rounded-md border border-border p-3" data-testid="deployment-file-profile-bundle">
	            <div className="flex flex-wrap gap-2">
	              <Button
	                size="sm"
	                variant="outline"
	                disabled={exportBundle.isPending || !workloadID}
	                onClick={() => exportBundle.mutate()}
	              >
	                <Download className="h-3.5 w-3.5" aria-hidden />
	                Export bundle
	              </Button>
	              <input
	                data-testid="deployment-file-profile-bundle-reason"
	                value={bundleReason}
	                onChange={(e) => setBundleReason(e.target.value)}
	                placeholder="Import reason"
	                className="min-w-0 flex-1 rounded-md border border-border bg-background px-2 py-1.5 text-xs"
	              />
	              <Button
	                size="sm"
	                variant="primary"
	                disabled={importBundle.isPending || !workloadID || bundleText.trim() === "" || bundleReason.trim() === ""}
	                onClick={() => importBundle.mutate()}
	              >
	                <Upload className="h-3.5 w-3.5" aria-hidden />
	                Import
	              </Button>
	            </div>
	            <textarea
	              data-testid="deployment-file-profile-bundle-json"
	              value={bundleText}
	              onChange={(e) => setBundleText(e.target.value)}
	              rows={5}
	              spellCheck={false}
	              placeholder="File profile bundle JSON"
	              className="w-full rounded-md border border-border bg-background p-2 font-mono text-xs"
	            />
	            {bundleError ? <p className="text-xs text-status-error" data-testid="deployment-file-profile-bundle-error">{bundleError}</p> : null}
	          </div>
	          <div className="space-y-2" data-testid="deployment-file-profile-watches">
            {watches.slice(0, 5).map((watch) => (
              <div key={`${watch.node}:${watch.rule_id}`} className="rounded-md border border-border p-2" data-testid="deployment-file-profile-watch-row">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="break-all font-mono text-xs font-medium">{watch.filter}</div>
                  <div className="flex flex-wrap gap-1">
                    <Pill tone={watch.enforcement_state === "unsupported" ? "warn" : watch.protect ? "ok" : "neutral"}>
                      {watch.enforcement_state}
                    </Pill>
                    {watch.desired_protect ? <Pill tone="warn">desired protect</Pill> : null}
                    <Pill tone="neutral">{watch.files_count} file{watch.files_count === 1 ? "" : "s"}</Pill>
                  </div>
                </div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                  <span>{watch.node}</span>
                  <span>{watch.profile_mode}</span>
                  <span>synced {formatDate(watch.observed_at)}</span>
                </div>
                {watch.files.length > 0 ? (
                  <div className="mt-2 space-y-1">
                    {watch.files.slice(0, 3).map((file) => (
                      <div key={`${watch.rule_id}:${file.container_id ?? ""}:${file.path}`} className="break-all font-mono text-[11px] text-muted-foreground">
                        {file.path}
                      </div>
                    ))}
                    {watch.files.length > 3 ? <div className="text-[11px] text-muted-foreground">{watch.files.length - 3} additional files</div> : null}
                  </div>
                ) : null}
              </div>
            ))}
            {watches.length > 5 ? <p className="text-[11px] text-muted-foreground">{watches.length - 5} additional watched rule snapshots.</p> : null}
            {watches.length === 0 ? <p className="text-xs text-muted-foreground" data-testid="deployment-file-profile-watches-empty">No synced watched files reported yet.</p> : null}
          </div>
          {profile.transitions && profile.transitions.length > 0 ? (
            <ol className="space-y-2" data-testid="deployment-file-profile-transitions">
              {profile.transitions.slice(-5).map((transition) => (
                <li key={`${transition.at}-${transition.from}-${transition.to}`} className="rounded-md border border-border p-2 text-xs">
                  <div className="font-medium">{transition.from} to {transition.to}</div>
                  <div className="mt-1 text-muted-foreground">{transition.reason}</div>
                  <div className="mt-1 font-mono text-[11px] text-muted-foreground">{formatDate(transition.at)}</div>
                </li>
              ))}
            </ol>
          ) : null}
          <div className="space-y-2" data-testid="deployment-file-profile-paths">
            {files.slice(0, 5).map((file) => (
              <div key={`${file.path}:${file.comm ?? ""}:${file.operation}`} className="rounded-md border border-border p-2" data-testid="deployment-file-profile-path-row">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="break-all font-mono text-xs font-medium">{file.path}</div>
                  <div className="flex flex-wrap gap-1">
                    {file.sensitive ? <Pill tone="warn">sensitive</Pill> : null}
                    <Pill tone="neutral">{file.observed_count}x</Pill>
                  </div>
                </div>
                <div className="mt-1 flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                  <span>{file.operation}</span>
                  {file.comm ? <span className="font-mono">{file.comm}</span> : null}
                  <span>last seen {formatDate(file.last_seen)}</span>
                </div>
              </div>
            ))}
            {files.length > 5 ? <p className="text-[11px] text-muted-foreground">{files.length - 5} additional paths observed.</p> : null}
            {files.length === 0 ? <p className="text-xs text-muted-foreground" data-testid="deployment-file-profile-empty">No file monitor events reported yet.</p> : null}
          </div>
        </div>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground" data-testid="deployment-file-profile-empty">No file monitor evidence recorded yet.</p>
      )}
    </section>
  );
}

function CompliancePanel({ evidence }: { evidence: DeploymentComplianceEvidence[] }) {
  const sorted = [...evidence].sort((a, b) => statusRank(a.effective_status) - statusRank(b.effective_status) || a.framework.localeCompare(b.framework));
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Compliance evidence</h2>
          <p className="mt-1 text-xs text-muted-foreground">{evidence.length} workload control row{evidence.length === 1 ? "" : "s"} linked to this workload.</p>
        </div>
        <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      <div className="mt-3 space-y-2" data-testid="deployment-compliance-evidence">
        {sorted.slice(0, 10).map((item) => (
          <div key={item.id} className="rounded-md border border-border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="min-w-0">
                <div className="truncate text-xs font-medium">{item.title}</div>
                <div className="mt-1 font-mono text-[11px] text-muted-foreground">{item.framework} · {item.control_id}</div>
              </div>
              <StatusPill status={item.effective_status} />
            </div>
            <div className="mt-2 flex flex-wrap gap-1">
              <SeverityPill severity={item.severity} />
              <Pill tone="neutral">{item.source}</Pill>
              {item.exemption ? <Pill tone="ok">exempted</Pill> : null}
            </div>
            {item.evidence ? <p className="mt-2 break-words font-mono text-[11px] leading-5 text-muted-foreground">{item.evidence}</p> : null}
          </div>
        ))}
        {evidence.length > 10 ? <p className="text-[11px] text-muted-foreground">{evidence.length - 10} additional controls available in Compliance.</p> : null}
        {evidence.length === 0 ? <p className="text-xs text-muted-foreground">No workload compliance evidence recorded yet.</p> : null}
      </div>
    </section>
  );
}

function PackageEvidencePanel({ evidence }: { evidence: DeploymentPackageEvidence[] }) {
  const selected = evidence[0];
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Package evidence</h2>
          <p className="mt-1 text-xs text-muted-foreground">{evidence.length} inventory report{evidence.length === 1 ? "" : "s"}</p>
        </div>
        <Database className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      {selected ? (
        <>
          <dl className="mt-3 grid gap-2 text-sm">
            <Field label="Workload" value={selected.workload_id} />
            <Field label="Node" value={selected.node || "-"} />
            <Field label="Pod" value={selected.pod_name || "-"} />
            <Field label="Runtime" value={selected.runtime || "-"} />
            <Field label="Distro" value={[selected.distro, selected.distro_version].filter(Boolean).join(" ") || "-"} />
            <Field label="Packages" value={`${selected.package_count}`} />
            <Field label="Containers" value={`${selected.container_count}`} />
            <Field label="Observed" value={formatDate(selected.observed_at)} />
            <Field label="Inventory hash" value={selected.inventory_hash} wide />
          </dl>
          <pre className="mt-3 max-h-[280px] overflow-auto rounded-md border border-border bg-background p-3 text-[11px] leading-5 text-muted-foreground">
            {renderPayload(selected.payload)}
          </pre>
        </>
      ) : (
        <p className="mt-3 text-xs text-muted-foreground">No runtime-agent package evidence reported yet.</p>
      )}
    </section>
  );
}

function RuntimeEventsPanel({ events }: { events: RuntimeEvent[] }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Runtime events</h2>
          <p className="mt-1 text-xs text-muted-foreground">Recent exec, file, network, WAF, DLP, and Falco-style signals.</p>
        </div>
        <TerminalSquare className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      <div className="mt-3 space-y-2" data-testid="deployment-runtime-events">
        {events.slice(0, 8).map((event) => (
          <div key={event.id} className="rounded-md border border-border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="font-mono text-xs font-medium">{event.kind}</div>
              <SeverityPill severity={event.severity} />
            </div>
            <div className="mt-1 text-xs text-muted-foreground">{event.verdict} · {event.source} · {formatDate(event.at)}</div>
            <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{event.workload_id}</div>
          </div>
        ))}
        {events.length === 0 ? <p className="text-xs text-muted-foreground">No runtime events recorded for this workload.</p> : null}
      </div>
    </section>
  );
}

function ViolationsPanel({ violations }: { violations: Violation[] }) {
  return (
    <section className="rounded-lg border border-border bg-card p-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Violations</h2>
          <p className="mt-1 text-xs text-muted-foreground">Policy and finding lifecycle events for this workload.</p>
        </div>
        <ShieldCheck className="h-4 w-4 text-muted-foreground" aria-hidden />
      </div>
      <div className="mt-3 space-y-2" data-testid="deployment-violations">
        {violations.map((violation) => (
          <div key={violation.id} className="rounded-md border border-border p-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="font-mono text-xs font-medium">{violation.policy_name || violation.kind}</div>
              <SeverityPill severity={violation.severity} />
            </div>
            <p className="mt-1 text-xs text-muted-foreground">{violation.message || "-"}</p>
            <div className="mt-1 text-[11px] text-muted-foreground">{formatDate(violation.at)}</div>
          </div>
        ))}
        {violations.length === 0 ? <p className="text-xs text-muted-foreground">No violations on this workload.</p> : null}
      </div>
    </section>
  );
}

function Field({ label, value, wide }: { label: string; value: ReactNode; wide?: boolean }) {
  return (
    <div className={cn("grid gap-1", wide && "sm:col-span-2")}>
      <dt className="text-[10px] uppercase text-muted-foreground">{label}</dt>
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
        "inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium",
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

function deploymentWorkloadID(detail: DeploymentDetail): string {
  const base = `${detail.namespace}/${detail.name}`;
  return detail.workload_ids?.find((id) => id === base) ?? base;
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

function deploymentActionIdempotencyKey(workload: string, action: string): string {
  if (typeof window !== "undefined" && "randomUUID" in window.crypto) {
    return `deployment-policy:${workload}:${action}:${window.crypto.randomUUID()}`;
  }
  return `deployment-policy:${workload}:${action}:${Date.now()}`;
}

function positiveInt(value: string): number | undefined {
  const parsed = Number.parseInt(value.trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function actionErrorMessage(error: unknown): string {
  if (typeof error === "object" && error && "response" in error) {
    const response = (error as { response?: { data?: { error?: string } } }).response;
    if (response?.data?.error) return response.data.error;
  }
  if (error instanceof Error && error.message) return error.message;
  return "Action failed. Refresh and review the latest workload state.";
}

function nextBaselinePromoteMode(mode: BaselineMode): BaselineMode | null {
  if (mode === "learn") return "monitor";
  if (mode === "monitor") return "enforce";
  return null;
}

function nextBaselineRollbackMode(mode: BaselineMode): BaselineMode | null {
  if (mode === "monitor") return "learn";
  if (mode === "enforce") return "monitor";
  return null;
}

function splitCSV(value: string): string[] {
  return Array.from(new Set(value.split(",").map((part) => part.trim()).filter(Boolean))).sort();
}

function displayFileRuleBehavior(behavior: FileProfileRuleBehavior): string {
  if (behavior === "block_access") return "block";
  return "monitor";
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
