// CVEDetailPage — single-CVE drill-down with entity breadcrumbs + KEV / EPSS
// banner + entity tile rail + fix advisor.
import { useMemo } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ChevronRight, ExternalLink, Wrench, BookOpen, Bug } from "lucide-react";

import { api, cve as cveApi, type CVEAffectedImage, type CVEAffectedResponse, type Severity } from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { EntityHeader } from "@/components/EntityHeader";
import { KevBadge, EpssBadge } from "@/components/ui/kev-badge";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { cn } from "@/lib/cn";

interface CVEDetail {
  cve_id: string;
  title: string;
  description: string;
  cvss_base?: number;
  kev_listed: boolean;
  epss_probability?: number;
  aliases: string[];
}

export function CVEDetailPage() {
  // Two routes render this page:
  //   global   /cve/:id                       → params.id = CVE, no cluster
  //   cluster  /clusters/:id/cve/:cveId        → params.id = CLUSTER, params.cveId = CVE
  // The distinct `:cveId` param name is REQUIRED: if the nested route reused `:id` it
  // would shadow the cluster's `:id`, so useCluster() (which reads params.id) would get
  // the CVE id, "not find" the cluster, and ClusterRouter would bounce to /clusters.
  const { id, cveId } = useParams<{ id: string; cveId: string }>();
  const clusterScoped = !!cveId;
  const cveKey = cveId ?? id;
  // useCluster reads params.id — correct (the cluster) only on the nested route.
  const { cluster } = useCluster();
  const clusterId = clusterScoped ? id : undefined;
  const cveQ = useQuery({
    queryKey: ["cve", cveKey],
    queryFn: () => api.get<CVEDetail>(`/cve/${cveKey}`).then((r) => r.data),
    enabled: !!cveKey,
  });
  const relatedQ = useQuery({
    queryKey: ["cve-affected", cveKey, clusterId ?? "all"],
    queryFn: () => cveApi.affected(cveKey!, clusterId),
    enabled: !!cveKey,
  });

  const affected = relatedQ.data;
  const grouped = useMemo(() => groupByAffected(affected), [affected]);
  const topSev = useMemo<Severity>(() => {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    const images = affected?.images ?? [];
    for (const s of order) if (images.some((img) => (img.severity_counts?.[s] ?? 0) > 0)) return s;
    if ((affected?.summary.max_risk_score ?? 0) >= 90) return "critical";
    if ((affected?.summary.max_risk_score ?? 0) >= 70) return "high";
    if ((affected?.summary.max_risk_score ?? 0) >= 40) return "medium";
    return "medium";
  }, [affected]);

  if (cveQ.isPending) return <p className="text-xs text-muted-foreground">Loading CVE…</p>;
  if (cveQ.isError)   return <p className="text-xs text-destructive">CVE not found.</p>;
  const cve = cveQ.data!;

  return (
    <div className="space-y-5" data-testid="cve-detail-page">
      <EntityHeader
        breadcrumbs={
          clusterId
            ? [
                { label: "Clusters", to: "/clusters" },
                { label: cluster?.name || clusterId.slice(0, 14), to: `/clusters/${clusterId}/dashboard` },
                { label: "Findings", to: `/clusters/${clusterId}/findings` },
                { label: cve.cve_id },
              ]
            : [
                { label: "CVE DB", to: "/cve" },
                { label: cve.cve_id },
              ]
        }
        title={<span className="text-mono">{cve.cve_id}</span>}
        subtitle={clusterId ? `${cve.title} · scoped to ${cluster?.name || "this cluster"}` : cve.title}
        badges={
          <>
            {cve.cvss_base != null && (
              <span className="rounded bg-muted px-2 py-0.5 text-[10px] text-mono">CVSS {cve.cvss_base}</span>
            )}
            {cve.kev_listed && <KevBadge />}
            {cve.epss_probability != null && <EpssBadge probability={cve.epss_probability} />}
            <SeverityBadge severity={topSev} />
          </>
        }
        stats={[
          { label: "Affected Images",      value: grouped.images.length,      tone: grouped.images.length > 0 ? "high" : "neutral" },
          { label: "Affected Deployments", value: grouped.deployments.length, tone: grouped.deployments.length > 0 ? "high" : "neutral" },
          { label: "Affected Clusters",    value: grouped.clusters.length,    tone: grouped.clusters.length > 0 ? "accent" : "neutral" },
          { label: "Image Findings",       value: affected?.summary.finding_count ?? 0, tone: "accent" },
        ]}
        actions={
          <>
            <Button size="sm" variant="outline" asChild>
              <a href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`} target="_blank" rel="noopener noreferrer">
                NVD <ExternalLink className="h-3 w-3" />
              </a>
            </Button>
            <Button size="sm" variant="primary" asChild>
              <a href="#affected-images">
                View {grouped.images.length} image{grouped.images.length === 1 ? "" : "s"}
              </a>
            </Button>
          </>
        }
      />

      {/* KEV alert banner */}
      {cve.kev_listed && (
        <div className="rounded-md border border-[color-mix(in_oklab,var(--color-severity-critical)_36%,var(--color-border))] bg-[color-mix(in_oklab,var(--color-severity-critical)_8%,transparent)] p-3 flex items-start gap-3">
          <Bug className="h-4 w-4 text-[color:var(--color-severity-critical)] flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <div className="text-sm font-semibold text-[color:var(--color-severity-critical)]">CISA Known-Exploited Vulnerability</div>
            <p className="text-xs text-foreground/80 mt-0.5">
              This CVE is on CISA's KEV catalog. Active exploitation has been observed in the wild — prioritize remediation immediately.
            </p>
          </div>
          <Button size="sm" variant="primary" asChild>
            <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer">
              CISA catalog
            </a>
          </Button>
        </div>
      )}

      {/* EPSS probability bar */}
      {cve.epss_probability != null && (
        <section className="rounded-md border border-border bg-card p-3">
          <div className="flex items-baseline justify-between gap-2">
            <h2 className="text-display text-sm font-semibold tracking-tight">EPSS Exploit Probability</h2>
            <span className="text-mono text-2xl font-semibold" style={{ color: cve.epss_probability >= 0.7 ? "var(--color-severity-critical)" : cve.epss_probability >= 0.3 ? "var(--color-severity-high)" : "var(--color-severity-medium)" }}>
              {(cve.epss_probability * 100).toFixed(2)}%
            </span>
          </div>
          <div className="mt-2 h-2 w-full rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${cve.epss_probability * 100}%`,
                background: cve.epss_probability >= 0.7 ? "var(--color-severity-critical)" : cve.epss_probability >= 0.3 ? "var(--color-severity-high)" : "var(--color-severity-medium)",
              }}
            />
          </div>
          <p className="mt-2 text-[10px] text-muted-foreground">Probability that this CVE is exploited in the wild within 30 days. Source: FIRST.org EPSS.</p>
        </section>
      )}

      {/* Description */}
      {cve.description && (
        <section className="rounded-md border border-border bg-card p-3">
          <h2 className="text-display text-sm font-semibold tracking-tight mb-1.5 flex items-center gap-1.5">
            <BookOpen className="h-3.5 w-3.5 text-muted-foreground" />
            Description
          </h2>
          <p className="text-xs text-foreground/85 leading-relaxed">{cve.description}</p>
          {cve.aliases.length > 0 && (
            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Aliases</span>
              {cve.aliases.map((a) => (
                <span key={a} className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono">{a}</span>
              ))}
            </div>
          )}
        </section>
      )}

      {/* Fix advisor */}
      <section className="rounded-md border border-border bg-card p-3 flex items-start gap-3">
        <Wrench className="h-4 w-4 text-[color:var(--color-primary)] flex-shrink-0 mt-0.5" />
        <div className="flex-1 space-y-1">
          <h2 className="text-display text-sm font-semibold tracking-tight">Fix Advisor</h2>
          <p className="text-xs text-foreground/85">
            <span className="font-medium">Highest-impact action: </span>
            Upgrade affected images to a fixed version. {grouped.images.length > 0 && (
              <>
                Currently observed across <span className="text-mono">{grouped.images.length} image{grouped.images.length === 1 ? "" : "s"}</span>.
              </>
            )}
          </p>
          <p className="text-[11px] text-muted-foreground">
            Alternatives: apply a NetworkPolicy to restrict exposure · accept-risk with expiry · suppress with rationale.
          </p>
        </div>
        <Button size="sm" variant="primary" asChild>
          <a href="#affected-images">Review affected images</a>
        </Button>
      </section>

      {/* Entity breadcrumb pivots */}
      <nav className="flex flex-wrap items-center gap-1.5 rounded-md border border-border bg-card p-3 text-xs" data-testid="cve-breadcrumbs">
        <Crumb label="CVE" count={1} active />
        <Sep />
        <Crumb label="Image"      count={grouped.images.length}      href="#affected-images" />
        <Sep />
        <Crumb label="Deployment" count={grouped.deployments.length} href="#affected-workloads" />
        <Sep />
        <Crumb label="Cluster"    count={grouped.clusters.length}    href="#affected-clusters" />
      </nav>

      {/* Tile rail */}
      <section className="grid grid-cols-1 gap-3 md:grid-cols-3" data-testid="cve-tile-lists">
        <TileList id="affected-images" title="Affected Images" items={grouped.images} emptyHint="No images observed with this CVE." />
        <TileList id="affected-workloads" title="Affected Deployments" items={grouped.deployments} emptyHint="No deployments observed with this CVE." />
        <TileList id="affected-clusters" title="Affected Clusters" items={grouped.clusters} emptyHint="No clusters observed with this CVE." />
      </section>
    </div>
  );
}

function Crumb({ label, count, href, active }: { label: string; count: number; href?: string; active?: boolean }) {
  const inner = (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded h-6 px-2 text-[11px] transition-colors",
        active
          ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] text-[color:var(--color-primary)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-primary)_36%,transparent)]"
          : "bg-card border border-border text-foreground hover:bg-accent",
      )}
    >
      <span className="font-medium">{label}</span>
      <span className="text-mono text-[10px] opacity-80">({count})</span>
    </span>
  );
  return href ? <Link to={href}>{inner}</Link> : inner;
}

function Sep() {
  return <ChevronRight className="h-3 w-3 text-muted-foreground/60" aria-hidden />;
}

function TileList({ id, title, items, emptyHint }: { id: string; title: string; items: TileEntry[]; emptyHint: string }) {
  return (
    <div id={id} className="rounded-md border border-border bg-card">
      <header className="border-b border-border px-3 py-2">
        <h3 className="text-display text-sm font-semibold tracking-tight">{title}</h3>
        <p className="text-[10px] text-muted-foreground text-mono">{items.length} observed</p>
      </header>
      {items.length === 0 ? (
        <EmptyState title="None observed" hint={emptyHint} />
      ) : (
        <ul className="divide-y divide-border">
          {items.map((it) => (
            <li key={it.id}>
              <TileLink href={it.href}>
                <div className="text-xs text-mono truncate">{it.label}</div>
                {it.sub && <div className="text-[10px] text-muted-foreground truncate">{it.sub}</div>}
              </TileLink>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function TileLink({ href, children }: { href?: string; children: ReactNode }) {
  const className = "accent-slide block px-3 py-1.5 hover:bg-muted/40 transition-colors";
  return href ? <Link to={href} className={className}>{children}</Link> : <div className={className}>{children}</div>;
}

interface TileEntry { id: string; label: string; sub?: string; href?: string }

function groupByAffected(affected?: CVEAffectedResponse): { images: TileEntry[]; deployments: TileEntry[]; clusters: TileEntry[] } {
  const firstWorkloadByImage = new Map<string, string>();
  for (const workload of affected?.workloads ?? []) {
    if (workload.image_digest) firstWorkloadByImage.set(workload.image_digest, workload.cluster_id);
    if (workload.image_ref_normalized) firstWorkloadByImage.set(workload.image_ref_normalized, workload.cluster_id);
    if (workload.image_ref) firstWorkloadByImage.set(workload.image_ref, workload.cluster_id);
  }
  const images = (affected?.images ?? []).map((image) => imageTile(image, firstWorkloadByImage));
  const deployments = (affected?.workloads ?? []).map((workload) => ({
    id: `${workload.cluster_id}:${workload.deployment_id}`,
    label: `${workload.namespace}/${workload.name}`,
    sub: `${workload.kind} · ${workload.finding_count} finding${workload.finding_count === 1 ? "" : "s"}`,
    href: `/clusters/${workload.cluster_id}/deployments/${workload.deployment_id}`,
  }));
  const clusters = (affected?.clusters ?? []).map((cluster) => ({
    id: cluster.cluster_id,
    label: cluster.name || cluster.cluster_id.slice(0, 14),
    sub: `${cluster.workload_count} workload${cluster.workload_count === 1 ? "" : "s"} · ${cluster.finding_count} finding${cluster.finding_count === 1 ? "" : "s"}`,
    href: `/clusters/${cluster.cluster_id}/dashboard`,
  }));
  return {
    images,
    deployments,
    clusters,
  };
}

function imageTile(image: CVEAffectedImage, firstWorkloadByImage: Map<string, string>): TileEntry {
  const label = image.image_tag ? `${image.image_repository}:${image.image_tag}` : image.image_repository || image.image_digest.slice(0, 19);
  const clusterID =
    firstWorkloadByImage.get(image.image_digest) ??
    firstWorkloadByImage.get(image.image_ref_normalized) ??
    firstWorkloadByImage.get(image.image_ref);
  return {
    id: image.image_scan_result_id,
    label,
    sub: `${image.platform || "platform"} · ${image.finding_count} package${image.finding_count === 1 ? "" : "s"}`,
    href: clusterID ? `/clusters/${clusterID}/images/${image.image_scan_result_id}` : undefined,
  };
}
