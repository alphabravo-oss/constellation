// FindingsPage — power-user list.
//
// Surfaces:
//   - QueryInput at top with chip hints (severity:high, kev:true, …)
//   - Saved Views dropdown (localStorage-backed) on the right
//   - State tabs: Observed · Accepted · Suppressed
//   - Group-by toggle: none / severity / kind / asset
//   - DataTable with sticky header, density toggle, sortable columns, bulk-select
//   - ActionBar slides up when rows are selected (Triage / Suppress / Accept / Comment)
//   - Right Drawer opens on row click with full detail + inline triage
//
// Filtering uses the existing /findings?lifecycle= and ?kind= params; the
// free-text query refines client-side until the backend's DSL is wired through.
import { useEffect, useMemo, useState, useTransition } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query";
import { Save, Tag, Bookmark, ChevronDown, ListFilter } from "lucide-react";

import {
  findings,
  type Finding,
  type FindingKind,
  type Lifecycle,
  type Severity,
  type CVERollup,
} from "@/api/client";
import { useCluster } from "@/hooks/useCluster";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { LifecycleBadge } from "@/components/ui/status-pill";
import { RiskScore } from "@/components/ui/risk-score";
import { DataTable, type Column, type Density } from "@/components/ui/data-table";
import { PageHeader } from "@/components/ui/page";
import { QueryInput } from "@/components/ui/query-input";
import { FilterChip } from "@/components/ui/filter-chip";
import { Button } from "@/components/ui/button";
import { ActionBar } from "@/components/ui/action-bar";
import { EmptyState } from "@/components/ui/empty-state";
import { fmtRelative } from "@/lib/format";
import { downloadCsv } from "@/lib/csv";
import { SEVERITY_RANK } from "@/lib/severity";
import { cn } from "@/lib/cn";
import { Pager } from "@/components/ui/pager";
import { useDebounced } from "@/hooks/useDebounced";

interface SavedView {
  id: string;
  name: string;
  kind: FindingKind | "";
  lifecycle: Lifecycle | "";
  query: string;
}

const SAVED_VIEWS_KEY = "constellation.findings.views.v1";
const DENSITY_KEY     = "constellation.findings.density";

const STATE_TABS: Array<{ label: string; lifecycle: Lifecycle; description: string }> = [
  { label: "Observed",   lifecycle: "open",       description: "open · in-flight" },
  { label: "Accepted",   lifecycle: "accepted",   description: "risk accepted" },
  { label: "Suppressed", lifecycle: "suppressed", description: "hidden by rule" },
];

const QUERY_HINTS: Array<{ label: string; value: string; example: string }> = [
  { label: "severity", value: "severity:critical", example: "severity:critical" },
  { label: "kev",      value: "kev:true",          example: "kev:true" },
  { label: "kind",     value: "kind:vulnerability", example: "kind:vulnerability" },
  { label: "cve",      value: "cve:CVE-",          example: "cve:CVE-2024-3094" },
  { label: "package",  value: "package:openssl",   example: "package:openssl" },
  { label: "source",   value: "canonical_engine:vulndb", example: "canonical_engine:vulndb" },
  { label: "diff",     value: "disagreement:true", example: "disagreement:true" },
  { label: "not",      value: "!status:resolved",  example: "!status:resolved" },
];

type GroupBy = "none" | "severity" | "kind" | "asset";

export function FindingsPage() {
  const qc = useQueryClient();
  // Cluster scope: when mounted under /clusters/:id/findings, all queries are
  // filtered to that cluster. At org-level (legacy) we pass undefined.
  const { clusterId } = useCluster();

  // Filters
  const [kind, setKind] = useState<FindingKind | "">("");
  const [lifecycle, setLifecycle] = useState<Lifecycle | "">("open");
  const [query, setQuery] = useState("");
  const [groupBy, setGroupBy] = useState<GroupBy>("none");
  const [, startTransition] = useTransition();

  // Density
  const [density, setDensity] = useState<Density>(() => (localStorage.getItem(DENSITY_KEY) as Density) || "cozy");
  useEffect(() => { localStorage.setItem(DENSITY_KEY, density); }, [density]);

  // Saved views
  const [views, setViews] = useState<SavedView[]>(() => {
    try { return JSON.parse(localStorage.getItem(SAVED_VIEWS_KEY) ?? "[]"); } catch { return []; }
  });
  useEffect(() => { localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(views)); }, [views]);

  // Selection + view mode (instance rows vs NeuVector-style CVE rollup)
  const [selected, setSelected] = useState<Set<React.Key>>(new Set());
  // CVE-first by default, matching NeuVector's vulnerability view (one row per CVE +
  // blast radius). "Instances" (one row per CVE×workload) stays one click away.
  const [view, setView] = useState<"instances" | "cve">("cve");
  const navigate = useNavigate();
  const openFinding = (f: Finding) => navigate(`/clusters/${clusterId}/findings/${f.id}`);

  // Fixable-only toggle (hide won't-fix / not-fixed vulns) — shared by both the findings
  // list and the by-CVE rollup.
  const [fixableOnly, setFixableOnly] = useState(false);
  // Data — cluster_id is threaded so the URL is the source of truth for scope.
  const q = useQuery({
    queryKey: ["findings", kind, lifecycle, clusterId, fixableOnly],
    queryFn: () => findings.list({
      kind: kind || undefined,
      lifecycle: lifecycle || undefined,
      cluster_id: clusterId,
      // Only meaningful for vulnerabilities; harmless on other kinds (they have no fixed field).
      fixable: fixableOnly || undefined,
      limit: 500,
    }),
  });

  // CVE rollup (NeuVector-style): one row per CVE + its blast radius. Server-side
  // search + paging (NV-style) so we never fetch-all-then-truncate. Only fetched when
  // the "By CVE" view is active.
  const CVE_PAGE = 100;
  const [cvePage, setCvePage] = useState(0);
  const cveSearch = useDebounced(query.trim(), 300);
  useEffect(() => { setCvePage(0); }, [cveSearch, lifecycle, clusterId, fixableOnly]);
  const cveQ = useQuery({
    queryKey: ["findings-cve", lifecycle, clusterId, fixableOnly, cveSearch, cvePage],
    queryFn: () => findings.byCVE({
      cluster_id: clusterId, lifecycle: lifecycle || undefined, fixable: fixableOnly || undefined,
      q: cveSearch || undefined, limit: CVE_PAGE, offset: cvePage * CVE_PAGE,
    }),
    enabled: view === "cve",
    placeholderData: keepPreviousData,
  });
  const cveRows = cveQ.data?.cves ?? [];
  const cveTotal = cveQ.data?.total ?? 0;

  const rows = useMemo(() => {
    const all = q.data?.findings ?? [];
    if (!query.trim()) return all;
    return clientFilter(all, query);
  }, [q.data, query]);

  const grouped = useMemo(() => groupRows(rows, groupBy), [rows, groupBy]);

  // Active filter chips (for the chip rail below the input)
  const activeChips = useMemo(() => {
    const out: Array<{ label: string; value: string; onRemove: () => void }> = [];
    if (kind)      out.push({ label: "kind",      value: kind,      onRemove: () => setKind("") });
    if (lifecycle) out.push({ label: "lifecycle", value: lifecycle, onRemove: () => setLifecycle("") });
    if (query)     out.push({ label: "q",         value: query,     onRemove: () => setQuery("") });
    return out;
  }, [kind, lifecycle, query]);

  function saveView() {
    const name = prompt("Name this view");
    if (!name) return;
    setViews((v) => [...v, { id: crypto.randomUUID(), name, kind, lifecycle, query }]);
  }
  function applyView(v: SavedView) {
    setKind(v.kind);
    setLifecycle(v.lifecycle);
    setQuery(v.query);
  }

  const columns: Column<Finding>[] = [
    {
      id: "severity",
      header: "Severity",
      cell: (f) => <SeverityBadge severity={f.severity} kev={isKev(f)} />,
      sort: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity],
      width: "108px",
    },
    {
      id: "cve",
      header: "CVE / ID",
      cell: (f) => (
        <span className="flex items-center gap-1.5">
          {f.external_id
            ? <Link to={clusterId ? `/clusters/${clusterId}/cve/${f.external_id}` : `/cve/${f.external_id}`} className="text-mono text-xs hover:text-[color:var(--color-primary)]">{f.external_id}</Link>
            : <span className="text-mono text-xs text-muted-foreground">{f.id.slice(0, 10)}</span>}
          {f.kev && <span className="rounded px-1 py-px text-[9px] font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
        </span>
      ),
      sort: (a, b) => (a.external_id ?? "").localeCompare(b.external_id ?? ""),
      width: "170px",
    },
    {
      id: "cvss",
      header: "CVSS",
      numeric: true,
      width: "70px",
      cell: (f) => <span className="text-mono text-xs" style={{ color: (f.cvss ?? 0) >= 9 ? "var(--color-severity-critical)" : (f.cvss ?? 0) >= 7 ? "var(--color-severity-high)" : "var(--color-foreground)" }}>{f.cvss ? f.cvss.toFixed(1) : "—"}</span>,
      sort: (a, b) => (a.cvss ?? 0) - (b.cvss ?? 0),
    },
    {
      id: "title",
      header: "Title",
      cell: (f) => (
        <button
          type="button"
          onClick={() => openFinding(f)}
          className="text-left text-sm hover:text-[color:var(--color-primary)] truncate max-w-[420px] block"
          title={f.title}
        >
          {f.title}
        </button>
      ),
      sort: (a, b) => a.title.localeCompare(b.title),
    },
    {
      id: "asset",
      header: "Asset",
      cell: (f) => (
        <Link to={`/clusters/${clusterId}/risk/asset/${encodeURIComponent(f.asset_id)}`} className="text-mono text-[10px] text-muted-foreground hover:text-foreground" title="Open risk workspace">
          {f.asset_id.slice(0, 14)}
        </Link>
      ),
      sort: (a, b) => a.asset_id.localeCompare(b.asset_id),
      width: "150px",
    },
    {
      id: "risk",
      header: "Risk",
      numeric: true,
      cell: (f) => <RiskScore score={f.risk_score} />,
      sort: (a, b) => a.risk_score - b.risk_score,
      width: "80px",
    },
    {
      id: "lifecycle",
      header: "Lifecycle",
      cell: (f) => <LifecycleBadge lifecycle={f.lifecycle} />,
      sort: (a, b) => a.lifecycle.localeCompare(b.lifecycle),
      width: "118px",
    },
    {
      id: "kind",
      header: "Kind",
      cell: (f) => <span className="text-[10px] text-mono text-muted-foreground">{f.kind}</span>,
      sort: (a, b) => a.kind.localeCompare(b.kind),
      width: "108px",
    },
    {
      id: "age",
      header: "Age",
      numeric: true,
      cell: (f) => <span className="text-[10px] text-muted-foreground">{fmtRelative(f.last_seen_at)}</span>,
      sort: (a, b) => +new Date(a.last_seen_at) - +new Date(b.last_seen_at),
      width: "120px",
    },
  ];

  const totalSelected = selected.size;

  // Bulk mutations
  const bulkSuppress = useMutation({
    mutationFn: async () => {
      const ids = Array.from(selected) as string[];
      await Promise.all(ids.map((id) => findings.suppress(id, { reason: "bulk suppress via Findings" })));
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); setSelected(new Set()); },
  });
  const bulkAccept = useMutation({
    mutationFn: async () => {
      const ids = Array.from(selected) as string[];
      await Promise.all(ids.map((id) => findings.acceptRisk(id, {
        reason: "bulk accept-risk via Findings",
        accepted_until: new Date(Date.now() + 30 * 86400_000).toISOString(),
      })));
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); setSelected(new Set()); },
  });
  const bulkTriage = useMutation({
    mutationFn: async () => {
      const ids = Array.from(selected) as string[];
      await Promise.all(ids.map((id) => findings.triage(id, { priority: "high" })));
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["findings"] }); setSelected(new Set()); },
  });

  return (
    <div className="space-y-4" data-testid="findings-page" data-cluster-id={clusterId ?? ""}>
      <PageHeader
        title="Findings"
        description="Every security finding across the org, ranked by Constellation Risk Score."
        actions={
          <>
            {views.length > 0 && (
              <SavedViewsMenu views={views} onApply={applyView} onDelete={(id) => setViews(views.filter((v) => v.id !== id))} />
            )}
            <Button size="sm" variant="outline" onClick={saveView}>
              <Save className="h-3.5 w-3.5" /> Save view
            </Button>
          </>
        }
      />

      {/* Query input + hints */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <QueryInput
            value={query}
            placeholder="severity:critical kev:true cve:CVE-2024- !status:resolved"
            onChange={(e) => startTransition(() => setQuery(e.target.value))}
            onClear={() => setQuery("")}
          />
          <Select value={kind} onChange={(v) => setKind(v as FindingKind | "")}
            options={[["", "any kind"], ["vulnerability","vulnerability"], ["iac","iac"], ["license","license"],
                      ["cloud-config","cloud-config"], ["drift","drift"], ["signature","signature"],
                      ["ml-model","ml-model"], ["compliance","compliance"], ["runtime","runtime"]]} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Try</span>
          {QUERY_HINTS.map((h) => (
            <FilterChip
              key={h.value}
              label={h.label}
              value={h.example.split(":")[1]}
              onClick={() => setQuery((cur) => cur ? `${cur} ${h.example}` : h.example)}
            />
          ))}
          {activeChips.length > 0 && (
            <>
              <span className="mx-1 h-3 w-px bg-border" aria-hidden />
              <span className="text-[10px] uppercase tracking-wider text-muted-foreground">Active</span>
              {activeChips.map((c, i) => (
                <FilterChip key={i} label={c.label} value={c.value} onRemove={c.onRemove} active />
              ))}
            </>
          )}
        </div>
      </div>

      {/* State tabs */}
      <section className="grid grid-cols-1 gap-2 md:grid-cols-3" data-testid="finding-state-tabs">
        {STATE_TABS.map((tab) => {
          const count = tab.lifecycle === "open"
            ? (q.data?.lifecycle_counts?.open ?? 0) + (q.data?.lifecycle_counts?.triaged ?? 0) + (q.data?.lifecycle_counts?.in_progress ?? 0)
            : q.data?.lifecycle_counts?.[tab.lifecycle] ?? 0;
          const active = lifecycle === tab.lifecycle;
          return (
            <button
              key={tab.lifecycle}
              type="button"
              onClick={() => setLifecycle(tab.lifecycle)}
              className={cn(
                "rounded-md border bg-card px-3 py-2.5 text-left transition-all duration-100",
                active
                  ? "border-[color:var(--color-primary)] ring-1 ring-[color:var(--color-primary)]"
                  : "border-border hover:border-[color-mix(in_oklab,var(--color-primary)_30%,var(--color-border))]",
              )}
            >
              <div className="flex items-center justify-between">
                <span className="text-display text-sm font-semibold">{tab.label}</span>
                <span className={cn(
                  "rounded h-5 px-1.5 text-[11px] text-mono",
                  active ? "bg-[color:var(--color-primary)] text-[color:var(--color-primary-foreground)]" : "bg-muted text-muted-foreground",
                )}>{count}</span>
              </div>
              <div className="mt-0.5 text-[10px] text-muted-foreground">{tab.description}</div>
            </button>
          );
        })}
      </section>

      {/* View: per-instance rows vs NeuVector-style CVE rollup */}
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground">View</span>
        {([["instances", "Instances"], ["cve", "By CVE"]] as Array<["instances" | "cve", string]>).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setView(v)}
            className={cn(
              "rounded h-6 px-2 text-[11px] border transition-colors",
              view === v
                ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
                : "bg-card border-border hover:bg-accent",
            )}
          >{l}</button>
        ))}
        <span className="ml-2 text-[10px] text-muted-foreground">
          {view === "cve" ? "one row per CVE with its blast radius" : "one row per CVE × workload"}
        </span>
        <button
          type="button"
          onClick={() => setFixableOnly((v) => !v)}
          className={cn(
            "ml-auto rounded h-6 px-2 text-[11px] border transition-colors",
            fixableOnly
              ? "bg-[color-mix(in_oklab,var(--color-severity-low)_18%,transparent)] border-[color-mix(in_oklab,var(--color-severity-low)_36%,transparent)] text-[color:var(--color-severity-low)]"
              : "bg-card border-border hover:bg-accent",
          )}
          title="Hide vulnerabilities with no available fix (won't-fix / not-fixed)"
        >{fixableOnly ? "✓ " : ""}Fixable only</button>
        {view === "cve" && (
          <button
            type="button"
            onClick={() => exportCveCsv(cveRows)}
            className="rounded h-6 px-2 text-[11px] border border-border bg-card hover:bg-accent transition-colors"
            title="Export the current CVE list as CSV"
          >Export CSV</button>
        )}
      </div>

      {/* Group by (instance view only) */}
      {view === "instances" && (
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] uppercase tracking-wider text-muted-foreground"><ListFilter className="h-3 w-3 inline" /> Group</span>
        {([
          ["none", "None"], ["severity", "Severity"], ["kind", "Kind"], ["asset", "Asset"],
        ] as Array<[GroupBy, string]>).map(([v, l]) => (
          <button
            key={v}
            type="button"
            onClick={() => setGroupBy(v)}
            className={cn(
              "rounded h-6 px-2 text-[11px] border transition-colors",
              groupBy === v
                ? "bg-[color-mix(in_oklab,var(--color-primary)_18%,transparent)] border-[color-mix(in_oklab,var(--color-primary)_36%,transparent)] text-[color:var(--color-primary)]"
                : "bg-card border-border hover:bg-accent",
            )}
          >{l}</button>
        ))}
        <div className="ml-auto flex items-center gap-2">
          <span className="text-[11px] text-muted-foreground text-mono">{rows.length} match{rows.length === 1 ? "" : "es"}</span>
          <button
            type="button"
            onClick={() => downloadCsv("constellation-findings", ["CVE/ID", "Severity", "CVSS", "KEV", "Title", "Package", "Fixed", "Risk", "Lifecycle", "LastSeen"],
              rows.map((f) => [f.external_id ?? f.id, f.severity, f.cvss ?? "", f.kev ? "yes" : "", f.title, f.package_name ?? "", f.fixed_version ?? "", f.risk_score, f.lifecycle, f.last_seen_at]))}
            className="rounded h-6 px-2 text-[11px] border border-border bg-card hover:bg-accent transition-colors"
            title="Export the current findings list as CSV"
          >Export CSV</button>
        </div>
      </div>
      )}

      {/* CVE rollup view */}
      {view === "cve" ? (
        <>
          <CVETable rows={cveRows} loading={cveQ.isPending} clusterId={clusterId} />
          <Pager page={cvePage} pageSize={CVE_PAGE} total={cveTotal} rowsOnPage={cveRows.length} onPage={setCvePage} />
        </>
      ) : groupBy === "none" ? (
        <DataTable
          rows={rows}
          columns={columns}
          rowKey={(f) => f.id}
          density={density}
          onDensityChange={setDensity}
          selectable
          selected={selected}
          onSelectedChange={setSelected}
          onRowClick={(f) => openFinding(f)}
          defaultSort={{ id: "risk", dir: "desc" }}
          emptyState={
            <EmptyState
              title="No findings match"
              hint="Adjust your filters or clear the query."
              icon={<Tag className="h-8 w-8" />}
              action={<Button size="sm" variant="outline" onClick={() => { setQuery(""); setKind(""); setLifecycle("open"); }}>Reset filters</Button>}
            />
          }
        />
      ) : (
        <div className="space-y-3">
          {grouped.map((g) => (
            <details key={g.label} open className="rounded-md border border-border bg-card">
              <summary className="flex cursor-pointer items-center justify-between gap-2 border-b border-border px-3 py-2 list-none">
                <div className="flex items-center gap-2">
                  <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-display text-sm font-semibold">{g.label}</span>
                  <span className="rounded bg-muted px-1.5 py-0.5 text-[10px] text-mono text-muted-foreground">{g.items.length}</span>
                </div>
              </summary>
              <DataTable
                rows={g.items}
                columns={columns}
                rowKey={(f) => f.id}
                density={density}
                onDensityChange={setDensity}
                selectable
                selected={selected}
                onSelectedChange={setSelected}
                onRowClick={(f) => openFinding(f)}
                showDensityToggle={false}
                className="rounded-none border-0"
              />
            </details>
          ))}
        </div>
      )}

      {/* Bulk action bar */}
      <ActionBar count={totalSelected} onClear={() => setSelected(new Set())}>
        <Button size="sm" variant="outline" onClick={() => bulkTriage.mutate()}>Triage</Button>
        <Button size="sm" variant="outline" onClick={() => bulkSuppress.mutate()}>Suppress</Button>
        <Button size="sm" variant="outline" onClick={() => bulkAccept.mutate()}>Accept risk · 30d</Button>
      </ActionBar>
    </div>
  );
}

// CVETable — the NeuVector-style rollup: one row per CVE with its blast radius
// (how many images / clusters it hits and total instances), sorted by risk.
// exportCveCsv downloads the current CVE rollup as CSV (client-side). Addresses the
// NeuVector-parity gap where nearly every table lacks ad-hoc export.
function exportCveCsv(rows: CVERollup[]) {
  const header = ["CVE", "Severity", "CVSS", "KEV", "Package", "FixedVersion", "AffectedImages", "AffectedClusters", "Instances", "Risk", "LastSeen"];
  const esc = (v: unknown) => { const s = String(v ?? ""); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const lines = [header.join(",")];
  for (const c of rows) {
    lines.push([c.cve, c.severity, c.cvss ?? "", c.kev ? "yes" : "", c.package ?? "", c.fixed_version ?? "", c.affected_images, c.affected_clusters, c.instances, c.risk_score, c.last_seen_at].map(esc).join(","));
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `constellation-cves-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function CVETable({ rows, loading, clusterId }: { rows: CVERollup[]; loading: boolean; clusterId?: string }) {
  const columns: Column<CVERollup>[] = [
    { id: "severity", header: "Severity", width: "108px",
      cell: (c) => <SeverityBadge severity={c.severity} />,
      sort: (a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] },
    { id: "cve", header: "CVE", width: "190px",
      cell: (c) => (
        <span className="flex items-center gap-1.5">
          <Link to={clusterId ? `/clusters/${clusterId}/cve/${c.cve}` : `/cve/${c.cve}`} className="text-mono text-xs hover:text-[color:var(--color-primary)]">{c.cve}</Link>
          {c.kev && <span className="rounded px-1 py-px text-[9px] font-semibold text-white" style={{ background: "var(--color-severity-critical)" }} title="CISA Known-Exploited">KEV</span>}
        </span>
      ),
      sort: (a, b) => a.cve.localeCompare(b.cve) },
    { id: "cvss", header: "CVSS", numeric: true, width: "72px",
      cell: (c) => <span className="text-mono text-xs" style={{ color: (c.cvss ?? 0) >= 9 ? "var(--color-severity-critical)" : (c.cvss ?? 0) >= 7 ? "var(--color-severity-high)" : "var(--color-foreground)" }}>{c.cvss ? c.cvss.toFixed(1) : "—"}</span>,
      sort: (a, b) => (a.cvss ?? 0) - (b.cvss ?? 0) },
    { id: "package", header: "Package",
      cell: (c) => <span className="text-mono text-xs">{c.package || "—"}</span> },
    { id: "fixed", header: "Fixed in",
      cell: (c) => <span className="text-mono text-xs text-muted-foreground">{c.fixed_version || "—"}</span> },
    { id: "affected", header: "Affected", numeric: true,
      cell: (c) => (
        <span className="text-xs" title={c.images.join("\n")}>
          {c.affected_images} image{c.affected_images === 1 ? "" : "s"}
          {c.affected_clusters > 1 ? ` · ${c.affected_clusters} clusters` : ""}
        </span>
      ),
      sort: (a, b) => a.affected_images - b.affected_images },
    { id: "instances", header: "Instances", numeric: true, width: "96px",
      cell: (c) => <span className="text-mono text-xs">{c.instances}</span>,
      sort: (a, b) => a.instances - b.instances },
    { id: "risk", header: "Risk", numeric: true, width: "80px",
      cell: (c) => <RiskScore score={c.risk_score} />,
      sort: (a, b) => a.risk_score - b.risk_score },
    { id: "age", header: "Age", numeric: true,
      cell: (c) => <span className="text-[10px] text-muted-foreground">{fmtRelative(c.last_seen_at)}</span>,
      sort: (a, b) => +new Date(a.last_seen_at) - +new Date(b.last_seen_at) },
  ];
  if (loading) return <p className="text-sm text-muted-foreground">Loading CVE rollup…</p>;
  return (
    <DataTable
      rows={rows}
      columns={columns}
      rowKey={(c) => c.cve}
      defaultSort={{ id: "risk", dir: "desc" }}
      emptyState={<EmptyState title="No open CVEs" hint="No open vulnerabilities on this cluster." icon={<Tag className="h-8 w-8" />} />}
    />
  );
}

function SavedViewsMenu({ views, onApply, onDelete }: { views: SavedView[]; onApply: (v: SavedView) => void; onDelete: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="inline-flex items-center gap-1.5 h-7 px-2.5 rounded border border-border bg-card text-xs hover:bg-accent"
      >
        <Bookmark className="h-3.5 w-3.5" /> Views <span className="text-mono text-muted-foreground">({views.length})</span>
      </button>
      {open && (
        <div
          className="absolute right-0 top-full z-30 mt-1 w-[260px] rounded-md border border-border bg-popover p-2 shadow-[var(--elev-popover)]"
          onMouseLeave={() => setOpen(false)}
        >
          <ul className="space-y-1">
            {views.map((v) => (
              <li key={v.id} className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => { onApply(v); setOpen(false); }}
                  className="flex-1 rounded px-2 py-1 text-left text-xs hover:bg-accent"
                >
                  <div className="font-medium">{v.name}</div>
                  <div className="text-[10px] text-mono text-muted-foreground truncate">
                    {[v.lifecycle, v.kind, v.query].filter(Boolean).join(" · ") || "all"}
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => onDelete(v.id)}
                  aria-label={`delete view ${v.name}`}
                  className="rounded p-1 text-muted-foreground hover:bg-muted"
                >×</button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function Select({
  value, onChange, options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: [string, string][];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 rounded-md border border-input bg-card px-2.5 text-xs text-mono outline-none focus:border-[color:var(--color-primary)]"
    >
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  );
}

function clientFilter(items: Finding[], query: string): Finding[] {
  // Tiny client-side DSL: tokenized by whitespace, each token can be
  // key:value or free text. Supports a negation prefix "!".
  const tokens = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return items;
  return items.filter((f) => tokens.every((tok) => matchToken(f, tok)));
}

function matchToken(f: Finding, tok: string): boolean {
  let neg = false;
  if (tok.startsWith("!")) { neg = true; tok = tok.slice(1); }
  const result = (() => {
    if (tok.includes(":")) {
      const [k, ...rest] = tok.split(":");
      const v = rest.join(":");
      switch (k) {
        case "severity": return f.severity === v;
        case "kind":     return f.kind === v;
        case "lifecycle":
        case "status":   return f.lifecycle === v;
        case "cve":      return (f.external_id ?? "").toLowerCase().includes(v);
        case "asset":    return f.asset_id.toLowerCase().includes(v);
        case "package":  return formatPackage(f).toLowerCase().includes(v);
        case "purl":     return (f.package_purl ?? f.affected_range?.package_purl ?? "").toLowerCase().includes(v);
        case "fixed":    return (f.fixed_version ?? f.affected_range?.fixed_version ?? "").toLowerCase().includes(v);
        case "kev":      return v === "true" ? isKev(f) : !isKev(f);
        case "canonical_engine":
        case "canonical": return (f.canonical_engine ?? "").toLowerCase().includes(v);
        case "engine":   return (f.engines ?? []).some((engine) => engine.engine.toLowerCase().includes(v));
        case "disagreement": {
          const hasDisagreement = (f.reconciliation_count ?? f.reconciliation?.length ?? 0) > 0;
          return v === "true" || v === "1" ? hasDisagreement : !hasDisagreement;
        }
        default:         return f.title.toLowerCase().includes(v) || (f.external_id ?? "").toLowerCase().includes(v);
      }
    }
    return f.title.toLowerCase().includes(tok) ||
      (f.external_id ?? "").toLowerCase().includes(tok) ||
      formatPackage(f).toLowerCase().includes(tok);
  })();
  return neg ? !result : result;
}

function isKev(f: Finding): boolean {
  // Backend hasn't surfaced KEV yet on findings; mark critical+vulnerability
  // pairs with high risk as proxy KEV until field is added.
  return f.severity === "critical" && f.kind === "vulnerability" && f.risk_score >= 88;
}

function formatPackage(f: Finding): string {
  const name = f.package_name ?? f.affected_range?.package_name;
  if (!name) return "—";
  const version = f.package_version ? `@${f.package_version}` : "";
  const ecosystem = f.package_ecosystem ? ` (${f.package_ecosystem})` : "";
  return `${name}${version}${ecosystem}`;
}

function groupRows(rows: Finding[], by: GroupBy): Array<{ label: string; items: Finding[] }> {
  if (by === "none") return [{ label: "All", items: rows }];
  const map = new Map<string, Finding[]>();
  for (const f of rows) {
    const key = by === "severity" ? f.severity : by === "kind" ? f.kind : f.asset_id;
    if (!map.has(key)) map.set(key, []);
    map.get(key)!.push(f);
  }
  let entries = Array.from(map.entries());
  if (by === "severity") {
    const order: Severity[] = ["critical", "high", "medium", "low", "info"];
    entries = entries.sort((a, b) => order.indexOf(a[0] as Severity) - order.indexOf(b[0] as Severity));
  } else {
    entries.sort((a, b) => b[1].length - a[1].length);
  }
  return entries.map(([label, items]) => ({ label, items }));
}
