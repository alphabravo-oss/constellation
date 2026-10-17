import { useQuery } from "@tanstack/react-query";
import { compliance, type ComplianceEvidenceItem, type ComplianceEvidenceParams, type ComplianceEvidenceResponse } from "@/api/client";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useRouteSearchParams } from "@/lib/route-search";
import { useDebounced } from "@/hooks/useDebounced";
import { Button } from "@/components/ui/button";
import { DigestDisclosure } from "@/components/ui/digest-disclosure";
import { Collapse } from "@/components/ui/collapse";
import { DataTable, type Column } from "@/components/ui/data-table";
import { Field, Select, TextInput } from "@/components/ui/form";
import { Pager } from "@/components/ui/pager";
import { EmptyState, ErrorState, LoadingState } from "@/components/ui/states";
import { ScanInventoryExport } from "./inventory-workspace";

const scopes = ["", "kubernetes", "node", "workload", "cloud"];
const statuses = ["", "pass", "fail", "manual", "not_applicable", "exempted"];
const sorts = ["observed", "scope", "target", "framework", "control", "status", "severity"];
const statusKeys = ["pass", "fail", "manual", "not_applicable", "exempted"] as const;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function summaryShapeValid(value: unknown) {
  if (!isRecord(value) || !Number.isSafeInteger(value.total) || (value.total as number) < 0) return false;
  return statusKeys.every(key => Number.isSafeInteger(value[key]) && (value[key] as number) >= 0)
    && statusKeys.reduce((sum, key) => sum + (value[key] as number), 0) === value.total;
}

function evidenceRowShapeValid(value: unknown): value is ComplianceEvidenceItem {
  if (!isRecord(value)) return false;
  const requiredText = ["id", "scope", "source", "framework", "control_id", "title", "severity", "status", "effective_status", "target_kind", "target", "observed_at"];
  if (!requiredText.every(key => typeof value[key] === "string") || !value.id || !scopes.slice(1).includes(value.scope as string) || !Number.isFinite(Date.parse(value.observed_at as string))) return false;
  if (!["internal_id", "cluster_id", "namespace", "evidence", "remediation"].every(key => value[key] === undefined || typeof value[key] === "string")) return false;
  const exemption = value.exemption;
  if (exemption !== undefined && (!isRecord(exemption) || !["id", "reason", "expires_at"].every(key => typeof exemption[key] === "string") || !exemption.id || !Number.isFinite(Date.parse(exemption.expires_at as string)))) return false;
  return true;
}

// eslint-disable-next-line react-refresh/only-export-components
export function evidenceResponseMatches(data: ComplianceEvidenceResponse | null | undefined, request: ComplianceEvidenceParams) {
  if (!isRecord(data) || !summaryShapeValid(data.summary) || !Array.isArray(data.items) || !data.items.every(evidenceRowShapeValid)) return false;
  const total = data.total;
  if (!Number.isSafeInteger(total) || total! < 0 || data.summary.total !== total) return false;
  if (data.summary.by_scope !== undefined) {
    if (!isRecord(data.summary.by_scope) || !Object.entries(data.summary.by_scope).every(([scope, summary]) => scopes.slice(1).includes(scope) && summaryShapeValid(summary))) return false;
    if (["total", ...statusKeys].some(key => Object.values(data.summary.by_scope!).reduce((sum, summary) => sum + summary[key as keyof typeof summary], 0) !== data.summary[key as keyof typeof data.summary])) return false;
  }
  if (data.cluster_id !== request.cluster_id || data.limit !== request.limit || data.offset !== request.offset || data.sort !== request.sort || data.order !== request.order) return false;
  if (!["scope", "framework", "namespace", "control_id", "status", "q", "target"].every(key => {
    const value = data[key as keyof ComplianceEvidenceResponse];
    return (value === undefined || typeof value === "string") && (value || "") === (request[key as keyof ComplianceEvidenceParams] || "");
  })) return false;
  const rows = data.items;
  return rows.length === Math.min(request.limit!, Math.max(0, total! - request.offset!))
    && data.has_more === (total! > request.offset! + rows.length)
    && new Set(rows.map(row => row.id)).size === rows.length
    && rows.every(row => (!row.cluster_id || row.cluster_id === request.cluster_id)
      && (!request.scope || row.scope === request.scope)
      && (!request.framework || row.framework === request.framework)
      && (!request.control_id || row.control_id === request.control_id)
      && (!request.status || (statuses.includes(row.effective_status) ? row.effective_status : "manual") === request.status)
      && (!request.target || row.target === request.target)
      && (!request.namespace || row.scope !== "workload" || row.namespace === request.namespace));
}

function EvidenceText({ value }: { value: string }) {
  const digests = [...new Set(value.match(/sha256:[a-fA-F0-9]{64}/g) || [])];
  return <><span>{value.replace(/sha256:[a-fA-F0-9]{64}/g, "[digest]")}</span>{digests.map(digest => <DigestDisclosure key={digest} digest={digest} />)}</>;
}

const columns: Column<ComplianceEvidenceItem>[] = [
  { id: "scope", header: "Scope", kind: "status", size: 120, sort: () => 0, cell: row => row.scope, exportValue: row => row.scope },
  { id: "target", header: "Target", kind: "name", minSize: 220, grow: true, wrap: true, sort: () => 0, cell: row => <><div><EvidenceText value={row.target} /></div><div className="text-xs text-muted-foreground">{row.target_kind}</div></>, exportValue: row => row.target },
  { id: "framework", header: "Framework", kind: "text", minSize: 180, wrap: true, sort: () => 0, cell: row => row.framework, exportValue: row => row.framework },
  { id: "control", header: "Control", kind: "id", minSize: 180, wrap: true, sort: () => 0, cell: row => <><div>{row.control_id}</div><div className="text-xs text-muted-foreground">{row.title}</div></>, exportValue: row => `${row.framework} · ${row.control_id}` },
  { id: "status", header: "Status", kind: "status", size: 144, sort: () => 0, cell: row => <><div>{row.effective_status}</div>{row.exemption && <div className="text-xs text-muted-foreground">Exempt until {row.exemption.expires_at} · {row.exemption.reason}</div>}</>, exportValue: row => row.effective_status },
  { id: "severity", header: "Severity", kind: "badge", size: 112, sort: () => 0, cell: row => row.severity, exportValue: row => row.severity },
  { id: "evidence", header: "Evidence", kind: "text", minSize: 280, grow: true, wrap: true, cell: row => <EvidenceText value={row.evidence || "No evidence text"} />, exportValue: row => row.evidence || "" },
  { id: "observed", header: "Observed", kind: "date", size: 224, sort: () => 0, cell: row => new Date(row.observed_at).toLocaleString(), exportValue: row => row.observed_at },
];

export function ComplianceEvidenceInventory({ clusterId, ready, active }: { clusterId: string; ready: boolean; active: boolean }) {
  const identity = useTablePreferencesIdentity();
  const owner = identity?.org_id && identity.user_id ? `${identity.org_id}:${identity.user_id}` : "";
  const [params, setParams] = useRouteSearchParams();
  const get = (key: string) => params.get(`evidence_${key}`) || "";
  const query = get("q");
  const debounced = useDebounced(query, 250);
  const rawPage = get("page");
  const page = rawPage ? Number(rawPage) - 1 : 0;
  const sort = get("sort") || "observed";
  const order = get("order") || "desc";
  const valid = scopes.includes(get("scope")) && statuses.includes(get("status")) && sorts.includes(sort) && ["asc", "desc"].includes(order) && (!rawPage || /^\d+$/.test(rawPage) && Number.isSafeInteger(page) && page >= 0 && page <= 10000);
  const update = (changes: Record<string, string | null>, reset = true, replace = false) => setParams(current => {
    const next = new URLSearchParams(current);
    for (const [key, value] of Object.entries(changes)) { if (!value) next.delete(`evidence_${key}`); else next.set(`evidence_${key}`, value); }
    if (reset) next.delete("evidence_page");
    return next;
  }, { replace });
  const request: ComplianceEvidenceParams = { cluster_id: clusterId, scope: get("scope") || undefined, framework: get("framework").trim() === "all" ? undefined : get("framework").trim() || undefined, namespace: get("namespace").trim() || undefined, control_id: get("control_id").trim() || undefined, status: get("status") || undefined, q: debounced.trim() || undefined, target: get("target").trim() || undefined, sort, order: order as "asc" | "desc", limit: 100, offset: valid ? page * 100 : 0 };
  const key = ["compliance", "evidence", owner, request];
  const source = useQuery({ queryKey: key, queryFn: () => compliance.evidence(request), enabled: ready && active && !!owner && valid && query === debounced });
  const invalid = (source.data !== undefined || source.isSuccess) && !evidenceResponseMatches(source.data, request);
  const available = active && ready && !!owner && valid && query === debounced && source.isSuccess && !source.isFetching && !invalid;
  const data = available ? source.data : undefined;
  return <section className="space-y-4" data-testid="compliance-evidence-panel">
    <div className="flex flex-wrap items-end gap-3">
      <Field label="Evidence scope" htmlFor="evidence-scope"><Select id="evidence-scope" value={get("scope")} onChange={event => update({ scope: event.target.value })}>{scopes.map(value => <option key={value} value={value}>{value || "All sources"}</option>)}</Select></Field>
      <Field label="Evidence status" htmlFor="evidence-status"><Select id="evidence-status" value={get("status")} onChange={event => update({ status: event.target.value })}>{statuses.map(value => <option key={value} value={value}>{value.replaceAll("_", " ") || "All statuses"}</option>)}</Select></Field>
      <Field label="Search source evidence" htmlFor="evidence-search" className="min-w-56 flex-1"><TextInput id="evidence-search" value={query} onChange={event => update({ q: event.target.value }, true, true)} /></Field>
      <Button disabled={!ready || !owner || !valid || source.isFetching || query !== debounced} onClick={() => void source.refetch()}>Refresh source evidence</Button>
    </div>
    <Collapse label="Advanced: exact evidence filters">
      <div className="grid gap-3 sm:grid-cols-2">{[["framework", "Exact framework"], ["control_id", "Exact control"], ["namespace", "Workload namespace"], ["target", "Exact target"]].map(([key, label]) => <Field key={key} label={label} htmlFor={`evidence-${key}`}><TextInput id={`evidence-${key}`} value={get(key)} onChange={event => update({ [key]: event.target.value }, true, true)} /></Field>)}</div>
      <p className="mt-2 text-xs text-muted-foreground">Namespace filters apply to workload evidence. Node, Kubernetes and cloud retain their existing source scope. Exact target and framework filters apply to every source.</p>
    </Collapse>
    {!valid ? <ErrorState title="The requested evidence filter or page is invalid." action={<Button onClick={() => update({ scope: null, status: null, sort: null, order: null, page: null })}>Reset evidence filters</Button>} /> : !ready || !owner ? <ErrorState title="Resolve the current cluster and account before loading source evidence." /> : source.isError || invalid ? <ErrorState title="Compliance source evidence could not be loaded or refreshed. Counts and export are unavailable." action={<Button onClick={() => void source.refetch()}>Retry evidence</Button>} /> : !data ? <LoadingState label="Loading evidence…" /> : <>
      <p className="text-sm text-muted-foreground">{data.total!.toLocaleString()} source evidence rows match these filters.</p>
      <ScanInventoryExport context={JSON.stringify(key)} disabled={!available} download={shouldDownload => compliance.exportEvidenceCSV(request, shouldDownload)} />
      <Collapse label="Evidence status details">
        <p className="mb-2 text-sm text-muted-foreground">Each source record and framework mapping counts separately. Summaries cover all matches across pages; manual includes unrecognized source statuses. Page CSV uses visible columns; matching CSV includes all fields, up to 100,000 rows.</p>
        <div data-testid="compliance-evidence-summary" className="space-y-2 text-sm"><p>{statusKeys.map(key => `${data.summary[key]} ${key.replaceAll("_", " ")}`).join(" · ")}</p>{Object.entries(data.summary.by_scope || {}).map(([scope, summary]) => <p key={scope}>{scope}: {summary.total} matching rows · {summary.fail} failing · {summary.exempted} exempted</p>)}</div></Collapse>
      <DataTable testId="compliance-source-evidence-table" rows={data.items} columns={columns} rowKey={row => row.id} preferencesKey="compliance-evidence" exportFileName="compliance-evidence-page.csv" pagination={false} manualSorting sort={{ id: sort, dir: order as "asc" | "desc" }} onSortChange={next => update({ sort: next?.id || null, order: next?.dir || null })} emptyState={<EmptyState title="No source evidence matches these filters" hint="A filtered empty cohort does not establish cluster compliance." />} />
      {page > 0 && data.items.length === 0 && <Button onClick={() => update({ page: null }, false)}>First page</Button>}
      <Pager page={page} pageSize={100} total={data.total} rowsOnPage={data.items.length} onPage={next => update({ page: next ? String(next + 1) : null }, false)} />
    </>}
  </section>;
}
