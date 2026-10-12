import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { assets, deployments, findings, nodes, network, enterprise, fileProfiles, compliance, type AssetDetail, type DeploymentDetail, type Finding, type NodeDetail } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TestRouter } from "@/test/router";
import { RiskDetailPage } from "./RiskDetailPage";

const state = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster", name: "Demo" } as { id: string; name: string } | undefined, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => state }));
vi.mock("@/api/client", () => ({ assets: { get: vi.fn() }, deployments: { get: vi.fn() }, findings: { get: vi.fn(), list: vi.fn(), exportCSV: vi.fn() }, nodes: { get: vi.fn() }, network: { map: vi.fn() }, enterprise: { runtime: vi.fn() }, fileProfiles: { get: vi.fn() }, compliance: { summary: vi.fn() } }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
const assetID = "11111111-1111-4111-8111-111111111111";
const asset = (): AssetDetail => ({ asset: { id: assetID, cluster_id: "cluster", kind: "host", name: "exact-asset", criticality: "high", labels: {}, ai_workload: false, finding_count: 0, critical_findings: 0, high_findings: 0, open_findings: 0, sbom_count: 0, first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z" }, findings: [], sboms: [], image_acceptances: [] });
const finding = (id = "finding", severity: Finding["severity"] = "high"): Finding => ({ id, asset_id: assetID, cluster_id: "cluster", kind: "vulnerability", title: `Finding ${id}`, severity, lifecycle: "open", risk_score: 42, attack_techniques: [], first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z" });
const node = (): NodeDetail => ({ node: { node: "node-a", cluster_id: "cluster", last_seen_at: "2026-10-12T00:00:00Z", last_scanned_at: "2026-10-12T00:00:00Z", scan_status: "completed", runtime_agent_status: "healthy", open_vulns: 303, critical_vulns: 200, high_vulns: 103, coverage_gaps: [] }, vulnerabilities: [], processes: { items: [{ pid: 101, comm: "node-process", cmdline: "actual command", uid: 0 }] }, cis: { checks: [{ id: "1.1.1", title: "Node CIS check", result: "fail", detail: "actual CIS evidence" }] } } as unknown as NodeDetail);
const deployment = (): DeploymentDetail => ({ id: "deployment", cluster_id: "cluster", name: "app", namespace: "payments", kind: "Deployment", labels: {}, risk_score: 73, risk_factors: { vulnerabilities: 55 }, finding_count: 905, critical_count: 605, high_count: 300, first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z", image_refs: [], workload_ids: ["payments/app"], images: [], package_evidence: [], findings: [{ ...finding("deployment-direct"), target_type: "workload", target_ref: "payments/app" }], runtime_events: [{ id: "runtime", kind: "process_exec", workload_id: "payments/app", node_id: "node-a", source: "agent", severity: "high", verdict: "deny", at: "2026-10-12T00:00:00Z", payload: {}, attack_techniques: [] }], network_flows: [{ id: "flow", src: "payments/app", dst: "payments/db", dst_port: 5432, protocol: "TCP", verdict: "block", bytes: 100, packets: 2, last_seen_at: "2026-10-12T00:00:00Z" }], threat_pivots: [], file_risks: [], violations: [], compliance_evidence: [{ id: "check", framework: "cis", control_id: "5.2.2", title: "Deployment control", severity: "high", status: "fail", effective_status: "fail", source: "agent", target_kind: "workload", target: "payments/app", evidence: "actual deployment evidence", observed_at: "2026-10-12T00:00:00Z" }], process_baseline: { cluster_id: "cluster", workload_id: "payments/app", control_workload_id: "payments/app", mode: "monitor", learned_processes_count: 1, monitored_alerts_24h: 1, enforced_blocks_24h: 0, processes: [{ name: "actual-process", args: [], path: "/bin/process", observed_count: 3, first_seen: "2026-10-12T00:00:00Z", last_seen: "2026-10-12T00:00:00Z" }] }, file_profile: { cluster_id: "cluster", workload_id: "payments/app", control_workload_id: "payments/app", mode: "monitor", learned_paths_count: 1, sensitive_path_count: 0, rule_count: 0, watched_file_count: 0, monitored_alerts_24h: 0, enforced_blocks_24h: 0, files: [{ path: "/actual-file", operation: "read", observed_count: 3, sensitive: false, flags: 0, mode: 0, first_seen: "2026-10-12T00:00:00Z", last_seen: "2026-10-12T00:00:00Z" }], rules: [], exceptions: [], watched_files: [] } });
const response = (rows: Finding[], total = rows.length) => ({ findings: rows, total, limit: 100, offset: 0, has_more: total > rows.length, lifecycle_counts: { open: total, in_progress: 0, accepted: 0, suppressed: 0, triaged: 0, resolved: 0 } });
let host: HTMLDivElement; let root: Root | undefined; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  Object.assign(state, { clusterId: "cluster", cluster: { id: "cluster", name: "Demo" }, isLoading: false, error: null });
  localStorage.clear();
  vi.mocked(assets.get).mockResolvedValue(asset()); vi.mocked(deployments.get).mockResolvedValue(deployment()); vi.mocked(nodes.get).mockResolvedValue(node()); vi.mocked(findings.get).mockResolvedValue(finding());
  vi.mocked(findings.list).mockImplementation(async params => response(params?.q?.includes("severity:critical") ? [finding("critical", "critical")] : params?.q?.includes("severity:high") ? [finding("high")] : [finding("generic")]));
});
afterEach(() => { act(() => root?.unmount()); root = undefined; client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function render(type = "asset", id = assetID, search = "", seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); seed?.(client);
  history = createMemoryHistory({ initialEntries: [`/clusters/cluster/risk/${type}/${id}${search}`] });
  await act(async () => root!.render(<QueryClientProvider client={client}><TestRouter history={history} path="/clusters/$clusterId/risk/$entityType/$entityId"><RiskDetailPage /></TestRouter></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
const button = (label: string) => [...host.querySelectorAll("button")].find(item => item.textContent?.trim() === label)!;
async function tab(label: string) { await act(async () => { [...host.querySelectorAll('[role="tab"]')].find(item => item.textContent === label)!.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true })); }); }

it.each(["loading", "missing", "wrong", "error", "transition"])("suppresses all entity queries and cached evidence for %s scope", async condition => {
  if (condition === "loading") state.isLoading = true;
  if (condition === "missing") state.cluster = undefined;
  if (condition === "wrong") state.cluster = { id: "other", name: "Foreign" };
  if (condition === "error") state.error = new Error("lookup failed");
  if (condition === "transition") state.clusterId = undefined;
  await render("asset", assetID, "", q => q.setQueryData(["risk-entity", state.clusterId, "asset", assetID], { type: "asset", data: asset() }));
  await settled(() => expect(host.querySelector('[data-testid="risk-summary"]')).not.toBeNull());
  expect(assets.get).not.toHaveBeenCalled(); expect(findings.list).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("exact-asset"); expect(host.textContent).not.toContain("Foreign");
  expect(host.querySelector('[data-testid="risk-summary"]')?.children).toHaveLength(5); expect(host.querySelector('[role="tab"]')).toBeNull();
});

it.each(["asset", "deployment", "finding", "node"])("rejects a foreign-cluster %s entity before loading associated evidence", async type => {
  const a = asset(); a.asset.cluster_id = "other"; const d = deployment(); d.cluster_id = "other"; const f = finding(); f.cluster_id = "other"; const n = node(); n.node.cluster_id = "other";
  vi.mocked(assets.get).mockResolvedValue(a); vi.mocked(deployments.get).mockResolvedValue(d); vi.mocked(findings.get).mockResolvedValue(f); vi.mocked(nodes.get).mockResolvedValue(n);
  await render(type, type === "asset" ? assetID : type === "node" ? "node-a" : type);
  await settled(() => expect(host.textContent).toContain("Entity does not match this cluster"));
  expect(findings.list).not.toHaveBeenCalled(); expect(host.querySelector('[role="tab"]')).toBeNull(); expect(host.textContent).not.toContain("Finding finding");
});

it("resolves nodes through exact cluster/node lookup and displays actual host evidence", async () => {
  await render("node", "node-a", "?tab=process"); await settled(() => expect(host.textContent).toContain("node-process"));
  expect(nodes.get).toHaveBeenCalledWith("cluster", "node-a"); expect(assets.get).not.toHaveBeenCalled(); expect(findings.list).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="risk-summary"]')?.textContent).toContain("200"); expect(host.textContent).toContain("Not reported");
  await tab("Compliance"); await settled(() => expect(host.textContent).toContain("actual CIS evidence")); expect(history.location.search).toBe("?tab=compliance");
});

it("shows only server-reported finding risk decomposition", async () => {
  vi.mocked(findings.get).mockResolvedValue({ ...finding(), risk: { composite: 42, factors: [{ name: "actual_factor", description: "Reported explanation", score: 11, raw: 20, weight: 0.55 }] } });
  await render("finding", "finding"); await settled(() => expect(host.textContent).toContain("11 weighted points"));
  expect(findings.get).toHaveBeenCalledWith("finding"); expect(findings.list).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("Exploitability"); expect(host.textContent).not.toContain("Generate runbook"); expect(host.textContent).not.toContain("watch list"); expect(host.textContent).toContain("Reported risk: 42/100");
});

it("uses server asset/cluster filters, exact full totals, URL paging and full-source export", async () => {
  vi.mocked(findings.list).mockImplementation(async params => {
    if (params?.q?.includes("severity:critical")) return response([finding("critical", "critical")], 195);
    if (params?.q?.includes("severity:high")) return response([finding("high")], 53);
    return { ...response(Array.from({ length: params?.offset === 300 ? 5 : 100 }, (_, index) => finding(String((params?.offset ?? 0) + index + 1))), 305), lifecycle_counts: { open: 201, in_progress: 8, accepted: 20, suppressed: 30, triaged: 20, resolved: 26 } };
  });
  await render("asset", assetID, "?tab=findings&findings_page=3"); await settled(() => expect(host.textContent).toContain("305 matching generic records"));
  expect(findings.list).toHaveBeenCalledWith({ cluster_id: "cluster", q: `asset:${assetID}`, limit: 100, offset: 200, sort: "risk", order: "desc" });
  const summary = host.querySelector('[data-testid="risk-summary"]')!;
  await settled(() => { expect(summary.textContent).toContain("195"); expect(summary.textContent).toContain("53"); expect(summary.textContent).toContain("209"); });
  expect(host.querySelector('[data-testid="risk-generic-findings"] tbody')?.children).toHaveLength(100);
  await act(async () => button("Next").click()); await settled(() => expect(host.textContent).toContain("Finding 305")); expect(history.location.search).toBe("?tab=findings&findings_page=4");
  await act(async () => button("Export matching records (up to 10,000)").click()); expect(findings.exportCSV).toHaveBeenCalledWith({ cluster_id: "cluster", q: `asset:${assetID}`, sort: "risk", order: "desc", limit: 10000 });
  expect(host.querySelector('a[href="/clusters/cluster/findings/305"]')).not.toBeNull(); expect(host.querySelector('[data-testid="scope-bar"]')).toBeNull();
});

it("reports failed or foreign asset findings without cached rows or healthy zeros", async () => {
  await render("asset", assetID, "?tab=findings"); await settled(() => expect(host.textContent).toContain("Finding generic"));
  vi.mocked(findings.list).mockRejectedValue(new Error("source failed")); await act(async () => { await client.invalidateQueries({ queryKey: ["risk-related"] }); });
  await settled(() => expect(host.textContent).toContain("Could not load asset finding records")); expect(host.textContent).not.toContain("Finding generic"); expect(button("Export matching records (up to 10,000)").disabled).toBe(true);
  expect(host.textContent).not.toContain("No findings in this source response");
  vi.mocked(findings.list).mockResolvedValue(response([{ ...finding("foreign"), asset_id: "other", cluster_id: "other" }])); await act(async () => { await client.invalidateQueries({ queryKey: ["risk-related"] }); });
  await settled(() => expect(host.textContent).toContain("Finding evidence does not match this asset and cluster")); expect(host.textContent).not.toContain("Finding foreign"); expect(button("Export matching records (up to 10,000)").disabled).toBe(true);
});

it("suppresses a cached entity after its refresh fails", async () => {
  await render("deployment", "deployment"); await settled(() => expect(host.textContent).toContain("Reported risk: 73/100"));
  vi.mocked(deployments.get).mockRejectedValue(new Error("entity failed")); await act(async () => { await client.invalidateQueries({ queryKey: ["risk-entity"] }); });
  await settled(() => expect(host.textContent).toContain("Entity evidence unavailable")); expect(host.textContent).not.toContain("payments/app"); expect(host.textContent).not.toContain("Reported risk: 73"); expect(host.querySelector('[role="tab"]')).toBeNull();
});

it.each(["network", "process", "files", "compliance"])("does not invent an asset-to-%s mapping or query unrelated cluster sources", async name => {
  await render("asset", assetID, `?tab=${name}`); await settled(() => expect(host.textContent).toContain("mapping not reported"));
  for (const fn of [network.map, enterprise.runtime, fileProfiles.get, compliance.summary]) expect(fn).not.toHaveBeenCalled();
  expect(host.textContent).not.toContain("No runtime events for this workload"); expect(host.querySelector(`a[href="/clusters/cluster/assets/${assetID}"]`)).not.toBeNull();
});

it("uses embedded deployment evidence with source limits and exact directed network links", async () => {
  await render("deployment", "deployment", "?tab=network"); await settled(() => expect(host.textContent).toContain("payments/db"));
  expect(deployments.get).toHaveBeenCalledWith("deployment"); expect(findings.list).not.toHaveBeenCalled(); expect(host.textContent).toContain("At most 50 network flows");
  expect(host.querySelector('a[href="/clusters/cluster/network?tab=conversations&hours=24&from=payments%2Fapp&to=payments%2Fdb&hide_platform=false"]')).not.toBeNull();
  await tab("Process"); await settled(() => expect(host.textContent).toContain("actual-process")); expect(host.textContent).toContain("Latest 50 events"); expect(host.textContent).toContain("No 24-hour time bound");
  await tab("Compliance"); await settled(() => expect(host.textContent).toContain("actual deployment evidence")); expect(compliance.summary).not.toHaveBeenCalled();
});

it("makes every returned file path accessible and exports all available rows", async () => {
  const d = deployment(); const first = d.file_profile!.files[0]; d.file_profile!.files = Array.from({ length: 165 }, (_, index) => ({ ...first, path: `/file-${index + 1}` }));
  vi.mocked(deployments.get).mockResolvedValue(d);
  await render("deployment", "deployment", "?tab=files"); await settled(() => expect(host.textContent).toContain("/file-100"));
  expect(host.textContent).not.toContain("/file-165"); await act(async () => button("Next").click()); expect(host.textContent).toContain("/file-165");
  const exportButton = host.querySelector<HTMLButtonElement>('[aria-label="Export CSV"]')!; await act(async () => exportButton.click());
  expect(downloadCsv).toHaveBeenCalledWith("risk-returned-deployment-files", expect.any(Array), expect.any(Array)); expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(165);
  expect(host.textContent).toContain("configured rules alone do not prove enforcement");
});

it("separates canonical image findings from generic lifecycle totals", async () => {
  const a = asset(); a.asset.kind = "image"; a.findings = [{ id: "canonical", image_scan_result_id: "scan", external_id: "CVE-CANONICAL", title: "Canonical image finding", kind: "vulnerability", severity: "critical", lifecycle: "open", risk_score: 88, last_seen_at: "2026-10-12T00:00:00Z" }];
  vi.mocked(assets.get).mockResolvedValue(a); await render("asset", assetID, "?tab=findings"); await settled(() => expect(host.textContent).toContain("Canonical image finding"));
  expect(host.textContent).toContain("Generic finding records"); expect(host.querySelector('a[href="/clusters/cluster/findings/canonical"]')).toBeNull(); expect(host.querySelector('a[href="/cve/CVE-CANONICAL"]')).not.toBeNull(); expect(host.textContent).not.toContain("Reported risk: 88");
});

it("does not turn missing host scan/CIS evidence into a passing assessment", async () => {
  const n = node(); n.node.last_scanned_at = undefined; n.cis = undefined;
  vi.mocked(nodes.get).mockResolvedValue(n); await render("node", "node-a", "?tab=compliance"); await settled(() => expect(host.textContent).toContain("Compliance is not established"));
  expect(host.querySelector('[data-testid="risk-summary"]')?.textContent).not.toContain("303"); expect(host.textContent).not.toContain("0% pass");
});


it("rejects unsafe finding offsets before querying and offers a URL reset", async () => {
  await render("asset", assetID, "?tab=findings&findings_page=9007199254740991");
  await settled(() => expect(host.textContent).toContain("This finding page cannot be queried safely"));
  expect(findings.list).not.toHaveBeenCalled(); expect(button("Export matching records (up to 10,000)").disabled).toBe(true);
  await act(async () => button("Return to first page").click());
  await settled(() => expect(host.textContent).toContain("Finding generic")); expect(history.location.search).toBe("?tab=findings");
  expect(findings.list).toHaveBeenCalledWith(expect.objectContaining({ offset: 0 }));
});

it("shows capped export pending and failure feedback without dropping filters", async () => {
  let fail!: (error: Error) => void;
  vi.mocked(findings.exportCSV).mockImplementation(() => new Promise((_resolve, reject) => { fail = reject; }));
  await render("asset", assetID, "?tab=findings"); await settled(() => expect(button("Export matching records (up to 10,000)")?.disabled).toBe(false));
  await act(async () => button("Export matching records (up to 10,000)").click());
  await settled(() => expect(button("Exporting…")?.disabled).toBe(true));
  expect(findings.exportCSV).toHaveBeenCalledWith({ cluster_id: "cluster", q: `asset:${assetID}`, sort: "risk", order: "desc", limit: 10000 });
  await act(async () => fail(new Error("download failed")));
  await settled(() => expect(host.textContent).toContain("Could not export asset finding records")); expect(button("Export matching records (up to 10,000)").disabled).toBe(false); expect(history.location.search).toBe("?tab=findings");
});

it("keeps embedded flow endpoint roles in risk network CSV",async()=>{
 const d=deployment();d.network_flows=[{...d.network_flows[0],cluster_id:"cluster",src_platform_role:"core",dst_platform_role:""}];vi.mocked(deployments.get).mockResolvedValue(d);await render("deployment","deployment","?tab=network");await settled(()=>expect(host.textContent).toContain("Not classified"));expect(host.textContent).toContain("From role");expect(host.textContent).toContain("To role");await act(async()=>host.querySelector<HTMLButtonElement>('[data-testid="risk-network-tab"] [aria-label="Export CSV"]')!.click());const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;expect(headers).toContain("src_platform_role");expect(headers).toContain("dst_platform_role");expect(rows[0][headers.indexOf("src_platform_role")]).toBe("core");expect(rows[0][headers.indexOf("dst_platform_role")]).toBe("");
});
it("keeps embedded runtime cluster and role in risk process CSV",async()=>{
 const d=deployment();d.runtime_events=[{...d.runtime_events[0],cluster_id:"cluster",platform_role:"core"}];vi.mocked(deployments.get).mockResolvedValue(d);await render("deployment","deployment","?tab=process");await settled(()=>expect(host.textContent).toContain("Platform role"));const table=[...host.querySelectorAll('[data-testid="risk-process-tab"] table')].find(item=>item.textContent?.includes("Platform role"))!;expect(table.textContent).toContain("core");expect(table.textContent).toContain("cluster");await act(async()=>table.closest('.app-data-table')!.querySelector<HTMLButtonElement>('[aria-label="Export CSV"]')!.click());const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;expect(rows[0][headers.indexOf("platform_role")]).toBe("core");expect(rows[0][headers.indexOf("cluster_id")]).toBe("cluster");
});

it.each(["network","process"])("withholds foreign embedded deployment evidence in risk%s",async kind=>{
 const d=deployment();d.network_flows=[{...d.network_flows[0],cluster_id:"foreign",src:"private/source"}];d.runtime_events=[{...d.runtime_events[0],cluster_id:"foreign",workload_id:"private/workload"}];vi.mocked(deployments.get).mockResolvedValue(d);await render("deployment","deployment",`?tab=${kind}`);await settled(()=>expect(host.textContent).toContain(`Embedded ${kind==="network"?"network flows":"runtime events"} do not match this cluster`));expect(host.textContent).not.toContain(kind==="network"?"private/source":"private/workload");expect(downloadCsv).not.toHaveBeenCalled();
});

it("exports the selected finding's actual platform role when its optional column is selected", async () => {
  vi.mocked(findings.get).mockResolvedValue({ ...finding(), platform_role: "core" });
  await render("finding", "finding", "?tab=findings"); await settled(() => expect(host.querySelector('[data-testid="risk-generic-findings"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="risk-generic-findings"] thead')?.textContent).not.toContain("Platform role");
  await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="risk-generic-findings-columns-trigger"]')!.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, button: 0 })));
  await settled(() => expect(document.querySelector('[role="menuitemcheckbox"]')).not.toBeNull());
  await act(async () => [...document.querySelectorAll<HTMLElement>('[role="menuitemcheckbox"]')].find(item => item.textContent === "Platform role")!.click());
  expect(host.querySelector('[data-testid="risk-generic-findings"] tbody')?.textContent).toContain("Core");
  await act(async () => button("Export returned findings").click());
  const [, headers, rows] = vi.mocked(downloadCsv).mock.calls.at(-1)!;
  expect(rows[0][headers.indexOf("Platform role")]).toBe("core");
});
