import { deploymentFindingPage, deploymentFindingFixture } from "./deployment-findings/test-fixtures";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { deployments, fileProfiles, type DeploymentDetail } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TestRouter } from "@/test/router";
import { DeploymentDetailPage } from "./DeploymentDetailPage";
import { fixtureDeployment, fixturePolicy } from "./deployment-detail/test-fixtures";
const scope = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ deployments: { get: vi.fn(), findings: vi.fn(), findingsCSV: vi.fn() }, fileProfiles: { exportBundle: vi.fn() } }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let root: Root | undefined; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
 vi.mocked(deployments.findings).mockImplementation(async (_id, params) => deploymentFindingPage(params));vi.mocked(deployments.findingsCSV).mockResolvedValue({total:1,exported:1,limit:100000,truncated:false}); (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); localStorage.clear(); vi.mocked(deployments.get).mockResolvedValue(fixtureDeployment()); });
afterEach(() => { act(() => root?.unmount()); root = undefined; client?.clear(); host?.remove(); vi.restoreAllMocks(); vi.resetAllMocks(); });
async function render(search = "", seed?: (client: QueryClient) => void) {
 host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); seed?.(client);
 history = createMemoryHistory({ initialEntries: [`/clusters/cluster/deployments/deployment${search}`] });
 await act(async () => root!.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{org_id:"org",user_id:"operator"}}><TestRouter history={history} path="/clusters/$clusterId/deployments/$did"><DeploymentDetailPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function tab(name: string) { await act(async () => [...host.querySelectorAll('[role="tab"]')].find((item) => item.textContent === name || item.getAttribute("aria-label") === name)!.dispatchEvent(new MouseEvent("mousedown", { button: 0, bubbles: true }))); }
const button = (label: string) => [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label)!;
it.each(["loading", "missing", "wrong", "error", "transition"])("blocks queries and cached deployment evidence for %s cluster", async condition => {
 if (condition === "loading") scope.isLoading = true; if (condition === "missing") scope.cluster = undefined; if (condition === "wrong") scope.cluster = { id: "other" }; if (condition === "error") scope.error = new Error("unavailable"); if (condition === "transition") scope.clusterId = undefined;
 await render("", qc => qc.setQueryData(["deployment", scope.clusterId, "deployment"], fixtureDeployment()));
 await settled(() => expect(host.querySelector('[data-testid="deployment-stats"]')).not.toBeNull()); expect(deployments.get).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("payments/app"); expect(host.querySelector('[role="tab"]')).toBeNull(); expect(host.querySelector('[data-testid="deployment-stats"]')?.textContent?.match(/—/g)).toHaveLength(5);
});
it.each(["foreign-cluster", "wrong-id", "failure"])("does not show a %s source as a deployment", async scenario => {
 if (scenario === "failure") vi.mocked(deployments.get).mockRejectedValue(new Error("failed")); else vi.mocked(deployments.get).mockResolvedValue({ ...fixtureDeployment(), ...(scenario === "foreign-cluster" ? { cluster_id: "other" } : { id: "other" }) });
 await render(); await settled(() => expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull()); expect(host.textContent).not.toContain("payments/app"); expect(host.querySelector('[role="tab"]')).toBeNull();
});
it("has five authoritative metrics and one URL workspace instead of every evidence section", async () => {
 await render(); await settled(() => expect(host.textContent).toContain("Reported deployment risk: 73/100")); expect(host.querySelector('[data-testid="deployment-stats"]')?.children).toHaveLength(5); expect(host.querySelector('[data-testid="deployment-stats"]')?.textContent).toContain("905"); expect(host.querySelector('[data-testid="deployment-file-profile"]')).toBeNull();
 await tab("Runtime"); await settled(() => expect(host.querySelector('[data-testid="deployment-process-baseline"]')).not.toBeNull()); expect(history.location.search).toBe("?tab=runtime"); expect(host.querySelector("input,textarea,select")).toBeNull();
 await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="deployment-process-baseline"]')).toBeNull());
});
it("suppresses cached detail after a failed refresh and retries", async () => {
 await render("?tab=files"); await settled(() => expect(host.querySelector('[data-testid="deployment-file-profile"]')).not.toBeNull()); vi.mocked(deployments.get).mockRejectedValue(new Error("refresh")); await act(async () => { await client.invalidateQueries({ queryKey: ["deployment"] }); });
 await settled(() => expect(host.textContent).toContain("Could not load or refresh deployment evidence")); expect(host.textContent).not.toContain("payments/app"); expect(host.querySelector('[data-testid="deployment-stats"]')?.textContent?.match(/—/g)).toHaveLength(5);
 vi.mocked(deployments.get).mockResolvedValue(fixtureDeployment()); await act(async () => button("Retry").click()); await settled(() => expect(host.querySelector('[data-testid="deployment-file-profile"]')).not.toBeNull());
});
it("routes all supported file authoring and modes to exact dedicated pages", async () => {
 await render("?tab=files"); await settled(() => expect(host.querySelector('[data-testid="deployment-file-profile"]')).not.toBeNull()); expect(host.querySelector("input,textarea,select")).toBeNull();
 for (const [testId, path] of [["deployment-file-profile-promote", "/actions/file-mode?mode=monitor"], ["deployment-file-profile-exception-add", "/actions/file-exception"]]) expect(host.querySelector(`[data-testid="${testId}"]`)?.getAttribute("href")).toBe(`/clusters/cluster/deployments/deployment${path}`);
 expect(host.querySelector('[data-testid="deployment-file-profile-rule-add"]')?.getAttribute("href")).toContain("/clusters/cluster/file-monitor/new?workload=payments%2Fapp&return_to=");
 expect(host.querySelector('[data-testid="deployment-file-profile-rule-delete"]')?.getAttribute("href")).toBe("/clusters/cluster/deployments/deployment/actions/file-rule-delete?rule=rule");
});
it("preserves network review, canonical approve/quarantine links, and remaining dedicated action links", async () => {
 const d = fixtureDeployment(); d.network_policy = { ...fixturePolicy(), approval_status: "pending" }; vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=network"); await settled(() => expect(host.querySelector('[data-testid="deployment-policy-approve"]')).not.toBeNull()); expect(host.querySelector("input,textarea,select")).toBeNull();
 expect(host.querySelector('[data-testid="deployment-policy-approve"]')?.getAttribute("href")).toContain("/clusters/cluster/network/actions/approve-policy?workload=payments%2Fapp"); expect(host.querySelector('[data-testid="deployment-quarantine-create"]')?.getAttribute("href")).toContain("/network/actions/quarantine?workload=payments%2Fapp");
 expect(host.querySelector('[data-testid="deployment-policy-demote"]')?.getAttribute("href")).toContain("/actions/demote-policy"); expect(host.querySelector('[data-testid="deployment-policy-rollback"]')?.getAttribute("href")).toContain("/actions/rollback-policy");
 await act(async () => button("Review candidate").click()); expect(host.textContent).toContain("kind: CiliumNetworkPolicy"); expect(host.textContent).toContain("Reported policy difference");
});
it("discloses actual source bounds and directed network pair links", async () => {
 const d = fixtureDeployment(); d.network_flows = [{ id: "flow", src: "payments/app", dst: "payments/db", protocol: "tcp", verdict: "deny", bytes: 10, packets: 2, last_seen_at: "2026-10-12T00:00:00Z" }]; vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=network"); await settled(() => expect(host.textContent).toContain("Latest 50 network flows")); expect(host.querySelector('a[href="/clusters/cluster/network?tab=conversations&hours=24&from=payments%2Fapp&to=payments%2Fdb&hide_platform=false"]')).not.toBeNull();
 await tab("Runtime"); await settled(() => expect(host.textContent).toContain("Latest 50 returned events")); expect(host.textContent).toContain("no 24-hour bound"); expect(host.textContent).toContain("Up to 60 returned");
});
it("makes all returned file observations and controls accessible, with complete returned-row export", async () => {
 const d = fixtureDeployment(); d.file_profile!.files = Array.from({ length: 165 }, (_, index) => ({ path: `/path-${index+1}`, operation: "read", flags: 0, mode: 0, observed_count: 1, sensitive: false, first_seen: "2026-10-12T00:00:00Z", last_seen: "2026-10-12T00:00:00Z" })); vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=files"); await settled(() => expect(host.textContent).toContain("/path-100")); await act(async () => button("Next").click()); expect(host.textContent).toContain("/path-165");
 await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="deployment-file-profile-paths"] [aria-label="Export returned evidence"]')!.click()); expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(165);
});
it("shows every returned compliance row instead of a ten-control teaser", async () => {
 const d = fixtureDeployment(); d.compliance_evidence = Array.from({ length: 15 }, (_, index) => ({ id: `c${index}`, source: "agent", framework: "cis", control_id: String(index+1), title: `Control ${index+1}`, severity: "high", status: "fail", effective_status: "fail", target_kind: "workload", target: "payments/app", evidence: "actual", observed_at: "2026-10-12T00:00:00Z" })); vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=compliance"); await settled(() => expect(host.textContent).toContain("Control 15")); expect(host.querySelector('[data-testid="deployment-compliance-evidence"] tbody')?.children).toHaveLength(15);
});
it("retains every package report and lets the user inspect its returned payload", async () => {
 const d = fixtureDeployment(); d.package_evidence = [{ id: "first", scan_target_id: "target", target_ref: "payments/app", workload_id: "payments/app", inventory_hash: "hash1", package_count: 2, container_count: 1, payload: { marker: "first-report" }, observed_at: "2026-10-12T00:00:00Z" }, { id: "second", scan_target_id: "target", target_ref: "payments/app", workload_id: "payments/owned-pod", inventory_hash: "hash2", package_count: 3, container_count: 1, payload: { marker: "second-report" }, observed_at: "2026-10-12T00:00:00Z" }] as DeploymentDetail["package_evidence"]; vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=packages"); await settled(() => expect(host.textContent).toContain("first-report")); await act(async () => host.querySelectorAll('[data-testid="deployment-package-evidence"] tbody tr')[1].dispatchEvent(new MouseEvent("click", { bubbles: true }))); expect(host.textContent).toContain("second-report"); expect(host.textContent).not.toContain("first-report");
});
it("rejects foreign nested profile or policy evidence instead of enabling its controls", async () => {
 const d = fixtureDeployment(); d.file_profile!.cluster_id = "other"; vi.mocked(deployments.get).mockResolvedValue(d); await render("?tab=files"); await settled(() => expect(host.textContent).toContain("File profile does not match this deployment")); expect(host.querySelector('[data-testid="deployment-file-profile-rule-add"]')).toBeNull(); expect(fileProfiles.exportBundle).not.toHaveBeenCalled();
});


it("resolves a selected threat from current evidence and closes it when removed", async () => {
  const d = fixtureDeployment(); d.threat_pivots = [{ id: "threat", kind: "file", has_packet: false, title: "Original threat", workload_id: "payments/app", node_id: "node", namespace: "payments", severity: "high", verdict: "alert", at: "2026-10-12T00:00:00Z", file: { path: "/old-path" }, attack_techniques: [] }] as DeploymentDetail["threat_pivots"];
  vi.mocked(deployments.get).mockResolvedValue(d); await render("?tab=runtime"); await settled(() => expect(host.textContent).toContain("Original threat"));
  await act(async () => host.querySelector('[data-testid="deployment-threat-pivots"] tbody tr')!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
  expect(host.querySelector('[data-testid="deployment-threat-drawer"]')?.textContent).toContain("/old-path");
  const updated = { ...d, threat_pivots: [{ ...d.threat_pivots[0], title: "Updated threat", file: { path: "/new-path" } }] };
  await act(async () => client.setQueryData(["deployment", "cluster", "deployment"], updated));
  await settled(() => expect(host.querySelector('[data-testid="deployment-threat-drawer"]')?.textContent).toContain("/new-path")); expect(host.querySelector('[data-testid="deployment-threat-drawer"]')?.textContent).not.toContain("/old-path");
  await act(async () => client.setQueryData(["deployment", "cluster", "deployment"], { ...updated, threat_pivots: [] })); await settled(() => expect(host.querySelector('[data-testid="deployment-threat-drawer"]')).toBeNull());
});

it("does not substitute another package report after explicit selection disappears", async () => {
  const d = fixtureDeployment(); d.package_evidence = [{ id: "first", scan_target_id: "target", target_ref: "payments/app", workload_id: "payments/app", inventory_hash: "hash1", package_count: 1, container_count: 1, payload: { marker: "first-payload" }, observed_at: "2026-10-12T00:00:00Z" }, { id: "second", scan_target_id: "target", target_ref: "payments/app", workload_id: "payments/pod", inventory_hash: "hash2", package_count: 1, container_count: 1, payload: { marker: "selected-payload" }, observed_at: "2026-10-12T00:00:00Z" }] as DeploymentDetail["package_evidence"];
  vi.mocked(deployments.get).mockResolvedValue(d); await render("?tab=packages"); await settled(() => expect(host.textContent).toContain("first-payload")); await act(async () => host.querySelectorAll('[data-testid="deployment-package-evidence"] tbody tr')[1].dispatchEvent(new MouseEvent("click", { bubbles: true })));
  await act(async () => client.setQueryData(["deployment", "cluster", "deployment"], { ...d, package_evidence: [d.package_evidence[0]] }));
  await settled(() => expect(host.textContent).toContain("The selected package report is no longer available")); expect(host.textContent).not.toContain("first-payload"); expect(host.textContent).not.toContain("selected-payload");
  await act(async () => button("Select the latest report").click()); expect(host.textContent).toContain("first-payload");
});

it("shows both embedded flow roles and exports exact classifier values including unknown", async () => {
 const d=fixtureDeployment();d.network_flows=[{id:"classified",cluster_id:"cluster",src:"custom-install/api",dst:"custom-install/pod/api-pod",src_platform_role:"core",dst_platform_role:"core",protocol:"tcp",verdict:"allow",bytes:10,packets:2,last_seen_at:"2026-10-12T00:00:00Z"},{id:"unknown",cluster_id:"cluster",src:"custom-install/api",dst:"kube-system/10.42.0.2",src_platform_role:"core",dst_platform_role:"",protocol:"tcp",verdict:"allow",bytes:1,packets:1,last_seen_at:"2026-10-12T00:00:00Z"}];vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=network");await settled(()=>expect(host.textContent).toContain("From role"));const table=[...host.querySelectorAll("table")].find(item=>item.textContent?.includes("From role"))!;expect(table.textContent).toContain("To role");expect(table.textContent).toContain("Not classified");expect(table.textContent).toContain("core");
 await act(async()=>table.closest('.app-data-table')!.querySelector<HTMLButtonElement>('[aria-label="Export CSV"]')!.click());const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;expect(headers).toContain("src_platform_role");expect(headers).toContain("dst_platform_role");expect(rows.map(row=>[row[headers.indexOf("src_platform_role")],row[headers.indexOf("dst_platform_role")]])).toEqual([["core","core"],["core",""]]);expect(rows).toHaveLength(2);
});
it("shows actual embedded runtime cluster and role while CSV preserves unclassified values", async () => {
 const d=fixtureDeployment();d.runtime_events=[{id:"known",cluster_id:"cluster",platform_role:"core",kind:"process_exec",workload_id:"custom-install/pod/api-pod",node_id:"node",source:"ebpf",severity:"high",verdict:"alert",at:"2026-10-12T00:00:00Z",attack_techniques:[],payload:{}},{id:"unknown",cluster_id:"cluster",platform_role:"",kind:"process_exec",workload_id:"ambiguous/api",node_id:"node",source:"ebpf",severity:"high",verdict:"alert",at:"2026-10-12T00:00:00Z",attack_techniques:[],payload:{}}];vi.mocked(deployments.get).mockResolvedValue(d);
 await render("?tab=runtime");await settled(()=>expect(host.querySelector('[data-testid="deployment-runtime-events"]')!.textContent).toContain("Not classified"));const section=host.querySelector('[data-testid="deployment-runtime-events"]')!;expect(section.textContent).toContain("Platform role");expect(section.textContent).toContain("Cluster");expect(section.textContent).toContain("core");
 await act(async()=>section.querySelector<HTMLButtonElement>('[aria-label="Export returned evidence"]')!.click());const [,headers,rows]=vi.mocked(downloadCsv).mock.calls.at(-1)!;expect(rows.map(row=>[row[headers.indexOf("Cluster")],row[headers.indexOf("Platform role")]])).toEqual([["cluster","core"],["cluster",""]]);expect(rows).toHaveLength(2);
});

it.each(["network","runtime"])("withholds foreign embedded %s rows and CSV",async kind=>{
 const d=fixtureDeployment();d.network_flows=[{id:"foreign-flow",cluster_id:"foreign",src:"private/source",dst:"private/dest",src_platform_role:"core",dst_platform_role:"core",protocol:"tcp",verdict:"allow",bytes:10,packets:1,last_seen_at:"2026-10-12T00:00:00Z"}];d.runtime_events=[{id:"foreign-event",cluster_id:"foreign",platform_role:"core",kind:"process_exec",workload_id:"private/workload",node_id:"node",source:"ebpf",severity:"high",verdict:"alert",at:"2026-10-12T00:00:00Z",attack_techniques:[],payload:{}}];vi.mocked(deployments.get).mockResolvedValue(d);await render(`?tab=${kind}`);await settled(()=>expect(host.textContent).toContain(`Embedded ${kind==="network"?"network flows":"runtime events"} do not match this cluster`));expect(host.textContent).not.toContain(kind==="network"?"private/source":"private/workload");expect(downloadCsv).not.toHaveBeenCalled();
});

it("replaces the direct finding sample with a scoped full inventory beyond1000 and matching export", async () => {
 const corpus=Array.from({length:1207},(_,index)=>deploymentFindingFixture(index));
 vi.mocked(deployments.findings).mockImplementation(async(id,params)=>deploymentFindingPage(params,corpus,id));
 await render("?tab=findings&findings_page=13&custom=keep");await settled(()=>expect(host.querySelectorAll('[data-testid="deployment-findings-table"] tbody tr')).toHaveLength(7));
 expect(host.textContent).toContain("1,207 matching workload finding records");expect(host.textContent).not.toContain("Up to 100 open direct workload findings");expect([...host.querySelectorAll("h2")].some(header=>header.textContent==="Running images")).toBe(true);
 expect(deployments.findings).toHaveBeenCalledWith("deployment",expect.objectContaining({cluster_id:"cluster",offset:1200,lifecycle:"open"}));
 await act(async()=>button("Export matching CSV").click());await settled(()=>expect(deployments.findingsCSV).toHaveBeenCalledWith("deployment",expect.objectContaining({cluster_id:"cluster",offset:1200,limit:100}), expect.any(Function)));expect(history.location.search).toContain("custom=keep");
});
it("blocks finding rows when the parent deployment cache is invalidated before refresh", async () => {
 await render("?tab=findings");await settled(()=>expect(host.querySelector('[data-testid="deployment-findings-table"]')).not.toBeNull());
 await act(async()=>client.getQueryCache().find({queryKey:["deployment","cluster","deployment"],exact:true})!.setState({isInvalidated:true}));
 await settled(()=>expect(host.querySelector('[data-testid="deployment-findings-table"]')).toBeNull());expect(button("Export matching CSV")).toBeUndefined();
});
