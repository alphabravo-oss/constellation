import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DashboardPage } from "./DashboardPage";
import { dashboard, network, findings, clusters, systemHealth, compliance, enterprise, scannerOperations, federation, type PlatformFactsResponse } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
const scope = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster", name: "Demo" } as { id: string; name: string } | undefined, isLoading: false, error: null as Error | null }));
const route = vi.hoisted(() => ({ params: new URLSearchParams(), setParams: vi.fn() }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [route.params, route.setParams] }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn(), Link: ({ children, href, to, className, ...props }: { children: ReactNode; href?: string; to?: string; className?: string }) => <a href={href ?? to} className={className} {...props}>{children}</a> }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
vi.mock("@/api/client", () => ({
  findings: { list: vi.fn().mockResolvedValue({ findings: [] }) },
  cve: { bundle: vi.fn().mockResolvedValue({}), stats: vi.fn().mockResolvedValue({}) },
  dashboard: { summary: vi.fn(), eventsTimeline: vi.fn().mockResolvedValue({ events_timeline: [] }) },
  clusters: { platformFacts: vi.fn().mockResolvedValue({ cluster_id: "cluster" }), scanPlatform: vi.fn() },
  compliance: { summary: vi.fn().mockResolvedValue({ frameworks: [] }) },
  enterprise: { runtime: vi.fn().mockResolvedValue({ summary: {} }) },
  federation: { state: vi.fn().mockResolvedValue({}), members: vi.fn().mockResolvedValue({ members: [] }) },
  network: { exposure: vi.fn(), conversations: vi.fn().mockResolvedValue({ conversations: [] }) },
  scannerOperations: { status: vi.fn().mockResolvedValue({}), workers: vi.fn().mockResolvedValue([]) },
  systemHealth: { cluster: vi.fn().mockResolvedValue({ heartbeats: [] }), overview: vi.fn() },
  downloadAPIFile: vi.fn(),
}));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster", name: "Demo" }, isLoading: false, error: null });
  localStorage.clear();
  route.params = new URLSearchParams();
  vi.mocked(clusters.platformFacts).mockResolvedValue({ cluster_id: "cluster" } as PlatformFactsResponse);
  vi.mocked(scannerOperations.status).mockResolvedValue({} as Awaited<ReturnType<typeof scannerOperations.status>>);
  vi.mocked(federation.state).mockResolvedValue({ state: "standalone" } as Awaited<ReturnType<typeof federation.state>>);
  vi.mocked(federation.members).mockResolvedValue({ members: [] });
  vi.mocked(systemHealth.overview).mockResolvedValue({ heartbeats: [] } as unknown as Awaited<ReturnType<typeof systemHealth.overview>>);
  vi.mocked(dashboard.summary).mockResolvedValue({ findings_by_severity: { critical: 1234, high: 2345 }, open_findings: 6789, accepted_risks: 42, posture: { security_score: 27 }, recent_activity: [] } as unknown as Awaited<ReturnType<typeof dashboard.summary>>);
  vi.mocked(network.exposure).mockResolvedValue({ ingress: [], egress: [] } as Awaited<ReturnType<typeof network.exposure>>);
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function renderPage(seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  client.setQueryData(["clusters"], { clusters: [{ id: "cluster", name: "Demo" }] });
  seed?.(client);
  await act(async () => root.render(<QueryClientProvider client={client}><DashboardPage /></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
it("shows five authoritative metrics despite an empty loaded finding sample", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Security risk: 27/100"));
  const summary = host.querySelector('[data-testid="dashboard-summary"]')!;
  expect(summary.children).toHaveLength(5);
  for (const count of ["1234", "2345", "6789", "42"]) expect(summary.textContent).toContain(count);
  expect(summary.querySelector('a[href="/clusters/cluster/findings?severity=critical&lifecycle=open"]')).not.toBeNull();
  expect(host.textContent).toContain("No critical or high findings in the loaded sample");
  expect(host.textContent).not.toContain("Policy Mode Maturity");
});
it("does not turn a failed summary into a healthy zero-risk score", async () => {
  route.params = new URLSearchParams("tab=posture"); vi.mocked(dashboard.summary).mockRejectedValue(new Error("private"));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Security summary unavailable"));
  expect(host.textContent).toContain("Risk score unavailable"); expect(host.textContent).not.toContain("Security risk: 0/100"); expect(host.textContent).not.toContain("Good");
  expect(host.querySelector('[data-testid="dashboard-summary"]')?.textContent?.match(/—/g)).toHaveLength(5);
});
it("honors the network deep link and exports server platform-role evidence", async () => {
  route.params = new URLSearchParams("tab=network");
  vi.mocked(network.exposure).mockResolvedValue({ ingress: [{ workload: "app", name: "app", protocols: [], ports: [], namespace: "ns", platform_role: "controller", external_peers: 2, sessions: 3, policy_mode: "monitor", critical: 0, high: 0 }], egress: [] } as unknown as Awaited<ReturnType<typeof network.exposure>>);
  await renderPage(); await settled(() => expect(host.textContent).toContain("Exposed Services"));
  await settled(() => expect([...host.querySelectorAll("button")].find(b => b.textContent === "Export CSV")?.disabled).toBe(false));
  await act(async () => { [...host.querySelectorAll("button")].find(b => b.textContent === "Export CSV")!.click(); });
  expect(downloadCsv).toHaveBeenCalledWith("constellation-exposure", expect.arrayContaining(["Platform role"]), [["ingress", "app", "ns", "controller", 2, 3, "monitor"]]);
  expect(host.querySelector('a[href="/clusters/cluster/groups/settings"]')).not.toBeNull(); expect(host.querySelector("select")).toBeNull();
});

const platformFacts = (count = 9): PlatformFactsResponse => ({
  cluster_id: "cluster", cluster_name: "Demo", distro: "k3s", status: "reported",
  facts: { cluster_id: "cluster", updated_at: "2026-10-12T00:00:00Z", distro: "k3s", platform_provider: "local", node_count: 3, observed_at: "2026-10-12T00:00:00Z", kubernetes_git_version: "v1.34.1", components: [] },
  evidence: { id: "evidence", inventory_hash: "hash", observed_at: "2026-10-12T00:00:00Z", package_count: count, packages: Array.from({ length: count }, (_, index) => ({ name: `package-${String(index + 1).padStart(3, "0")}`, version: "1.0", ecosystem: "generic", namespace_name: "platform" })) },
  findings_summary: { open: 2, critical: 1, high: 1, medium: 0, low: 0 }, findings: [],
} as PlatformFactsResponse);
const button = (text: string) => [...host.querySelectorAll("button")].find((element) => element.textContent?.trim() === text)!;
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><DashboardPage /></QueryClientProvider>)); }

it.each(["loading", "missing", "wrong", "error", "transition"])("blocks queries and cached metrics for %s cluster scope", async (condition) => {
  route.params = new URLSearchParams("tab=operations");
  if (condition === "loading") scope.isLoading = true;
  if (condition === "missing") scope.cluster = undefined;
  if (condition === "wrong") scope.cluster = { id: "other", name: "Foreign" };
  if (condition === "error") scope.error = new Error("lookup failed");
  if (condition === "transition") scope.clusterId = undefined;
  await renderPage((queryClient) => {
    queryClient.setQueryData(["dashboard", scope.clusterId], { posture: { security_score: 99 }, open_findings: 999 });
    queryClient.setQueryData(["cluster-platform", scope.clusterId], platformFacts());
  });
  for (const api of [dashboard.summary, dashboard.eventsTimeline, findings.list, clusters.platformFacts, systemHealth.cluster, systemHealth.overview, compliance.summary, enterprise.runtime, network.exposure, network.conversations]) expect(api).not.toHaveBeenCalled();
  expect(host.querySelector('[data-testid="dashboard-summary"]')?.textContent?.match(/—/g)).toHaveLength(5);
  expect(host.querySelector('[data-testid="dashboard-summary"] a')).toBeNull();
  expect(host.textContent).not.toContain("Security risk: 99"); expect(host.textContent).not.toContain("Foreign");
  expect(host.querySelector('[data-testid="dashboard-platform-workspace"]')).toBeNull();
  expect(host.textContent).toContain(condition === "error" ? "Cluster context unavailable" : condition === "loading" ? "Resolving cluster" : "Select a resolved cluster");
});

it("suppresses cached totals after a failed refresh", async () => {
  vi.mocked(dashboard.summary).mockRejectedValue(new Error("refresh failed"));
  await renderPage((queryClient) => queryClient.setQueryData(["dashboard", "cluster"], { posture: { security_score: 99 }, open_findings: 999 }));
  await settled(() => expect(host.textContent).toContain("Security summary unavailable"));
  expect(host.querySelector('[data-testid="dashboard-summary"]')?.textContent?.match(/—/g)).toHaveLength(5);
  expect(host.textContent).not.toContain("Security risk: 99");
});

it("shows failed facts with Retry rather than an empty inventory and recovers", async () => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockRejectedValue(new Error("facts failed"));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Could not refresh platform facts"));
  expect(host.textContent).not.toContain("No platform facts reported"); expect(button("Scan platform").disabled).toBe(true);
  vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts());
  const retry = host.querySelector('[data-testid="dashboard-platform-workspace"] button') as HTMLButtonElement;
  await act(async () => retry.click());
  await settled(() => expect(host.textContent).toContain("package-009")); expect(button("Scan platform").disabled).toBe(false);
});

it("paginates all returned package evidence and exports all rows", async () => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts(105));
  await renderPage(); await settled(() => expect(host.textContent).toContain("All 105 returned packages"));
  const table = host.querySelector('[data-testid="dashboard-platform-packages"]')!;
  expect(table.querySelectorAll("tbody tr")).toHaveLength(100); expect(table.textContent).not.toContain("package-105");
  await act(async () => button("Next").click()); expect(table.textContent).toContain("package-105"); expect(table.querySelectorAll("tbody tr")).toHaveLength(5);
  await act(async () => button("Export returned packages").click());
  expect(downloadCsv).toHaveBeenCalledWith("constellation-platform-packages", ["Package", "Version", "Namespace / ecosystem"], expect.any(Array));
  expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2]).toHaveLength(105);
  expect(host.querySelector("details summary")?.textContent).toContain("Organization");
  expect([...host.querySelectorAll("summary")].some((summary) => summary.textContent?.includes("Advanced: scan job"))).toBe(true);
});

it("labels partial returned evidence instead of implying a complete inventory", async () => {
  route.params = new URLSearchParams("tab=operations"); const facts = platformFacts(9); facts.evidence!.package_count = 25;
  vi.mocked(clusters.platformFacts).mockResolvedValue(facts);
  await renderPage(); await settled(() => expect(host.textContent).toContain("Reported inventory contains 25 packages; this response includes 9"));
  expect(host.textContent).toContain("package-009");
});

it("blocks a foreign platform payload and a failed cached platform refresh", async () => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockResolvedValue({ ...platformFacts(), cluster_id: "other" });
  await renderPage(); await settled(() => expect(host.textContent).toContain("Could not refresh platform facts"));
  expect(button("Scan platform").disabled).toBe(true); expect(host.textContent).not.toContain("package-009");
  vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts()); await act(async () => { await client.invalidateQueries({ queryKey: ["cluster-platform", "cluster"] }); });
  await settled(() => expect(host.textContent).toContain("package-009"));
  vi.mocked(clusters.platformFacts).mockRejectedValue(new Error("refresh failed")); await act(async () => { await client.invalidateQueries({ queryKey: ["cluster-platform", "cluster"] }); });
  await settled(() => expect(host.textContent).toContain("Could not refresh platform facts"));
  expect(button("Scan platform").disabled).toBe(true); expect(host.textContent).not.toContain("package-009");
});

it("prevents duplicate platform scan requests and distinguishes queued from unqueued responses", async () => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts());
  let finish!: (result: Awaited<ReturnType<typeof clusters.scanPlatform>>) => void;
  vi.mocked(clusters.scanPlatform).mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  await renderPage(); await settled(() => expect(button("Scan platform").disabled).toBe(false));
  await act(async () => { button("Scan platform").click(); button("Scan platform").click(); });
  expect(clusters.scanPlatform).toHaveBeenCalledTimes(1); expect(clusters.scanPlatform).toHaveBeenCalledWith("cluster");
  await settled(() => expect(button("Requesting scan…")?.disabled).toBe(true));
  await act(async () => finish({ scan_target_id: "target", scan_evidence_id: "evidence", inventory_hash: "hash", scan_job_enqueued: true, scan_job_id: "job" }));
  await settled(() => expect(host.textContent).toContain("Platform scan queued"));
  vi.mocked(clusters.scanPlatform).mockResolvedValue({ scan_target_id: "target", scan_evidence_id: "evidence", inventory_hash: "hash", scan_job_enqueued: false });
  await settled(() => expect(button("Scan platform").disabled).toBe(false)); await act(async () => button("Scan platform").click());
  await settled(() => expect(host.textContent).toContain("No new platform scan job was queued"));
});

it("shows scan failure and hides old cluster feedback after switching scope", async () => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts()); vi.mocked(clusters.scanPlatform).mockRejectedValue(new Error("scan failed"));
  await renderPage(); await settled(() => expect(button("Scan platform").disabled).toBe(false)); await act(async () => button("Scan platform").click());
  await settled(() => expect(host.textContent).toContain("Platform scan request failed"));
  Object.assign(scope, { clusterId: "other", cluster: { id: "other", name: "Other" } });
  vi.mocked(clusters.platformFacts).mockResolvedValue({ ...platformFacts(), cluster_id: "other" }); await rerender();
  await settled(() => expect(host.textContent).toContain("Other — Dashboard"));
  expect(host.textContent).not.toContain("Platform scan request failed");
  expect(host.querySelector('a[href="/clusters/other/components?role=controller"]')).not.toBeNull();
  expect(host.querySelector('a[href="/clusters/cluster/components?role=controller"]')).toBeNull();
});

it("labels organization operations and suppresses cached scanner/federation metrics on refresh failure", async () => {
  route.params = new URLSearchParams("tab=operations");
  vi.mocked(scannerOperations.status).mockRejectedValue(new Error("scanner unavailable")); vi.mocked(federation.state).mockRejectedValue(new Error("federation unavailable"));
  await renderPage((queryClient) => {
    queryClient.setQueryData(["scan-status", "dashboard"], { cvedb_version: "old-version", scheduled: 999 });
    queryClient.setQueryData(["fed-state", "dashboard"], { state: "master", revision: 999 });
  });
  await act(async () => { await client.invalidateQueries({ queryKey: ["scan-status", "dashboard"] }); await client.invalidateQueries({ queryKey: ["fed-state", "dashboard"] }); });
  await settled(() => expect(host.textContent).toContain("Could not refresh organization scanner health"));
  await settled(() => expect(host.textContent).toContain("Could not refresh organization federation health"));
  expect(host.textContent).toContain("Organization Scanner DB"); expect(host.textContent).toContain("Organization Federation");
  expect(host.textContent).not.toContain("old-version");
  expect(host.querySelector('[data-testid="dashboard-scanner-freshness"]')?.getAttribute("href")).toBe("/settings/scanner");
});

it.each(["registry", "registry-invalidated", "detail", "platform-invalidated", "platform-refresh", "platform-error", "foreign-platform"])("rechecks %s cache at scan submission before React rerenders", async (condition) => {
  route.params = new URLSearchParams("tab=operations"); vi.mocked(clusters.platformFacts).mockResolvedValue(platformFacts());
  await renderPage(); await settled(() => expect(button("Scan platform").disabled).toBe(false));
  const source = client.getQueryCache().find({ queryKey: ["cluster-platform", "cluster"], exact: true })!;
  await act(async () => {
    if (condition === "registry") client.setQueryData(["clusters"], { clusters: [{ id: "other" }] });
    if (condition === "detail") {
      client.setQueryData(["cluster", "cluster"], { id: "cluster" });
      client.getQueryCache().find({ queryKey: ["cluster", "cluster"], exact: true })!.setState({ status: "error", error: new Error("detail unavailable") });
    }
    if (condition === "registry-invalidated") client.getQueryCache().find({ queryKey: ["clusters"], exact: true })!.setState({ isInvalidated: true });
    if (condition === "platform-invalidated") source.setState({ isInvalidated: true });
    if (condition === "platform-refresh") source.setState({ fetchStatus: "fetching" });
    if (condition === "platform-error") source.setState({ status: "error", error: new Error("facts unavailable") });
    if (condition === "foreign-platform") client.setQueryData(["cluster-platform", "cluster"], { ...platformFacts(), cluster_id: "other" });
    button("Scan platform").click();
  });
  expect(clusters.scanPlatform).not.toHaveBeenCalled();
});

it("keeps the runtime posture drilldown on its evidence window", async () => {
  route.params = new URLSearchParams("tab=posture"); await renderPage();
  expect(host.querySelector('a[href="/clusters/cluster/runtime?tab=evidence&hours=24"]')).not.toBeNull();
});

it("links denied pairs and exposure to exact directed server-filtered conversations", async () => {
  route.params = new URLSearchParams("tab=network");
  vi.mocked(network.conversations).mockResolvedValue({ conversations: [{ from: "prod/api", to: "other/api", bytes: 50, packets: 2, edges: 1, last_seen: "2026-10-12T00:00:00Z", verdict: "block" }], nodes: [], node_kinds: {}, edges: [], window_hours: 24 });
  vi.mocked(network.exposure).mockResolvedValue({ ingress: [{ workload: "prod/api", namespace: "prod", name: "api", protocols: [], ports: [], external_peers: 1, sessions: 1, critical: 0, high: 0, risk_score: 0, policy_mode: "monitor" }], egress: [] });
  await renderPage();
  await settled(() => expect(host.querySelector('[data-testid="dashboard-network-denies"] a')).not.toBeNull());
  expect(network.conversations).toHaveBeenCalledWith({ hours: 24, cluster_id: "cluster", verdict_group: "blocked", limit: 5000 });
  const pair = new URL(host.querySelector<HTMLAnchorElement>('[data-testid="dashboard-network-denies"] a')!.href, "http://localhost");
  expect(pair.searchParams.get("from")).toBe("prod/api"); expect(pair.searchParams.get("to")).toBe("other/api");
  expect(pair.searchParams.get("verdict_group")).toBe("blocked"); expect(pair.searchParams.get("hide_platform")).toBe("false");
  const exposure = [...host.querySelectorAll<HTMLAnchorElement>("a")].find(a => new URL(a.href, "http://localhost").searchParams.get("from") === "external")!;
  expect(exposure).toBeDefined(); const target = new URL(exposure.href, "http://localhost");
  expect(target.searchParams.get("to")).toBe("prod/api"); expect(target.searchParams.get("hours")).toBe("168");
});
it("links top vulnerable workload IDs exactly and labels legacy namespace/name search", async () => {
 route.params = new URLSearchParams("tab=network");
 vi.mocked(dashboard.summary).mockResolvedValue({ findings_by_severity: {}, open_findings: 0, accepted_risks: 0, recent_activity: [], posture: { security_score: 5, top_vulnerable: [{id:"deployment-exact",namespace:"one",name:"api",critical:2,high:3},{namespace:"two",name:"api",critical:1,high:4}] } } as unknown as Awaited<ReturnType<typeof dashboard.summary>>);
 await renderPage(); await settled(() => expect(host.querySelector('a[href="/clusters/cluster/deployments/deployment-exact"]')).not.toBeNull());
 expect(host.querySelector('a[href="/clusters/cluster/deployments?q=api&namespace=two&hide_platform=false"]')).not.toBeNull(); expect(host.textContent).toContain("namespace + name search"); expect(host.textContent).toContain("Up to six reported workloads");
});
it("uses matching finding instance cohorts and makes unsupported location/fact destinations explicit", async () => {
 route.params = new URLSearchParams("tab=posture");
 await renderPage(); await settled(() => expect(host.textContent).toContain("Additional posture metrics"));
 expect(host.querySelector('[data-testid="dashboard-summary"] a[href="/clusters/cluster/findings?view=instances&lifecycle=open"]')).not.toBeNull();
 expect(host.querySelector('a[href="/clusters/cluster/findings?view=instances&kind=vulnerability&lifecycle=open&fixable=true"]')).not.toBeNull();
 expect(host.textContent).toContain("image-location filter unavailable"); expect(host.textContent).toContain("privileged fact filter unavailable"); expect(host.textContent).toContain("destination groups named nodes");
});
it("exports a source matrix with aggregate-versus-sample counts and failed sources marked unavailable", async () => {
 vi.mocked(network.conversations).mockRejectedValue(new Error("source offline"));
 await renderPage(); await settled(() => expect(host.querySelector('[data-testid="dashboard-source-matrix"]')?.textContent).toContain("Unavailable"));
 const table=host.querySelector('[data-testid="dashboard-source-matrix"]')!;
 expect(table.textContent).toContain("up to 5,000 pairs"); expect(table.textContent).toContain("up to 50 workloads per direction"); expect(table.textContent).toContain("Organization-wide latest 20"); expect(table.textContent).toContain("Not master; member inventory not requested");
 await act(async () => button("Export source matrix").click());
 expect(downloadCsv).toHaveBeenCalledWith("dashboard-source-matrix.csv",expect.arrayContaining(["Metric or view","Reported / loaded count","Scope and source limits"]),expect.arrayContaining([expect.arrayContaining(["critical open records",1234]),expect.arrayContaining(["Loaded blocked conversation pairs","Unavailable"])]));
});
it("renders the risk-by-mode matrix through canonical table headers and truthful configured counts", async () => {
 route.params = new URLSearchParams("tab=network");
 vi.mocked(dashboard.summary).mockResolvedValue({ findings_by_severity: {}, recent_activity: [], posture: {security_score: 5,enforcement:{groups:3,discover:1,monitor:1,protect:1},cves_by_mode:{discover:4,monitor:5,protect:6},exposed_by_mode:{discover:1,monitor:2,protect:3}} } as unknown as Awaited<ReturnType<typeof dashboard.summary>>);
 await renderPage();await settled(()=>expect(host.querySelector('[data-testid="dashboard-risk-by-mode"]')).not.toBeNull());
 const table=host.querySelector('[data-testid="dashboard-risk-by-mode"]')!;expect([...table.querySelectorAll("thead th")].map(th=>th.textContent?.trim())).toEqual(["Configured mode","Open CVE records","Exposure facts"]);expect(table.querySelectorAll("tbody tr")).toHaveLength(3);expect(host.textContent).toContain("not applier health");
});
