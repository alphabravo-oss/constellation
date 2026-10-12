import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { DashboardPage } from "./DashboardPage";
import { dashboard, network } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
const route = vi.hoisted(() => ({ params: new URLSearchParams(), setParams: vi.fn() }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [route.params, route.setParams] }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", cluster: { name: "Demo" } }) }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn(), Link: ({ children, href, to, className }: { children: ReactNode; href?: string; to?: string; className?: string }) => <a href={href ?? to} className={className}>{children}</a> }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
vi.mock("@/api/client", () => ({
  findings: { list: vi.fn().mockResolvedValue({ findings: [] }) },
  cve: { bundle: vi.fn().mockResolvedValue({}), stats: vi.fn().mockResolvedValue({}) },
  dashboard: { summary: vi.fn(), eventsTimeline: vi.fn().mockResolvedValue({ events_timeline: [] }) },
  clusters: { platformFacts: vi.fn().mockResolvedValue({}), scanPlatform: vi.fn() },
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
  route.params = new URLSearchParams();
  vi.mocked(dashboard.summary).mockResolvedValue({ findings_by_severity: { critical: 1234, high: 2345 }, open_findings: 6789, accepted_risks: 42, posture: { security_score: 27 }, recent_activity: [] } as unknown as Awaited<ReturnType<typeof dashboard.summary>>);
  vi.mocked(network.exposure).mockResolvedValue({ ingress: [], egress: [] } as Awaited<ReturnType<typeof network.exposure>>);
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function renderPage() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
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
