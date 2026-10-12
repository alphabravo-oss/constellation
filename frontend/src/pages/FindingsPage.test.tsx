/* global HTMLSelectElement */
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { findings, type Finding, type CVERollup } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { FindingsPage } from "./FindingsPage";

const route = vi.hoisted(() => ({ initial: "view=instances", latest: "", clusterId: "cluster", clusterError: null as Error | null, navigate: vi.fn() }));
vi.mock("@/lib/route-search", async () => {
  const { useState, useCallback } = await import("react");
  return { useRouteSearchParams: () => {
    const [params, setParams] = useState(() => new URLSearchParams(route.initial));
    const update = useCallback((next: URLSearchParams | ((current: URLSearchParams) => URLSearchParams)) => setParams((current) => {
      const result = typeof next === "function" ? next(new URLSearchParams(current)) : next;
      route.latest = result.toString(); return new URLSearchParams(result);
    }), []);
    return [params, update];
  } };
});
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: { id: route.clusterId }, error: route.clusterError, isLoading: false }) }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => route.navigate, useLocation: () => "", Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
vi.mock("@/api/client", () => ({ findings: { list: vi.fn(), byCVE: vi.fn(), exportCSV: vi.fn(), triage: vi.fn(), suppress: vi.fn(), acceptRisk: vi.fn() } }));
const identity = { org_id: "org", user_id: "operator" };
const fixture = (index: number): Finding => ({ id: `finding-${index}`, asset_id: `asset-${index % 2}`, kind: "vulnerability", title: `Finding ${index}`, external_id: `CVE-fixture-${index}`, severity: "critical", lifecycle: "open", risk_score: 99, first_seen_at: "2026-01-01T00:00:00Z", last_seen_at: "2026-01-01T00:00:00Z", kev: false } as Finding);
const counts = { open: 701, triaged: 22, in_progress: 33, accepted: 44, suppressed: 55, resolved: 66 };
const listed = (offset = 0, total = 705) => ({ findings: Array.from({ length: Math.min(10, Math.max(0, total - offset)) }, (_, index) => fixture(offset + index)), limit: 100, offset, total, has_more: offset + 100 < total, lifecycle_counts: counts });
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  route.initial = "view=instances"; route.latest = route.initial; route.clusterId = "cluster"; route.clusterError = null;
  localStorage.clear();
  vi.mocked(findings.list).mockImplementation(async (params) => listed(params?.offset));
  vi.mocked(findings.byCVE).mockResolvedValue({ cves: [{ cve: "CVE-last", severity: "critical", risk_score: 99, instances: 300, affected_images: 1, affected_clusters: 1, images: ["image"], last_seen_at: "2026-01-01T00:00:00Z", kev: false } as CVERollup], total: 701, limit: 100, offset: 0 });
  vi.mocked(findings.exportCSV).mockResolvedValue(); vi.mocked(findings.triage).mockResolvedValue({}); vi.mocked(findings.suppress).mockResolvedValue({}); vi.mocked(findings.acceptRisk).mockResolvedValue({});
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks(); vi.unstubAllGlobals(); localStorage.clear(); });
async function renderPage() {
  route.latest = route.initial;
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await rerenderPage();
}
async function rerenderPage() { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><FindingsPage /></TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 3000 }); }
function button(label: string) { return [...host.querySelectorAll<HTMLButtonElement>("button")].find((element) => element.textContent?.trim() === label)!; }
async function click(label: string) { await act(async () => button(label).click()); }
async function search(value: string) {
  await act(async () => { const input = host.querySelector<HTMLInputElement>('[aria-label="Search findings"]')!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}
async function selectFilter(label: string, value: string) { await act(async () => { const select = host.querySelector<HTMLSelectElement>(`select[aria-label="${label}"]`)!; select.value = value; select.dispatchEvent(new Event("change", { bubbles: true })); }); }
async function selectFirst() { await act(async () => host.querySelector<HTMLInputElement>('[data-testid="findings-table"] tbody input[type="checkbox"]')!.click()); }
const params = () => new URLSearchParams(route.latest);

it("loads and paginates matching records beyond the former 500-row cap without local sorting", async () => {
  route.initial = "view=instances&page=6&sort=risk&order=asc";
  vi.mocked(findings.list).mockImplementation(async (request) => ({ ...listed(request?.offset), findings: [fixture((request?.offset ?? 0) + 2), { ...fixture(request?.offset ?? 0), risk_score: 1 }] }));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 502"));
  expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100, offset: 500, sort: "risk", order: "asc", cluster_id: "cluster" }));
  const names = [...host.querySelectorAll('[data-testid="findings-table"] tbody tr')].map((row) => row.textContent);
  expect(names[0]).toContain("Finding 502"); expect(names[1]).toContain("Finding 500");
  await click("Next"); await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 600 })));
  expect(params().get("page")).toBe("7");
});
it("restores filters, group, view, page, and sort from a shared URL and reload", async () => {
  route.initial = "view=instances&group=asset&page=3&sort=age&order=asc&kind=vulnerability&lifecycle=accepted&severity=medium&fixable=true&q=openssl%20!kev:true";
  await renderPage(); await settled(() => expect(host.querySelector('[data-testid="findings-group-scope"]')).not.toBeNull());
  expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "vulnerability", lifecycle: "accepted", q: "openssl !kev:true severity:medium", fixable: true, offset: 200, sort: "age", order: "asc" }));
  expect(host.querySelector<HTMLInputElement>('[aria-label="Search findings"]')!.value).toBe("openssl !kev:true");
  expect(host.textContent).toContain("2 groups from 10 instances on this server page");
  route.initial = route.latest || route.initial;
  await act(async () => root.unmount()); client.clear(); host.remove();
  await renderPage(); await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 200, q: "openssl !kev:true severity:medium" })));
});
it("debounces server search, resets page immediately, preserves unknown URL keys and clears selection", async () => {
  route.initial = "view=instances&page=6&custom=retain";
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500")); await selectFirst();
  expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).not.toBeNull();
  const calls = vi.mocked(findings.list).mock.calls.length;
  await search("package:openssl");
  expect(params().has("page")).toBe(false); expect(params().get("custom")).toBe("retain");
  expect(button("Export filtered instances CSV").disabled).toBe(true); expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).toBeNull();
  expect(findings.list).toHaveBeenCalledTimes(calls);
  await search("package:openssl !kev:true");
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ q: "package:openssl !kev:true", offset: 0 })));
  await settled(() => expect(host.textContent).toContain("Finding 0")); // The server's response is not filtered a second time.
});
it.each(["Kind", "Severity"])("resets the URL page when the %s filter changes", async (filter) => {
  route.initial = "view=instances&page=6"; await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500"));
  await selectFilter(filter, filter === "Kind" ? "runtime" : "low");
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0, ...(filter === "Kind" ? { kind: "runtime" } : { q: "severity:low" }) })));
  expect(params().has("page")).toBe(false);
});
it("uses actual open counts and only backend KEV flags", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0"));
  const tabs = host.querySelector('[data-testid="finding-state-tabs"]')!;
  expect(tabs.textContent).toContain("Open701"); expect(tabs.textContent).not.toContain("756");
  expect(host.querySelector('[data-testid="findings-table"] tbody')!.textContent).not.toContain("KEV");
});
it("changes global server sort and keeps a chosen Instances view when lifecycle changes", async () => {
  route.initial = "view=instances&page=6"; await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500"));
  const severityHeader = [...host.querySelectorAll<HTMLButtonElement>('thead button')].find((item) => item.textContent?.includes("Severity"))!;
  await act(async () => severityHeader.click());
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "severity", order: "desc", offset: 0 })));
  expect(params().get("sort")).toBe("severity");
  const accepted = [...host.querySelectorAll<HTMLButtonElement>('[data-testid="finding-state-tabs"] button')].find((item) => item.textContent?.startsWith("Accepted"))!;
  await act(async () => accepted.click());
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ lifecycle: "accepted" })));
  expect(params().get("view")).toBe("instances");
});
it.each(["instances", "cve"])("shows explicit %s failure with retry and no false empty state", async (view) => {
  route.initial = `view=${view}&q=invalid:query`;
  if (view === "instances") vi.mocked(findings.list).mockRejectedValueOnce(new Error("private server detail"));
  else vi.mocked(findings.byCVE).mockRejectedValueOnce(new Error("private server detail"));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Could not load findings"));
  expect(host.textContent).not.toContain("No findings match"); expect(host.textContent).not.toContain("private server detail"); expect(button("Export filtered instances CSV").disabled).toBe(true);
  await click("Retry"); await settled(() => expect(host.querySelector(`[data-testid="${view === "instances" ? "findings-table" : "findings-cve-table"}"]`)).not.toBeNull());
});
it.each(["instances", "cve"])("recovers truthfully from an out-of-range %s URL page", async (view) => {
  route.initial = `view=${view}&page=999`;
  if (view === "cve") vi.mocked(findings.byCVE).mockResolvedValue({ cves: [], total: 1, limit: 100, offset: 99800 });
  await renderPage(); await settled(() => expect(host.textContent).toContain("This page is outside the current results"));
  expect(host.textContent).not.toContain("0–99,800");
  await click("First page"); expect(params().has("page")).toBe(false);
  await settled(() => expect(view === "instances" ? findings.list : findings.byCVE).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 0 })));
});
it("exports all matching instances with the same predicates and global sort, independent of the page", async () => {
  route.initial = "view=instances&page=6&kind=runtime&lifecycle=suppressed&severity=high&fixable=true&q=asset:api%20!kev:true&sort=title&order=asc";
  await renderPage(); await settled(() => expect(button("Export filtered instances CSV").disabled).toBe(false));
  await click("Export filtered instances CSV");
  await settled(() => expect(findings.exportCSV).toHaveBeenCalledWith({ kind: "runtime", lifecycle: "suppressed", cluster_id: "cluster", q: "asset:api !kev:true severity:high", fixable: true, sort: "title", order: "asc", limit: 100000, offset: 0 }));
  expect(host.textContent).toContain("Up to 100,000 matching instances");
  expect(button("Export this page CSV")).toBeDefined();
});
it("keeps CVE global risk order, uses full DSL and discloses instance and page exports", async () => {
  route.initial = "view=cve&page=6&severity=high&fixable=true&q=package:openssl%20!kev:true";
  await renderPage(); await settled(() => expect(host.textContent).toContain("CVE-last"));
  expect(findings.byCVE).toHaveBeenLastCalledWith(expect.objectContaining({ q: "package:openssl !kev:true severity:high", fixable: true, offset: 500, limit: 100 }));
  expect(host.querySelector('[data-testid="findings-cve-table"] thead [aria-sort]')).toBeNull();
  await click("Export filtered instances CSV");
  await settled(() => expect(findings.exportCSV).toHaveBeenCalledWith(expect.objectContaining({ kind: "vulnerability", q: "package:openssl !kev:true severity:high cve:CVE-", sort: "risk", order: "desc", offset: 0, limit: 100000 })));
  expect(button("Export this CVE page CSV")).toBeDefined();
});
it("shows export failure without discarding filters or results", async () => {
  vi.mocked(findings.exportCSV).mockRejectedValue(new Error("private export detail"));
  route.initial = "view=instances&q=openssl"; await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0"));
  await click("Export filtered instances CSV"); await settled(() => expect(host.textContent).toContain("Could not export matching instances"));
  expect(host.textContent).toContain("Finding 0"); expect(host.textContent).not.toContain("private export detail"); expect(host.querySelector<HTMLInputElement>('[aria-label="Search findings"]')!.value).toBe("openssl");
});
it("navigates to a dedicated saved-view form with exact filters and context without prompting", async () => {
  route.initial = "view=instances&group=asset&kind=runtime&lifecycle=accepted&severity=low&fixable=true&q=api&sort=title&order=asc&page=2&context=keep";
  await renderPage(); await settled(() => expect(host.querySelector('[data-testid="findings-group-scope"]')).not.toBeNull());
  await click("Save view");
  expect(route.navigate).toHaveBeenCalledWith({ href: `/clusters/cluster/findings/views/new?${route.initial}` });
  expect(localStorage.getItem(operatorStorageKey("constellation.findings.views.v1", identity)!)).toBeNull();
});

it("merges selections across page-scoped groups and only mutates those selected IDs", async () => {
  route.initial = "view=instances&group=asset"; vi.mocked(findings.list).mockResolvedValue({ ...listed(), findings: [fixture(0), fixture(1)] });
  await renderPage(); await settled(() => expect(host.querySelector('[data-testid="findings-group-scope"]')).not.toBeNull());
  const selectors = [...host.querySelectorAll<HTMLInputElement>('tbody input[type="checkbox"]')];
  await act(async () => selectors[0].click()); await act(async () => selectors[1].click());
  expect(host.querySelector('[aria-label="Bulk actions, 2 selected"]')).not.toBeNull();
  await click("Triage"); await settled(() => expect(findings.triage).toHaveBeenCalledTimes(2));
  expect(findings.triage).toHaveBeenCalledWith("finding-0", { priority: "high" }); expect(findings.triage).toHaveBeenCalledWith("finding-1", { priority: "high" });
});
it("clears selection on page and cluster changes", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await selectFirst(); await click("Next");
  await settled(() => expect(host.textContent).toContain("Finding 100")); expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).toBeNull();
  await selectFirst(); route.clusterId = "other-cluster"; await rerenderPage();
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "other-cluster" })));
  expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).toBeNull();
});
it("blocks stale bulk mutations before query observer notification", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await selectFirst();
  const triage = button("Triage");
  await act(async () => { for (const query of client.getQueryCache().findAll({ queryKey: ["findings"] })) client.setQueryData(query.queryKey, { ...listed(), findings: [] }); triage.click(); });
  await settled(() => expect(host.textContent).toContain("Some selected findings could not be updated")); expect(findings.triage).not.toHaveBeenCalled();
});
it("retains truthful refresh errors and drops stale selections during fetching", async () => {
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await selectFirst();
  let reject!: (error: Error) => void;
  vi.mocked(findings.list).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  await act(async () => { void client.invalidateQueries({ queryKey: ["findings"] }); });
  await settled(() => expect(host.textContent).toContain("Updating findings"));
  expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).toBeNull(); expect(button("Export filtered instances CSV").disabled).toBe(true);
  await act(async () => reject(new Error("private refresh detail")));
  await settled(() => expect(host.textContent).toContain("Could not load findings")); expect(host.textContent).not.toContain("No findings match"); expect(findings.triage).not.toHaveBeenCalled();
});
it("reports partial bulk failure and refetches current state", async () => {
  vi.mocked(findings.triage).mockRejectedValue(new Error("private mutation detail"));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await selectFirst(); await click("Triage");
  await settled(() => expect(host.textContent).toContain("Some selected findings could not be updated"));
  expect(host.textContent).not.toContain("private mutation detail"); expect(host.querySelector('[aria-label="Bulk actions, 1 selected"]')).toBeNull();
});
it("blocks requests when active cluster resolution fails", async () => {
  route.clusterError = new Error("private scope detail"); await renderPage();
  expect(host.textContent).toContain("The active cluster could not be resolved"); expect(findings.list).not.toHaveBeenCalled(); expect(findings.byCVE).not.toHaveBeenCalled(); expect(button("Export filtered instances CSV").disabled).toBe(true);
});
it("renders the full one-hundred-row server page without a second fifty-row pagination layer", async () => {
  vi.mocked(findings.list).mockResolvedValue({ ...listed(), findings: Array.from({ length: 100 }, (_, index) => fixture(index)) });
  await renderPage();
  await settled(() => expect(host.querySelectorAll('[data-testid="findings-table"] tbody tr')).toHaveLength(100));
  expect(host.textContent).toContain("Finding 99"); expect(host.querySelectorAll('[aria-label="Next page"]')).toHaveLength(0);
  expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 100, offset: 0 }));
});

it("does not query across the organization while cluster context is missing", async () => {
  route.clusterId = ""; await renderPage();
  expect(findings.list).not.toHaveBeenCalled(); expect(findings.byCVE).not.toHaveBeenCalled();
  expect(host.textContent).toContain("The active cluster could not be resolved");
});
it("ignores malformed saved view payloads and applies only a validated named view", async () => {
  localStorage.setItem(operatorStorageKey("constellation.findings.views.v1", identity)!, JSON.stringify([{ id: "valid", name: "Valid saved filters", kind: "runtime", lifecycle: "accepted", query: "api" }, { id: "bad", name: "Malformed", kind: [], lifecycle: {}, query: null }]));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await click("Views (1)");
  expect(host.textContent).toContain("1 saved view record was rejected");
  expect(host.textContent).not.toContain("Malformed"); const apply = [...host.querySelectorAll<HTMLButtonElement>("button")].find(item => item.textContent?.startsWith("Valid saved filters"))!; await act(async () => apply.click());
  await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "runtime", lifecycle: "accepted", q: "api" })));
});
it("reports a failed saved-view delete without removing the persisted or visible record", async () => {
  const key = operatorStorageKey("constellation.findings.views.v1", identity)!;
  localStorage.setItem(key, JSON.stringify([{ id: "valid", name: "Retained view", kind: "runtime", lifecycle: "open", query: "api" }]));
  await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 0")); await click("Views (1)");
  const original = localStorage; vi.stubGlobal("localStorage", { getItem: original.getItem.bind(original), setItem: () => { throw new Error("quota"); } });
  await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="delete view Retained view"]')!.click()); await settled(() => expect(host.textContent).toContain("could not be stored")); expect(host.textContent).toContain("Retained view");
  vi.unstubAllGlobals(); expect(JSON.parse(localStorage.getItem(key)!)).toHaveLength(1);
});

it("keeps the exact target cohort across paging, CVE rollup, export and selection changes", async () => {
 route.initial = "view=instances&kind=vulnerability&target_type=image-workload&page=6";
 await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500"));
 expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ target_type: "image-workload", offset: 500 }));
 expect(host.textContent).toContain("image-workload"); await selectFirst();
 await selectFilter("Target type", "host");
 await settled(() => { expect(params().get("page")).toBeNull(); expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ target_type: "host", offset: 0 })); expect(host.textContent).toContain("Finding 0"); });
 expect(host.querySelector<HTMLInputElement>('[data-testid="findings-table"] tbody input[type="checkbox"]')?.checked).toBe(false);
 await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="findings-view-cve"]')!.click());
 await settled(() => expect(host.textContent).toContain("CVE-last"));
 expect(findings.byCVE).toHaveBeenLastCalledWith(expect.objectContaining({ target_type: "host", cluster_id: "cluster" }));
 await click("Export filtered instances CSV");
 expect(findings.exportCSV).toHaveBeenCalledWith(expect.objectContaining({ target_type: "host", offset: 0, limit: 100000 }));
});

it("applies saved target cohorts and clears them when applying a legacy view", async () => {
 const key = operatorStorageKey("constellation.findings.views.v1", identity)!;
 localStorage.setItem(key, JSON.stringify([{ id: "target", name: "Host cohort", kind: "vulnerability", lifecycle: "open", query: "", targetType: "host", view: "instances" }, { id: "legacy", name: "All targets", kind: "vulnerability", lifecycle: "open", query: "", view: "instances" }]));
 route.initial = "view=instances&target_type=image-workload&page=6";
 await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500")); await click("Views (2)");
 await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b => b.textContent?.startsWith("Host cohort"))!.click());
 await settled(() => { expect(params().get("target_type")).toBe("host"); expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ target_type: "host", offset: 0 })); });
 await click("Views (2)"); await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b => b.textContent?.startsWith("All targets"))!.click());
 await settled(() => { expect(params().has("target_type")).toBe(false); expect(findings.list).toHaveBeenLastCalledWith(expect.not.objectContaining({ target_type: expect.anything() })); });
});

it("loads an exact strongest-mode ID cohort and exports advisories without adding a CVE-only restriction", async () => {
 route.initial = "view=cve&kind=vulnerability&target_type=image-workload&group_mode=protect&id_scope=all&page=2";
 vi.mocked(findings.byCVE).mockResolvedValue({ cves: [{ cve: "GHSA-advisory", severity: "high", risk_score: 80, instances: 3, affected_images: 1, affected_clusters: 1, images: ["image"], last_seen_at: "2026-01-01T00:00:00Z", kev: false } as CVERollup], total: 101, limit: 100, offset: 100 });
 await renderPage(); await settled(() => expect(host.textContent).toContain("GHSA-advisory"));
 expect(findings.byCVE).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", group_mode: "protect", id_scope: "all", target_type: "image-workload", offset: 100 }));
 expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode: "protect", id_scope: "all" }));
 expect(host.textContent).toContain("101 matching vulnerability IDs"); expect(host.textContent).toContain("By vulnerability ID");
 expect(host.textContent).toContain("an ID may appear in more than one mode"); expect(host.querySelector('a[href*="/cve/GHSA"]')).toBeNull();
 await click("Export filtered instances CSV"); expect(findings.exportCSV).toHaveBeenCalledWith(expect.objectContaining({ group_mode: "protect", id_scope: "all", q: undefined, offset: 0 }));
 await selectFilter("Strongest group mode", "monitor"); await settled(() => expect(findings.byCVE).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode: "monitor", offset: 0 })));
 expect(params().get("page")).toBeNull();
});
it("clears selected instances after a mode change and restores a saved exact mode cohort", async () => {
 const key = operatorStorageKey("constellation.findings.views.v1", identity)!;
 localStorage.setItem(key, JSON.stringify([{ id: "mode", name: "Discover ID cohort", kind: "vulnerability", lifecycle: "open", query: "", targetType: "image-workload", groupMode: "discover", idScope: "all", view: "instances" }, { id: "legacy", name: "Legacy cohort", kind: "vulnerability", lifecycle: "open", query: "", view: "instances" }]));
 route.initial = "view=instances&group_mode=protect&id_scope=all&page=6";
 await renderPage(); await settled(() => expect(host.textContent).toContain("Finding 500")); await selectFirst();
 await selectFilter("Strongest group mode", "monitor"); await settled(() => expect(host.textContent).toContain("Finding 0"));
 expect(host.querySelector<HTMLInputElement>('[data-testid="findings-table"] tbody input[type="checkbox"]')?.checked).toBe(false);
 await click("Views (2)"); await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent?.startsWith("Discover ID cohort"))!.click());
 await settled(() => expect(findings.list).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode: "discover", id_scope: "all", offset: 0 })));
 await click("Views (2)"); await act(async () => [...host.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent?.startsWith("Legacy cohort"))!.click());
 await settled(() => { expect(params().has("group_mode")).toBe(false); expect(params().has("id_scope")).toBe(false); });
});
