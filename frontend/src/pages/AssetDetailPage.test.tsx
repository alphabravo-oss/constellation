import { downloadCsv } from "@/lib/csv";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { assets, sbom, type AssetDetail, type AssetFindingInventoryResponse } from "@/api/client";
import { TestRouter } from "@/test/router";
import { AssetDetailPage } from "./AssetDetailPage";

const identity = vi.hoisted(() => ({ org_id: "org-a", user_id: "user-a" }));
vi.mock("@/contexts/TablePreferencesContext", () => ({ useTablePreferencesIdentity: () => identity }));
const scope = vi.hoisted(() => ({ available: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
  const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
  return { useCluster: () => { const { id } = router.useParams({ strict: false }); return { clusterId: id, cluster: scope.available ? { id: scope.resolvedId || id } : undefined, isLoading: scope.loading, error: scope.error }; } };
});
vi.mock("@/api/client", () => ({ assets: { get: vi.fn(), findings: vi.fn(), findingsCSV: vi.fn(), createImageAcceptance: vi.fn(), revokeImageAcceptance: vi.fn() }, sbom: { downloadSpdx: vi.fn(), downloadCyclonedx: vi.fn(), downloadMbom: vi.fn() } }));
const detail = (asset = "asset-a", cluster = "cluster-a"): AssetDetail => ({
  asset: { id: asset, cluster_id: cluster, name: `Image ${asset}`, kind: "image", criticality: "high", digest: "sha256:exact", labels: { owner: "inventory-team" }, ai_workload: false, finding_count: 999, critical_findings: 999, high_findings: 999, open_findings: 999, sbom_count: 999, first_seen_at: "2026-10-10T12:00:00Z", last_seen_at: "2026-10-12T12:00:00Z" },
  image: { registry: "registry.example", repository: `team/${asset}`, tag: "v1", digest: "sha256:exact", layers: [{ digest: "sha256:layer" }], architectures: ["amd64"], signed: true, signature_info: { signer: "reported-key" }, pulled_at: "2026-10-12T12:00:00Z" },
  findings: [{ id: `${asset}-finding`, kind: "vulnerability", title: `${asset} vulnerable package`, external_id: "CVE-example", severity: "high", risk_score: 70, lifecycle: "open", last_seen_at: "2026-10-12T12:00:00Z" }],
  sboms: [{ id: "document-a", format: "spdx-2.3", sha256: "sha256:inventory", created_at: "2026-10-12T12:00:00Z" }], image_acceptances: [],
});
function findingPage(id = "asset-a", params: Parameters<typeof assets.findings>[1] = {}): AssetFindingInventoryResponse {
  const all = detail(id).findings.map(f => ({ ...f, row_id: `asset:${f.id}:1791842400.000000`, source: "asset" as const }));
  const offset = params.offset ?? 0, limit = params.limit ?? 100;
  return { asset_id: id, cluster_id: params.cluster_id ?? "cluster-a", items: all.slice(offset, offset + limit), total: all.length, summary: { total: all.length, high: all.length, critical: 0, open: all.length, asset_findings: all.length, image_scan_findings: 0 }, limit, offset, has_more: all.length > offset + limit, sort: params.sort ?? "risk", order: params.order ?? "desc", q: params.q ?? "", severity: params.severity ?? "", lifecycle: params.lifecycle ?? "", source: params.source ?? "" };
}
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  identity.org_id = "org-a"; identity.user_id = "user-a";
  scope.available = true; scope.resolvedId = ""; scope.loading = false; scope.error = null;
  vi.mocked(assets.findings).mockImplementation(async (id, params) => findingPage(id, params));
  vi.mocked(assets.findingsCSV).mockResolvedValue({ total: 1, exported: 1, truncated: false, limit: 100000 });
  vi.mocked(assets.get).mockImplementation(async (id) => detail(id, id === "asset-b" ? "cluster-b" : "cluster-a"));
});
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function render(url = "/clusters/cluster-a/assets/asset-a", seed?: (client: QueryClient) => void) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); seed?.(client);
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter path="/clusters/$id/assets/$aid" history={history}><AssetDetailPage /></TestRouter></QueryClientProvider>));
}
async function tab(label: string) { const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === label)!; await act(async () => trigger.focus()); await settled(() => expect(trigger.getAttribute('aria-selected')).toBe("true")); }
const stats = () => [...host.querySelectorAll('[data-testid="asset-stats"] .app-stat-value')].map((item) => item.textContent);
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>('button')].find((item) => item.textContent === label)!;

it("shows a complete evidence verdict, four matching KPIs and findings as the sole primary workspace", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull());
  expect(stats()).toEqual(["1", "1", "1", "1"]); expect(host.querySelector('[data-testid="asset-stats"]')!.children).toHaveLength(4);
  expect(host.textContent).toContain("1 high or critical matching findings"); expect(host.textContent).toContain("1 matching findings");
  expect(host.querySelector('[data-testid="asset-image-card"]')).toBeNull(); expect(host.querySelector('[data-testid="image-acceptance-card"]')).toBeNull(); expect(host.querySelector('[data-testid="asset-sbom-card"]')).toBeNull();
  expect(host.querySelector('textarea')).toBeNull(); expect(host.querySelector<HTMLAnchorElement>('a[href*="/findings/"]')?.getAttribute('href')).toBe('/clusters/cluster-a/findings/asset-a-finding');
});
it("does not query during unresolved, mismatched or errored cluster scope", async () => {
  scope.loading = true; await render(); expect(host.textContent).toContain("Resolving asset cluster"); expect(assets.get).not.toHaveBeenCalled();
  scope.loading = false; scope.resolvedId = "another"; await act(async () => history.push('/clusters/cluster-a/assets/asset-a?scope=mismatch')); await settled(() => expect(host.textContent).toContain("cluster could not be resolved"));
  scope.resolvedId = ""; scope.error = new Error("Registry unavailable"); await act(async () => history.push('/clusters/cluster-a/assets/asset-a?scope=error')); await settled(() => expect(host.textContent).toContain("Registry unavailable")); expect(assets.get).not.toHaveBeenCalled();
});
it.each([{ asset: "another", cluster: "cluster-a" }, { asset: "asset-a", cluster: "another" }, { asset: "asset-a", cluster: undefined }])("rejects asset responses outside exact entity and cluster scope: %o", async ({ asset, cluster }) => {
  const wrong = detail(asset); wrong.asset.cluster_id = cluster; vi.mocked(assets.get).mockResolvedValue(wrong);
  await render(); await settled(() => expect(host.textContent).toContain("does not belong to the requested cluster and asset ID")); expect(host.querySelector('[data-testid="asset-stats"]')).toBeNull(); expect(host.querySelector('[data-testid="asset-findings-table"]')).toBeNull();
});
it("keeps pending reads distinct from zero findings and exposes a retryable fetch failure", async () => {
  let reject!: (error: Error) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })); await render(); await settled(() => expect(host.textContent).toContain("Loading asset evidence")); expect(host.textContent).not.toContain("No findings returned");
  await act(async () => reject(new Error("Asset API unavailable"))); await settled(() => expect(host.textContent).toContain("Asset API unavailable")); expect(stats()).toEqual([]);
  await act(async () => button("Retry asset").click()); await settled(() => expect(stats()[0]).toBe("1"));
});
it("pauses findings during refresh then hides all invalid evidence on refresh failure", async () => {
  await render(); await settled(() => expect(stats()[0]).toBe("1")); let reject!: (error: Error) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
  let fetch!: Promise<void>; await act(async () => { fetch = client.refetchQueries({ queryKey: ["asset", "cluster-a", "asset-a"] }); });
  await settled(() => expect(host.textContent).toContain("Refreshing asset evidence")); expect(host.textContent).not.toContain("asset-a vulnerable package"); expect(stats()[0]).toBe("—");
  await act(async () => { reject(new Error("Refresh failed")); await fetch; }); await settled(() => expect(host.textContent).toContain("Refresh failed")); expect(host.querySelector('[data-testid="asset-findings-table"]')).toBeNull(); expect(stats()).toEqual([]);
});
it("deep-links peer evidence and preserves URL context through tab and history changes", async () => {
  await render('/clusters/cluster-a/assets/asset-a?tab=image&context=keep'); await settled(() => expect(host.querySelector('[data-testid="asset-image-card"]')).not.toBeNull()); expect(host.textContent).toContain("Signature presence is not a verification"); expect(host.textContent).toContain("Not reported");
  await tab("Risk acceptance"); expect(history.location.search).toContain('tab=acceptance'); expect(history.location.search).toContain('context=keep'); expect(host.querySelector('textarea')).toBeNull(); expect(host.querySelector<HTMLAnchorElement>('a[href$="/image-acceptance/new"]')).not.toBeNull();
  await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="asset-image-card"]')).not.toBeNull());
  await act(async () => history.forward()); await settled(() => expect(host.querySelector('[data-testid="image-acceptance-card"]')).not.toBeNull());
});
it("changes entity and cluster without leaking old evidence or navigation targets", async () => {
  await render('/clusters/cluster-a/assets/asset-a?tab=acceptance'); await settled(() => expect(host.querySelector('[data-testid="image-acceptance-card"]')).not.toBeNull());
  await act(async () => history.push('/clusters/cluster-b/assets/asset-b?tab=acceptance')); await settled(() => expect(host.textContent).toContain("registry.example/team/asset-b:v1")); expect(host.textContent).not.toContain("registry.example/team/asset-a:v1"); expect(host.querySelector<HTMLAnchorElement>('a[href$="/image-acceptance/new"]')?.getAttribute('href')).toBe('/clusters/cluster-b/assets/asset-b/image-acceptance/new');
});
it("pauses evidence when a cached cluster registry starts refreshing and hides it on registry failure", async () => {
  await render(undefined, (qc) => qc.setQueryData(["clusters"], { clusters: [{ id: "cluster-a" }] })); await settled(() => expect(stats()[0]).toBe("1"));
  let reject!: (error: Error) => void; let fetch!: Promise<unknown>;
  await act(async () => { fetch = client.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise((_, fail) => { reject = fail; }) }).catch(() => {}); }); await settled(() => expect(host.textContent).toContain("Resolving asset cluster")); expect(stats()).toEqual([]);
  await act(async () => { reject(new Error("Registry refresh failed")); await fetch; }); await settled(() => expect(host.textContent).toContain("cluster could not be resolved")); expect(host.querySelector('[data-testid="asset-findings-table"]')).toBeNull();
});
it("reports full matching summaries independently of bounded legacy detail findings", async () => {
  vi.mocked(assets.findings).mockImplementation(async (id, params) => { const page = findingPage(id, params); return { ...page, items: Array.from({ length: 100 }, (_, n) => ({ ...page.items[0], id: `f-${n}`, row_id: `asset:f-${n}:1791842400.000000` })), total: 1205, has_more: true, summary: { total: 1205, high: 1000, critical: 205, open: 1205, asset_findings: 1000, image_scan_findings: 205 } }; });
  await render(); await settled(() => expect(stats()[0]).toBe('1205')); expect(stats()[1]).toBe('1205'); expect(host.textContent).toContain("1,205 matching findings"); expect(host.textContent).not.toContain("100 asset-finding limit");
});
it("reports missing image metadata truthfully and never exposes image acceptance authoring", async () => {
  const data = detail(); delete data.image; data.findings = []; vi.mocked(assets.get).mockResolvedValue(data);
  await render('/clusters/cluster-a/assets/asset-a?tab=acceptance'); await settled(() => expect(stats()[3]).toBe("Not reported")); expect(host.textContent).toContain("Image metadata is required"); expect(host.querySelector('a[href$="/image-acceptance/new"]')).toBeNull();
});
it("exposes all SBOM formats with explicit metadata and exact-asset export errors", async () => {
  vi.mocked(sbom.downloadSpdx).mockRejectedValueOnce(new Error("No inventory available")); vi.mocked(sbom.downloadCyclonedx).mockResolvedValue(); vi.mocked(sbom.downloadMbom).mockResolvedValue();
  await render('/clusters/cluster-a/assets/asset-a?tab=sbom'); await settled(() => expect(host.querySelector('[data-testid="asset-sbom-card"]')).not.toBeNull()); expect(host.textContent).toContain("latest inventory per format"); expect(host.textContent).toContain("sha256:inventory");
  await act(async () => button("SPDX").click()); await settled(() => expect(host.textContent).toContain("SBOM export failed: No inventory available")); expect(sbom.downloadSpdx).toHaveBeenCalledWith("asset-a");
  await act(async () => button("CycloneDX").click()); await settled(() => expect(sbom.downloadCyclonedx).toHaveBeenCalledWith("asset-a")); await act(async () => button("MBOM").click()); await settled(() => expect(sbom.downloadMbom).toHaveBeenCalledWith("asset-a")); expect(assets.createImageAcceptance).not.toHaveBeenCalled(); expect(assets.revokeImageAcceptance).not.toHaveBeenCalled();
});
it('accepts a settled registry match when the unused single-cluster fallback query is disabled and pending', async () => {
 await render(undefined, (qc) => {
  qc.setQueryData(['clusters'], { clusters: [{ id: 'cluster-a' }] });
  qc.getQueryCache().build(qc, { queryKey: ['cluster', 'cluster-a'], queryFn: () => Promise.resolve({ id: 'cluster-a' }) });
 });
 await settled(() => expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull()); expect(assets.get).toHaveBeenCalledWith('asset-a');
});

it.each([
  (p: AssetFindingInventoryResponse) => ({ ...p, items: null as unknown as AssetFindingInventoryResponse["items"] }),
  (p: AssetFindingInventoryResponse) => ({ ...p, items: [null] as unknown as AssetFindingInventoryResponse["items"] }),
  (p: AssetFindingInventoryResponse) => ({ ...p, asset_id: "another" }),
  (p: AssetFindingInventoryResponse) => ({ ...p, cluster_id: "another" }),
  (p: AssetFindingInventoryResponse) => ({ ...p, offset: 100 }),
  (p: AssetFindingInventoryResponse) => ({ ...p, total: 200 }),
  (p: AssetFindingInventoryResponse) => ({ ...p, source: "image_scan" }),
  (p: AssetFindingInventoryResponse) => ({ ...p, items: [{ ...p.items[0], row_id: "unstable" }] }),
])("rejects mismatched finding evidence and suppresses exports", async (alter) => {
  vi.mocked(assets.findings).mockImplementation(async (id, params) => alter(findingPage(id, params)));
  await render(); await settled(() => expect(host.textContent).toContain("Asset findings are unavailable")); expect(stats()[0]).toBe("—"); expect(button("Export matching CSV")).toBeUndefined();
});
it("uses matching CSV and preserves filters and page through URL history", async () => {
  await render('/clusters/cluster-a/assets/asset-a?tab=findings&severity=high&page=2&context=keep');
  await settled(() => expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull()); expect(assets.findings).toHaveBeenLastCalledWith("asset-a", expect.objectContaining({ severity: "high", offset: 100 }));
  expect(host.textContent).toContain("No findings match"); await act(async () => button("First page").click()); await settled(() => expect(host.textContent).toContain("asset-a vulnerable package")); expect(history.location.search).toContain("context=keep");
  await act(async () => button("Export matching CSV").click()); await settled(() => expect(assets.findingsCSV).toHaveBeenCalledWith("asset-a", expect.objectContaining({ cluster_id: "cluster-a", severity: "high", offset: 0 }), expect.any(Function)));
  await act(async () => history.back()); await settled(() => expect(assets.findings).toHaveBeenLastCalledWith("asset-a", expect.objectContaining({ offset: 100 })));
});
it("keeps a failed inventory refresh distinct from an empty result and recovers", async () => {
 await render(); await settled(() => expect(stats()[0]).toBe("1")); vi.mocked(assets.findings).mockRejectedValueOnce(new Error("offline"));
 await act(async () => { await client.refetchQueries({ queryKey: ["asset-findings"] }); }); await settled(() => expect(host.textContent).toContain("Asset findings are unavailable")); expect(stats()[0]).toBe("—");
 await act(async () => button("Retry findings").click()); await settled(() => expect(stats()[0]).toBe("1"));
});

it("isolates parent asset metadata and findings across account changes", async () => {
  await render(); await settled(() => expect(stats()[0]).toBe("1"));
  identity.user_id = "user-b"; vi.mocked(assets.get).mockImplementationOnce(() => new Promise(() => {}));
  await act(async () => history.push('/clusters/cluster-a/assets/asset-a?context=account-switch'));
  await settled(() => expect(host.textContent).toContain("Loading asset evidence")); expect(stats()).toEqual([]); expect(button("Export matching CSV")).toBeUndefined();
  expect(client.getQueryData(["asset", "cluster-a", "asset-a", "org-a:user-a"])).toBeDefined();
  expect(client.getQueryData(["asset", "cluster-a", "asset-a", "org-a:user-b"])).toBeUndefined();
});
it("hides malformed cached inventory data without crashing the detail page", async () => {
 await render(); await settled(() => expect(stats()[0]).toBe("1"));
 await act(async () => { client.setQueriesData({ queryKey: ["asset-findings"] }, (previous: AssetFindingInventoryResponse | undefined) => previous ? { ...previous, items: null } : previous); });
 await settled(() => expect(host.textContent).toContain("Asset findings are unavailable")); expect(stats()[0]).toBe("—"); expect(button("Export matching CSV")).toBeUndefined();
});
it("keeps distinct historical instances sharing a finding UUID", async () => {
 vi.mocked(assets.findings).mockImplementation(async (id, params) => { const p=findingPage(id,params); return { ...p, total: 2, items: [p.items[0], { ...p.items[0], row_id: `asset:${p.items[0].id}:1791842500.000000`, title: "Historical second instance" }], summary: { ...p.summary, total: 2, high: 2, open: 2, asset_findings: 2 } }; });
 await render(); await settled(() => expect(stats()[0]).toBe("2")); expect(host.textContent).toContain("Historical second instance"); expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull();
});

it("identifies a URL sort on the hidden observed column and lets it be revealed", async () => {
  await render('/clusters/cluster-a/assets/asset-a?sort=observed&order=asc');
  await settled(() => expect(host.textContent).toContain("Sorted by Observed (ascending) · hidden column"));
  expect([...host.querySelectorAll('th')].some(th => th.textContent === "Observed")).toBe(false);
  await act(async () => button("Show sort column").click());
  expect([...host.querySelectorAll('th')].some(th => th.textContent === "Observed")).toBe(true);
});

it("exports the asset finding inventory's actual roles in the visible page columns", async () => {
  vi.mocked(assets.findings).mockImplementation(async (id, params) => {
    const response = findingPage(id, params);
    return { ...response, items: response.items.map(row => ({ ...row, platform_role: "" })) };
  });
  await render(); await settled(() => expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull());
  expect(host.querySelector('[data-testid="asset-findings-table"] thead')?.textContent).not.toContain("Platform role");
  await act(async () => host.querySelector<HTMLButtonElement>('[data-testid="asset-findings-table-columns-trigger"]')!.dispatchEvent(new MouseEvent("pointerdown", { bubbles: true, button: 0 })));
  await settled(() => expect(document.querySelector('[role="menuitemcheckbox"]')).not.toBeNull());
  await act(async () => [...document.querySelectorAll<HTMLElement>('[role="menuitemcheckbox"]')].find(item => item.textContent === "Platform role")!.click());
  expect(host.textContent).toContain("Unclassified");
  await act(async () => button("Export this page CSV").click());
  const [, headers, rows] = vi.mocked(downloadCsv).mock.calls.at(-1)!;
  const role = headers.indexOf("Platform role"); expect(role).toBeGreaterThanOrEqual(0);
  expect(rows.map(row => row[role])).toEqual([""]);
});
it('links generic recurrences using raw observation timestamps while leaving canonical image evidence read-only', async () => {
  const older = { ...detail().findings[0], id: 'shared', row_id: 'asset:shared:1791763200.123456', first_seen_at: '2026-10-12T00:00:00.123456Z', revision: '4', source_cluster_id: 'cluster-a', target_cluster_id: null, source: 'asset' as const };
  const newer = { ...older, row_id: 'asset:shared:1791763200.123457', first_seen_at: '2026-10-12T00:00:00.123457Z' };
  const image = { ...older, row_id: 'image:shared', image_scan_result_id: 'scan', source: 'image_scan' as const, first_seen_at: null, revision: undefined, source_cluster_id: null, title: 'Canonical image observation' };
  vi.mocked(assets.findings).mockResolvedValue({ ...findingPage(), items: [older, newer, image], total: 3, summary: { total: 3, high: 3, critical: 0, open: 3, asset_findings: 2, image_scan_findings: 1 } });
  await render(); await settled(() => expect(host.querySelectorAll('[data-testid="asset-findings-table"] tbody tr')).toHaveLength(3));
  const hrefs = [...host.querySelectorAll<HTMLAnchorElement>('tbody a[href*="/findings/"]')].map(link => link.getAttribute('href'));
  expect(hrefs).toEqual(['/clusters/cluster-a/findings/shared?first_seen_at=2026-10-12T00%3A00%3A00.123456Z', '/clusters/cluster-a/findings/shared?first_seen_at=2026-10-12T00%3A00%3A00.123457Z']); expect(host.querySelector('[data-testid="asset-findings-table"] tbody')?.textContent).toContain('Canonical image observation');
});
