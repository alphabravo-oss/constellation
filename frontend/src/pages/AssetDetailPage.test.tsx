import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { assets, sbom, type AssetDetail } from "@/api/client";
import { TestRouter } from "@/test/router";
import { AssetDetailPage } from "./AssetDetailPage";

const scope = vi.hoisted(() => ({ available: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
  const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
  return { useCluster: () => { const { id } = router.useParams({ strict: false }); return { clusterId: id, cluster: scope.available ? { id: scope.resolvedId || id } : undefined, isLoading: scope.loading, error: scope.error }; } };
});
vi.mock("@/api/client", () => ({ assets: { get: vi.fn(), createImageAcceptance: vi.fn(), revokeImageAcceptance: vi.fn() }, sbom: { downloadSpdx: vi.fn(), downloadCyclonedx: vi.fn(), downloadMbom: vi.fn() } }));
const detail = (asset = "asset-a", cluster = "cluster-a"): AssetDetail => ({
  asset: { id: asset, cluster_id: cluster, name: `Image ${asset}`, kind: "image", criticality: "high", digest: "sha256:exact", labels: { owner: "inventory-team" }, ai_workload: false, finding_count: 999, critical_findings: 999, high_findings: 999, open_findings: 999, sbom_count: 999, first_seen_at: "2026-10-10T12:00:00Z", last_seen_at: "2026-10-12T12:00:00Z" },
  image: { registry: "registry.example", repository: `team/${asset}`, tag: "v1", digest: "sha256:exact", layers: [{ digest: "sha256:layer" }], architectures: ["amd64"], signed: true, signature_info: { signer: "reported-key" }, pulled_at: "2026-10-12T12:00:00Z" },
  findings: [{ id: `${asset}-finding`, kind: "vulnerability", title: `${asset} vulnerable package`, external_id: "CVE-example", severity: "high", risk_score: 70, lifecycle: "open", last_seen_at: "2026-10-12T12:00:00Z" }],
  sboms: [{ id: "document-a", format: "spdx-2.3", sha256: "sha256:inventory", created_at: "2026-10-12T12:00:00Z" }], image_acceptances: [],
});
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  scope.available = true; scope.resolvedId = ""; scope.loading = false; scope.error = null;
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

it("shows a bounded evidence verdict, four loaded KPIs and findings as the sole primary workspace", async () => {
  await render(); await settled(() => expect(host.querySelector('[data-testid="asset-findings-table"]')).not.toBeNull());
  expect(stats()).toEqual(["1", "1", "1", "1"]); expect(host.querySelector('[data-testid="asset-stats"]')!.children).toHaveLength(4);
  expect(host.textContent).toContain("1 high or critical findings in loaded evidence"); expect(host.textContent).toContain("up to 100 asset findings");
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
it("retains current rows during refresh then hides all invalid evidence on refresh failure", async () => {
  await render(); await settled(() => expect(stats()[0]).toBe("1")); let reject!: (error: Error) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; }));
  let fetch!: Promise<void>; await act(async () => { fetch = client.refetchQueries({ queryKey: ["asset", "cluster-a", "asset-a"] }); });
  await settled(() => expect(host.textContent).toContain("Refreshing asset evidence")); expect(host.textContent).toContain("asset-a vulnerable package"); expect(stats()[0]).toBe("1");
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
it("reports capped generic findings separately from shared digest findings", async () => {
  const data = detail(); data.findings = Array.from({ length: 100 }, (_, index) => ({ ...data.findings[0], id: `finding-${index}` })); data.findings.push({ ...data.findings[0], id: 'scan-only', title: 'Shared digest finding', image_scan_result_id: 'scan-a' }); vi.mocked(assets.get).mockResolvedValue(data);
  await render(); await settled(() => expect(stats()[0]).toBe('101')); expect(host.textContent).toContain("100 asset-finding limit was reached"); expect(host.textContent).toContain("table exports cover loaded evidence");
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
