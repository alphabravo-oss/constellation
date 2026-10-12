import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, cve, nodes, serverlessFunctions, type NodeDetail, type ServerlessFunctionDetail, type CVEAffectedResponse } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { TestRouter } from "@/test/router";
import { NodeDetailPage } from "./NodeDetailPage";
import { ServerlessFunctionDetailPage } from "./ServerlessFunctionDetailPage";
import { CVEDetailPage } from "./CVEDetailPage";

const scope = vi.hoisted(() => ({ resolved: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
 const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
 return { useCluster: () => { const { id } = router.useParams({ strict: false }); return { clusterId: id, cluster: scope.resolved ? { id: scope.resolvedId || id, name: `Resolved ${id}` } : undefined, isLoading: scope.loading, error: scope.error }; } };
});
vi.mock("@/api/client", () => ({ api: { get: vi.fn() }, cve: { affected: vi.fn() }, nodes: { get: vi.fn(), scan: vi.fn() }, serverlessFunctions: { get: vi.fn() } }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
const at = "2026-10-12T12:00:00Z";
const nodeDetail = (cluster = "cluster-a", name = "node-a"): NodeDetail => ({
 node: { node: name, cluster_id: cluster, package_count: 4, container_count: 1, process_count: 1, cis_passed: 3, cis_failed: 1, cis_warned: 0, cis_skipped: 0, critical_vulns: 1, high_vulns: 1, medium_vulns: 0, low_vulns: 0, open_vulns: 2401, runtime_agent_status: "healthy", scan_status: "completed", scan_target_id: `target-${name}`, last_scanned_at: at, last_seen_at: at, packages_observed_at: at, containers_observed_at: at, processes_observed_at: at, cis_observed_at: at, host_facts_observed_at: at },
 vulnerabilities: [{ node: name, cluster_id: cluster, vuln_id: "CVE-2026-1234", package_name: "host-package", package_version: "1.0", fixed_version: "1.1", severity: "high", observed_at: at, source: "trivy" }],
 facts: { os: "Fixture OS" }, packages: { packages: [{ name: "host-package", version: "1.0", ecosystem: "deb" }] },
 containers: { items: [{ id: "container-a", name: "api-container", pod_name: "api-123-abc", pod_namespace: "default", image_ref: "registry.example/full-image-reference-without-clipping:v1", state: "CONTAINER_RUNNING" }] },
 processes: { items: [{ pid: 42, comm: "fixture-process", uid: 0, cmdline: "fixture-process --keep-full-command" }] },
 cis: { checks: [{ id: "CIS-1", title: "Fixture benchmark", result: "fail", detail: "Apply recorded remediation" }] },
});
const functionDetail = (id = "function-a"): ServerlessFunctionDetail => ({
 serverless_function: { id, function_ref: `arn:aws:lambda:fixture:${id}`, function_name: `Function ${id}`, source_type: "discoverer", package_count: 400, open_findings: 125, critical_findings: 2, high_findings: 3, last_seen_at: at, permission_status: "completed", permission_level: "medium", layers: ["layer-a"], permission_analysis: { findings: [{ id: "role-issue", title: "Permission issue", severity: "high" }], attached_policies: Array.from({ length: 8 }, (_, index) => ({ name: `managed-${index}`, arn: `arn:policy:${index}` })), inline_policies: Array.from({ length: 8 }, (_, index) => `inline-${index}`) } },
 latest_evidence: { id: "evidence-a", inventory_hash: "hash-a", package_count: 400, observed_at: at, packages: [{ name: "function-package", version: "2.0", ecosystem: "npm", purl: "pkg:npm/function-package@2.0" }] },
 findings: [{ id: "org-finding", title: "Organization function finding", kind: "vulnerability", external_id: "CVE-2026-1234", severity: "high", risk_score: 80, lifecycle: "open", first_seen_at: at, last_seen_at: at }],
 jobs: [{ id: "job-a", status: "completed", package_count: 400, finding_count: 125, requested_at: at, finished_at: at }],
});
const intelligence = (id = "CVE-2026-1234") => ({ cve_id: id, title: `Metadata ${id}`, description: "Recorded vulnerability description", cvss_base: 8.1, kev_listed: true, epss_probability: 0.42, aliases: ["GHSA-fixture"] });
const affected = (cluster = "cluster-a", id = "CVE-2026-1234"): CVEAffectedResponse => ({
 cve_id: id, summary: { image_count: 1, workload_count: 1, cluster_count: 1, finding_count: 2, max_risk_score: 80 },
 images: [{ image_scan_result_id: "image-a", image_ref: "registry.example/api:v1", image_ref_normalized: "registry.example/api:v1", image_repository: "registry.example/api", image_tag: "v1", image_digest: "sha256:exact", scanner_profile: "trivy", finding_count: 2, max_risk_score: 80, severity_counts: { high: 2 }, last_seen_at: at, last_scanned_at: at, packages: [{ finding_id: "scan-finding", package_name: "vulnerable-package", package_version: "1.0", fixed_version: "1.1", severity: "high", risk_score: 80 }] }],
 workloads: [{ cluster_id: cluster, cluster_name: cluster, deployment_id: "deployment-a", workload_id: "default/api", namespace: "default", name: "api", kind: "Deployment", image_ref: "registry.example/api:v1", image_ref_normalized: "registry.example/api:v1", image_digest: "sha256:exact", finding_count: 2, max_risk_score: 80, critical_count: 0, high_count: 2, last_seen_at: at }],
 clusters: [{ cluster_id: cluster, name: cluster, workload_count: 1, finding_count: 2, max_risk_score: 80 }],
});
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
 scope.resolved = true; scope.resolvedId = ""; scope.loading = false; scope.error = null;
 vi.mocked(nodes.get).mockImplementation(async (cluster, name) => nodeDetail(cluster, name)); vi.mocked(nodes.scan).mockResolvedValue({ data: {} } as never);
 vi.mocked(serverlessFunctions.get).mockImplementation(async (id) => functionDetail(id));
 vi.mocked(api.get).mockImplementation(async (url) => ({ data: intelligence(String(url).split('/').at(-1)) }) as never);
 vi.mocked(cve.affected).mockImplementation(async (id, cluster) => affected(cluster, id));
});
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function render(kind: "node" | "function" | "cve" | "global-cve", url?: string, seed?: (client: QueryClient) => void) {
 host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); seed?.(client);
 const path = kind === 'node' ? '/clusters/$id/nodes/$nodeName' : kind === 'function' ? '/clusters/$id/serverless/$functionId' : kind === 'cve' ? '/clusters/$id/cve/$cveId' : '/cve/$id';
 const initial = url ?? (kind === 'node' ? '/clusters/cluster-a/nodes/node-a' : kind === 'function' ? '/clusters/cluster-a/serverless/function-a' : kind === 'cve' ? '/clusters/cluster-a/cve/CVE-2026-1234' : '/cve/CVE-2026-1234');
 history = createMemoryHistory({ initialEntries: [initial] });
 await act(async () => root.render(<QueryClientProvider client={client}><TestRouter path={path} history={history}>{kind === 'node' ? <NodeDetailPage /> : kind === 'function' ? <ServerlessFunctionDetailPage /> : <CVEDetailPage />}</TestRouter></QueryClientProvider>));
}
const stats = (name: string) => [...host.querySelectorAll(`[data-testid="${name}"] .app-stat-value`)].map((item) => item.textContent);
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>('button')].find((item) => item.textContent === label)!;
async function tab(label: string) { const trigger = [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')].find((item) => item.textContent === label)!; await act(async () => trigger.focus()); await settled(() => expect(trigger.getAttribute('aria-selected')).toBe('true')); }

it('shows five reported node KPIs with a single bounded host-vulnerability workspace', async () => {
 await render('node'); await settled(() => expect(host.querySelector('[data-testid="node-vulnerabilities"]')).not.toBeNull()); expect(stats('node-stats')).toEqual(['2401', '4', '1', '1', '1']);
 expect(host.textContent).toContain('Server fetch limit: 2,000 rows'); expect(host.textContent).toContain('summary can exceed this detail limit'); expect(host.textContent).toContain('host-package'); expect(host.textContent).not.toContain('Fixture benchmark'); expect(host.textContent).not.toContain('fixture-process'); expect(host.querySelector('[data-testid="node-stats"]')!.children).toHaveLength(5);
});
it.each(['node', 'function', 'cve'] as const)('does not query %s details before cluster scope is settled', async (kind) => {
 scope.loading = true; await render(kind); expect(nodes.get).not.toHaveBeenCalled(); expect(serverlessFunctions.get).not.toHaveBeenCalled(); expect(api.get).not.toHaveBeenCalled(); expect(cve.affected).not.toHaveBeenCalled();
 scope.loading = false; scope.resolvedId = 'another'; await act(async () => history.push(`${history.location.pathname.replace("cluster-a", "cluster-b")}?scope=mismatched`)); await settled(() => expect(host.textContent).toContain('could not be resolved')); expect(nodes.get).not.toHaveBeenCalled(); expect(serverlessFunctions.get).not.toHaveBeenCalled(); expect(api.get).not.toHaveBeenCalled();
});
it('keeps uncollected node values distinct from zero and preserves peer evidence through URL history', async () => {
 const data = nodeDetail(); delete data.node.last_scanned_at; delete data.node.packages_observed_at; vi.mocked(nodes.get).mockResolvedValue(data);
 await render('node', '/clusters/cluster-a/nodes/node-a?context=keep'); await settled(() => expect(stats('node-stats')[0]).toBe('Not scanned')); expect(stats('node-stats')[1]).toBe('Not collected'); expect(host.textContent).toContain('collection or scan gaps');
 await tab('CIS benchmark'); expect(history.location.search).toContain('tab=cis'); expect(history.location.search).toContain('context=keep'); expect(host.textContent).toContain('Fixture benchmark');
 await tab('Containers'); expect(host.textContent).toContain('registry.example/full-image-reference-without-clipping:v1'); await act(async () => history.back()); await settled(() => expect(host.textContent).toContain('Fixture benchmark'));
 await tab('Packages'); expect(host.querySelector('[data-testid="node-package-inventory"]')).not.toBeNull(); expect(host.textContent).toContain('host-package');
});
it('rejects wrong-node and wrong-cluster returned or cached evidence', async () => {
 vi.mocked(nodes.get).mockResolvedValue(nodeDetail('another', 'node-b')); await render('node', undefined, (qc) => qc.setQueryData(['node-detail', 'cluster-a', 'node-a'], nodeDetail('another', 'node-b')));
 await settled(() => expect(host.textContent).toContain('does not match the requested node and cluster')); expect(host.querySelector('[data-testid="node-stats"]')).toBeNull(); expect(host.textContent).not.toContain('host-package'); expect(nodes.scan).not.toHaveBeenCalled();
});
it('retains node rows during a deferred refresh then hides them on failure with Retry', async () => {
 await render('node'); await settled(() => expect(stats('node-stats')[0]).toBe('2401'));
 let reject!: (error: Error) => void; vi.mocked(nodes.get).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })); let fetch!: Promise<void>;
 await act(async () => { fetch = client.refetchQueries({ queryKey: ['node-detail'] }); }); await settled(() => expect(host.textContent).toContain('Refreshing node evidence')); expect(host.textContent).toContain('host-package'); expect(button('Scan node').disabled).toBe(true);
 await act(async () => { reject(new Error('Node refresh failed')); await fetch; }); await settled(() => expect(host.textContent).toContain('Node refresh failed')); expect(stats('node-stats')).toEqual([]); expect(host.textContent).not.toContain('host-package');
 await act(async () => button('Retry node').click()); await settled(() => expect(stats('node-stats')[0]).toBe('2401'));
});
it('queues only the freshly reviewed exact node target and visibly reports action failure', async () => {
 vi.mocked(nodes.scan).mockRejectedValueOnce(new Error('Queue unavailable')); await render('node'); await settled(() => expect(button('Scan node')).toBeDefined()); await act(async () => button('Scan node').click());
 await settled(() => expect(host.textContent).toContain('Scan request failed: Queue unavailable')); expect(nodes.scan).toHaveBeenCalledWith('target-node-a'); expect(nodes.get).toHaveBeenCalledWith('cluster-a', 'node-a');
});
it('does not queue an old node after navigation during scan preflight', async () => {
 await render('node'); await settled(() => expect(button('Scan node')).toBeDefined()); let release!: (data: NodeDetail) => void; vi.mocked(nodes.get).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await act(async () => button('Scan node').click()); await settled(() => expect(release).toBeDefined());
 await act(async () => history.push('/clusters/cluster-b/nodes/node-b')); await settled(() => expect(host.textContent).toContain('node-b')); await act(async () => release(nodeDetail())); expect(nodes.scan).not.toHaveBeenCalled(); expect(host.querySelector<HTMLAnchorElement>('a')?.getAttribute('href')).toBe('/clusters/cluster-b/nodes');
});
it('rejects a changed scan target discovered during preflight', async () => {
 await render('node'); await settled(() => expect(button('Scan node')).toBeDefined()); const changed = nodeDetail(); changed.node.scan_target_id = 'another-target'; vi.mocked(nodes.get).mockResolvedValueOnce(changed); await act(async () => button('Scan node').click()); await settled(() => expect(host.textContent).toContain('scan target changed')); expect(nodes.scan).not.toHaveBeenCalled();
});
it('retains the literal router-decoded node name instead of decoding it a second time', async () => {
 await render('node', '/clusters/cluster-a/nodes/node%252Fa'); await settled(() => expect(nodes.get).toHaveBeenCalledWith('cluster-a', 'node%2Fa')); expect(nodes.get).not.toHaveBeenCalledWith('cluster-a', 'node/a');
});
it('discloses organization-wide serverless scope and replaces the synthetic role-risk count', async () => {
 await render('function'); await settled(() => expect(stats('serverless-function-stats')).toEqual(['125', '400', '1', '5'])); expect(host.textContent).toContain('Organization-wide cloud evidence'); expect(host.textContent).toContain('navigation context only'); expect(host.textContent).toContain('Server fetch limit: 100 rows');
 expect(host.textContent).toContain('Organization function finding'); expect(host.querySelector('a[href*="/findings/"]')).toBeNull(); expect(host.textContent).not.toContain('Role Risk'); expect(host.textContent).not.toContain('function-package'); expect(host.textContent).not.toContain('job-a');
});
it('deep-links serverless packages and jobs with honest source limits and full evidence', async () => {
 await render('function', '/clusters/cluster-a/serverless/function-a?tab=jobs&context=keep'); await settled(() => expect(host.textContent).toContain('job-a')); expect(host.textContent).toContain('Server fetch limit: 25 rows');
 await tab('Packages'); expect(history.location.search).toContain('tab=packages'); expect(history.location.search).toContain('context=keep'); expect(host.textContent).toContain('function-package'); expect(host.textContent).not.toContain('job-a');
});
it('retains every reported attached policy beyond the old six-row cutoff', async () => {
 await render('function', '/clusters/cluster-a/serverless/function-a?tab=permissions'); await settled(() => expect(host.textContent).toContain('Permission issue')); const summary = [...host.querySelectorAll('summary')].find((item) => item.textContent === 'Attached policy evidence')!;
 await act(async () => summary.click()); expect(host.textContent).toContain('managed-7'); expect(host.textContent).toContain('inline-7');
});
it('keeps serverless missing package and layer metadata unknown', async () => {
 const data = functionDetail(); data.latest_evidence = null; delete data.serverless_function.layers; vi.mocked(serverlessFunctions.get).mockResolvedValue(data); await render('function'); await settled(() => expect(stats('serverless-function-stats')[1]).toBe('Not collected')); expect(stats('serverless-function-stats')[2]).toBe('Not reported'); expect(host.textContent).toContain('No collected package evidence returned');
});
it('rejects an unrelated serverless function response and does not reuse old entity evidence after navigation', async () => {
 vi.mocked(serverlessFunctions.get).mockResolvedValueOnce(functionDetail('wrong')); await render('function'); await settled(() => expect(host.textContent).toContain('does not match the requested function ID')); expect(host.querySelector('[data-testid="serverless-function-stats"]')).toBeNull();
 await act(async () => history.push('/clusters/cluster-b/serverless/function-b?tab=jobs')); await settled(() => expect(host.textContent).toContain('Function function-b')); expect(host.querySelector<HTMLAnchorElement>('a')?.getAttribute('href')).toBe('/clusters/cluster-b/serverless');
});
it('keeps successful serverless rows during refresh then exposes failure without empty success', async () => {
 await render('function'); await settled(() => expect(stats('serverless-function-stats')[0]).toBe('125')); let reject!: (error: Error) => void; vi.mocked(serverlessFunctions.get).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })); let fetch!: Promise<void>;
 await act(async () => { fetch = client.refetchQueries({ queryKey: ['serverless-function'] }); }); await settled(() => expect(host.textContent).toContain('Refreshing serverless evidence')); expect(host.textContent).toContain('Organization function finding');
 await act(async () => { reject(new Error('Function refresh failed')); await fetch; }); await settled(() => expect(host.textContent).toContain('Function refresh failed')); expect(stats('serverless-function-stats')).toEqual([]); expect(host.textContent).not.toContain('Organization function finding');
});
it('shows four bounded CVE metrics and a paginated semantic image workspace', async () => {
 await render('cve'); await settled(() => expect(stats('cve-detail-stats')).toEqual(['1', '1', '1', '2'])); expect(host.textContent).toContain('listed as known exploited'); expect(host.textContent).toContain('Server fetch limit: 500 rows'); expect(host.textContent).toContain('1,000 workload associations'); expect(host.querySelector('[data-testid="cve-tile-lists"]')).toBeNull(); expect(host.querySelector('[data-testid="cve-affected-workloads"]')).toBeNull();
 expect(host.querySelector<HTMLAnchorElement>('a[href*="/images/"]')?.getAttribute('href')).toBe('/clusters/cluster-a/images/image-a'); expect(cve.affected).toHaveBeenCalledWith('CVE-2026-1234', 'cluster-a');
});
it('keeps global CVE evidence organization scoped without requiring or inventing a selected cluster', async () => {
 scope.resolved = false; scope.error = new Error('No navigation cluster'); await render('global-cve'); await settled(() => expect(stats('cve-detail-stats')[0]).toBe('1')); expect(host.textContent).toContain('across the organization'); expect(cve.affected).toHaveBeenCalledWith('CVE-2026-1234', undefined); expect(host.querySelector<HTMLAnchorElement>('a')?.getAttribute('href')).toBe('/cve');
});
it('keeps pending affected evidence unknown instead of zero and visibly recovers after Retry', async () => {
 let reject!: (error: Error) => void; vi.mocked(cve.affected).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })); await render('cve'); await settled(() => expect(stats('cve-detail-stats')).toEqual(['—', '—', '—', '—'])); expect(host.textContent).toContain('Loading affected evidence'); expect(host.textContent).not.toContain('No affected image scans');
 await act(async () => reject(new Error('Affected unavailable'))); await settled(() => expect(host.textContent).toContain('Affected unavailable')); expect(stats('cve-detail-stats')).toEqual(['—', '—', '—', '—']);
 await act(async () => button('Retry affected evidence').click()); await settled(() => expect(stats('cve-detail-stats')[0]).toBe('1'));
});
it.each(['cve', 'cluster'] as const)('rejects affected evidence with the wrong %s identity', async (identity) => {
 vi.mocked(cve.affected).mockResolvedValue(affected(identity === 'cluster' ? 'another' : 'cluster-a', identity === 'cve' ? 'CVE-2026-9999' : 'CVE-2026-1234')); await render('cve'); await settled(() => expect(host.textContent).toContain('does not match the requested CVE and cluster scope')); expect(stats('cve-detail-stats')).toEqual(['—', '—', '—', '—']); expect(host.querySelector('[data-testid="cve-affected-images"]')).toBeNull();
});
it('rejects cached affected evidence from another cluster before its refresh resolves', async () => {
 vi.mocked(cve.affected).mockImplementation(() => new Promise(() => {})); await render('cve', undefined, (qc) => qc.setQueryData(['cve-affected', 'CVE-2026-1234', 'cluster-a'], affected('another')));
 await settled(() => expect(host.textContent).toContain('does not match the requested CVE and cluster scope')); expect(host.querySelector('[data-testid="cve-affected-images"]')).toBeNull(); expect(stats('cve-detail-stats')).toEqual(['—', '—', '—', '—']);
});
it('rejects CVE metadata returned for another ID', async () => {
 vi.mocked(api.get).mockResolvedValue({ data: intelligence('CVE-2026-9999') } as never); await render('cve'); await settled(() => expect(host.textContent).toContain('does not match the requested CVE ID')); expect(host.querySelector('[data-testid="cve-detail-stats"]')).toBeNull();
});
it('keeps successful CVE rows during refresh but hides stale affected evidence after failure', async () => {
 await render('cve'); await settled(() => expect(stats('cve-detail-stats')[0]).toBe('1')); let reject!: (error: Error) => void; vi.mocked(cve.affected).mockImplementationOnce(() => new Promise((_, fail) => { reject = fail; })); let fetch!: Promise<void>;
 await act(async () => { fetch = client.refetchQueries({ queryKey: ['cve-affected'] }); }); await settled(() => expect(host.textContent).toContain('Refreshing CVE evidence')); expect(host.querySelector('[data-testid="cve-affected-images"]')).not.toBeNull();
 await act(async () => { reject(new Error('Affected refresh failed')); await fetch; }); await settled(() => expect(host.textContent).toContain('Affected refresh failed')); expect(stats('cve-detail-stats')).toEqual(['—', '—', '—', '—']); expect(host.querySelector('[data-testid="cve-affected-images"]')).toBeNull();
});
it('preserves CVE URL tabs and package evidence without false generic finding links', async () => {
 await render('cve', '/clusters/cluster-a/cve/CVE-2026-1234?tab=workloads&context=keep'); await settled(() => expect(host.querySelector('[data-testid="cve-affected-workloads"]')).not.toBeNull()); expect(host.textContent).toContain('Server fetch limit: 1,000 rows');
 await tab('Package evidence'); expect(history.location.search).toContain('tab=packages'); expect(history.location.search).toContain('context=keep'); expect(host.textContent).toContain('vulnerable-package'); expect(host.textContent).toContain('1.1'); expect(host.querySelector('a[href*="/findings/"]')).toBeNull(); await act(async () => history.back()); await settled(() => expect(host.querySelector('[data-testid="cve-affected-workloads"]')).not.toBeNull());
});
it('paginates and exports all loaded CVE image rows rather than only the visible table page', async () => {
 const data = affected(); data.images = Array.from({ length: 120 }, (_, index) => ({ ...data.images[0], image_scan_result_id: `image-${index}`, image_repository: `registry.example/image-${index}` })); vi.mocked(cve.affected).mockResolvedValue(data); await render('cve'); await settled(() => expect(host.textContent).toContain('Page 1 of 2'));
 await act(async () => button('Export CSV').click()); expect(downloadCsv).toHaveBeenCalledOnce(); expect(vi.mocked(downloadCsv).mock.calls[0][2]).toHaveLength(120); expect(vi.mocked(downloadCsv).mock.calls[0][0]).toBe('CVE-2026-1234-cluster-a-affected-images-loaded');
});
it('pauses all scoped detail evidence during a cluster registry refresh and hides it on error', async () => {
 await render('node', undefined, (qc) => { qc.setQueryData(['clusters'], { clusters: [{ id: 'cluster-a' }] }); qc.getQueryCache().build(qc, { queryKey: ['cluster', 'cluster-a'], queryFn: async () => ({ id: 'cluster-a' }) }); }); await settled(() => expect(stats('node-stats')[0]).toBe('2401'));
 let reject!: (error: Error) => void; let fetch!: Promise<unknown>; await act(async () => { fetch = client.fetchQuery({ queryKey: ['clusters'], queryFn: () => new Promise((_, fail) => { reject = fail; }) }).catch(() => {}); }); await settled(() => expect(host.textContent).toContain('Resolving node cluster')); expect(stats('node-stats')).toEqual([]);
 await act(async () => { reject(new Error('Registry failed')); await fetch; }); await settled(() => expect(host.textContent).toContain('could not be resolved')); expect(host.querySelector('[data-testid="node-detail-page"]')).toBeNull();
});
