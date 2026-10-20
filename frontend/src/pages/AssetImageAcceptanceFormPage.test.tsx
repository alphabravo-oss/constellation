import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { assets, type AssetDetail, type ImageAcceptance } from "@/api/client";
import { TestRouter } from "@/test/router";
import { AssetImageAcceptanceFormPage } from "./AssetImageAcceptanceFormPage";
vi.mock("@/contexts/TablePreferencesContext", () => ({ useTablePreferencesIdentity: () => ({ org_id: "org-a", user_id: "user-a" }) }));
const scope = vi.hoisted(() => ({ available: true, resolvedId: "", loading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", async () => {
 const router = await vi.importActual<typeof import("@tanstack/react-router")>("@tanstack/react-router");
 return { useCluster: () => { const { id } = router.useParams({ strict: false }); return { clusterId: id, cluster: scope.available ? { id: scope.resolvedId || id } : undefined, isLoading: scope.loading, error: scope.error }; } };
});
vi.mock("@/api/client", () => ({ assets: { get: vi.fn(), createImageAcceptance: vi.fn(), revokeImageAcceptance: vi.fn() } }));
const acceptance = (status: ImageAcceptance['status'] = 'active'): ImageAcceptance => ({ id: 'acceptance-a', image_digest: 'sha256:reviewed', rationale: 'Reviewed compensating controls', approver_id: 'user-a', accepted_until: new Date(Date.now() + 7 * 86400000).toISOString(), created_at: '2026-10-12T12:00:00Z', status });
const detail = (asset = 'asset-a', cluster = 'cluster-a'): AssetDetail => ({ asset: { id: asset, cluster_id: cluster, kind: 'image', name: `Image ${asset}`, criticality: 'high', labels: {}, digest: 'sha256:reviewed' } as AssetDetail['asset'], image: { digest: 'sha256:reviewed', registry: 'registry.example', repository: `team/${asset}`, tag: 'v1', layers: [], architectures: [], signed: false, signature_info: {}, pulled_at: '' }, findings: [], sboms: [], image_acceptances: [] });
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
 scope.available = true; scope.resolvedId = ''; scope.loading = false; scope.error = null;
 vi.mocked(assets.get).mockImplementation(async (id) => detail(id, id === 'asset-b' ? 'cluster-b' : 'cluster-a'));
 vi.mocked(assets.createImageAcceptance).mockImplementation(async (id, body) => ({ id: 'created-a', asset_id: id, cluster_id: body.cluster_id, image_digest: body.expected_image_digest, image_acceptances: [{ ...acceptance(), id: 'created-a', rationale: body.rationale, accepted_until: body.accepted_until }] }));
});
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function render(action: 'create' | 'revoke' = 'create', url?: string, seed?: (client: QueryClient) => void) {
 host = document.createElement('div'); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); seed?.(client);
 const path = action === 'create' ? '/clusters/$id/assets/$aid/image-acceptance/new' : '/clusters/$id/assets/$aid/image-acceptance/$acceptanceId/revoke';
 history = createMemoryHistory({ initialEntries: [url ?? (action === 'create' ? '/clusters/cluster-a/assets/asset-a/image-acceptance/new' : '/clusters/cluster-a/assets/asset-a/image-acceptance/acceptance-a/revoke')] });
 await act(async () => root.render(<QueryClientProvider client={client}><TestRouter path={path} history={history}><AssetImageAcceptanceFormPage action={action} /></TestRouter></QueryClientProvider>));
}
async function rationale(value = 'Reviewed compensating controls') { await act(async () => { const el = host.querySelector<HTMLTextAreaElement>('#image-accept-rationale')!; Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value')!.set!.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); }); }
async function expiry(value: string) { await act(async () => { const el = host.querySelector<HTMLInputElement>('#image-accept-until')!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); }); }
async function submit() { await act(async () => host.querySelector('form')!.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }))); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>('button')].find((item) => item.textContent === label || item.getAttribute("aria-label") === label || item.getAttribute("data-export-label") === label)!;

it('requires reason and future bounded expiry before recording a reviewed organization-wide digest', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); expect(button('Save acceptance').disabled).toBe(true); expect(host.textContent).toContain('organization-wide scope'); expect(host.textContent).toContain('sha256:reviewed');
 await rationale('too short'); await submit(); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
 await rationale(); await expiry('2020-01-01'); expect(button('Save acceptance').disabled).toBe(true); await expiry('2099-01-01'); expect(button('Save acceptance').disabled).toBe(true);
 const until = new Date(Date.now() + 14 * 86400000).toISOString().slice(0, 10); await expiry(until); await submit(); await settled(() => expect(host.querySelector('[data-testid="image-acceptance-result"]')).not.toBeNull());
 expect(assets.createImageAcceptance).toHaveBeenCalledWith('asset-a', { rationale: 'Reviewed compensating controls', accepted_until: `${until}T23:59:59.000Z`, expected_image_digest: 'sha256:reviewed', cluster_id: 'cluster-a' }); expect(assets.revokeImageAcceptance).not.toHaveBeenCalled();
 expect([...host.querySelectorAll<HTMLAnchorElement>('a')].every((link) => link.getAttribute('href') === '/clusters/cluster-a/assets/asset-a?tab=acceptance')).toBe(true);
});
it('retains the draft and server error after failed save', async () => {
 vi.mocked(assets.createImageAcceptance).mockRejectedValueOnce({ response: { data: { error: 'Acceptance already recorded' } } }); await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale('Preserve my reviewed rationale'); await submit();
 await settled(() => expect(host.textContent).toContain('Acceptance already recorded')); expect(host.querySelector<HTMLTextAreaElement>('#image-accept-rationale')?.value).toBe('Preserve my reviewed rationale'); expect(button('Save acceptance').disabled).toBe(false);
});
it('does not capture cached image data until initial refresh settles', async () => {
 vi.mocked(assets.get).mockImplementation(() => new Promise(() => {})); await render('create', undefined, (qc) => qc.setQueryData(['asset', 'cluster-a', 'asset-a', 'org-a:user-a'], detail()));
 await settled(() => expect(host.textContent).toContain('Loading exact image digest')); expect(host.querySelector('form')).toBeNull();
});
it('never loads or writes an image decision in unresolved cluster scope', async () => {
 scope.resolvedId = 'another'; await render(); expect(host.textContent).toContain('cluster could not be resolved'); expect(assets.get).not.toHaveBeenCalled(); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
});
it('retains draft during failed refresh and blocks save until a valid retry', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale('Keep my image rationale'); vi.mocked(assets.get).mockRejectedValueOnce(new Error('Refresh failed'));
 await act(async () => { await client.refetchQueries({ queryKey: ['asset', 'cluster-a', 'asset-a', 'org-a:user-a'] }); }); await settled(() => expect(button('Save acceptance').disabled).toBe(true)); expect(host.textContent).toContain('draft is preserved'); expect(host.querySelector<HTMLTextAreaElement>('#image-accept-rationale')?.value).toBe('Keep my image rationale'); await submit(); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
 await act(async () => { await client.refetchQueries({ queryKey: ['asset', 'cluster-a', 'asset-a', 'org-a:user-a'] }); }); await settled(() => expect(button('Save acceptance').disabled).toBe(false));
});
it('blocks a changed digest in a fresh submit preflight while preserving the reviewed reason', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale(); const updated = detail(); updated.image!.digest = 'sha256:changed'; vi.mocked(assets.get).mockResolvedValueOnce(updated); await submit();
 await settled(() => expect(host.textContent).toContain('digest or acceptance changed before submission')); expect(assets.createImageAcceptance).not.toHaveBeenCalled(); expect(host.querySelector<HTMLTextAreaElement>('#image-accept-rationale')?.value).toBe('Reviewed compensating controls');
});
it('blocks a newly active acceptance discovered during preflight', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale(); vi.mocked(assets.get).mockResolvedValueOnce({ ...detail(), image_acceptances: [acceptance()] }); await submit(); await settled(() => expect(host.textContent).toContain('changed before submission')); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
});
it('pauses a retained draft while the exact cluster registry refreshes and rejects an in-flight race', async () => {
 await render('create', undefined, (qc) => qc.setQueryData(['clusters'], { clusters: [{ id: 'cluster-a' }] })); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale();
 let release!: (data: AssetDetail) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await submit(); await settled(() => expect(release).toBeDefined());
 let finishRegistry!: (data: { clusters: Array<{ id: string }> }) => void; let registry!: Promise<unknown>;
 await act(async () => { registry = client.fetchQuery({ queryKey: ['clusters'], queryFn: () => new Promise((resolve) => { finishRegistry = resolve; }) }); }); await act(async () => release(detail())); await settled(() => expect(host.textContent).toContain('changed before submission')); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
 await act(async () => { finishRegistry({ clusters: [{ id: 'cluster-a' }] }); await registry; });
});
it('abandons a stale-target preflight when URL cluster and entity change and resets the new draft', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale(); let release!: (data: AssetDetail) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await submit(); await settled(() => expect(release).toBeDefined());
 await act(async () => history.push('/clusters/cluster-b/assets/asset-b/image-acceptance/new')); await settled(() => expect(host.textContent).toContain('registry.example/team/asset-b:v1')); await act(async () => release(detail())); expect(assets.createImageAcceptance).not.toHaveBeenCalled(); expect(host.querySelector<HTMLTextAreaElement>('#image-accept-rationale')?.value).toBe(''); expect([...host.querySelectorAll<HTMLAnchorElement>('a')].every((link) => link.getAttribute('href') === '/clusters/cluster-b/assets/asset-b?tab=acceptance')).toBe(true);
});
it('refuses an unrelated response digest and requires history review instead of repeat writes', async () => {
 vi.mocked(assets.createImageAcceptance).mockResolvedValue({ id: 'wrong', asset_id: 'asset-a', cluster_id: 'cluster-a', image_digest: 'sha256:unreviewed', image_acceptances: [{ ...acceptance(), id: 'wrong', image_digest: 'sha256:unreviewed' }] }); await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale(); await submit();
 await settled(() => expect(host.textContent).toContain('response did not confirm the reviewed digest')); expect(host.querySelector('[data-testid="image-acceptance-result"]')).toBeNull(); expect(button('Save acceptance').disabled).toBe(true); await submit(); expect(assets.createImageAcceptance).toHaveBeenCalledOnce();
});
it('revokes only the exact reviewed active acceptance and verifies the returned identity', async () => {
 const item = acceptance(); vi.mocked(assets.get).mockResolvedValue({ ...detail(), image_acceptances: [item] }); vi.mocked(assets.revokeImageAcceptance).mockResolvedValue({ status: 'revoked', asset_id: 'asset-a', cluster_id: 'cluster-a', image_digest: 'sha256:reviewed', image_acceptances: [{ ...item, status: 'revoked' }] });
 await render('revoke'); await settled(() => expect(button('Revoke acceptance')).toBeDefined()); expect(host.querySelector('textarea')).toBeNull(); await submit(); await settled(() => expect(host.querySelector('[data-testid="image-acceptance-result"]')?.textContent).toContain('revoked'));
 expect(assets.revokeImageAcceptance).toHaveBeenCalledWith('asset-a', 'acceptance-a', { expected_image_digest: 'sha256:reviewed', cluster_id: 'cluster-a' }); expect(assets.createImageAcceptance).not.toHaveBeenCalled();
});
it('does not substitute another active acceptance for a missing selected record', async () => {
 vi.mocked(assets.get).mockResolvedValue({ ...detail(), image_acceptances: [{ ...acceptance(), id: 'another' }] }); await render('revoke'); await settled(() => expect(host.textContent).toContain('No other acceptance has been substituted')); expect(button('Revoke acceptance').disabled).toBe(true); await submit(); expect(assets.revokeImageAcceptance).not.toHaveBeenCalled();
});
it('rejects changed acceptance metadata during revoke preflight', async () => {
 const item = acceptance(); vi.mocked(assets.get).mockResolvedValueOnce({ ...detail(), image_acceptances: [item] }).mockResolvedValue({ ...detail(), image_acceptances: [{ ...item, accepted_until: '2099-01-01T00:00:00Z' }] }); await render('revoke'); await settled(() => expect(button('Revoke acceptance').disabled).toBe(false)); await submit(); await settled(() => expect(host.textContent).toContain('changed before submission')); expect(assets.revokeImageAcceptance).not.toHaveBeenCalled();
});

it.each(['asset_id', 'cluster_id'] as const)('does not claim success for a response with changed %s', async (field) => {
 vi.mocked(assets.createImageAcceptance).mockImplementation(async (_id, body) => ({ id: 'created-a', asset_id: 'asset-a', cluster_id: 'cluster-a', image_digest: 'sha256:reviewed', [field]: 'another', image_acceptances: [{ ...acceptance(), id: 'created-a', rationale: body.rationale, accepted_until: body.accepted_until }] }));
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale(); await submit(); await settled(() => expect(host.textContent).toContain('response did not confirm')); expect(host.querySelector('[data-testid="image-acceptance-result"]')).toBeNull(); expect(button('Save acceptance').disabled).toBe(true);
});
it('prevents two immediate form submissions from issuing duplicate risk writes', async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await rationale();
 let release!: (data: AssetDetail) => void; vi.mocked(assets.get).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; }));
 await act(async () => { const form = host.querySelector('form')!; form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true })); });
 await settled(() => expect(release).toBeDefined()); await act(async () => release(detail())); await settled(() => expect(host.querySelector('[data-testid="image-acceptance-result"]')).not.toBeNull()); expect(assets.createImageAcceptance).toHaveBeenCalledOnce();
});
it('refuses a revoke response for another acceptance rather than showing successful revocation', async () => {
 const item = acceptance(); vi.mocked(assets.get).mockResolvedValue({ ...detail(), image_acceptances: [item] }); vi.mocked(assets.revokeImageAcceptance).mockResolvedValue({ status: 'revoked', asset_id: 'asset-a', cluster_id: 'cluster-a', image_digest: 'sha256:reviewed', image_acceptances: [{ ...item, id: 'another', status: 'revoked' }] });
 await render('revoke'); await settled(() => expect(button('Revoke acceptance').disabled).toBe(false)); await submit(); await settled(() => expect(host.textContent).toContain('response did not confirm revocation')); expect(host.querySelector('[data-testid="image-acceptance-result"]')).toBeNull(); expect(button('Revoke acceptance').disabled).toBe(true);
});
