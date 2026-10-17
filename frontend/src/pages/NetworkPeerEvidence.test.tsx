import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { network, type NetworkPeerEvidenceResponse } from '@/api/client';
import { TablePreferencesProvider } from '@/contexts/TablePreferencesContext';
import { downloadCsv } from '@/lib/csv';
import { NetworkPeerEvidence } from './NetworkPeerEvidence';
const scope = vi.hoisted(() => ({ clusterId: 'cluster', cluster: { id: 'cluster' }, isLoading: false, error: null as Error | null }));
vi.mock('@/hooks/useCluster', () => ({ useCluster: () => scope }));
vi.mock('@/api/client', () => ({ network: { peersEvidence: vi.fn() } }));
vi.mock('@/lib/csv', () => ({ downloadCsv: vi.fn() }));
let root: Root, host: HTMLDivElement, client: QueryClient;
let owner = { org_id: 'org', user_id: 'user' }, hidden = false;
const response = (): NetworkPeerEvidenceResponse => ({ workload: 'custom/agent', cluster_id: 'cluster', workload_platform_role: '', hide_platform: hidden, source_limit: 500, total: 1, has_more: false, peers: [{ peer_ip: '10.0.0.2', peer: 'custom/controller', direction: 'egress', external: false, peer_platform_role: hidden ? '' : 'core', peer_cluster_id: hidden ? null : 'cluster', bytes: 100, packets: 1, sessions: 2, ports: [443], protocols: ['tcp'], verdict: 'allow', last_seen_at: '2026-10-12T00:00:00Z' }] });
beforeEach(() => { Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true }); Object.assign(scope, { clusterId: 'cluster', cluster: { id: 'cluster' }, isLoading: false, error: null }); owner = { org_id: 'org', user_id: 'user' }; hidden = false; localStorage.clear(); vi.mocked(network.peersEvidence).mockImplementation(async () => response()); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
const tree = () => <QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}><NetworkPeerEvidence clusterID='cluster' workload='custom/agent' hours={24} hidePlatform={hidden} active direction='egress' testId='peer-evidence' /></TablePreferencesProvider></QueryClientProvider>;
async function render() { host = document.createElement('div'); document.body.append(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); await act(async () => root.render(tree())); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 3000 }); }
it('passes owned scope and platform preference, preserving actual custom-install roles in shown CSV', async () => {
  await render(); await settle(() => expect(host.querySelector('tbody')).not.toBeNull()); expect(network.peersEvidence).toHaveBeenCalledWith({ workload: 'custom/agent', cluster_id: 'cluster', hours: 24, hide_platform: false }); expect(host.querySelector('tbody')?.textContent).toContain('Core');
  await act(async () => [...host.querySelectorAll<HTMLButtonElement>('button')].find(button => button.textContent === 'Export shown peers CSV')!.click()); const [,headers,rows] = vi.mocked(downloadCsv).mock.calls.at(-1)!; expect(rows[0][headers.indexOf('Platform role')]).toBe('core');
  hidden = true; await act(async () => root.render(tree())); await settle(() => expect(network.peersEvidence).toHaveBeenLastCalledWith(expect.objectContaining({ hide_platform: true }))); await settle(() => expect(host.querySelector('tbody')?.textContent).toContain('Unclassified')); expect(host.querySelector('tbody')?.textContent).not.toContain('Core');
});
it('discloses the capped diagnostic source without claiming the selected direction is complete', async () => {
  vi.mocked(network.peersEvidence).mockImplementation(async () => ({ ...response(), total: 805, has_more: true, peers: Array.from({ length: 500 }, (_, index) => ({ ...response().peers[0], peer_ip: `10.0.${Math.floor(index / 250)}.${index % 250 + 1}`, direction: index % 2 ? 'ingress' : 'egress' })) }));
  await render(); await settle(() => expect(host.textContent).toContain('250 peer groups shown')); expect(host.textContent).toContain('500 returned of 805 matching'); expect(host.textContent).toContain('direction/external selection to that returned set'); expect(host.querySelectorAll('tbody tr')).toHaveLength(100);
});
it.each(['scope', 'role', 'nullable-cluster', 'duplicate', 'total'])('withholds malformed %s metadata', async kind => {
  vi.mocked(network.peersEvidence).mockImplementation(async () => { const data = response(); if (kind === 'scope') data.cluster_id = 'foreign'; if (kind === 'role') delete (data.peers[0] as Partial<NetworkPeerEvidenceResponse['peers'][number]>).peer_platform_role; if (kind === 'nullable-cluster') data.peers[0].peer_cluster_id = 'foreign'; if (kind === 'duplicate') { data.peers.push(data.peers[0]); data.total = 2; } if (kind === 'total') data.total = 3; return data; });
  await render(); await settle(() => expect(host.textContent).toContain('could not be loaded or refreshed')); expect(host.querySelector('table')).toBeNull();
});
it('hides old rows after refresh failure and never describes that failure as empty evidence', async () => {
  await render(); await settle(() => expect(host.querySelector('table')).not.toBeNull()); vi.mocked(network.peersEvidence).mockRejectedValue(new Error('private source details')); await act(async () => { await client.invalidateQueries({ queryKey: ['network-peer-evidence'] }); }); await settle(() => expect(host.textContent).toContain('could not be loaded or refreshed')); expect(host.querySelector('table')).toBeNull(); expect(host.textContent).not.toContain('No matching peers'); expect(downloadCsv).not.toHaveBeenCalled();
});
it('isolates actor cache and blocks reads without settled cluster or actor', async () => {
  scope.error = new Error('scope unavailable'); await render(); expect(network.peersEvidence).not.toHaveBeenCalled(); scope.error = null; await act(async () => root.render(tree())); await settle(() => expect(host.querySelector('table')).not.toBeNull()); owner.user_id = 'other'; vi.mocked(network.peersEvidence).mockImplementationOnce(() => new Promise(() => {})); await act(async () => root.render(tree())); expect(host.querySelector('table')).toBeNull(); owner.org_id = ''; await act(async () => root.render(tree())); expect(host.textContent).toContain('Organization and user context are unavailable');
});
