import { useQuery, useQueryClient } from '@tanstack/react-query';
import { network, type NetworkPeerEvidenceResponse } from '@/api/client';
import { useTablePreferencesIdentity } from '@/contexts/TablePreferencesContext';
import { DataTable, type Column } from '@/components/ui/data-table';
import { Button } from '@/components/ui/button';
import { Collapse } from '@/components/ui/collapse';
import { ErrorState, LoadingState } from '@/components/ui/states';
import { exportQueryReady } from '@/hooks/useExportGuard';
import { clusterCacheReady } from '@/lib/cluster-evidence';
import { fmtBytes } from '@/lib/format';
import { useInventoryScope } from './inventory-workspace';

type Peer = NetworkPeerEvidenceResponse['peers'][number];
function peerEvidenceMatches(value: unknown, workload: string, cluster: string, hidden: boolean): value is NetworkPeerEvidenceResponse {
  if (!value || typeof value !== 'object') return false;
  const data = value as NetworkPeerEvidenceResponse;
  if (data.workload !== workload || data.cluster_id !== cluster || data.hide_platform !== hidden || !['', 'core'].includes(data.workload_platform_role) || data.source_limit !== 500 || !Number.isSafeInteger(data.total) || data.total < 0 || !Array.isArray(data.peers) || data.peers.length !== Math.min(data.total, 500) || data.has_more !== (data.total > data.peers.length)) return false;
  return data.peers.every(peer => !!peer && typeof peer.peer_ip === 'string' && !!peer.peer_ip && [peer.peer, peer.fqdn].every(text => text === undefined || typeof text === 'string') && ['ingress', 'egress'].includes(peer.direction) && typeof peer.external === 'boolean' && ['', 'core'].includes(peer.peer_platform_role) && (peer.peer_cluster_id === null || peer.peer_cluster_id === cluster) && (!hidden || peer.peer_platform_role !== 'core' && data.workload_platform_role !== 'core') && [peer.bytes, peer.packets, peer.sessions].every(count => Number.isSafeInteger(count) && count >= 0) && Array.isArray(peer.ports) && peer.ports.every(port => Number.isInteger(port) && port >= 0 && port <= 65535) && Array.isArray(peer.protocols) && peer.protocols.every(protocol => typeof protocol === 'string') && typeof peer.verdict === 'string' && typeof peer.last_seen_at === 'string' && Number.isFinite(Date.parse(peer.last_seen_at))) && new Set(data.peers.map(peer => JSON.stringify([peer.direction, peer.peer_ip]))).size === data.peers.length;
}
export function NetworkPeerEvidence({ clusterID, workload, hours, hidePlatform, active, direction, externalOnly = false, blockHref, testId }: {
  clusterID: string; workload: string; hours: number; hidePlatform: boolean; active: boolean;
  direction?: 'ingress' | 'egress'; externalOnly?: boolean; blockHref?: (peer: Peer) => string; testId: string;
}) {
  const scope = useInventoryScope(), client = useQueryClient(), identity = useTablePreferencesIdentity();
  const owner = `${identity?.org_id}:${identity?.user_id}`;
  const request = { workload, cluster_id: clusterID, hours, hide_platform: hidePlatform };
  const key = ['network-peer-evidence', owner, request];
  const enabled = !!identity?.org_id && !!identity?.user_id && clusterCacheReady(client, clusterID) && scope.ready && scope.clusterId === clusterID && active && !!workload && workload !== 'external' && !workload.startsWith('external/');
  const q = useQuery({ queryKey: key, enabled, queryFn: async () => { const response = await network.peersEvidence(request); if (!peerEvidenceMatches(response, workload, clusterID, hidePlatform)) throw new Error('Peer evidence does not match its scope'); return response; } });
  const available = enabled && q.isSuccess && !q.isFetching && exportQueryReady(client, key) && peerEvidenceMatches(q.data, workload, clusterID, hidePlatform);
  const fresh = () => available && clusterCacheReady(client, clusterID) && exportQueryReady(client, key, q.data);
  if (!active) return null;
  if (!identity?.org_id || !identity?.user_id) return <ErrorState title="Organization and user context are unavailable." />;
  if (!scope.ready || scope.clusterId !== clusterID) return <ErrorState title="Resolve the selected cluster before loading peer evidence." />;
  if (q.isError || q.isSuccess && !peerEvidenceMatches(q.data, workload, clusterID, hidePlatform)) return <ErrorState title="Peer evidence could not be loaded or refreshed." action={<Button onClick={() => void q.refetch()}>Retry peers</Button>} />;
  if (!available) return <LoadingState label="Loading peer evidence…" />;
  const rows = q.data!.peers.filter(peer => (!direction || peer.direction === direction) && (!externalOnly || peer.external));
  const columns: Column<Peer>[] = [
    { id: 'peer', header: 'Peer', kind: 'name', wrap: true, cell: peer => <div><span>{peer.fqdn || peer.peer || peer.peer_ip}</span>{peer.fqdn || peer.peer ? <div className="text-xs text-muted-foreground">{peer.peer_ip}</div> : null}</div>, exportValue: peer => `${peer.fqdn || peer.peer || peer.peer_ip}${peer.fqdn || peer.peer ? ` (${peer.peer_ip})` : ""}` },
    { id: 'role', header: 'Platform role', kind: 'status', cell: peer => peer.peer_platform_role === 'core' ? 'Core' : 'Unclassified', exportValue: peer => peer.peer_platform_role },
    { id: 'bytes', header: 'Bytes', kind: 'bytes', numeric: true, cell: peer => fmtBytes(peer.bytes), exportValue: peer => peer.bytes },
    { id: 'sessions', header: 'Sessions', kind: 'count', numeric: true, cell: peer => peer.sessions, exportValue: peer => peer.sessions },
    { id: 'ports', header: 'Ports', kind: 'text', wrap: true, cell: peer => peer.ports.join(', ') || 'Not reported', exportValue: peer => peer.ports.join(';') },
    { id: 'direction', header: 'Direction', kind: 'status', cell: peer => peer.direction, exportValue: peer => peer.direction },
    { id: 'peer-ip', header: 'Peer IP', kind: 'id', cell: peer => peer.peer_ip, exportValue: peer => peer.peer_ip },
    { id: 'peer-cluster', header: 'Peer cluster', kind: 'id', wrap: true, cell: peer => peer.peer_cluster_id ?? 'Unknown', exportValue: peer => peer.peer_cluster_id ?? '' },
    ...(blockHref ? [{ id: 'actions', header: 'Actions', kind: 'actions' as const, exportable: false, cell: (peer: Peer) => peer.external ? <a href={blockHref(peer)} className="text-sm underline">Block IP</a> : null }] : []),
  ];
  return <div className="space-y-2" data-testid={testId}>
    <div className="flex items-center justify-between gap-2 text-xs"><span>{rows.length} peer groups shown</span><Button size="sm" disabled={q.isFetching} onClick={() => void q.refetch()}>Refresh peers</Button></div>
    <DataTable rows={rows} columns={columns} rowKey={peer => JSON.stringify([peer.direction, peer.peer_ip])} preferencesKey="network-diagnostic-peers" defaultHiddenColumnIds={['peer-ip', 'peer-cluster', 'direction', 'ports']} showDensityToggle={false} density="compact" canExport={fresh} exportFileName="network-returned-peer-groups" exportLabel="Export shown peers CSV" emptyState={<p className="p-4 text-xs text-muted-foreground">No matching peers in the returned evidence.</p>} />
    <Collapse label="Peer evidence details"><p className="text-xs text-muted-foreground">{q.data!.peers.length} returned of {q.data!.total} matching peer IP/direction groups across this workload’s ingress and egress in {hours} hours. The source returns at most 500 groups, ordered by bytes. This view applies its direction/external selection to that returned set. CSV contains selected columns from shown returned groups. Workload platform role: {q.data!.workload_platform_role || 'Unclassified'}.</p></Collapse>
  </div>;
}
