import { useIsFetching, useQueryClient } from '@tanstack/react-query';
import { useTablePreferencesIdentity } from '@/contexts/TablePreferencesContext';
import { useCluster } from '@/hooks/useCluster';
import { clusterCacheReady } from '@/lib/cluster-evidence';
import { findingRevisionValid } from '@/lib/finding-instance';
import type { RuntimePolicy } from '@/api/client';

export function useRuntimePolicyScope() {
  const operator = useTablePreferencesIdentity();
  const { clusterId, cluster, isLoading, error } = useCluster();
  const client = useQueryClient();
  const registryFetching = useIsFetching({ queryKey: ['clusters'], exact: true });
  const detailFetching = useIsFetching({ queryKey: ['cluster', clusterId], exact: true });
  const owner = `${operator?.org_id}:${operator?.user_id}`;
  const ready = !!operator?.org_id && !!operator?.user_id && !!clusterId && cluster?.id === clusterId && !isLoading && !error && !registryFetching && !detailFetching && clusterCacheReady(client, clusterId);
  const recheck = () => ready && !!clusterId && clusterCacheReady(client, clusterId);
  const retry = () => { void client.invalidateQueries({ queryKey: ['clusters'], exact: true }); if (clusterId) void client.invalidateQueries({ queryKey: ['cluster', clusterId], exact: true }); };
  return { retry, owner, org: operator?.org_id ?? '', clusterId, ready, recheck, isLoading, error, client };
}
export function policyRevision(policy: RuntimePolicy | undefined): string | undefined {
  if (!policy) return undefined;
  if (policy.revision !== undefined) return findingRevisionValid(policy.revision) ? policy.revision : undefined;
  return Number.isSafeInteger(policy.version) && policy.version > 0 ? String(policy.version) : undefined;
}
export function policyRules(policy: Pick<RuntimePolicy, 'rules'>): unknown[] | undefined {
  try { const value = typeof policy.rules === 'string' ? JSON.parse(policy.rules) : policy.rules; return Array.isArray(value) ? value : undefined; } catch { return undefined; }
}
export function policyMatches(value: unknown, org: string, cluster: string, id?: string): value is RuntimePolicy {
  if (!value || typeof value !== 'object') return false;
  const policy = value as RuntimePolicy;
  return typeof policy.id === 'string' && !!policy.id && (!id || policy.id === id) && policy.org_id === org && policy.cluster_id === cluster &&
    [policy.workload, policy.namespace, policy.name].every(field => typeof field === 'string' && !!field.trim()) && ['monitor', 'enforce', 'disabled'].includes(policy.mode) &&
    !!policyRevision(policy) && typeof policy.updated_at === 'string' && Number.isFinite(Date.parse(policy.updated_at)) && policyRules(policy) !== undefined;
}
function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).sort(([a], [b]) => a.localeCompare(b)).map(([key, item]) => [key, canonical(item)]));
  return value;
}
export function rulesEqual(left: unknown, right: unknown) { return JSON.stringify(canonical(left)) === JSON.stringify(canonical(right)); }
export function policyFingerprint(policy: RuntimePolicy) {
  return JSON.stringify([policy.id, policy.org_id, policy.cluster_id, policy.workload, policy.namespace, policy.name, policy.mode, policyRevision(policy), policy.updated_at, canonical(policyRules(policy)), policy.def_action, policy.apply_dir]);
}
export function policyReceiptMatches(value: unknown, reviewed: RuntimePolicy, mode?: RuntimePolicy['mode']) {
  return policyMatches(value, reviewed.org_id, reviewed.cluster_id, reviewed.id) && value.workload === reviewed.workload && value.namespace === reviewed.namespace &&
    value.name === reviewed.name && value.def_action === reviewed.def_action && value.apply_dir === reviewed.apply_dir && rulesEqual(policyRules(value), policyRules(reviewed)) && (!mode || value.mode === mode) && BigInt(policyRevision(value)!) > BigInt(policyRevision(reviewed)!);
}
