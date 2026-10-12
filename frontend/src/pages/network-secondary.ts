import type { NetworkPolicyLifecycle } from "@/api/client";
export function policyRevision(p: NetworkPolicyLifecycle) {
  return JSON.stringify([
    p.cluster_id,
    p.workload,
    p.current_mode,
    p.target_mode,
    p.candidate_hash,
    p.approved_candidate_hash,
    p.approval_status,
    p.candidate_stale,
    p.rollback_available,
    p.rollback_ref,
  ]);
}
export function policyActionAvailable(
  action: string,
  p: NetworkPolicyLifecycle,
) {
  const stale =
    p.candidate_stale ||
    !!(
      p.approved_candidate_hash &&
      p.candidate_hash &&
      p.approved_candidate_hash !== p.candidate_hash
    );
  return action === "apply-policy"
    ? !!p.target_mode &&
        p.approval_status === "approved" &&
        !stale &&
        !!p.candidate_hash &&
        p.approved_candidate_hash === p.candidate_hash
    : action === "demote-policy"
      ? p.current_mode !== "discover" && !!p.candidate_hash
      : action === "rollback-policy"
        ? p.rollback_available && !!p.rollback_ref
        : action === "approve-policy"
          ? !!p.target_mode &&
            (p.approval_status === "pending" || stale) &&
            !!p.candidate_hash
          : false;
}
export function policySource(params: URLSearchParams) {
  const back = new URLSearchParams(params.get("back") ?? "");
  const number = Number(params.get("hours") ?? back.get("hours"));
  const hours =
    Number.isInteger(number) && number > 0 && number <= 720 ? number : 24;
  return {
    hours,
    namespace: params.get("namespace") || back.get("namespace") || undefined,
    group: params.get("group") || back.get("group") || undefined,
    verdict: params.get("verdict") || back.get("verdict") || undefined,
  };
}
export function networkReturn(clusterId: string, params: URLSearchParams) {
  const back = params.get("back");
  return `/clusters/${encodeURIComponent(clusterId)}/network${back ? `?${new URLSearchParams(back)}` : ""}`;
}
