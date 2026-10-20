package runtime

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type runtimePolicyPodBinding struct {
	Namespace string `json:"namespace"`
	PodName   string `json:"pod_name"`
	PodUID    string `json:"pod_uid"`
}

type runtimePolicyBindings struct {
	Status string
	Pods   []runtimePolicyPodBinding
}

// Bindings are exact owned discovery records, never pod-name prefix guesses.
// Retained old pod generations are harmless: the agent also requires the UID
// currently observed by CRI behind each registered endpoint MAC.
func loadRuntimePolicyBindings(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID, policies []*RuntimePolicy) (map[uuid.UUID]runtimePolicyBindings, error) {
	out := make(map[uuid.UUID]runtimePolicyBindings, len(policies))
	expected := make(map[uuid.UUID]*RuntimePolicy, len(policies))
	ids := make([]uuid.UUID, 0, len(policies))
	for _, policy := range policies {
		ids = append(ids, policy.ID)
		expected[policy.ID] = policy
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := pool.Query(ctx, `SELECT p.id,p.version,p.workload,p.namespace,o.owner_count,
COALESCE(l.namespace,''),COALESCE(l.pod_name,''),COALESCE(l.pod_uid,'')
FROM runtime_policies p
LEFT JOIN LATERAL (
 SELECT count(*) owner_count,min(d.id::text)::uuid owner_id,min(d.kind) owner_kind,min(d.name) owner_name
 FROM deployments d WHERE d.org_id=p.org_id AND d.cluster_id=p.cluster_id
 AND d.namespace=p.namespace AND p.workload=d.namespace||'/'||d.name
) o ON true
LEFT JOIN pod_workload_links l ON l.org_id=p.org_id AND l.cluster_id=p.cluster_id
 AND l.namespace=p.namespace AND l.pod_name<>'' AND l.pod_uid<>''
 AND l.pod_workload_id=l.namespace||'/pod/'||l.pod_name
 AND (p.workload=l.pod_workload_id OR (o.owner_count=1 AND l.deployment_id=o.owner_id
  AND l.owner_workload_id=p.workload AND l.owner_kind=o.owner_kind AND l.owner_name=o.owner_name))
WHERE p.org_id=$1 AND p.cluster_id=$2 AND p.id=ANY($3::uuid[])
ORDER BY p.id,l.namespace,l.pod_name,l.pod_uid`, org, cluster, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var version, owners int64
		var workload, namespace string
		var pod runtimePolicyPodBinding
		if err := rows.Scan(&id, &version, &workload, &namespace, &owners, &pod.Namespace, &pod.PodName, &pod.PodUID); err != nil {
			return nil, err
		}
		policy, exists := expected[id]
		if !exists || policy.Version != version || policy.Workload != workload || policy.Namespace != namespace {
			return nil, errors.New("runtime policy changed while resolving workload bindings")
		}
		binding, seen := out[id]
		if !seen {
			binding = runtimePolicyBindings{Status: "unresolved", Pods: []runtimePolicyPodBinding{}}
		}
		binding = addRuntimePolicyBinding(binding, workload, namespace, owners, pod)
		out[id] = binding
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) != len(expected) {
		return nil, errors.New("runtime policy disappeared while resolving workload bindings")
	}
	return out, nil
}

func addRuntimePolicyBinding(binding runtimePolicyBindings, workload, namespace string, owners int64, pod runtimePolicyPodBinding) runtimePolicyBindings {
	parts := strings.Split(workload, "/")
	canonical := len(parts) == 2 && parts[0] == namespace && parts[1] != ""
	direct := len(parts) == 3 && parts[0] == namespace && parts[1] == "pod" && parts[2] != ""
	if canonical && owners > 1 {
		binding.Status = "ambiguous"
	}
	if (direct || canonical && owners == 1) && pod.Namespace == namespace && pod.PodName != "" && pod.PodUID != "" {
		binding.Status = "resolved"
		binding.Pods = append(binding.Pods, pod)
	}
	return binding
}
