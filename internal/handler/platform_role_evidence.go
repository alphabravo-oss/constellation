package handler

import (
	"context"
	"encoding/json"
	"net"
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PlatformWorkloadIdentity keeps evidence with its actual cluster. Names alone
// cannot identify an installation in an organization containing multiple clusters.
type PlatformWorkloadIdentity struct {
	ClusterID uuid.UUID
	Workload  string
	Namespace string
}

// PlatformRoleQuerier lets read-only exports keep evidence and role lookup in
// one database snapshot, without reserving a second pooled connection.
type PlatformRoleQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

// EvidencePlatformRoles classifies an already tenant-scoped evidence batch. It
// never resolves a missing cluster to another cluster or interprets IP/host
// endpoints as deployments. An unresolved identity remains unclassified.
func EvidencePlatformRoles(ctx context.Context, pool PlatformRoleQuerier, orgID uuid.UUID, identities []PlatformWorkloadIdentity) ([]string, error) {
	roles := make([]string, len(identities))
	clusters, workloads, namespaces, names := []string{}, []string{}, []string{}, []string{}
	indices := []int{}
	for i, identity := range identities {
		workload := identity.Workload
		// PCAP and older threat reporters may provide the namespace and name
		// separately. This tuple is exact only when both values are present;
		// a bare name without a namespace must never borrow an installation.
		if !strings.Contains(workload, "/") && workload != "" && identity.Namespace != "" && net.ParseIP(workload) == nil {
			workload = identity.Namespace + "/" + workload
		}
		parts := strings.Split(workload, "/")
		if net.ParseIP(parts[len(parts)-1]) != nil {
			continue
		}
		namespace := identity.Namespace
		if len(parts) >= 2 {
			namespace = parts[0]
		}
		switch namespace {
		case "external", "host", "node", "cluster":
			continue
		}
		roles[i] = PlatformRole(namespace, nil)
		if roles[i] != "" || identity.ClusterID == uuid.Nil || len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			continue
		}
		// Only canonical namespace/name or namespace/pod/name identities can
		// participate in deployment ownership lookup.
		if len(parts) != 2 && (len(parts) != 3 || parts[1] != "pod" || parts[2] == "") {
			continue
		}
		clusters = append(clusters, identity.ClusterID.String())
		workloads = append(workloads, workload)
		namespaces = append(namespaces, namespace)
		names = append(names, parts[1])
		indices = append(indices, i)
	}
	if len(indices) == 0 {
		return roles, nil
	}
	rows, err := pool.Query(ctx, `
WITH wanted AS (
 SELECT * FROM unnest($2::uuid[], $3::text[], $4::text[], $5::text[])
 WITH ORDINALITY AS w(cluster_id, workload, namespace, name, position)
), candidates AS (
 SELECT w.position, d.id, d.labels FROM wanted w
 JOIN deployments d ON d.org_id=$1 AND d.cluster_id=w.cluster_id
  AND d.namespace=w.namespace AND d.name=w.name
 WHERE w.workload=w.namespace || '/' || w.name
 UNION
 SELECT w.position, d.id, d.labels FROM wanted w
 JOIN pod_workload_links p ON p.org_id=$1 AND p.cluster_id=w.cluster_id
  AND p.pod_workload_id=w.workload AND p.namespace=w.namespace
 JOIN deployments d ON d.id=p.deployment_id AND d.org_id=$1 AND d.cluster_id=w.cluster_id AND d.namespace=w.namespace
 WHERE split_part(w.workload,'/',2)='pod'
)
SELECT position, labels FROM (
 SELECT position, labels, COUNT(*) OVER (PARTITION BY position) AS matches
 FROM candidates
) resolved WHERE matches=1`, orgID, clusters, workloads, namespaces, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var position int
		var labels json.RawMessage
		if err := rows.Scan(&position, &labels); err != nil {
			return nil, err
		}
		index := indices[position-1]
		roles[index] = PlatformRoleJSON(namespaces[position-1], labels)
	}
	return roles, rows.Err()
}

// EvidencePlatformRoleSQL retains the shared resolver's public handler contract.
func EvidencePlatformRoleSQL(org, cluster, workload, namespace string) string {
	return platformrole.EvidenceSQL(org, cluster, workload, namespace)
}
