// Package clusterinventory reads bounded cluster pages and their summaries.
package clusterinventory

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler/platformrole"
	"github.com/alphabravocompany/constellation/internal/inventorypresence"
)

// List aggregates only the selected clusters. A workload's presence and scope are
// evaluated once, rather than separately for every count and top-workload field.
func List(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, components []string, scope string, limit, offset int) (pgx.Rows, error) {
	findingScope, err := platformrole.ScopeSQL(scope, platformrole.ConstellationFindingSQL("f"))
	if err != nil {
		return nil, err
	}
	deploymentScope, err := platformrole.ScopeSQL(scope, platformrole.ConstellationDeploymentSQL("d"))
	if err != nil {
		return nil, err
	}
	query := strings.NewReplacer("{{finding_scope}}", findingScope, "{{deployment_scope}}", deploymentScope, "{{presence}}", inventorypresence.WorkloadStatusSQL("d")).Replace(listSQL)
	return pool.Query(ctx, query, org, components, limit, offset)
}

const listSQL = `WITH page AS MATERIALIZED (
 SELECT c.*,count(*) OVER() AS total FROM clusters c WHERE org_id=$1
 ORDER BY name,id LIMIT $3 OFFSET $4
), workloads AS MATERIALIZED (
 SELECT d.* FROM deployments d JOIN page c ON c.id=d.cluster_id
 WHERE d.org_id=$1 AND ({{deployment_scope}}) AND ({{presence}})<>'absent'
), workload_counts AS (
 SELECT cluster_id,count(*) AS deployments,max(risk_score) AS max_risk FROM workloads GROUP BY cluster_id
), top_workload AS (
 SELECT DISTINCT ON(cluster_id) cluster_id,namespace||'/'||name AS name,risk_score
 FROM workloads ORDER BY cluster_id,risk_score DESC NULLS LAST,last_seen_at DESC NULLS LAST,id
), finding_counts AS (
 SELECT f.cluster_id,count(*) FILTER(WHERE severity='critical' AND lifecycle='open') AS critical_open,
 count(*) FILTER(WHERE severity='high' AND lifecycle='open') AS high_open,
 count(*) FILTER(WHERE lifecycle='open') AS open_findings,count(*) AS total_findings
 FROM findings f JOIN page c ON c.id=f.cluster_id
 WHERE f.org_id=$1 AND ({{finding_scope}}) GROUP BY f.cluster_id
), sensors AS (
 SELECT ch.cluster_id,count(DISTINCT component) AS ready FROM component_heartbeats ch JOIN page c ON c.id=ch.cluster_id
 WHERE ch.org_id=$1 AND ch.component=ANY($2::text[]) AND ch.last_seen_at>NOW()-INTERVAL '2 minutes' GROUP BY ch.cluster_id
)
SELECT c.id,c.name,c.distro,COALESCE(c.cloud_provider,''),COALESCE(c.region,''),c.state,COALESCE(c.agent_version,''),
 COALESCE(w.deployments,0),COALESCE(w.max_risk,0),c.last_heartbeat_at,
 COALESCE(cpf.kubernetes_git_version,''),COALESCE(cpf.platform_provider,''),cpf.observed_at,
 COALESCE(f.critical_open,0),COALESCE(f.high_open,0),COALESCE(f.open_findings,0),COALESCE(f.total_findings,0),
 (SELECT MAX(nf.at) FROM network_flows nf WHERE nf.org_id=$1 AND nf.cluster_id=c.id),
 COALESCE(s.ready,0),t.name,t.risk_score,c.total
FROM page c LEFT JOIN workload_counts w ON w.cluster_id=c.id
LEFT JOIN top_workload t ON t.cluster_id=c.id LEFT JOIN finding_counts f ON f.cluster_id=c.id
LEFT JOIN sensors s ON s.cluster_id=c.id LEFT JOIN cluster_platform_facts cpf ON cpf.org_id=$1 AND cpf.cluster_id=c.id
ORDER BY c.name,c.id`

// Count preserves the matching total when an offset falls beyond the last row.
func Count(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID) (int64, error) {
	var total int64
	err := pool.QueryRow(ctx, "SELECT count(*) FROM clusters WHERE org_id=$1", org).Scan(&total)
	return total, err
}
