package inventorypresence

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func StoreWorkloads(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID, observed, expires time.Time, workloads map[string]string) error {
	raw, err := json.Marshal(workloads)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `INSERT INTO cluster_workload_presence(org_id,cluster_id,observed_at,expires_at,workloads)
 SELECT $1,$2,$3,$4,$5::jsonb FROM clusters WHERE org_id=$1 AND id=$2
 ON CONFLICT(org_id,cluster_id) DO UPDATE SET observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,workloads=EXCLUDED.workloads
 WHERE cluster_workload_presence.observed_at<EXCLUDED.observed_at`, org, cluster, observed, expires, raw)
	return err
}

// WorkloadStatusSQL accepts only trusted SQL aliases. Absence requires a fresh,
// complete snapshot for the owning cluster, observed after this inventory row.
func WorkloadStatusSQL(alias string) string {
	return `COALESCE((SELECT CASE WHEN p.expires_at<=NOW() THEN 'unverified'
 WHEN p.workloads ? (` + alias + `.namespace||'/'||` + alias + `.kind||'/'||` + alias + `.name) THEN p.workloads->>(` + alias + `.namespace||'/'||` + alias + `.kind||'/'||` + alias + `.name)
 WHEN p.observed_at<` + alias + `.last_seen_at THEN 'unverified'
 WHEN ` + alias + `.kind IN ('Deployment','StatefulSet','DaemonSet') THEN 'absent' ELSE 'unverified' END
 FROM cluster_workload_presence p WHERE p.org_id=` + alias + `.org_id AND p.cluster_id=` + alias + `.cluster_id),'unverified')`
}
