package handler

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestScanQueueMetricsIgnoresJobsLinkedToForeignOrgTargets(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := context.Background()
	pool := database.Pool()
	jobOrgID, targetOrgID := uuid.New(), uuid.New()
	ownedTargetID, foreignTargetID := uuid.New(), uuid.New()
	for _, orgID := range []uuid.UUID{jobOrgID, targetOrgID} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, $2)`, orgID, "queue-metrics-scope-"+orgID.String()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1, $2)`, jobOrgID, targetOrgID)
	}()
	if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type)
		VALUES ($1, $2, 'image', $3, 'manual'), ($4, $5, 'serverless', $6, 'manual')`,
		ownedTargetID, jobOrgID, "image-"+ownedTargetID.String(), foreignTargetID, targetOrgID, "function-"+foreignTargetID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (org_id, target_id, status)
		VALUES ($1, $2, 'pending'), ($1, $3, 'pending')`, jobOrgID, ownedTargetID, foreignTargetID); err != nil {
		t.Fatal(err)
	}
	metrics, err := ScanQueueMetrics(ctx, pool, jobOrgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 1 || metrics[0].TargetType != "image" || metrics[0].Pending != 1 {
		t.Fatalf("metrics include foreign target data: %+v", metrics)
	}
}
