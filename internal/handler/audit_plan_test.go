//go:build integration

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// This fixture is used only on the explicitly configured disposable test DB.
// Its synthetic audit rows remain inside a rolled-back transaction, so it never
// changes the shared audit chain or reaches the live database.
func TestAuditClusterLookupPlan(t *testing.T) {
	f := newAuditListFixture(t)
	ctx := t.Context()
	tx, err := f.database.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	marker := uuid.NewString()
	if _, err := tx.Exec(ctx, `INSERT INTO audit_events (org_id,action,target_kind,target_id,prev_hash,chain_hash)
 SELECT $1,'audit.plan.fixture','fixture',CASE WHEN g <= 17 THEN $2 ELSE $3 || g::text END,
 repeat('0',64),$3 || g::text FROM generate_series(1,30000) g`, f.orgA, f.assetA.String(), marker); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ANALYZE audit_events; ANALYZE findings; ANALYZE assets; ANALYZE deployments; ANALYZE compliance_checks; ANALYZE policies`); err != nil {
		t.Fatal(err)
	}
	query, _ := auditListQuery(f.orgA, f.clusterA, "", nil, nil, nil, 101, 0)
	statement := "audit_cluster_plan_" + strings.ReplaceAll(marker, "-", "")
	if _, err := tx.Exec(ctx, "PREPARE "+statement+"(uuid,bigint,bigint,uuid,bigint,text) AS "+query); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = tx.Exec(context.Background(), "DEALLOCATE "+statement) }()
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		if _, err := tx.Exec(ctx, "SET LOCAL plan_cache_mode='"+mode+"'"); err != nil {
			t.Fatal(err)
		}
		explain := fmt.Sprintf("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) EXECUTE %s('%s',101,0,'%s',101,'%s')", statement, f.orgA, f.clusterA, f.clusterA)
		var raw []byte
		if err := tx.QueryRow(ctx, explain).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var plans []struct {
			Plan          auditPlanNode
			ExecutionTime float64 `json:"Execution Time"`
		}
		if err := json.Unmarshal(raw, &plans); err != nil {
			t.Fatal(err)
		}
		if len(plans) != 1 {
			t.Fatalf("%s returned %d plans", mode, len(plans))
		}
		var auditScans []auditPlanNode
		walkAuditPlan(plans[0].Plan, func(node auditPlanNode) {
			if node.RelationName == "audit_events" {
				auditScans = append(auditScans, node)
			}
		})
		if len(auditScans) == 0 {
			t.Fatalf("%s has no audit scan", mode)
		}
		for _, node := range auditScans {
			lookupKey := "target_id"
			switch node.IndexName {
			case "idx_audit_org_target_id":
			case "idx_audit_finding_source_cluster":
				lookupKey = "finding_source_cluster_id"
			case "idx_audit_finding_effective_cluster":
				lookupKey = "finding_target_cluster_id"
			default:
				t.Fatalf("%s scans audit history through %s %s", mode, node.NodeType, node.IndexName)
			}
			if !strings.Contains(node.IndexCond, "org_id") || !strings.Contains(node.IndexCond, lookupKey) {
				t.Fatalf("%s lacks both scoped lookup keys for %s: %s", mode, node.IndexName, node.IndexCond)
			}
			// Sparse matching targets should visit a few index/heap pages, not read
			// the 30,000 unrelated receipts. This also catches a scan followed by
			// an ID sort or post-scan cluster filter despite an index-shaped plan.
			if node.SharedHitBlocks+node.SharedReadBlocks > 200 {
				t.Fatalf("%s audit lookup visited %d blocks", mode, node.SharedHitBlocks+node.SharedReadBlocks)
			}
		}
		if plans[0].Plan.ActualRows != 17 {
			t.Fatalf("%s returned %.0f rows, want 17", mode, plans[0].Plan.ActualRows)
		}
		t.Logf("%s: indexed sparse cluster page, execution %.3fms", mode, plans[0].ExecutionTime)
	}
}

type auditPlanNode struct {
	NodeType         string  `json:"Node Type"`
	RelationName     string  `json:"Relation Name"`
	IndexName        string  `json:"Index Name"`
	IndexCond        string  `json:"Index Cond"`
	ActualRows       float64 `json:"Actual Rows"`
	SharedHitBlocks  int     `json:"Shared Hit Blocks"`
	SharedReadBlocks int     `json:"Shared Read Blocks"`
	Plans            []auditPlanNode
}

func walkAuditPlan(node auditPlanNode, visit func(auditPlanNode)) {
	visit(node)
	for _, child := range node.Plans {
		walkAuditPlan(child, visit)
	}
}
