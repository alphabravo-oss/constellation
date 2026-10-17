package compliance

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/jackc/pgx/v5"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

// Used by both scheduled ingestion and atomic execution-result completion.
func persistBenchChecks(ctx context.Context, tx pgx.Tx, scope complianceWriteScope, node string, checks []compliancepkg.Check) ([]complianceFailure, error) {
	var failures []complianceFailure
	for _, ck := range checks {
		if strings.EqualFold(ck.Status, "fail") {
			failures = append(failures, complianceFailure{
				CheckID:   ck.ControlID,
				Title:     ck.Title,
				Framework: ck.Framework,
				Severity:  ck.Severity,
				Detail:    ck.Evidence,
			})
		}
		// Populate tags_v2 from the cross-framework expansion when the check
		// title maps to a known internal id. Best-effort: lookup by control id title.
		tags := compliancepkg.TagsV2{}
		for _, m := range compliancepkg.CoreMappings {
			if m.Title == ck.Title {
				tags = compliancepkg.BuildTagsV2(m.InternalID)
				break
			}
		}
		tagsRaw, _ := json.Marshal(tags)
		// CMP-CLOBBER-03: upsert on the per-cluster/per-node host-compliance key so a re-run
		// of the kube-bench/docker-bench CronJob refreshes each control in place for THAT
		// cluster/node instead of clobbering another cluster's rows. Matches the composite
		// partial unique index from migration 136 (WHERE node IS NOT NULL — the k8s-object
		// collector, which stores many rows per control with node NULL, is unaffected).
		if _, err := tx.Exec(ctx, `
INSERT INTO compliance_checks (org_id, cluster_id, node, framework, control_id, title, description, status, severity, evidence, tags_v2, remediation)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
ON CONFLICT (org_id, COALESCE(cluster_id, '00000000-0000-0000-0000-000000000000'::uuid), node, framework, control_id) WHERE node IS NOT NULL
DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    status = EXCLUDED.status,
    severity = EXCLUDED.severity,
    evidence = EXCLUDED.evidence,
    tags_v2 = EXCLUDED.tags_v2,
    remediation = EXCLUDED.remediation,
    evaluated_at = NOW()`,
			scope.orgID, scope.clusterID, node, ck.Framework, ck.ControlID, ck.Title, ck.Description, ck.Status, ck.Severity, ck.Evidence, tagsRaw, ck.Remediation,
		); err != nil {
			return nil, err
		}
	}
	return failures, nil
}
