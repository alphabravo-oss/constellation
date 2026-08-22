// P2-3 federated runtime profiles — master authoring + joint serving.
//
// A master org federates two per-workload runtime domains that expose a
// runtime-agent pull bundle: file-monitor profiles (file-profile-rules:bundle)
// and process baselines (process-baselines:bundle). On every master mutation the
// handler records a fed revision (recordFedFileProfileRule / recordFedBaseline)
// carrying the exact agent-bundle row the joint's agents consume; the joint's
// poller (internal/handler/fed_sync.go) replicates it into fed_runtime_profiles,
// and the two AgentRulesBundle / AgentBaselineBundle serving paths merge those
// rows read-only into what agents receive across every cluster.
//
// The payload shipped is the agent-bundle row itself, so master (author) and
// joint (serve) share one wire shape and the merge is a plain JSON round-trip.
package runtime

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// recordFedFileProfileRule authors (or tombstones) a federated file-profile rule
// on a master mutation. Best-effort and a no-op unless the org is in the master
// federation state — LogFedRevision guards on that. Keyed by the rule id so the
// joint can replace/drop exactly this row.
func recordFedFileProfileRule(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, ruleID string, row fileProfileRuleBundleRow, deleted bool) {
	if deleted {
		handler.LogFedRevision(ctx, pool, orgID, handler.FedKindFileProfile+"_delete", ruleID, map[string]string{"id": ruleID})
		return
	}
	handler.LogFedRevision(ctx, pool, orgID, handler.FedKindFileProfile, ruleID, row)
}

// recordFedBaseline authors a federated process-baseline row on a master mutation
// (mode change). Keyed by workload id. Best-effort / master-only via
// LogFedRevision.
func recordFedBaseline(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, row processBaselineBundleRow) {
	handler.LogFedRevision(ctx, pool, orgID, handler.FedKindHostProcessProfile, row.WorkloadID, row)
}

// recordFedDLPRule authors (or tombstones) a federated DLP/WAF rule on a master
// mutation. Best-effort and a no-op unless the org is in the master federation
// state — LogFedRevision guards on that. Keyed by the rule id so the joint can
// replace/drop exactly this row. A disabled rule is tombstoned rather than
// authored, so the fed template mirrors the enabled-only cluster bundle
// (ListForCluster excludes mode='disabled').
func recordFedDLPRule(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, row *DLPRule) {
	if row == nil {
		return
	}
	if row.Mode == DLPModeDisabled {
		recordFedDLPRuleDelete(ctx, pool, orgID, row.ID)
		return
	}
	handler.LogFedRevision(ctx, pool, orgID, handler.FedKindRuntimeDLP, row.ID.String(), row)
}

// recordFedDLPRuleDelete tombstones a federated DLP/WAF rule on a master delete.
func recordFedDLPRuleDelete(ctx context.Context, pool *pgxpool.Pool, orgID, ruleID uuid.UUID) {
	handler.LogFedRevision(ctx, pool, orgID, handler.FedKindRuntimeDLP+"_delete",
		ruleID.String(), map[string]string{"id": ruleID.String()})
}

// appendFedDLPRows decodes each replicated fed payload into a DLP rule and
// appends it to the cluster-scoped rows an agent already receives. Malformed
// payloads are skipped so one bad fed row can never break a bundle. Pure — unit
// tested without a DB.
func appendFedDLPRows(rows []*DLPRule, payloads [][]byte) []*DLPRule {
	for _, raw := range payloads {
		var r DLPRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		rows = append(rows, &r)
	}
	return rows
}

// fetchFedRuntimeProfilePayloads returns every replicated fed row payload for the
// given org and kind, oldest-key first for a stable bundle order. On a master or
// standalone controller the table is empty, so this is a no-op there.
func fetchFedRuntimeProfilePayloads(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind string) ([][]byte, error) {
	rows, err := pool.Query(ctx,
		`SELECT payload FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind=$2 ORDER BY rule_key`, orgID, kind)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	return out, rows.Err()
}

// appendFedFileProfileRows decodes each replicated fed payload into a bundle row
// and appends it to the cluster-scoped rows an agent already receives. Malformed
// payloads are skipped so one bad fed row can never break a bundle. Pure — unit
// tested without a DB.
func appendFedFileProfileRows(rows []fileProfileRuleBundleRow, payloads [][]byte) []fileProfileRuleBundleRow {
	for _, raw := range payloads {
		var row fileProfileRuleBundleRow
		if err := json.Unmarshal(raw, &row); err != nil {
			continue
		}
		row.PodWorkloadIDs = nonNilStrings(row.PodWorkloadIDs)
		row.Applications = nonNilStrings(row.Applications)
		rows = append(rows, row)
	}
	return rows
}

// appendFedProcessBaselineRows decodes each replicated fed payload into a process
// baseline bundle row and appends it. Malformed payloads are skipped. Pure.
func appendFedProcessBaselineRows(rows []processBaselineBundleRow, payloads [][]byte) []processBaselineBundleRow {
	for _, raw := range payloads {
		var row processBaselineBundleRow
		if err := json.Unmarshal(raw, &row); err != nil {
			continue
		}
		row.PodWorkloadIDs = nonNilStrings(row.PodWorkloadIDs)
		if row.Processes == nil {
			row.Processes = []string{}
		}
		rows = append(rows, row)
	}
	return rows
}
