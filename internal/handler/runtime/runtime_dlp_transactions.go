package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type dlpInputError struct{ error }

func dlpInvalid(message string) error { return dlpInputError{errors.New(message)} }

func validateDLPPatterns(patterns json.RawMessage) error {
	specs, err := dlp.ParsePatternSpecs(patterns)
	if err != nil {
		return dlpInvalid("patterns is not valid JSON")
	}
	if err := dlp.ValidateSpecs(specs); err != nil {
		return dlpInputError{err}
	}
	return nil
}

func normalizeDLPRule(rule DLPRule) (DLPRule, error) {
	if !rule.Mode.Valid() {
		return rule, dlpInvalid(fmt.Sprintf("invalid mode %q", rule.Mode))
	}
	if strings.TrimSpace(rule.Name) == "" {
		return rule, dlpInvalid("name is required")
	}
	if rule.Severity < 1 || rule.Severity > 9 {
		return rule, dlpInvalid("severity must be 1..9")
	}
	if rule.Category == "" {
		rule.Category = CategoryDLP
	}
	if !rule.Category.Valid() {
		return rule, dlpInvalid(fmt.Sprintf("invalid category %q", rule.Category))
	}
	rule.ApplyDir = defaultDLPDirection(rule.Category, rule.ApplyDir)
	if rule.ApplyDir < 1 || rule.ApplyDir > 3 {
		return rule, dlpInvalid("apply_dir must be 1 (egress), 2 (ingress), or 3 (both)")
	}
	rule.Source = emptyDefaultString(rule.Source, "user")
	rule.CfgType = emptyDefaultString(rule.CfgType, "user_created")
	rule.SourcePath = strings.TrimSpace(rule.SourcePath)
	if !validDLPRuleSource(rule.Source) {
		return rule, dlpInvalid(fmt.Sprintf("invalid source %q", rule.Source))
	}
	if !validDLPRuleCfgType(rule.CfgType) {
		return rule, dlpInvalid(fmt.Sprintf("invalid cfg_type %q", rule.CfgType))
	}
	return rule, validateDLPPatterns(rule.Patterns)
}

func defaultDLPDirection(category DLPCategory, direction int16) int16 {
	if direction != 0 {
		return direction
	}
	switch category {
	case CategorySignature:
		return 3
	case CategoryWAF:
		return 2
	case CategoryDLP:
		return 1
	default:
		return 1
	}
}

func (s *RuntimeDLPStore) requireOwnedCluster(ctx context.Context, org, cluster uuid.UUID) error {
	var id uuid.UUID
	err := s.db.Pool().QueryRow(ctx, `SELECT id FROM clusters WHERE id=$1 AND org_id=$2`, cluster, org).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return errLegacyPolicyClusterNotFound
	}
	return err
}

func (s *RuntimeDLPStore) dlpTransaction(ctx context.Context, mutate func(pgx.Tx) (*DLPRule, error)) (*DLPRule, error) {
	tx, err := s.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rule, err := mutate(tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return rule, nil
}

func lockDLPRule(ctx context.Context, tx pgx.Tx, org, id uuid.UUID, categories []DLPCategory) (*DLPRule, error) {
	rule, err := scanDLP(tx.QueryRow(ctx, `SELECT `+dlpSelectCols+` FROM runtime_dlp_rules WHERE id=$1 AND org_id=$2 FOR UPDATE`, id, org))
	if err != nil {
		return nil, err
	}
	if len(categories) > 0 && !dlpCategoryAllowed(rule.Category, categories) {
		return nil, pgx.ErrNoRows
	}
	if err := requireLegacyPolicyCluster(ctx, tx, org, rule.ClusterID); err != nil {
		return nil, err
	}
	return rule, nil
}

func dlpCategoryAllowed(category DLPCategory, allowed []DLPCategory) bool {
	for _, candidate := range allowed {
		if category == candidate {
			return true
		}
	}
	return false
}

func (s *RuntimeDLPStore) insertDLPRule(ctx context.Context, rule *DLPRule, requestID string) (*DLPRule, error) {
	candidate, err := normalizeDLPRule(*rule)
	if err != nil {
		return nil, err
	}
	saved, err := s.dlpTransaction(ctx, func(tx pgx.Tx) (*DLPRule, error) {
		if err := requireLegacyPolicyCluster(ctx, tx, candidate.OrgID, candidate.ClusterID); err != nil {
			return nil, err
		}
		got, err := scanDLP(tx.QueryRow(ctx, `INSERT INTO runtime_dlp_rules
   (org_id,cluster_id,name,category,apply_dir,severity,mode,patterns,scope_macs,description,created_by,updated_by,source,cfg_type,source_path)
   VALUES($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$11,$11,$12,$13,$14) RETURNING `+dlpSelectCols,
			candidate.OrgID, candidate.ClusterID, candidate.Name, string(candidate.Category), candidate.ApplyDir, candidate.Severity, string(candidate.Mode), string(candidate.Patterns), scopeMACsJSON(candidate.ScopeMACs), candidate.Description, candidate.CreatedBy, candidate.Source, candidate.CfgType, candidate.SourcePath))
		if err != nil {
			return nil, err
		}
		return got, s.appendDLPAudit(ctx, tx, audit.ActionPolicyCreate, nil, got, candidate.CreatedBy, requestID)
	})
	if err != nil {
		return nil, err
	}
	*rule = *saved
	recordFedDLPRule(ctx, s.db.Pool(), saved.OrgID, saved)
	return saved, nil
}

func validateDLPPatch(req UpdateDLPRequest) error {
	if req.Severity != 0 && (req.Severity < 1 || req.Severity > 9) {
		return dlpInvalid("severity must be 1..9")
	}
	if req.Patterns != nil && len(*req.Patterns) > 0 {
		return validateDLPPatterns(*req.Patterns)
	}
	return nil
}

func (s *RuntimeDLPStore) updateDLPRule(ctx context.Context, org, id uuid.UUID, req UpdateDLPRequest, by uuid.UUID, requestID string, categories []DLPCategory) (*DLPRule, error) {
	if err := validateDLPPatch(req); err != nil {
		return nil, err
	}
	var patterns string
	if req.Patterns != nil {
		patterns = string(*req.Patterns)
	}
	var scope any
	if req.ScopeMACs != nil {
		scope = scopeMACsJSON(*req.ScopeMACs)
	}
	after, err := s.dlpTransaction(ctx, func(tx pgx.Tx) (*DLPRule, error) {
		before, err := lockDLPRule(ctx, tx, org, id, categories)
		if err != nil {
			return nil, err
		}
		got, err := scanDLP(tx.QueryRow(ctx, `UPDATE runtime_dlp_rules SET
   patterns=COALESCE(NULLIF($1::text,'')::jsonb,patterns),severity=COALESCE(NULLIF($2,0::smallint),severity),
   description=COALESCE(NULLIF($3,''),description),scope_macs=CASE WHEN $7 THEN $8::jsonb ELSE scope_macs END,updated_by=$4
   WHERE id=$5 AND org_id=$6 RETURNING `+dlpSelectCols, patterns, req.Severity, req.Description, by, id, org, req.ScopeMACs != nil, scope))
		if err != nil {
			return nil, err
		}
		return got, s.appendDLPAudit(ctx, tx, audit.ActionPolicyUpdate, before, got, &by, requestID)
	})
	if err == nil {
		recordFedDLPRule(ctx, s.db.Pool(), org, after)
	}
	return after, err
}

func (s *RuntimeDLPStore) setDLPMode(ctx context.Context, org, id uuid.UUID, mode DLPMode, by uuid.UUID, requestID string, categories []DLPCategory) (*DLPRule, error) {
	if !mode.Valid() {
		return nil, dlpInvalid(fmt.Sprintf("invalid mode %q", mode))
	}
	after, err := s.dlpTransaction(ctx, func(tx pgx.Tx) (*DLPRule, error) {
		before, err := lockDLPRule(ctx, tx, org, id, categories)
		if err != nil {
			return nil, err
		}
		got, err := scanDLP(tx.QueryRow(ctx, `UPDATE runtime_dlp_rules SET mode=$1,updated_by=$2 WHERE id=$3 AND org_id=$4 RETURNING `+dlpSelectCols, string(mode), by, id, org))
		if err != nil {
			return nil, err
		}
		action := legacyPolicyModeAction(PolicyMode(before.Mode), PolicyMode(got.Mode), false)
		return got, s.appendDLPAudit(ctx, tx, action, before, got, &by, requestID)
	})
	if err == nil {
		recordFedDLPRule(ctx, s.db.Pool(), org, after)
	}
	return after, err
}

func (s *RuntimeDLPStore) deleteDLPRule(ctx context.Context, org, id uuid.UUID, by *uuid.UUID, requestID string, categories []DLPCategory) error {
	_, err := s.dlpTransaction(ctx, func(tx pgx.Tx) (*DLPRule, error) {
		before, err := lockDLPRule(ctx, tx, org, id, categories)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM runtime_dlp_rules WHERE id=$1 AND org_id=$2`, id, org); err != nil {
			return nil, err
		}
		return nil, s.appendDLPAudit(ctx, tx, audit.ActionPolicyDelete, before, nil, by, requestID)
	})
	if err == nil {
		recordFedDLPRuleDelete(ctx, s.db.Pool(), org, id)
	}
	return err
}

func dlpAuditPayload(rule *DLPRule) any {
	if rule == nil {
		return nil
	}
	snap := snapshotDLP(rule)
	return map[string]any{"id": snap.ID, "cluster_id": rule.ClusterID, "name": snap.Name, "workload": snap.Workload, "namespace": snap.Namespace, "mode": snap.Mode, "rule_count": snap.RuleCount, "version": snap.Version, "category": rule.Category, "source": rule.Source, "cfg_type": rule.CfgType}
}

func (s *RuntimeDLPStore) appendDLPAudit(ctx context.Context, tx pgx.Tx, action string, before, after *DLPRule, actor *uuid.UUID, requestID string) error {
	if s.auditLog == nil {
		return nil
	}
	target := before
	if after != nil {
		target = after
	}
	_, _, err := s.auditLog.LogInTx(ctx, tx, audit.Event{OrgID: &target.OrgID, ActorID: actor, Action: action, TargetKind: audit.TargetKindPolicy, TargetID: target.ID.String(), Before: dlpAuditPayload(before), After: dlpAuditPayload(after), RequestID: requestID})
	return err
}

func dlpConflict(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "runtime_dlp_rules_org_id_cluster_id_name_key"
}

func writeDLPError(w http.ResponseWriter, err error) {
	var input dlpInputError
	switch {
	case errors.As(err, &input):
		jsonError(w, http.StatusBadRequest, input.Error())
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, errLegacyPolicyClusterNotFound):
		jsonError(w, http.StatusNotFound, "not found")
	case dlpConflict(err):
		jsonError(w, http.StatusConflict, "rule with this name already exists")
	default:
		jsonError(w, http.StatusInternalServerError, "rule operation failed")
	}
}

// Resolve authorization before even consulting the lazy-seed cache. A token
// with an unresolved or ambiguous cluster cannot choose a cluster via the URL.
func (h *RuntimeDLPHTTP) authorizeDLPAgent(w http.ResponseWriter, r *http.Request, cluster uuid.UUID) bool {
	tok, ok := handler.RuntimeAgentTokenFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "runtime-agent token required")
		return false
	}
	resolved, err := handler.ResolveAgentClusterID(r.Context(), h.store.db, tok)
	if errors.Is(err, handler.ErrAgentClusterScope) || (err == nil && (resolved == nil || *resolved != cluster)) {
		jsonError(w, http.StatusForbidden, "runtime-agent cluster scope required")
		return false
	}
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "cluster resolution failed")
		return false
	}
	return true
}
