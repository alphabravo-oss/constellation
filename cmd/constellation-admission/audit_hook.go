package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/admission"
	auditlog "github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/quarantine"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

func newAdmissionAuditHook(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID, logger *slog.Logger) (admission.DenyHook, uuid.UUID, error) {
	orgID, err := waitForClusterOrgID(ctx, pool, clusterID, 2*time.Minute, logger)
	if err != nil {
		return nil, uuid.Nil, err
	}
	auditor := auditlog.New(pool)
	return func(ctx context.Context, ev admission.DenyEvent) {
		suppressed := false
		if !ev.Monitor {
			suppressed = evaluateAdmissionResponseRules(ctx, pool, auditor, orgID, clusterID, ev, logger)
		}
		if !suppressed {
			if _, _, err := auditor.Log(ctx, admissionAuditEvent(orgID, clusterID, ev)); err != nil && logger != nil {
				logger.Warn("admission audit log failed", "err", err, "monitor", ev.Monitor, "rule_id", ev.RuleID, "namespace", ev.Namespace, "pod", ev.Pod)
			}
		}
	}, orgID, nil
}

func lookupClusterOrgID(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID) (uuid.UUID, error) {
	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT org_id FROM clusters WHERE id = $1`, clusterID).Scan(&orgID); err != nil {
		return uuid.Nil, fmt.Errorf("lookup org for cluster %s: %w", clusterID, err)
	}
	return orgID, nil
}

func waitForClusterOrgID(ctx context.Context, pool *pgxpool.Pool, clusterID uuid.UUID, timeout time.Duration, logger *slog.Logger) (uuid.UUID, error) {
	if timeout <= 0 {
		return lookupClusterOrgID(ctx, pool, clusterID)
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var lastErr error
	for {
		orgID, err := lookupClusterOrgID(waitCtx, pool, clusterID)
		if err == nil {
			return orgID, nil
		}
		lastErr = err
		if logger != nil {
			logger.Info("waiting for installed cluster row", "cluster_id", clusterID, "err", err)
		}
		select {
		case <-waitCtx.Done():
			if lastErr != nil {
				return uuid.Nil, lastErr
			}
			return uuid.Nil, waitCtx.Err()
		case <-ticker.C:
		}
	}
}

// admissionAuditEvent builds the durable audit row for one admission rule match.
// Enforce denies are recorded as action='admission.deny'; monitor-mode matches as
// action='admission.monitor' (NeuVector CLUSAuditAdmCtrlK8sReqViolation parity) so
// the monitor-then-enforce tuning workflow has durable events and rule-hit counts.
func admissionAuditEvent(orgID uuid.UUID, clusterID uuid.UUID, ev admission.DenyEvent) auditlog.Event {
	oid := orgID
	action := "admission.deny"
	if ev.Monitor {
		action = "admission.monitor"
	}
	targetID := ev.Namespace
	if targetID == "" {
		targetID = "unknown"
	}
	if ev.Pod != "" {
		targetID += "/" + ev.Pod
	}
	after := map[string]any{
		"cluster_id": clusterID.String(),
		"rule_id":    ev.RuleID,
		"reason":     ev.Reason,
		"namespace":  ev.Namespace,
		"pod":        ev.Pod,
		"operation":  ev.Operation,
		"user":       ev.UserInfo,
	}
	if len(ev.EvidenceDetails) > 0 {
		after["evidence_details"] = ev.EvidenceDetails
	}
	return auditlog.Event{
		OrgID:      &oid,
		Action:     action,
		TargetKind: "pod",
		TargetID:   targetID,
		After:      after,
	}
}

func chainDenyHooks(hooks ...admission.DenyHook) admission.DenyHook {
	return func(ctx context.Context, ev admission.DenyEvent) {
		for _, hook := range hooks {
			if hook == nil {
				continue
			}
			hook(ctx, ev)
		}
	}
}

// ---------------------------- E1 admission response rules ---------------------------

// evaluateAdmissionResponseRules loads the org's enabled EventAdmission response rules, matches
// them against this deny, and applies the ordered actions. It uses the pure pkg/responserule
// engine directly (rather than the API handler) so the lean webhook binary stays decoupled
// from internal/handler. Panic-isolated/best-effort: any error or panic is logged and
// swallowed so a misbehaving rule can never block pod admission. It returns true only
// when a matched suppress_log action was successfully audit-recorded.
//
// Webhook actions are NOT delivered here: the webhook pod has no notify dispatcher (that lives
// in the API). They are still audit-recorded so an operator can see the rule fired. Delivery of
// the deny itself to org receivers + the syslog/SIEM mirror is done API-side by
// handler.RunAdmissionNotifyDispatcher, which sweeps the admission.deny audit rows this pod
// writes and fans each one out through notify.Dispatcher (NeuVector EventAdmCtrl parity, P1-18).
func evaluateAdmissionResponseRules(ctx context.Context, pool *pgxpool.Pool, auditor *auditlog.Logger, orgID, clusterID uuid.UUID, ev admission.DenyEvent, logger *slog.Logger) (suppressed bool) {
	defer func() {
		if rec := recover(); rec != nil {
			suppressed = false
			if logger != nil {
				logger.Warn("admission response-rule dispatch panic", "recover", rec)
			}
		}
	}()
	rules, err := loadAdmissionResponseRules(ctx, pool, orgID)
	if err != nil {
		if logger != nil {
			logger.Warn("admission response-rule load failed", "err", err)
		}
		return
	}
	if len(rules) == 0 {
		return
	}
	rev := admissionResponseRuleEvent(ev)
	matched := responserule.MatchRules(rules, rev)
	order := 0
	actionAuditFailed := false
	for i := range matched {
		for _, a := range matched[i].Actions {
			if err := applyAdmissionResponseRuleAction(ctx, pool, auditor, orgID, clusterID, ev, rev, a, order, logger); err != nil {
				actionAuditFailed = true
			}
			if a.Type == responserule.ActionSuppressLog {
				suppressed = true
			}
			order++
		}
	}
	return suppressed && !actionAuditFailed
}

// loadAdmissionResponseRules reads the org's enabled event_type='admission' response rules,
// priority-ordered. Mirrors the API handler's loadRules SELECT (kept minimal so the webhook
// doesn't import the handler layer).
func loadAdmissionResponseRules(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]responserule.ResponseRule, error) {
	rows, err := pool.Query(ctx, `
SELECT id, name, enabled, priority, event_type, conditions, actions
  FROM response_rules
 WHERE org_id = $1 AND enabled = true AND event_type = 'admission'
 ORDER BY priority, name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []responserule.ResponseRule{}
	for rows.Next() {
		var rule responserule.ResponseRule
		var conds, acts []byte
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Enabled, &rule.Priority,
			&rule.EventType, &conds, &acts); err != nil {
			return nil, err
		}
		rule.OrgID = orgID
		if err := json.Unmarshal(conds, &rule.Conditions); err != nil {
			return nil, fmt.Errorf("decode conditions for response rule %s: %w", rule.ID, err)
		}
		if err := json.Unmarshal(acts, &rule.Actions); err != nil {
			return nil, fmt.Errorf("decode actions for response rule %s: %w", rule.ID, err)
		}
		for _, condition := range rule.Conditions {
			switch condition.Op {
			case responserule.OpEq, responserule.OpNe, responserule.OpContains:
			case responserule.OpRegex:
				if _, err := regexp.Compile(condition.Value); err != nil {
					return nil, fmt.Errorf("response rule %s condition: %w", rule.ID, err)
				}
			case responserule.OpGt, responserule.OpLt:
				if _, err := strconv.ParseFloat(strings.TrimSpace(condition.Value), 64); err != nil {
					return nil, fmt.Errorf("response rule %s condition: %w", rule.ID, err)
				}
			default:
				return nil, fmt.Errorf("response rule %s has unsupported condition op %q", rule.ID, condition.Op)
			}
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// admissionResponseRuleEvent folds an admission deny into the E1 EventAdmission shape. Fields
// are the string-valued attributes an EventAdmission rule's Condition.Field can reference.
func admissionResponseRuleEvent(ev admission.DenyEvent) *responserule.Event {
	workloadID := strings.TrimSpace(ev.Namespace)
	if pod := strings.TrimSpace(ev.Pod); pod != "" {
		if workloadID != "" {
			workloadID += "/" + pod
		} else {
			workloadID = pod
		}
	}
	fields := map[string]string{
		"kind":        "pod",
		"namespace":   strings.TrimSpace(ev.Namespace),
		"pod":         strings.TrimSpace(ev.Pod),
		"workload_id": workloadID,
		"rule_id":     strings.TrimSpace(ev.RuleID),
		"reason":      strings.TrimSpace(ev.Reason),
		"operation":   strings.TrimSpace(ev.Operation),
		"user":        strings.TrimSpace(ev.UserInfo),
		"verdict":     "deny",
		"action":      "deny",
	}
	return &responserule.Event{Type: responserule.EventAdmission, Fields: fields}
}

// applyAdmissionResponseRuleAction applies one ordered E1 action. quarantine records an
// origin='auto' quarantine_entries row (scope=workload when a pod is known, else namespace),
// reusing the same schema the runtime bridge uses; legacy tag actions report unsupported.
func applyAdmissionResponseRuleAction(ctx context.Context, pool *pgxpool.Pool, auditor *auditlog.Logger, orgID, clusterID uuid.UUID, ev admission.DenyEvent, rev *responserule.Event, a responserule.Action, order int, logger *slog.Logger) error {
	oid := orgID
	after := map[string]any{
		"action":    string(a.Type),
		"order":     order,
		"namespace": rev.Fields["namespace"],
		"pod":       rev.Fields["pod"],
		"reason":    rev.Fields["reason"],
		"rule_id":   rev.Fields["rule_id"],
	}
	for k, v := range a.Params {
		after["param_"+k] = v
	}
	if a.Type == responserule.ActionSuppressLog {
		after["enforced"] = "suppressed_log"
	}
	if a.Type == responserule.ActionTag {
		after["enforced"] = "unsupported"
		after["enforce_error"] = "tag action has no pod or workload label side effect"
	}
	if a.Type == responserule.ActionQuarantine {
		scope, matchKey := admissionQuarantineTarget(ev)
		if matchKey == "" {
			after["enforced"] = "skipped"
			after["enforce_skip_reason"] = "no namespace/pod to quarantine"
		} else if err := recordAdmissionQuarantine(ctx, pool, orgID, clusterID, scope, matchKey, "response_rule: admission deny "+rev.Fields["reason"]); err != nil {
			after["enforce_error"] = err.Error()
			if logger != nil {
				logger.Warn("admission response-rule quarantine", "err", err, "match_key", matchKey)
			}
		} else {
			after["enforced"] = string(scope)
			after["enforce_match_key"] = matchKey
		}
	}
	targetID := rev.Fields["workload_id"]
	if targetID == "" {
		targetID = "unknown"
	}
	if _, _, err := auditor.Log(ctx, auditlog.Event{
		OrgID:      &oid,
		Action:     "response_rule.action." + string(a.Type),
		TargetKind: "pod",
		TargetID:   targetID,
		After:      after,
	}); err != nil {
		if logger != nil {
			logger.Warn("admission response-rule audit failed", "err", err)
		}
		return err
	}
	return nil
}

// admissionQuarantineTarget picks the quarantine scope + match key for a deny: a concrete pod
// quarantines the workload ("<namespace>/<pod>"); a deny with only a namespace quarantines the
// namespace. Returns an empty key when neither is known (nothing to enforce on).
func admissionQuarantineTarget(ev admission.DenyEvent) (quarantine.Scope, string) {
	ns := strings.TrimSpace(ev.Namespace)
	pod := strings.TrimSpace(ev.Pod)
	if ns != "" && pod != "" {
		return quarantine.ScopeWorkload, ns + "/" + pod
	}
	if ns != "" {
		return quarantine.ScopeNamespace, ns
	}
	return quarantine.ScopeWorkload, ""
}

// recordAdmissionQuarantine inserts an origin='auto' quarantine entry, reusing the exact
// schema/semantics of the runtime quarantine bridge: a duplicate active entry (collapsed by
// uniq_quarantine_active_target) is treated as success.
func recordAdmissionQuarantine(ctx context.Context, pool *pgxpool.Pool, orgID, clusterID uuid.UUID, scope quarantine.Scope, matchKey, reason string) error {
	matchKey = strings.TrimSpace(matchKey)
	if matchKey == "" || clusterID == uuid.Nil {
		return nil
	}
	if strings.TrimSpace(reason) == "" {
		reason = "auto-response"
	}
	_, err := pool.Exec(ctx, `
INSERT INTO quarantine_entries
    (org_id, cluster_id, scope, match_key, reason, origin, source_kind, expires_at)
VALUES ($1, $2, $3, $4, $5, 'auto', 'admission', NOW() + INTERVAL '24 hours')`,
		orgID, clusterID, string(scope), matchKey, reason)
	if err != nil && strings.Contains(err.Error(), "uniq_quarantine_active_target") {
		return nil
	}
	return err
}
