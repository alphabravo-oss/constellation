package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/response"
)

type responseRulesYAML struct {
	APIVersion string                 `yaml:"api_version"`
	Kind       string                 `yaml:"kind"`
	Scope      string                 `yaml:"scope"`
	Rules      []responseRuleYAMLRule `yaml:"rules"`
}

type responseRuleYAMLRule struct {
	Name          string                    `yaml:"name"`
	Description   string                    `yaml:"description"`
	Enabled       bool                      `yaml:"enabled"`
	Priority      int                       `yaml:"priority"`
	EventType     string                    `yaml:"event_type"`
	Conditions    []response.Condition      `yaml:"conditions"`
	Actions       []response.Action         `yaml:"actions"`
	WorkloadMatch response.WorkloadSelector `yaml:"workload_match"`
	OnConflict    string                    `yaml:"on_conflict,omitempty"`
}

func responseRulesYAMLScope(clusterID any) string {
	if clusterID != nil {
		return "cluster"
	}
	return "global"
}

func responseRulesYAMLHasReferences(node *yaml.Node) bool {
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if responseRulesYAMLHasReferences(child) {
			return true
		}
	}
	return false
}

func responseRuleYAMLActionParamsValid(action response.Action) bool {
	for key, value := range action.Params {
		switch {
		case key == "receiver" && (action.Kind == response.ActionNotify || action.Kind == response.ActionTicket || action.Kind == response.ActionWebhook):
			if value == "" || value != strings.TrimSpace(value) || len(value) > 255 {
				return false
			}
		case key == "isolate" && action.Kind == response.ActionQuarantine:
			if value != "true" && value != "false" {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type responseRuleYAMLQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func responseRuleYAMLReceiverName(ctx context.Context, queryer responseRuleYAMLQueryer, orgID uuid.UUID, reference string, allowID bool) (uuid.UUID, string, error) {
	if reference == "" || reference != strings.TrimSpace(reference) || len(reference) > 255 {
		return uuid.Nil, "", pgx.ErrNoRows
	}
	if !allowID {
		if _, err := uuid.Parse(reference); err == nil {
			return uuid.Nil, "", pgx.ErrNoRows
		}
	}
	query := `SELECT id, name FROM receivers WHERE org_id=$1 AND name=$2 LIMIT 1 FOR SHARE`
	if allowID {
		query = `SELECT id, name FROM receivers WHERE org_id=$1 AND (name=$2 OR id::text=$2) ORDER BY (name=$2) DESC LIMIT 1`
	}
	var receiverID uuid.UUID
	var name string
	if err := queryer.QueryRow(ctx, query, orgID, reference).Scan(&receiverID, &name); err != nil {
		return uuid.Nil, "", err
	}
	if name == "" || name != strings.TrimSpace(name) || len(name) > 255 {
		return uuid.Nil, "", pgx.ErrNoRows
	}
	if _, err := uuid.Parse(name); err == nil {
		return uuid.Nil, "", pgx.ErrNoRows
	}
	return receiverID, name, nil
}

func decodeResponseRulesYAML(body io.Reader) (responseRulesYAML, error) {
	var document responseRulesYAML
	data, err := io.ReadAll(io.LimitReader(body, 1<<20+1))
	if err != nil || len(data) > 1<<20 {
		return document, errors.New("YAML document exceeds 1 MiB")
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return document, err
	}
	if responseRulesYAMLHasReferences(&node) {
		return document, errors.New("YAML anchors and aliases are not supported")
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return document, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return document, errors.New("only one YAML document is allowed")
	}
	return document, nil
}

func validateResponseRulesYAML(document responseRulesYAML, scope, defaultConflict string) error {
	if document.APIVersion != "constellation.io/v1" || document.Kind != "ResponseRules" || document.Scope != scope {
		return errors.New("api_version, kind, or scope does not match this endpoint")
	}
	if len(document.Rules) > 100 {
		return errors.New("at most 100 rules are allowed")
	}
	if defaultConflict != "error" && defaultConflict != "skip" && defaultConflict != "replace" {
		return errors.New("on_conflict must be error, skip, or replace")
	}
	seen := make(map[string]bool, len(document.Rules))
	for index, item := range document.Rules {
		name := strings.TrimSpace(item.Name)
		if name == "" || name != item.Name || len(name) > 255 || len(item.Description) > 4096 {
			return fmt.Errorf("rule %d has an invalid name or description", index+1)
		}
		if seen[name] {
			return fmt.Errorf("duplicate rule name %q", name)
		}
		seen[name] = true
		if item.Priority < 1 || item.Priority > 1000000 {
			return fmt.Errorf("rule %q has invalid priority", name)
		}
		if item.OnConflict != "" && item.OnConflict != "error" && item.OnConflict != "skip" && item.OnConflict != "replace" {
			return fmt.Errorf("rule %q has invalid on_conflict", name)
		}
		rule := response.Rule{Name: name, Enabled: item.Enabled, EventType: response.EventType(item.EventType), Conditions: item.Conditions, Actions: item.Actions, Selector: item.WorkloadMatch}
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule %q: %w", name, err)
		}
		for _, action := range item.Actions {
			if !responseRuleYAMLActionParamsValid(action) {
				return fmt.Errorf("rule %q contains unsupported action params", name)
			}
			if action.Kind == response.ActionNotify || action.Kind == response.ActionTicket || action.Kind == response.ActionWebhook {
				for _, reference := range []string{action.Target, action.Params["receiver"]} {
					if _, err := uuid.Parse(reference); err == nil {
						return fmt.Errorf("rule %q must use receiver names, not IDs", name)
					}
				}
			}
		}
	}
	return nil
}

func (h *ResponseRulesV2) ExportYAML(w http.ResponseWriter, r *http.Request) {
	subject, _ := authctx.SubjectFrom(r.Context())
	clusterID, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if clusterID != nil {
		var owned uuid.UUID
		err := h.db.Pool().QueryRow(r.Context(), `SELECT id FROM clusters WHERE org_id=$1 AND id=$2`, subject.OrgID, clusterID).Scan(&owned)
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
			return
		}
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify cluster"})
			return
		}
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT name, description, enabled, priority, event_type, conditions, actions, workload_match
  FROM response_rules_v2
 WHERE org_id=$1 AND cluster_id IS NOT DISTINCT FROM $2::uuid
 ORDER BY priority, name`, subject.OrgID, clusterID)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to export rules"})
		return
	}
	defer rows.Close()
	document := responseRulesYAML{APIVersion: "constellation.io/v1", Kind: "ResponseRules", Scope: responseRulesYAMLScope(clusterID), Rules: []responseRuleYAMLRule{}}
	for rows.Next() {
		var item responseRuleYAMLRule
		var conditions, actions, selector []byte
		if err := rows.Scan(&item.Name, &item.Description, &item.Enabled, &item.Priority, &item.EventType, &conditions, &actions, &selector); err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to export rules"})
			return
		}
		if json.Unmarshal(conditions, &item.Conditions) != nil || json.Unmarshal(actions, &item.Actions) != nil || json.Unmarshal(selector, &item.WorkloadMatch) != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "invalid stored response rule"})
			return
		}
		for index := range item.Actions {
			action := &item.Actions[index]
			if !responseRuleYAMLActionParamsValid(*action) {
				httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "response rule has unsupported action params"})
				return
			}
			if action.Kind != response.ActionNotify && action.Kind != response.ActionTicket && action.Kind != response.ActionWebhook {
				continue
			}
			var targetID uuid.UUID
			if action.Target != "" {
				var name string
				var err error
				targetID, name, err = responseRuleYAMLReceiverName(r.Context(), h.db.Pool(), subject.OrgID, action.Target, true)
				if err != nil {
					httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "response rule references an unavailable receiver"})
					return
				}
				action.Target = name
			}
			if reference := action.Params["receiver"]; reference != "" {
				receiverID, name, err := responseRuleYAMLReceiverName(r.Context(), h.db.Pool(), subject.OrgID, reference, true)
				if err != nil || (targetID != uuid.Nil && receiverID != targetID) {
					httpx.WriteJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "response rule references an unavailable or conflicting receiver"})
					return
				}
				action.Params["receiver"] = name
			}
		}
		document.Rules = append(document.Rules, item)
	}
	if rows.Err() != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to export rules"})
		return
	}
	data, err := yaml.Marshal(document)
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to encode rules"})
		return
	}
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="response-rules.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (h *ResponseRulesV2) ImportYAML(w http.ResponseWriter, r *http.Request) {
	mediaType, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || (mediaType != "application/yaml" && mediaType != "application/x-yaml" && mediaType != "text/yaml" && mediaType != "text/x-yaml") || (parameters["charset"] != "" && !strings.EqualFold(parameters["charset"], "utf-8")) {
		httpx.WriteJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be YAML with UTF-8 charset"})
		return
	}
	if h.auditLog == nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
		return
	}
	subject, _ := authctx.SubjectFrom(r.Context())
	clusterID, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	defaultConflict := r.URL.Query().Get("on_conflict")
	if defaultConflict == "" {
		defaultConflict = "error"
	}
	document, err := decodeResponseRulesYAML(r.Body)
	if err == nil {
		err = validateResponseRulesYAML(document, responseRulesYAMLScope(clusterID), defaultConflict)
	}
	if err != nil {
		httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if clusterID != nil {
		var owned uuid.UUID
		err := h.db.Pool().QueryRow(r.Context(), `SELECT id FROM clusters WHERE org_id=$1 AND id=$2`, subject.OrgID, clusterID).Scan(&owned)
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
			return
		}
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify cluster"})
			return
		}
	}
	names := make([]string, 0, len(document.Rules))
	for _, item := range document.Rules {
		names = append(names, item.Name)
	}
	targetID := subject.OrgID.String()
	if clusterID != nil {
		targetID = clusterID.(uuid.UUID).String()
	}
	attemptID, _, err := h.auditLog.Log(r.Context(), audit.Event{OrgID: &subject.OrgID, ActorID: &subject.UserID, Action: "response_rule_v2.import_attempt", TargetKind: "response-rule-v2", TargetID: targetID, After: map[string]any{"scope": responseRulesYAMLScope(clusterID), "names": names, "on_conflict": defaultConflict}})
	if err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
		return
	}
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to begin import"})
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if clusterID != nil {
		var owned uuid.UUID
		err := tx.QueryRow(r.Context(), `SELECT id FROM clusters WHERE org_id=$1 AND id=$2 FOR SHARE`, subject.OrgID, clusterID).Scan(&owned)
		if errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusNotFound, map[string]string{"error": "cluster not found"})
			return
		}
		if err != nil {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify cluster"})
			return
		}
	}
	var lockedOrgID uuid.UUID
	if err := tx.QueryRow(r.Context(), `SELECT id FROM orgs WHERE id=$1 FOR UPDATE`, subject.OrgID).Scan(&lockedOrgID); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to lock organization"})
		return
	}
	results := make([]map[string]string, 0, len(document.Rules))
	created, replaced, skipped := 0, 0, 0
	for _, item := range document.Rules {
		var existingID uuid.UUID
		var existingCluster *uuid.UUID
		err := tx.QueryRow(r.Context(), `SELECT id, cluster_id FROM response_rules_v2 WHERE org_id=$1 AND name=$2`, subject.OrgID, item.Name).Scan(&existingID, &existingCluster)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to inspect rule"})
			return
		}
		conflict := item.OnConflict
		if conflict == "" {
			conflict = defaultConflict
		}
		if err == nil {
			if (existingCluster == nil) != (clusterID == nil) || (existingCluster != nil && *existingCluster != clusterID.(uuid.UUID)) {
				httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("rule %q exists in another scope", item.Name)})
				return
			}
			if conflict == "error" {
				httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("rule %q already exists", item.Name)})
				return
			}
			if conflict == "skip" {
				skipped++
				results = append(results, map[string]string{"name": item.Name, "status": "skipped"})
				continue
			}
		}
		if selector := strings.TrimSpace(item.WorkloadMatch.Group); selector != "" {
			var groupID uuid.UUID
			err := tx.QueryRow(r.Context(), `SELECT id FROM groups WHERE org_id=$1 AND (id::text=$2 OR name=$2) AND (cluster_id IS NULL OR ($3::uuid IS NOT NULL AND cluster_id=$3)) FOR SHARE NOWAIT`, subject.OrgID, selector, clusterID).Scan(&groupID)
			if errors.Is(err, pgx.ErrNoRows) {
				httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("rule %q references a group outside this scope", item.Name)})
				return
			}
			var pgError *pgconn.PgError
			if errors.As(err, &pgError) && pgError.Code == "55P03" {
				httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": "group is being modified; retry"})
				return
			}
			if err != nil {
				httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate group"})
				return
			}
		}
		for _, action := range item.Actions {
			if action.Kind != response.ActionNotify && action.Kind != response.ActionTicket && action.Kind != response.ActionWebhook {
				continue
			}
			var targetID uuid.UUID
			if action.Target != "" {
				var err error
				targetID, _, err = responseRuleYAMLReceiverName(r.Context(), tx, subject.OrgID, action.Target, false)
				if errors.Is(err, pgx.ErrNoRows) {
					httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("rule %q references a receiver outside this organization", item.Name)})
					return
				}
				if err != nil {
					httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate receiver"})
					return
				}
			}
			if reference := action.Params["receiver"]; reference != "" {
				receiverID, _, err := responseRuleYAMLReceiverName(r.Context(), tx, subject.OrgID, reference, false)
				if errors.Is(err, pgx.ErrNoRows) || (err == nil && targetID != uuid.Nil && receiverID != targetID) {
					httpx.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf("rule %q references a receiver outside this organization", item.Name)})
					return
				}
				if err != nil {
					httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate receiver"})
					return
				}
			}
		}
		conditions, _ := json.Marshal(item.Conditions)
		actions, _ := json.Marshal(item.Actions)
		selector, _ := json.Marshal(item.WorkloadMatch)
		status := "created"
		if err == nil {
			_, err = tx.Exec(r.Context(), `UPDATE response_rules_v2 SET description=$1, enabled=$2, priority=$3, event_type=$4, conditions=$5, actions=$6, workload_match=$7, updated_at=NOW() WHERE id=$8 AND org_id=$9`, item.Description, item.Enabled, item.Priority, item.EventType, conditions, actions, selector, existingID, subject.OrgID)
			status = "replaced"
			replaced++
		} else {
			_, err = tx.Exec(r.Context(), `INSERT INTO response_rules_v2 (org_id, cluster_id, name, description, enabled, priority, event_type, conditions, actions, workload_match, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, subject.OrgID, clusterID, item.Name, item.Description, item.Enabled, item.Priority, item.EventType, conditions, actions, selector, subject.UserID)
			created++
		}
		if err != nil {
			var pgError *pgconn.PgError
			if errors.As(err, &pgError) && pgError.Code == "23505" {
				httpx.WriteJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("rule %q already exists", item.Name)})
			} else {
				httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to import rule"})
			}
			return
		}
		results = append(results, map[string]string{"name": item.Name, "status": status})
	}
	completionID, _, err := h.auditLog.LogInTx(r.Context(), tx, audit.Event{OrgID: &subject.OrgID, ActorID: &subject.UserID, Action: "response_rule_v2.import", TargetKind: "response-rule-v2", TargetID: targetID, After: map[string]any{"created": created, "replaced": replaced, "skipped": skipped, "results": results, "audit_attempt_id": attemptID}})
	if err != nil {
		httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "audit unavailable"})
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to commit import"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"created": created, "replaced": replaced, "skipped": skipped, "results": results, "audit_attempt_id": attemptID, "completion_audit_id": completionID})
}
