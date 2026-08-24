package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/handler/httpx"
	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type admissionDryRunHistoryDTO struct {
	ID              string `json:"id"`
	ClusterID       string `json:"cluster_id,omitempty"`
	ActorID         string `json:"actor_id,omitempty"`
	Image           string `json:"image"`
	Namespace       string `json:"namespace"`
	Decision        string `json:"decision"`
	EnforcementMode string `json:"enforcement_mode"`
	CurrentOutcome  string `json:"current_outcome,omitempty"`
	ProtectOutcome  string `json:"protect_outcome,omitempty"`
	Matches         int    `json:"matches"`
	AssessedAt      string `json:"assessed_at"`
}

// AdmissionDryRunHistory returns retained dry-run admission assessments for the
// caller's org, optionally scoped to one cluster. It mirrors the Admission page's
// local history shape so exports remain stable while making the evidence shared.
func (p *Policies) AdmissionDryRunHistory(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if p.db == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"history": []admissionDryRunHistoryDTO{}, "total": 0})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	limit := admissionHistoryLimit(r.URL.Query().Get("limit"))
	rows, err := p.db.Pool().Query(r.Context(), `
SELECT id::text,
       COALESCE(cluster_id::text, ''),
       COALESCE(actor_id::text, ''),
       image,
       COALESCE(namespace, ''),
       decision,
       COALESCE(enforcement_mode, 'none'),
       COALESCE(current_outcome, ''),
       COALESCE(protect_outcome, ''),
       jsonb_array_length(COALESCE(matches, '[]'::jsonb)),
       assessed_at
  FROM admission_dry_run_history
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
 ORDER BY assessed_at DESC, id DESC
 LIMIT $3`, subj.OrgID, clusterArg, limit)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	defer rows.Close()

	out := make([]admissionDryRunHistoryDTO, 0, limit)
	for rows.Next() {
		var item admissionDryRunHistoryDTO
		var assessedAt time.Time
		if err := rows.Scan(
			&item.ID,
			&item.ClusterID,
			&item.ActorID,
			&item.Image,
			&item.Namespace,
			&item.Decision,
			&item.EnforcementMode,
			&item.CurrentOutcome,
			&item.ProtectOutcome,
			&item.Matches,
			&assessedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, err.Error())
			return
		}
		item.AssessedAt = assessedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"history": out, "total": len(out)})
}

// ClearAdmissionDryRunHistory deletes retained dry-run assessments for the
// caller's org and optional cluster. The tamper-evident audit trail records the
// clear action; this table is operator history, not the append-only audit log.
func (p *Policies) ClearAdmissionDryRunHistory(w http.ResponseWriter, r *http.Request) {
	subj, ok := authctx.SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if p.db == nil {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": 0})
		return
	}
	clusterArg, err := sqlx.ParseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	tag, err := p.db.Pool().Exec(r.Context(), `
DELETE FROM admission_dry_run_history
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)`, subj.OrgID, clusterArg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	deleted := tag.RowsAffected()
	p.auditAdmissionDryRunClear(r, subj, clusterIDString(clusterArg), deleted)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

func (p *Policies) recordAdmissionDryRun(r *http.Request, subj authctx.Subject, clusterArg any, req admissionAssessRequest, resp *admissionAssessResponseDTO) error {
	if p.db == nil {
		return nil
	}
	id := uuid.New()
	assessedAt := time.Now().UTC().Truncate(time.Microsecond)
	current, protect := p.admissionDryRunOutcomes(r.Context(), subj.OrgID, clusterArg, resp.Decision)
	resp.DryRunID = id.String()
	resp.AssessedAt = assessedAt.Format(time.RFC3339Nano)
	resp.CurrentOutcome = current
	resp.ProtectOutcome = protect

	requestBody := map[string]any{
		"image":     strings.TrimSpace(req.Image),
		"namespace": resp.Namespace,
	}
	if len(req.Labels) > 0 {
		requestBody["labels"] = req.Labels
	}
	requestJSON, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal admission dry-run request: %w", err)
	}
	responseJSON, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal admission dry-run response: %w", err)
	}
	matchesJSON, err := json.Marshal(resp.Matches)
	if err != nil {
		return fmt.Errorf("marshal admission dry-run matches: %w", err)
	}

	_, err = p.db.Pool().Exec(r.Context(), `
INSERT INTO admission_dry_run_history (
    id, org_id, cluster_id, actor_id, image, namespace, decision,
    enforcement_mode, current_outcome, protect_outcome, matches,
    request, response, assessed_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7,
    $8, $9, $10, $11::jsonb,
    $12::jsonb, $13::jsonb, $14
)`,
		id,
		subj.OrgID,
		clusterArg,
		subj.UserID,
		resp.Image,
		resp.Namespace,
		resp.Decision,
		resp.EnforcementMode,
		resp.CurrentOutcome,
		resp.ProtectOutcome,
		string(matchesJSON),
		string(requestJSON),
		string(responseJSON),
		assessedAt,
	)
	if err != nil {
		return fmt.Errorf("record admission dry-run history: %w", err)
	}
	p.auditAdmissionDryRun(r, subj, id.String(), clusterIDString(clusterArg), *resp)
	return nil
}

func (p *Policies) admissionDryRunOutcomes(ctx context.Context, orgID uuid.UUID, clusterArg any, decision string) (string, string) {
	state := admissionStateDTO{Enabled: false, Mode: "monitor", DefaultAction: "allow", FailurePolicy: "ignore"}
	if clusterID, ok := clusterArg.(uuid.UUID); ok {
		_ = p.db.Pool().QueryRow(ctx, `
SELECT enabled, mode, default_action, failure_policy
  FROM admission_state
 WHERE org_id = $1 AND cluster_id = $2`, orgID, clusterID).
			Scan(&state.Enabled, &state.Mode, &state.DefaultAction, &state.FailurePolicy)
	}
	denyByRule := decision == "deny"
	denyByDefault := !denyByRule && state.DefaultAction == "deny"
	wouldDeny := denyByRule || denyByDefault
	current := "Admit"
	if state.Enabled && state.Mode == "monitor" && wouldDeny {
		current = "Admit + log"
	} else if state.Enabled && wouldDeny {
		current = "Block"
	}
	protect := "Admit"
	if wouldDeny {
		protect = "Block"
	}
	return current, protect
}

func admissionHistoryLimit(raw string) int {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 {
		return defaultLimit
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

func (p *Policies) auditAdmissionDryRun(r *http.Request, subj authctx.Subject, id, clusterID string, resp admissionAssessResponseDTO) {
	if p.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    remoteIP(r),
		Action:     "admission.dry-run.assess",
		TargetKind: "admission-dry-run",
		TargetID:   id,
		After: map[string]any{
			"cluster_id":       clusterID,
			"image":            resp.Image,
			"namespace":        resp.Namespace,
			"decision":         resp.Decision,
			"enforcement_mode": resp.EnforcementMode,
			"current_outcome":  resp.CurrentOutcome,
			"protect_outcome":  resp.ProtectOutcome,
			"matches":          len(resp.Matches),
		},
		RequestID: chimw.GetReqID(r.Context()),
	})
}

func (p *Policies) auditAdmissionDryRunClear(r *http.Request, subj authctx.Subject, clusterID string, deleted int64) {
	if p.auditLog == nil {
		return
	}
	orgID := subj.OrgID
	userID := subj.UserID
	targetID := clusterID
	if targetID == "" {
		targetID = "all"
	}
	_, _, _ = p.auditLog.Log(r.Context(), audit.Event{
		OrgID:      &orgID,
		ActorID:    &userID,
		ActorIP:    remoteIP(r),
		Action:     "admission.dry-run.clear",
		TargetKind: "admission-dry-run-history",
		TargetID:   targetID,
		After:      map[string]any{"cluster_id": clusterID, "deleted": deleted},
		RequestID:  chimw.GetReqID(r.Context()),
	})
}

func clusterIDString(clusterArg any) string {
	if id, ok := clusterArg.(uuid.UUID); ok {
		return id.String()
	}
	return ""
}

func remoteIP(r *http.Request) net.IP {
	actorIP := net.ParseIP(r.RemoteAddr)
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		actorIP = net.ParseIP(host)
	}
	return actorIP
}
