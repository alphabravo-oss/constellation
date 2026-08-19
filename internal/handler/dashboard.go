package handler

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

// Dashboard aggregates a one-shot summary the home page renders: severity counts,
// risk-score totals, the most recent activity, and queue depth. All queries scope to
// the calling org and run against the user-facing read replica path.
type Dashboard struct {
	db *db.DB
}

// NewDashboard constructs a Dashboard handler.
func NewDashboard(d *db.DB) *Dashboard { return &Dashboard{db: d} }

type dashboardSummaryDTO struct {
	GeneratedAt     string             `json:"generated_at"`
	FindingsByLevel map[string]int     `json:"findings_by_severity"`
	FindingsTotal   int                `json:"findings_total"`
	OpenFindings    int                `json:"open_findings"`
	AcceptedRisks   int                `json:"accepted_risks"`
	HighestRisk     float64            `json:"highest_risk"`
	AssetsTotal     int                `json:"assets_total"`
	ScanQueueDepth  int                `json:"scan_queue_depth"`
	RecentActivity  []dashboardEventDT `json:"recent_activity"`
}

type dashboardEventDT struct {
	At         string `json:"at"`
	Action     string `json:"action"`
	TargetKind string `json:"target_kind"`
	TargetID   string `json:"target_id"`
	ActorID    string `json:"actor_id,omitempty"`
}

// Summary returns the home-page aggregate. Subject must be present.
func (h *Dashboard) Summary(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}
	clusterArg, err := parseClusterIDParam(r)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.aggregate(r.Context(), subj.OrgID, clusterArg)
	if err != nil {
		slog.ErrorContext(r.Context(), "dashboard summary", slog.String("err", err.Error()))
		jsonError(w, http.StatusInternalServerError, fmt.Sprintf("summary: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Dashboard) aggregate(ctx context.Context, orgID uuid.UUID, clusterArg any) (dashboardSummaryDTO, error) {
	out := dashboardSummaryDTO{
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		FindingsByLevel: map[string]int{},
		RecentActivity:  []dashboardEventDT{},
	}

	// Severity rollup.
	rows, err := h.db.Pool().Query(ctx, `
SELECT severity, COUNT(*)::int FROM findings
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
 GROUP BY severity`, orgID, clusterArg)
	if err != nil {
		return out, fmt.Errorf("severity rollup: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return out, err
		}
		out.FindingsByLevel[sev] = n
		out.FindingsTotal += n
	}

	// Lifecycle + max risk.
	if err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE lifecycle = 'open')::int,
       COUNT(*) FILTER (WHERE lifecycle = 'accepted')::int,
       COALESCE(MAX(risk_score), 0)
  FROM findings
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).
		Scan(&out.OpenFindings, &out.AcceptedRisks, &out.HighestRisk); err != nil {
		return out, fmt.Errorf("lifecycle: %w", err)
	}

	// Assets total.
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*)::int FROM assets
          WHERE org_id = $1
            AND ($2::uuid IS NULL OR cluster_id = $2)`, orgID, clusterArg).Scan(&out.AssetsTotal); err != nil {
		return out, fmt.Errorf("assets: %w", err)
	}

	// Scan queue depth. Note: scan_jobs are org-scoped (no cluster_id column),
	// so this stays unfiltered — the queue depth is a control-plane signal,
	// not a per-cluster posture metric.
	if err := h.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*)::int FROM scan_jobs WHERE org_id = $1 AND status = 'pending'`, orgID).
		Scan(&out.ScanQueueDepth); err != nil {
		return out, fmt.Errorf("queue: %w", err)
	}

	// Recent audit-log activity (most recent 20 for the org), ordered by `at`
	// so the (org_id, at DESC) index serves it in ~1ms.
	//
	// Previously this filtered to the cluster via `target_id IN (SELECT id FROM
	// findings/assets/deployments/compliance_checks WHERE cluster_id=$2)` and
	// ordered by `id DESC`. audit_events has no cluster_id column, so that
	// correlated filter matched only a handful of 1.3M+ rows and forced a full
	// table scan (~23s) on every dashboard load. Showing recent org activity is
	// a fast, acceptable proxy for this widget. To restore precise per-cluster
	// scoping without the scan, denormalize cluster_id onto audit_events at
	// write time and index (org_id, cluster_id, at DESC).
	evRows, err := h.db.Pool().Query(ctx, `
SELECT at, action, target_kind, target_id, COALESCE(actor_id::text, '')
  FROM audit_events
 WHERE org_id = $1
 ORDER BY at DESC LIMIT 20`, orgID)
	if err != nil {
		return out, fmt.Errorf("audit: %w", err)
	}
	defer evRows.Close()
	for evRows.Next() {
		var ev dashboardEventDT
		var at time.Time
		if err := evRows.Scan(&at, &ev.Action, &ev.TargetKind, &ev.TargetID, &ev.ActorID); err != nil {
			return out, err
		}
		ev.At = at.UTC().Format(time.RFC3339)
		out.RecentActivity = append(out.RecentActivity, ev)
	}
	return out, nil
}
