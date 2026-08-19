package handler

// B8 — Score what-if / prediction.
//
// POST /api/v1/security/score/predict recomputes the projected org (or
// cluster) risk score if a given set of findings were resolved. Models
// NeuVector's "predict-score" control: the operator selects findings to fix
// and immediately sees "fix these N → score X→Y" before doing the work.
//
// The score is a saturating weighted composite of open-finding severity
// counts (see computeRiskScore, kept pure + unit-tested). Higher is worse,
// banded like NeuVector's security score:
//
//	Good  0..20   |   Fair 21..50   |   Poor 51..100
//
// This endpoint is read-only — it never mutates finding lifecycle. "Resolving"
// is purely hypothetical projection.

import (
	"encoding/json"
	"math"
	"net/http"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

// ScorePredict serves the what-if score projection.
type ScorePredict struct {
	db *db.DB
}

// NewScorePredict constructs the handler.
func NewScorePredict(database *db.DB) *ScorePredict { return &ScorePredict{db: database} }

// severityCounts holds open-finding counts per severity band.
type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// total returns the sum across bands.
func (c severityCounts) total() int { return c.Critical + c.High + c.Medium + c.Low + c.Info }

// add adjusts the count for a severity band by delta (may be negative).
func (c *severityCounts) add(severity string, delta int) {
	switch severity {
	case "critical":
		c.Critical += delta
	case "high":
		c.High += delta
	case "medium":
		c.Medium += delta
	case "low":
		c.Low += delta
	default:
		c.Info += delta
	}
}

// computeRiskScore maps open-finding severity counts to a 0..100 risk score.
//
// Pure, deterministic, unit-tested. The weighting mirrors NeuVector's
// vulnerability-exploit contribution: criticals dominate, then highs, with
// diminishing returns applied via a saturating exponential so a very large
// backlog asymptotes toward 100 rather than overflowing. Zero findings ⇒ 0.
func computeRiskScore(c severityCounts) int {
	raw := float64(c.Critical)*10.0 +
		float64(c.High)*4.0 +
		float64(c.Medium)*1.5 +
		float64(c.Low)*0.3
	if raw <= 0 {
		return 0
	}
	// 1 - e^(-raw/50) saturates: raw=50 ⇒ ~63, raw=150 ⇒ ~95.
	score := 100.0 * (1.0 - math.Exp(-raw/50.0))
	return int(math.Round(score))
}

// scoreGrade bands a score the way NeuVector labels its security score.
func scoreGrade(score int) string {
	switch {
	case score < 21:
		return "good"
	case score < 51:
		return "fair"
	default:
		return "poor"
	}
}

type scorePredictRequest struct {
	// ResolveFindingIDs marks specific open findings as hypothetically fixed.
	ResolveFindingIDs []string `json:"resolve_finding_ids"`
	// ResolveSeverities, when set, treats every open finding of those
	// severities as fixed (bulk "clear all criticals" what-if).
	ResolveSeverities []string `json:"resolve_severities"`
}

type scoreSnapshot struct {
	Score  int            `json:"score"`
	Grade  string         `json:"grade"`
	Counts severityCounts `json:"counts"`
	Total  int            `json:"total"`
}

// Predict handles POST /api/v1/security/score/predict.
func (h *ScorePredict) Predict(w http.ResponseWriter, r *http.Request) {
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

	var req scorePredictRequest
	if r.Body != nil {
		// Empty body is valid: it yields current == projected (delta 0).
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	// Current open-finding severity counts.
	current, err := h.openCounts(r, subj.OrgID, clusterArg)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Build the projection by removing the resolved findings.
	projected := current
	resolved := 0

	// Bulk severity resolution: clear the entire band.
	sevSet := map[string]bool{}
	for _, s := range req.ResolveSeverities {
		sevSet[s] = true
	}
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if !sevSet[s] {
			continue
		}
		var n int
		switch s {
		case "critical":
			n = projected.Critical
		case "high":
			n = projected.High
		case "medium":
			n = projected.Medium
		case "low":
			n = projected.Low
		default:
			n = projected.Info
		}
		projected.add(s, -n)
		resolved += n
	}

	// Per-id resolution: look up the severity of each still-open finding and
	// decrement its band. Ignores ids already covered by a bulk-severity
	// resolution or that aren't currently open (they can't lower the score).
	if len(req.ResolveFindingIDs) > 0 {
		ids := make([]uuid.UUID, 0, len(req.ResolveFindingIDs))
		for _, s := range req.ResolveFindingIDs {
			if id, perr := uuid.Parse(s); perr == nil {
				ids = append(ids, id)
			}
		}
		if len(ids) > 0 {
			bySev, lerr := h.severitiesForIDs(r, subj.OrgID, clusterArg, ids, sevSet)
			if lerr != nil {
				jsonError(w, http.StatusInternalServerError, lerr.Error())
				return
			}
			for sev, n := range bySev {
				projected.add(sev, -n)
				resolved += n
			}
		}
	}

	// Guard against underflow from double-counting.
	clampCounts(&projected)

	curScore := computeRiskScore(current)
	projScore := computeRiskScore(projected)

	writeJSON(w, http.StatusOK, map[string]any{
		"current": scoreSnapshot{
			Score: curScore, Grade: scoreGrade(curScore), Counts: current, Total: current.total(),
		},
		"projected": scoreSnapshot{
			Score: projScore, Grade: scoreGrade(projScore), Counts: projected, Total: projected.total(),
		},
		"delta":    curScore - projScore,
		"resolved": resolved,
	})
}

// openCounts returns per-severity counts of open/in-progress findings.
func (h *ScorePredict) openCounts(r *http.Request, orgID uuid.UUID, clusterArg any) (severityCounts, error) {
	var c severityCounts
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT lower(severity), COUNT(*)::int
  FROM findings
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND lifecycle IN ('open','in_progress')
 GROUP BY lower(severity)`, orgID, clusterArg)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return c, err
		}
		c.add(sev, n)
	}
	return c, rows.Err()
}

// severitiesForIDs returns, per severity band, how many of the given ids are
// currently-open findings. Ids whose severity is already being bulk-resolved
// are skipped to avoid double counting.
func (h *ScorePredict) severitiesForIDs(r *http.Request, orgID uuid.UUID, clusterArg any, ids []uuid.UUID, skipSev map[string]bool) (map[string]int, error) {
	out := map[string]int{}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT lower(severity)
  FROM findings
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id = $2)
   AND lifecycle IN ('open','in_progress')
   AND id = ANY($3::uuid[])`, orgID, clusterArg, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		if err := rows.Scan(&sev); err != nil {
			return nil, err
		}
		if skipSev[sev] {
			continue
		}
		out[sev]++
	}
	return out, rows.Err()
}

// clampCounts floors every band at zero.
func clampCounts(c *severityCounts) {
	if c.Critical < 0 {
		c.Critical = 0
	}
	if c.High < 0 {
		c.High = 0
	}
	if c.Medium < 0 {
		c.Medium = 0
	}
	if c.Low < 0 {
		c.Low = 0
	}
	if c.Info < 0 {
		c.Info = 0
	}
}
