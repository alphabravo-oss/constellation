// Host package vulnerability read endpoints.
//
//	GET /api/v1/host-vulnerabilities          — list latest per node/package/vuln
//	GET /api/v1/host-vulnerabilities/{node}   — narrow to one node
//
// Rows are read from unified scanner findings where target_type='host'.
package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
)

type HostVulnerabilitiesHandler struct {
	db *db.DB
}

func NewHostVulnerabilities(d *db.DB) *HostVulnerabilitiesHandler {
	return &HostVulnerabilitiesHandler{db: d}
}

// HostVulnRow is one row in a list response.
type HostVulnRow struct {
	Node           string     `json:"node"`
	ClusterID      *uuid.UUID `json:"cluster_id,omitempty"`
	PackageName    string     `json:"package_name"`
	PackageVersion string     `json:"package_version"`
	VulnID         string     `json:"vuln_id"`
	Aliases        []string   `json:"aliases,omitempty"`
	Severity       string     `json:"severity,omitempty"`
	Summary        string     `json:"summary,omitempty"`
	References     string     `json:"references,omitempty"`
	FixedVersion   string     `json:"fixed_version,omitempty"`
	Source         string     `json:"source"`
	ObservedAt     time.Time  `json:"observed_at"`
}

func (h *HostVulnerabilitiesHandler) List(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	severity := strings.TrimSpace(r.URL.Query().Get("severity"))
	node := strings.TrimSpace(r.URL.Query().Get("node"))
	var clusterID *uuid.UUID
	if raw := strings.TrimSpace(r.URL.Query().Get("cluster_id")); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid cluster_id")
			return
		}
		clusterID = &parsed
	}

	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(NULLIF(f.target_ref, ''), a.name, ''),
       COALESCE(f.target_cluster_id, f.cluster_id),
       COALESCE(f.detail_json->'package'->>'name', ''),
       COALESCE(f.detail_json->'package'->>'version', ''),
       COALESCE(f.external_id, ''),
       COALESCE(f.detail_json->'aliases', '[]'::jsonb),
       COALESCE(f.severity, ''),
       COALESCE(NULLIF(f.description, ''), f.title, ''),
       COALESCE(f.detail_json->'references', '[]'::jsonb),
       COALESCE(f.detail_json->>'fixed', ''),
       COALESCE(NULLIF(f.source_type, ''), NULLIF(f.canonical_engine, ''), 'scanner'),
       f.last_seen_at
  FROM findings f
  LEFT JOIN assets a ON a.id = f.asset_id
 WHERE f.org_id = $1
   AND f.kind = 'vulnerability'
   AND f.lifecycle = 'open'
   AND f.target_type = 'host'
   AND ($2 = '' OR f.severity = $2)
   AND ($3 = '' OR f.target_ref = $3)
   AND ($4::uuid IS NULL OR COALESCE(f.target_cluster_id, f.cluster_id) = $4)
 ORDER BY f.risk_score DESC NULLS LAST, f.last_seen_at DESC
 LIMIT 2000`, subj.OrgID, severity, node, clusterID)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostVulnRow, 0)
	for rows.Next() {
		var rrow HostVulnRow
		var aliasesRaw, refsRaw []byte
		if err := rows.Scan(
			&rrow.Node, &rrow.ClusterID, &rrow.PackageName, &rrow.PackageVersion,
			&rrow.VulnID, &aliasesRaw,
			&rrow.Severity, &rrow.Summary, &refsRaw,
			&rrow.FixedVersion, &rrow.Source, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		rrow.Aliases = decodeStringList(aliasesRaw)
		rrow.References = strings.Join(decodeStringList(refsRaw), ",")
		out = append(out, rrow)
	}
	// Summary counters help the UI render badges without re-querying.
	summary := summarizeVulns(out)
	writeJSON(w, http.StatusOK, map[string]any{
		"items":   out,
		"summary": summary,
	})
}

func (h *HostVulnerabilitiesHandler) Get(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	node := strings.TrimSpace(chi.URLParam(r, "node"))
	if node == "" {
		jsonError(w, http.StatusBadRequest, "node required")
		return
	}
	rows, err := h.db.Pool().Query(r.Context(), `
SELECT COALESCE(NULLIF(f.target_ref, ''), a.name, ''),
       COALESCE(f.target_cluster_id, f.cluster_id),
       COALESCE(f.detail_json->'package'->>'name', ''),
       COALESCE(f.detail_json->'package'->>'version', ''),
       COALESCE(f.external_id, ''),
       COALESCE(f.detail_json->'aliases', '[]'::jsonb),
       COALESCE(f.severity, ''),
       COALESCE(NULLIF(f.description, ''), f.title, ''),
       COALESCE(f.detail_json->'references', '[]'::jsonb),
       COALESCE(f.detail_json->>'fixed', ''),
       COALESCE(NULLIF(f.source_type, ''), NULLIF(f.canonical_engine, ''), 'scanner'),
       f.last_seen_at
  FROM findings f
  LEFT JOIN assets a ON a.id = f.asset_id
 WHERE f.org_id = $1
   AND f.kind = 'vulnerability'
   AND f.lifecycle = 'open'
   AND f.target_type = 'host'
   AND f.target_ref = $2
 ORDER BY f.risk_score DESC NULLS LAST, f.last_seen_at DESC
 LIMIT 2000`, subj.OrgID, node)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "query: "+err.Error())
		return
	}
	defer rows.Close()
	out := make([]HostVulnRow, 0)
	for rows.Next() {
		var rrow HostVulnRow
		var aliasesRaw, refsRaw []byte
		if err := rows.Scan(
			&rrow.Node, &rrow.ClusterID, &rrow.PackageName, &rrow.PackageVersion,
			&rrow.VulnID, &aliasesRaw,
			&rrow.Severity, &rrow.Summary, &refsRaw,
			&rrow.FixedVersion, &rrow.Source, &rrow.ObservedAt,
		); err != nil {
			jsonError(w, http.StatusInternalServerError, "scan: "+err.Error())
			return
		}
		rrow.Aliases = decodeStringList(aliasesRaw)
		rrow.References = strings.Join(decodeStringList(refsRaw), ",")
		out = append(out, rrow)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"node":    node,
		"items":   out,
		"summary": summarizeVulns(out),
	})
}

func decodeStringList(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// summarizeVulns counts rows by severity for badge rendering.
func summarizeVulns(rows []HostVulnRow) map[string]int {
	out := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0,
	}
	for _, r := range rows {
		switch r.Severity {
		case "critical":
			out["critical"]++
		case "high":
			out["high"]++
		case "medium":
			out["medium"]++
		case "low":
			out["low"]++
		default:
			out["unknown"]++
		}
	}
	return out
}
