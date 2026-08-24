package handler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/syscfg"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/version"
)

const (
	supportBundleSchemaVersion = "constellation.support_bundle.v1"
	supportBundleRedacted      = "***REDACTED***"
)

// SupportBundle generates a downloadable, redacted operations bundle for support
// handoff. It is intentionally synchronous for now: the payload is a bounded JSON
// manifest assembled from existing read models, without raw logs or credentials.
type SupportBundle struct {
	db    *db.DB
	audit *audit.Logger
}

func NewSupportBundle(d *db.DB, a *audit.Logger) *SupportBundle {
	return &SupportBundle{db: d, audit: a}
}

type supportBundleDTO struct {
	SchemaVersion string                    `json:"schema_version"`
	BundleID      string                    `json:"bundle_id"`
	GeneratedAt   time.Time                 `json:"generated_at"`
	OrgID         string                    `json:"org_id"`
	Format        string                    `json:"format"`
	Redaction     supportBundleRedactionDTO `json:"redaction"`
	Integrity     supportBundleIntegrityDTO `json:"integrity"`
	Sections      map[string]any            `json:"sections"`
}

type supportBundleRedactionDTO struct {
	Applied bool     `json:"applied"`
	Marker  string   `json:"marker"`
	Rules   []string `json:"rules"`
}

type supportBundleIntegrityDTO struct {
	Algorithm string `json:"algorithm"`
	Scope     string `json:"scope"`
	SHA256    string `json:"sha256"`
	Signed    bool   `json:"signed"`
	Note      string `json:"note"`
}

type supportBundleStatusCount struct {
	Status            string `json:"status"`
	Count             int    `json:"count"`
	OldestRequestedAt string `json:"oldest_requested_at,omitempty"`
}

type supportBundlePolicyCount struct {
	Category string `json:"category,omitempty"`
	Mode     string `json:"mode,omitempty"`
	Enabled  bool   `json:"enabled,omitempty"`
	Count    int    `json:"count"`
}

type supportBundleAuditEvent struct {
	ID         int64     `json:"id"`
	Action     string    `json:"action"`
	TargetKind string    `json:"target_kind,omitempty"`
	TargetID   string    `json:"target_id,omitempty"`
	At         time.Time `json:"at"`
}

// Download returns a redacted JSON support bundle and writes an audit row for
// accountability. Router RBAC gates this endpoint to GlobalAdmin-level verbs.
func (h *SupportBundle) Download(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "subject required")
		return
	}
	if h.db == nil {
		jsonError(w, http.StatusServiceUnavailable, "support bundle: db not wired")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	bundle, err := h.build(ctx, subj)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.audit != nil {
		oid, uid := subj.OrgID, subj.UserID
		_, _, _ = h.audit.Log(ctx, audit.Event{
			OrgID:      &oid,
			ActorID:    &uid,
			ActorIP:    actorIPFromRequest(r),
			Action:     "support.bundle.download",
			TargetKind: "support_bundle",
			TargetID:   bundle.BundleID,
			After: map[string]any{
				"schema_version": bundle.SchemaVersion,
				"sha256":         bundle.Integrity.SHA256,
				"sections":       sortedMapKeys(bundle.Sections),
			},
			RequestID: chimw.GetReqID(r.Context()),
		})
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, supportBundleFilename(bundle.GeneratedAt)))
	writeJSON(w, http.StatusOK, bundle)
}

func (h *SupportBundle) build(ctx context.Context, subj Subject) (supportBundleDTO, error) {
	generatedAt := time.Now().UTC()
	sections := map[string]any{
		"environment": h.collectEnvironment(),
	}

	warnings := []string{}
	addSection := func(name string, collect func() (any, error)) {
		value, err := collect()
		if err != nil {
			warnings = append(warnings, name+": "+err.Error())
			sections[name] = map[string]any{"error": err.Error()}
			return
		}
		sections[name] = value
	}

	addSection("system_config", func() (any, error) { return h.collectSystemConfig(ctx, subj.OrgID) })
	addSection("system_health", func() (any, error) { return h.collectSystemHealth(ctx) })
	addSection("component_inventory", func() (any, error) { return h.collectComponentInventory(ctx, subj.OrgID) })
	addSection("scanner_state", func() (any, error) { return h.collectScannerState(ctx, subj.OrgID) })
	addSection("policy_summaries", func() (any, error) { return h.collectPolicySummaries(ctx, subj.OrgID) })
	addSection("recent_audit", func() (any, error) { return h.collectRecentAudit(ctx, subj.OrgID) })
	if len(warnings) > 0 {
		sections["collection_warnings"] = warnings
	}

	redactedSections, err := redactSupportBundleSections(sections)
	if err != nil {
		return supportBundleDTO{}, err
	}
	sum, err := supportBundleHash(redactedSections)
	if err != nil {
		return supportBundleDTO{}, err
	}
	return supportBundleDTO{
		SchemaVersion: supportBundleSchemaVersion,
		BundleID:      uuid.NewString(),
		GeneratedAt:   generatedAt,
		OrgID:         subj.OrgID.String(),
		Format:        "json",
		Redaction: supportBundleRedactionDTO{
			Applied: true,
			Marker:  supportBundleRedacted,
			Rules: []string{
				"sensitive keys: password, secret, token, credential, api_key, private_key, client_key, authorization",
				"sensitive strings: bearer tokens, private keys, credentialed URLs, and values containing password/secret/token markers",
				"component metadata is reduced to public diagnostics fields before global redaction",
			},
		},
		Integrity: supportBundleIntegrityDTO{
			Algorithm: "sha256",
			Scope:     "sections",
			SHA256:    sum,
			Signed:    false,
			Note:      "Integrity hash covers the redacted sections payload; no deployment signing key is configured for support bundles yet.",
		},
		Sections: redactedSections,
	}, nil
}

func (h *SupportBundle) collectEnvironment() map[string]any {
	return map[string]any{
		"api": map[string]any{
			"component":    "api",
			"version":      version.Version,
			"commit":       version.Commit,
			"commit_short": version.ShortCommit(),
			"build_time":   version.BuildTimeParsed().Format(time.RFC3339),
			"uptime_s":     int64(version.Uptime().Seconds()),
		},
		"runtime": map[string]any{
			"go_version": runtime.Version(),
			"go_os":      runtime.GOOS,
			"go_arch":    runtime.GOARCH,
		},
	}
}

func (h *SupportBundle) collectSystemConfig(ctx context.Context, orgID uuid.UUID) (any, error) {
	cfg, rev, err := syscfg.Load(ctx, h.db.Pool(), orgID)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"revision": rev,
		"config":   cfg.Redacted(),
	}, nil
}

func (h *SupportBundle) collectSystemHealth(ctx context.Context) (any, error) {
	overview := systemHealthOverview()
	overview.ControlPlane = map[string]string{
		"component":    "api",
		"version":      version.Version,
		"commit":       version.Commit,
		"commit_short": version.ShortCommit(),
		"build_time":   version.BuildTimeParsed().Format(time.RFC3339),
		"uptime_s":     fmt.Sprintf("%d", int64(version.Uptime().Seconds())),
	}
	health := NewSystemHealth(h.db)
	health.overlayProbes(ctx, &overview)
	health.overlayHeartbeats(ctx, &overview)
	return overview, nil
}

func (h *SupportBundle) collectComponentInventory(ctx context.Context, orgID uuid.UUID) (any, error) {
	hbs, err := LoadHeartbeats(ctx, h.db.Pool(), orgID)
	if err != nil {
		return nil, err
	}
	clusterNames := loadClusterNames(ctx, h.db, hbs)
	scored := scoreHeartbeats(hbs, clusterNames, loadRecentRestarts(ctx, h.db.Pool(), orgID))
	instances := make([]componentInstanceDTO, 0, len(hbs))
	for i, hb := range hbs {
		instances = append(instances, componentInstanceFromHeartbeat(hb, scored[i]))
	}
	sort.Slice(instances, func(i, j int) bool {
		if instances[i].Component != instances[j].Component {
			return instances[i].Component < instances[j].Component
		}
		if instances[i].ClusterName != instances[j].ClusterName {
			return instances[i].ClusterName < instances[j].ClusterName
		}
		return instances[i].Hostname < instances[j].Hostname
	})
	rollups := componentInventoryRollups(instances, false, "")
	return map[string]any{
		"summary":    componentInventorySummary(rollups),
		"rollups":    rollups,
		"components": instances,
	}, nil
}

func (h *SupportBundle) collectScannerState(ctx context.Context, orgID uuid.UUID) (any, error) {
	out := map[string]any{}
	rows, err := h.db.Pool().Query(ctx, `
SELECT status, COUNT(*)::int, MIN(requested_at)
  FROM scan_jobs
 WHERE org_id = $1
 GROUP BY status
 ORDER BY status`, orgID)
	if err != nil {
		out["scan_jobs_error"] = err.Error()
	} else {
		defer rows.Close()
		counts := []supportBundleStatusCount{}
		for rows.Next() {
			var row supportBundleStatusCount
			var oldest sql.NullTime
			if err := rows.Scan(&row.Status, &row.Count, &oldest); err != nil {
				return nil, err
			}
			if oldest.Valid {
				row.OldestRequestedAt = oldest.Time.UTC().Format(time.RFC3339)
			}
			counts = append(counts, row)
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
		out["scan_jobs_by_status"] = counts
	}

	var ready, active, idle, degraded int
	err = h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes')::int,
       COALESCE(SUM((metadata->>'active_jobs')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COALESCE(SUM((metadata->>'idle_capacity')::int) FILTER (WHERE last_seen_at > NOW() - INTERVAL '2 minutes'), 0)::int,
       COUNT(*) FILTER (
         WHERE last_seen_at > NOW() - INTERVAL '2 minutes'
           AND COALESCE((metadata->'vulndb'->>'enabled')::boolean, false)
           AND NOT COALESCE((metadata->'vulndb'->>'ready')::boolean, false)
       )::int
  FROM component_heartbeats
 WHERE org_id = $1
   AND component = 'scanner'`, orgID).Scan(&ready, &active, &idle, &degraded)
	if err != nil {
		out["scanner_heartbeats_error"] = err.Error()
	} else {
		out["scanner_capacity"] = map[string]any{
			"ready_scanners":    ready,
			"active_jobs":       active,
			"idle_capacity":     idle,
			"degraded_scanners": degraded,
		}
	}
	return out, nil
}

func (h *SupportBundle) collectPolicySummaries(ctx context.Context, orgID uuid.UUID) (any, error) {
	out := map[string]any{}
	if rows, err := h.policyCounts(ctx, `
SELECT category, mode, enabled, COUNT(*)::int
  FROM policies
 WHERE org_id = $1
 GROUP BY category, mode, enabled
 ORDER BY category, mode, enabled`, orgID); err != nil {
		out["policies_error"] = err.Error()
	} else {
		out["policies"] = rows
	}
	if rows, err := h.modeCounts(ctx, `
SELECT mode, COUNT(*)::int
  FROM runtime_policies
 WHERE org_id = $1
 GROUP BY mode
 ORDER BY mode`, orgID); err != nil {
		out["runtime_policies_error"] = err.Error()
	} else {
		out["runtime_policies"] = rows
	}
	if rows, err := h.responseRuleCounts(ctx, orgID); err != nil {
		out["response_rules_error"] = err.Error()
	} else {
		out["response_rules"] = rows
	}
	if rows, err := h.admissionStateCounts(ctx, orgID); err != nil {
		out["admission_state_error"] = err.Error()
	} else {
		out["admission_state"] = rows
	}
	return out, nil
}

func (h *SupportBundle) policyCounts(ctx context.Context, query string, orgID uuid.UUID) ([]supportBundlePolicyCount, error) {
	rows, err := h.db.Pool().Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []supportBundlePolicyCount{}
	for rows.Next() {
		var row supportBundlePolicyCount
		if err := rows.Scan(&row.Category, &row.Mode, &row.Enabled, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *SupportBundle) modeCounts(ctx context.Context, query string, orgID uuid.UUID) ([]supportBundlePolicyCount, error) {
	rows, err := h.db.Pool().Query(ctx, query, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []supportBundlePolicyCount{}
	for rows.Next() {
		var row supportBundlePolicyCount
		if err := rows.Scan(&row.Mode, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *SupportBundle) responseRuleCounts(ctx context.Context, orgID uuid.UUID) ([]supportBundlePolicyCount, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT event_type, enabled, COUNT(*)::int
  FROM response_rules
 WHERE org_id = $1
 GROUP BY event_type, enabled
 ORDER BY event_type, enabled`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []supportBundlePolicyCount{}
	for rows.Next() {
		var row supportBundlePolicyCount
		if err := rows.Scan(&row.Category, &row.Enabled, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *SupportBundle) admissionStateCounts(ctx context.Context, orgID uuid.UUID) ([]supportBundlePolicyCount, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT mode, enabled, COUNT(*)::int
  FROM admission_state
 WHERE org_id = $1
 GROUP BY mode, enabled
 ORDER BY mode, enabled`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []supportBundlePolicyCount{}
	for rows.Next() {
		var row supportBundlePolicyCount
		row.Category = "admission"
		if err := rows.Scan(&row.Mode, &row.Enabled, &row.Count); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

func (h *SupportBundle) collectRecentAudit(ctx context.Context, orgID uuid.UUID) (any, error) {
	rows, err := h.db.Pool().Query(ctx, `
SELECT id, action, COALESCE(target_kind, ''), COALESCE(target_id, ''), at
  FROM audit_events
 WHERE org_id = $1
 ORDER BY id DESC
 LIMIT 50`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []supportBundleAuditEvent{}
	for rows.Next() {
		var ev supportBundleAuditEvent
		if err := rows.Scan(&ev.ID, &ev.Action, &ev.TargetKind, &ev.TargetID, &ev.At); err != nil {
			return nil, err
		}
		ev.At = ev.At.UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}

func supportBundleHash(sections map[string]any) (string, error) {
	b, err := json.Marshal(sections)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func supportBundleFilename(at time.Time) string {
	return "constellation-support-bundle-" + at.UTC().Format("20060102T150405Z") + ".json"
}

func redactSupportBundleSections(sections map[string]any) (map[string]any, error) {
	b, err := json.Marshal(sections)
	if err != nil {
		return nil, err
	}
	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		return nil, err
	}
	redacted, _ := redactSupportBundleValue(decoded, "").(map[string]any)
	return redacted, nil
}

func redactSupportBundleValue(raw any, key string) any {
	if supportBundleSensitiveKey(key) {
		return supportBundleRedacted
	}
	switch value := raw.(type) {
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, v := range value {
			out[k] = redactSupportBundleValue(v, k)
		}
		return out
	case []any:
		out := make([]any, 0, len(value))
		for _, v := range value {
			out = append(out, redactSupportBundleValue(v, key))
		}
		return out
	case string:
		if redacted, ok := redactSupportBundleString(value); ok {
			return redacted
		}
		return value
	default:
		return raw
	}
}

func supportBundleSensitiveKey(key string) bool {
	norm := strings.ToLower(strings.NewReplacer("_", "", "-", "", ".", "").Replace(strings.TrimSpace(key)))
	if norm == "" {
		return false
	}
	for _, marker := range []string{
		"password", "passwd", "secret", "token", "credential", "authorization",
		"apikey", "accesskey", "privatekey", "clientkey", "bindpassword",
		"authsecret", "spkeypem", "keypem", "signingkey", "jwtkey",
	} {
		if strings.Contains(norm, marker) {
			return true
		}
	}
	return false
}

func redactSupportBundleString(value string) (string, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return value, false
	}
	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "-----begin ") && strings.Contains(lower, "private key-----") {
		return supportBundleRedacted, true
	}
	if strings.HasPrefix(lower, "bearer ") || strings.HasPrefix(lower, "basic ") {
		return supportBundleRedacted, true
	}
	for _, marker := range []string{"password", "passwd", "secret", "token"} {
		if strings.Contains(lower, marker) {
			return supportBundleRedacted, true
		}
	}
	if redacted, ok := redactSupportBundleURL(trimmed); ok {
		return redacted, true
	}
	return value, false
}

func redactSupportBundleURL(value string) (string, bool) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return value, false
	}
	changed := false
	if u.User != nil {
		u.User = url.User(supportBundleRedacted)
		changed = true
	}
	q := u.Query()
	for key := range q {
		if supportBundleSensitiveKey(key) {
			q.Set(key, supportBundleRedacted)
			changed = true
		}
	}
	if changed {
		u.RawQuery = q.Encode()
		return u.String(), true
	}
	return value, false
}
