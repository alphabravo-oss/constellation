// Heartbeats ingest. Each Constellation component POSTs a small payload to
// /api/v1/heartbeats every 30s. The handler upserts into component_heartbeats
// on (org_id, cluster_id, component, hostname) and uses a backward-jumping
// uptime as the "restart detected" signal.
//
// Auth: the route is mounted behind ScannerTokenMiddleware OR
// RuntimeAgentTokenMiddleware (whichever the caller's existing service-token
// kind is). The body's `component` is honored as the logical identity, so a
// single scanner-token can also be reused by an audit-archiver or operator
// sharing the same org if needed for dev-mode bundling.
package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

// Heartbeats is the HTTP handler bundle for /api/v1/heartbeats. It also owns
// the small crashloop-detector that fans audit + notifier events out when the
// restart-rate-per-component crosses the >3/hour threshold.
type Heartbeats struct {
	db       *db.DB
	auditLog *audit.Logger
}

// NewHeartbeats constructs a Heartbeats handler. auditLog may be nil in tests.
func NewHeartbeats(d *db.DB, auditLog *audit.Logger) *Heartbeats {
	return &Heartbeats{db: d, auditLog: auditLog}
}

// known components — accepted set; anything outside is rejected with 400 so
// rogue payloads can't pollute the table with arbitrary strings.
var knownComponents = knownComponentSet()

type heartbeatBody struct {
	Component     string          `json:"component"`
	ClusterID     string          `json:"cluster_id,omitempty"`
	ClusterName   string          `json:"cluster_name,omitempty"`
	Version       string          `json:"version"`
	Commit        string          `json:"commit"`
	BuildTime     string          `json:"build_time,omitempty"`
	Hostname      string          `json:"hostname"`
	UptimeSeconds int64           `json:"uptime_seconds"`
	LastError     string          `json:"last_error,omitempty"`
	RestartCount  int             `json:"restart_count,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

// Ingest handles POST /api/v1/heartbeats. Caller must already be auth'd via
// scanner-token or runtime-agent-token middleware (we read org_id from the
// token subject in the request context).
func (h *Heartbeats) Ingest(w http.ResponseWriter, r *http.Request) {
	orgID, ok := orgFromTokenContext(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "missing service-token subject")
		return
	}

	var body heartbeatBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&body); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid heartbeat body: "+err.Error())
		return
	}
	body.Component = strings.TrimSpace(body.Component)
	body.ClusterName = strings.TrimSpace(body.ClusterName)
	if _, ok := knownComponents[body.Component]; !ok {
		jsonError(w, http.StatusBadRequest, "unknown component: "+body.Component)
		return
	}
	if body.Hostname == "" {
		// Hostname is the disambiguator inside the UNIQUE constraint; force
		// a value so multi-replica deployments don't collide.
		body.Hostname = "unknown-" + body.Component
	}
	body.Metadata = normalizeHeartbeatMetadata(body.Metadata)

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var clusterID *uuid.UUID
	if body.ClusterID != "" {
		id, err := uuid.Parse(body.ClusterID)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "invalid cluster_id")
			return
		}
		clusterID = &id
	} else if body.ClusterName != "" {
		var id uuid.UUID
		err := h.db.Pool().QueryRow(ctx, `
SELECT id
  FROM clusters
 WHERE org_id = $1 AND name = $2
 ORDER BY updated_at DESC
 LIMIT 1`, orgID, body.ClusterName).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			jsonError(w, http.StatusBadRequest, "unknown cluster_name: "+body.ClusterName)
			return
		}
		if err != nil {
			jsonError(w, http.StatusInternalServerError, "resolve cluster_name: "+err.Error())
			return
		}
		clusterID = &id
	}

	var buildTime *time.Time
	if body.BuildTime != "" {
		if t, err := time.Parse(time.RFC3339, body.BuildTime); err == nil {
			tt := t.UTC()
			buildTime = &tt
		}
	}

	// We need to know the prior uptime to infer a restart. UPSERT in one
	// round-trip via RETURNING old/new.
	prevUptime, restartCount, err := h.upsertAndDetectRestart(ctx, orgID, clusterID, body, buildTime)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "heartbeat persist: "+err.Error())
		return
	}

	// Restart inference: new uptime smaller than what we stored before ⇒ a
	// new process. (We treat 0→0 as "first row, no restart".)
	if prevUptime > 0 && body.UptimeSeconds < prevUptime {
		if err := h.recordRestart(ctx, orgID, clusterID, body, prevUptime); err != nil {
			slog.Default().Warn("heartbeat.restart.persist",
				slog.String("err", err.Error()),
				slog.String("component", body.Component),
				slog.String("hostname", body.Hostname))
		}
		// Crashloop threshold: >3 restarts of (component, hostname) inside 1 hour.
		if h.crashloopFor(ctx, orgID, body.Component, body.Hostname) {
			h.emitCrashloopAudit(ctx, orgID, clusterID, body, restartCount)
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":           "ok",
		"prev_uptime_s":    prevUptime,
		"restart_count":    restartCount,
		"detected_restart": prevUptime > 0 && body.UptimeSeconds < prevUptime,
	})
}

// upsertAndDetectRestart performs the UPSERT and returns (prev_uptime, new restart_count).
func (h *Heartbeats) upsertAndDetectRestart(
	ctx context.Context,
	orgID uuid.UUID,
	clusterID *uuid.UUID,
	body heartbeatBody,
	buildTime *time.Time,
) (prevUptime int64, restartCount int, err error) {
	var clusterArg any
	clusterKey := "null"
	if clusterID != nil {
		clusterArg = *clusterID
		clusterKey = clusterID.String()
	} else {
		clusterArg = nil
	}
	var buildArg any
	if buildTime != nil {
		buildArg = *buildTime
	} else {
		buildArg = nil
	}

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	lockKey := orgID.String() + ":" + clusterKey + ":" + body.Component + ":" + body.Hostname
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, lockKey); err != nil {
		return 0, 0, err
	}

	var heartbeatID uuid.UUID
	err = tx.QueryRow(ctx, `
SELECT id, uptime_seconds, restart_count
  FROM component_heartbeats
 WHERE org_id = $1
   AND ((cluster_id = $2) OR (cluster_id IS NULL AND $2::uuid IS NULL))
   AND component = $3
   AND hostname = $4
 ORDER BY last_seen_at DESC, first_seen_at DESC, id DESC
 LIMIT 1
 FOR UPDATE`,
		orgID, clusterArg, body.Component, body.Hostname,
	).Scan(&heartbeatID, &prevUptime, &restartCount)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err = tx.Exec(ctx, `
INSERT INTO component_heartbeats (
    org_id, cluster_id, component, version, commit, build_time,
    hostname, uptime_seconds, restart_count, last_error, metadata, last_seen_at
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, 0, NULLIF($9,''), $10::jsonb, NOW()
)`,
			orgID, clusterArg, body.Component, body.Version, body.Commit, buildArg,
			body.Hostname, body.UptimeSeconds, body.LastError, string(body.Metadata),
		); err != nil {
			return 0, 0, err
		}
		if err = tx.Commit(ctx); err != nil {
			return 0, 0, err
		}
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}

	if body.UptimeSeconds < prevUptime {
		restartCount++
	}
	if _, err = tx.Exec(ctx, `
UPDATE component_heartbeats
   SET version = $2,
       commit = $3,
       build_time = COALESCE($4, build_time),
       uptime_seconds = $5,
       restart_count = $6,
       last_error = NULLIF($7,''),
       metadata = $8::jsonb,
       last_seen_at = NOW()
 WHERE id = $1`,
		heartbeatID, body.Version, body.Commit, buildArg,
		body.UptimeSeconds, restartCount, body.LastError, string(body.Metadata),
	); err != nil {
		return 0, 0, err
	}
	// Garbage-collect this component's dead instances: when an instance beats, drop
	// same-(org, cluster, component) rows from prior pods (different hostname) that
	// haven't reported in >15m. Redeploys otherwise leave a stale row per old pod
	// name, cluttering System Health with phantom "stale" components. Live replicas
	// (all beating within the window) are preserved; a fully-down component keeps its
	// row and correctly surfaces as stale.
	if _, err = tx.Exec(ctx, `
DELETE FROM component_heartbeats
 WHERE org_id = $1
   AND ((cluster_id = $2) OR (cluster_id IS NULL AND $2::uuid IS NULL))
   AND component = $3
   AND id <> $4
   AND last_seen_at < NOW() - INTERVAL '15 minutes'`,
		orgID, clusterArg, body.Component, heartbeatID,
	); err != nil {
		return 0, 0, err
	}
	if err = tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	return prevUptime, restartCount, nil
}

func normalizeHeartbeatMetadata(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 || string(raw) == "null" {
		return json.RawMessage(`{}`)
	}
	if !json.Valid(raw) {
		return json.RawMessage(`{}`)
	}
	return raw
}

// recordRestart appends an immutable row to component_restart_events.
func (h *Heartbeats) recordRestart(
	ctx context.Context,
	orgID uuid.UUID,
	clusterID *uuid.UUID,
	body heartbeatBody,
	prevUptime int64,
) error {
	var clusterArg any
	if clusterID != nil {
		clusterArg = *clusterID
	} else {
		clusterArg = nil
	}
	_, err := h.db.Pool().Exec(ctx, `
INSERT INTO component_restart_events
       (org_id, cluster_id, component, hostname, prev_uptime_s, new_uptime_s, reason)
VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		orgID, clusterArg, body.Component, body.Hostname,
		prevUptime, body.UptimeSeconds, body.LastError)
	return err
}

// crashloopFor returns true when (component, hostname) has > 3 restart rows in
// the last hour FOR THE GIVEN ORG. The org_id predicate is required: rows are written
// with org_id and the same component+hostname (e.g. "constellation-scanner-0" or the
// "unknown-<component>" default) collide across tenants, so without it org A's restarts
// would trip org B's threshold and emit a spurious cross-tenant crashloop alarm.
func (h *Heartbeats) crashloopFor(ctx context.Context, orgID uuid.UUID, component, hostname string) bool {
	var n int
	err := h.db.Pool().QueryRow(ctx, `
SELECT COUNT(*) FROM component_restart_events
 WHERE org_id = $1 AND component = $2 AND hostname = $3
   AND detected_at > NOW() - INTERVAL '1 hour'`,
		orgID, component, hostname).Scan(&n)
	if err != nil {
		return false
	}
	return n > 3
}

// emitCrashloopAudit writes a component.crashloop audit event so it shows up
// in the audit log AND the existing notifier dispatcher fans it out via the
// configured receivers (Wave N3).
func (h *Heartbeats) emitCrashloopAudit(
	ctx context.Context,
	orgID uuid.UUID,
	clusterID *uuid.UUID,
	body heartbeatBody,
	restartCount int,
) {
	if h.auditLog == nil {
		return
	}
	ev := audit.Event{
		OrgID:      &orgID,
		Action:     "component.crashloop",
		TargetKind: "component",
		TargetID:   body.Component + "@" + body.Hostname,
		After: map[string]any{
			"component":      body.Component,
			"hostname":       body.Hostname,
			"restart_count":  restartCount,
			"last_error":     body.LastError,
			"cluster_id":     clusterID,
			"uptime_seconds": body.UptimeSeconds,
			"detected_at":    time.Now().UTC().Format(time.RFC3339),
		},
	}
	if _, _, err := h.auditLog.Log(ctx, ev); err != nil {
		slog.Default().Warn("heartbeat.audit", slog.String("err", err.Error()))
	}
}

// AnyServiceTokenMiddleware accepts EITHER a scanner-token (cst_*) or a
// runtime-agent-token (cra_*) bearer. New tokens use prefixes to select the
// table directly; legacy bootstrap tokens were prefixless, so we fall back to
// checking scanner_tokens and then runtime_agent_tokens for those installs.
func AnyServiceTokenMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearer(r)
			if raw == "" {
				jsonError(w, http.StatusUnauthorized, "service token required")
				return
			}
			sum := sha256.Sum256([]byte(raw))
			hash := hex.EncodeToString(sum[:])
			ctx := r.Context()

			if strings.HasPrefix(raw, "cra_") {
				tok, err := lookupRuntimeAgentToken(ctx, pool, hash)
				if err != nil {
					jsonError(w, http.StatusUnauthorized, "invalid runtime-agent token")
					return
				}
				_, _ = pool.Exec(ctx, `UPDATE runtime_agent_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
				ctx = context.WithValue(ctx, runtimeAgentTokenKey{}, tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if strings.HasPrefix(raw, "cst_") {
				tok, err := lookupScannerToken(ctx, pool, hash)
				if err != nil {
					jsonError(w, http.StatusUnauthorized, "invalid scanner token")
					return
				}
				_, _ = pool.Exec(ctx, `UPDATE scanner_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
				ctx = context.WithValue(ctx, scannerTokenKey{}, tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if tok, err := lookupScannerToken(ctx, pool, hash); err == nil {
				_, _ = pool.Exec(ctx, `UPDATE scanner_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
				ctx = context.WithValue(ctx, scannerTokenKey{}, tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else if !errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, http.StatusUnauthorized, "invalid scanner token")
				return
			}

			if tok, err := lookupRuntimeAgentToken(ctx, pool, hash); err == nil {
				_, _ = pool.Exec(ctx, `UPDATE runtime_agent_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
				ctx = context.WithValue(ctx, runtimeAgentTokenKey{}, tok)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else if !errors.Is(err, pgx.ErrNoRows) {
				jsonError(w, http.StatusUnauthorized, "invalid runtime-agent token")
				return
			}

			jsonError(w, http.StatusUnauthorized, "invalid service token")
		})
	}
}

func lookupScannerToken(ctx context.Context, pool *pgxpool.Pool, hash string) (*ScannerToken, error) {
	var tok ScannerToken
	err := pool.QueryRow(ctx, `
SELECT id, org_id, name
  FROM scanner_tokens
 WHERE token_hash = $1 AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())`, hash).
		Scan(&tok.ID, &tok.OrgID, &tok.Name)
	if err != nil {
		return nil, err
	}
	return &tok, nil
}

func lookupRuntimeAgentToken(ctx context.Context, pool *pgxpool.Pool, hash string) (*RuntimeAgentToken, error) {
	var tok RuntimeAgentToken
	err := pool.QueryRow(ctx, `
SELECT id, org_id, name
  FROM runtime_agent_tokens
 WHERE token_hash = $1 AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())`, hash).
		Scan(&tok.ID, &tok.OrgID, &tok.Name)
	if err != nil {
		return nil, err
	}
	return &tok, nil
}

// orgFromTokenContext extracts the org_id from a scanner-token or runtime-agent-token
// context. Returns false when neither subject is present (i.e. the route wasn't
// mounted behind the token middleware).
func orgFromTokenContext(ctx context.Context) (uuid.UUID, bool) {
	if t, ok := scannerTokenFrom(ctx); ok && t != nil {
		return t.OrgID, true
	}
	if t, ok := runtimeAgentTokenFrom(ctx); ok && t != nil {
		return t.OrgID, true
	}
	if subj, ok := SubjectFrom(ctx); ok {
		// Allow regular user-JWT subjects through too (admin tests, curl with
		// PAT). The component must still match knownComponents.
		return subj.OrgID, true
	}
	return uuid.Nil, false
}

// -----------------------------------------------------------------------------
// Helpers for system_health.go to read recent heartbeats.
// -----------------------------------------------------------------------------

// HeartbeatRow is the read-side row shape consumed by system_health.go.
type HeartbeatRow struct {
	ID            uuid.UUID  `json:"id"`
	OrgID         uuid.UUID  `json:"org_id"`
	ClusterID     *uuid.UUID `json:"cluster_id,omitempty"`
	Component     string     `json:"component"`
	Version       string     `json:"version"`
	Commit        string     `json:"commit"`
	BuildTime     *time.Time `json:"build_time,omitempty"`
	Hostname      string     `json:"hostname"`
	UptimeSeconds int64      `json:"uptime_seconds"`
	RestartCount  int        `json:"restart_count"`
	LastError     string     `json:"last_error,omitempty"`
	Metadata      map[string]any
	LastSeenAt    time.Time `json:"last_seen_at"`
	FirstSeenAt   time.Time `json:"first_seen_at"`
}

// LoadHeartbeats returns all heartbeats for the org, ordered by component
// then hostname, with stale rows (>24h) excluded so an old retired pod
// doesn't pollute the table.
func LoadHeartbeats(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) ([]HeartbeatRow, error) {
	rows, err := pool.Query(ctx, `
SELECT org_id, cluster_id, component, COALESCE(version,''), COALESCE(commit,''), build_time,
       hostname, uptime_seconds, restart_count, COALESCE(last_error,''), COALESCE(metadata, '{}'::jsonb), last_seen_at, first_seen_at, id
  FROM component_heartbeats
 WHERE org_id = $1
   AND last_seen_at > NOW() - INTERVAL '24 hours'
 ORDER BY component, hostname`,
		orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]HeartbeatRow, 0, 16)
	for rows.Next() {
		var r HeartbeatRow
		var rawMetadata []byte
		if err := rows.Scan(&r.OrgID, &r.ClusterID, &r.Component, &r.Version, &r.Commit, &r.BuildTime,
			&r.Hostname, &r.UptimeSeconds, &r.RestartCount, &r.LastError, &rawMetadata, &r.LastSeenAt, &r.FirstSeenAt, &r.ID); err != nil {
			return nil, err
		}
		if len(rawMetadata) > 0 {
			_ = json.Unmarshal(rawMetadata, &r.Metadata)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RestartEvent is one row from component_restart_events.
type RestartEvent struct {
	ID         int64      `json:"id"`
	OrgID      uuid.UUID  `json:"org_id"`
	ClusterID  *uuid.UUID `json:"cluster_id,omitempty"`
	Component  string     `json:"component"`
	Hostname   string     `json:"hostname"`
	PrevUptime int64      `json:"prev_uptime_s"`
	NewUptime  int64      `json:"new_uptime_s"`
	DetectedAt time.Time  `json:"detected_at"`
	Reason     string     `json:"reason,omitempty"`
}

// LoadRestartEvents returns the most recent N restart events for an org.
func LoadRestartEvents(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, limit int) ([]RestartEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	rows, err := pool.Query(ctx, `
SELECT id, org_id, cluster_id, component, hostname, prev_uptime_s, new_uptime_s, detected_at, COALESCE(reason,'')
  FROM component_restart_events
 WHERE org_id = $1
 ORDER BY detected_at DESC
 LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]RestartEvent, 0, limit)
	for rows.Next() {
		var ev RestartEvent
		if err := rows.Scan(&ev.ID, &ev.OrgID, &ev.ClusterID, &ev.Component, &ev.Hostname,
			&ev.PrevUptime, &ev.NewUptime, &ev.DetectedAt, &ev.Reason); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// LoadLicense returns the license JSON document for the org, defaulting to
// {"kind":"community"} when no row is present. The function is intentionally
// permissive — a malformed license blob shouldn't 500 the system health page.
func LoadLicense(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (map[string]any, error) {
	var raw []byte
	err := pool.QueryRow(ctx,
		`SELECT (settings->'license')::text FROM org_settings WHERE org_id = $1`, orgID).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) || len(raw) == 0 || string(raw) == "null" {
		return map[string]any{
			"kind":       "community",
			"issued_at":  nil,
			"expires_at": nil,
			"signed_by":  "self",
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load license: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return map[string]any{"kind": "community", "parse_error": err.Error()}, nil
	}
	return out, nil
}
