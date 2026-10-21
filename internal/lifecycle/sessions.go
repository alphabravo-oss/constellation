// Package lifecycle bounds disposable operational records without pruning evidence.
package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionKillLifetime matches the live network-session view's freshness window.
// A delayed command must not terminate an unrelated connection reusing an ID.
const SessionKillLifetime = 5 * time.Minute

type SessionCleanup struct {
	RefreshTokens   int64
	UserSessions    int64
	NetworkSessions int64
	KillRequests    int64
}

// ReapSessions performs at most batch deletes per family, skipping locked rows.
// Expired refresh records are removed before sessions; consumed-but-unexpired
// records remain available to detect reuse and revoke their entire session.
// Session deletion requires a recorded expiry and no remaining refresh rows,
// preventing an unbounded foreign-key cascade or accidental legacy logout.
func ReapSessions(ctx context.Context, pool *pgxpool.Pool, batch int) (SessionCleanup, error) {
	var result SessionCleanup
	if batch < 1 || batch > 5000 {
		return result, fmt.Errorf("session cleanup batch must be between 1 and 5000")
	}
	queries := []struct {
		name, sql string
		count     *int64
	}{
		{"login attempts", `WITH expired AS (SELECT state_hash FROM oidc_login_attempts WHERE expires_at<now() LIMIT $1 FOR UPDATE SKIP LOCKED) DELETE FROM oidc_login_attempts t USING expired e WHERE t.state_hash=e.state_hash`, &result.RefreshTokens},
		{"identity sessions", `WITH expired AS (SELECT token_hash FROM identity_sessions WHERE expires_at<now() ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED) DELETE FROM identity_sessions s USING expired e WHERE s.token_hash=e.token_hash`, &result.UserSessions},
		{"network sessions", `WITH expired AS (
 SELECT org_id, cluster_id, node, id FROM network_sessions
 WHERE updated_at < statement_timestamp() - interval '5 minutes'
 ORDER BY updated_at LIMIT $1 FOR UPDATE SKIP LOCKED
)
DELETE FROM network_sessions s USING expired e
 WHERE (s.org_id,s.cluster_id,s.node,s.id)=(e.org_id,e.cluster_id,e.node,e.id)`, &result.NetworkSessions},
		{"session kill requests", `WITH expired AS (
 SELECT org_id, cluster_id, node, session_id FROM network_session_kills
 WHERE requested_at < statement_timestamp() - interval '5 minutes'
 ORDER BY requested_at LIMIT $1 FOR UPDATE SKIP LOCKED
)
DELETE FROM network_session_kills k USING expired e
 WHERE (k.org_id,k.cluster_id,k.node,k.session_id)=(e.org_id,e.cluster_id,e.node,e.session_id)`, &result.KillRequests},
	}
	for _, query := range queries {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		tag, err := pool.Exec(bounded, query.sql, batch)
		cancel()
		if err != nil {
			return result, fmt.Errorf("reap %s: %w", query.name, err)
		}
		*query.count = tag.RowsAffected()
	}
	return result, nil
}

// RunSessionCleanup is started under the API leader's lifetime. Each pass is
// bounded; a backlog drains over subsequent ticks rather than monopolizing SQL.
func RunSessionCleanup(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, metrics *Metrics) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		started := time.Now()
		result, err := ReapSessions(ctx, pool, 1000)
		metrics.Record(result, time.Since(started), err)
		if err != nil && logger != nil {
			logger.Warn("operational session cleanup failed", "error", err)
		} else if result != (SessionCleanup{}) && logger != nil {
			logger.Info("operational session cleanup", "refresh_tokens", result.RefreshTokens,
				"user_sessions", result.UserSessions, "network_sessions", result.NetworkSessions, "kill_requests", result.KillRequests)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
