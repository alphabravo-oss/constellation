// Runtime-agent-token auth, retained in package handler as a cross-package seam.
//
// This block was relocated out of events_ingest.go during the ARC-1 runtime
// domain split: the runtime endpoints themselves moved to internal/handler/runtime,
// but the runtime-agent-token primitives are consumed by parent-retained handlers
// (heartbeats.go, cluster_init_bundles.go), by internal/server, and by several
// handler sub-packages (netpolicy, scanning, compliance). Keeping them in package
// handler preserves handler.RuntimeAgentToken / handler.RuntimeAgentTokenFrom /
// handler.RuntimeAgentTokenMiddleware / handler.IssueRuntimeAgentToken /
// handler.ErrNoToken as the stable import surface, while the runtime sub-package
// imports them as handler.* (no cycle: handler must not import handler/runtime).
//
// Runtime-agent-token auth is separate from user JWT auth: tokens are per-org
// service credentials that hold a SINGLE rbac verb (runtime-ingest), so a
// compromised agent cannot read findings, suppress them, etc. The hash is stored
// in runtime_agent_tokens.token_hash; the raw token is shown to the admin once at
// issuance.
package handler

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuntimeAgentToken is the subject for runtime-agent-token-authenticated calls.
type RuntimeAgentToken struct {
	ID    uuid.UUID
	OrgID uuid.UUID
	Name  string
}

type runtimeAgentTokenKey struct{}

func runtimeAgentTokenFrom(ctx context.Context) (*RuntimeAgentToken, bool) {
	t, ok := ctx.Value(runtimeAgentTokenKey{}).(*RuntimeAgentToken)
	return t, ok
}

// RuntimeAgentTokenFrom is the exported seam over runtimeAgentTokenFrom, used
// by handler sub-packages (e.g. handler/netpolicy, handler/runtime) during the
// god-package split. The sub-package imports handler for this, so handler must
// not import the sub-package back.
func RuntimeAgentTokenFrom(ctx context.Context) (*RuntimeAgentToken, bool) {
	return runtimeAgentTokenFrom(ctx)
}

// WithRuntimeAgentToken stores a runtime-agent token on the context. It is the
// exported seam over the unexported context key, used by sub-package tests that
// inject a token without driving the full middleware (mirrors WithSubject).
func WithRuntimeAgentToken(ctx context.Context, tok *RuntimeAgentToken) context.Context {
	return context.WithValue(ctx, runtimeAgentTokenKey{}, tok)
}

// RuntimeAgentTokenMiddleware validates the "Bearer <raw-token>" header against
// runtime_agent_tokens by comparing sha256(raw) to token_hash. Models exactly on
// ScannerTokenMiddleware (see scanjobs.go) — they're peer service-principal token kinds.
func RuntimeAgentTokenMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearer(r)
			if raw == "" {
				jsonError(w, http.StatusUnauthorized, "runtime-agent bearer token required")
				return
			}
			sum := sha256.Sum256([]byte(raw))
			hash := hex.EncodeToString(sum[:])

			var tok RuntimeAgentToken
			err := pool.QueryRow(r.Context(), `
SELECT id, org_id, name
  FROM runtime_agent_tokens
 WHERE token_hash = $1
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > NOW())`,
				hash).Scan(&tok.ID, &tok.OrgID, &tok.Name)
			if err != nil {
				jsonError(w, http.StatusUnauthorized, "invalid runtime-agent token")
				return
			}
			_, _ = pool.Exec(r.Context(),
				`UPDATE runtime_agent_tokens SET last_used_at = NOW() WHERE id = $1`, tok.ID)
			ctx := context.WithValue(r.Context(), runtimeAgentTokenKey{}, &tok)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// IssueRuntimeAgentToken creates a new runtime-agent token. Returns (raw_token, id, error).
func IssueRuntimeAgentToken(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, name string, ttl time.Duration) (string, uuid.UUID, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", uuid.Nil, err
	}
	token := "cra_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	id := uuid.New()
	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO runtime_agent_tokens (id, org_id, name, token_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)`, id, orgID, name, hex.EncodeToString(sum[:]), expires); err != nil {
		return "", uuid.Nil, fmt.Errorf("issue runtime-agent token: %w", err)
	}
	return token, id, nil
}

// Sentinel used by callers that want to distinguish "no row" from "real error" without
// importing pgx.
var ErrNoToken = errors.New("runtime-agent: no matching token")
