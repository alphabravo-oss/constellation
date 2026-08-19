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
	"os"
	"strings"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/abbot"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// AI implements POST /api/v1/ai/query. The handler:
//   - blocks with 503 + degrade hint when org.ai_enabled = false
//   - blocks with 503 + degrade hint when ABBOT_SERVICE_URL is unset (off-by-default)
//   - otherwise runs a RAG step against pgvector findings/assets, dispatches the
//     prompt to the Abbot service via pkg/abbot, and writes audit envelopes for every
//     tool invocation surfaced in the response.
//
// All tool catalog handlers re-check RBAC verbs at invocation; the registry is built
// per-request so the calling subject's role assignments scope what is reachable.
type AI struct {
	db       *db.DB
	auditLog *audit.Logger
	client   *abbot.Client
}

// NewAI constructs the AI handler. The Abbot client is configured from the
// ABBOT_SERVICE_URL env var; when empty, the off-by-default state surfaces as a 503.
func NewAI(database *db.DB, auditLog *audit.Logger) *AI {
	return &AI{
		db:       database,
		auditLog: auditLog,
		client:   abbot.NewClient(strings.TrimSpace(os.Getenv("ABBOT_SERVICE_URL"))),
	}
}

type aiQueryRequest struct {
	Prompt   string   `json:"prompt"`
	ToolHint []string `json:"tool_hint,omitempty"`
}

type aiQueryResponse struct {
	Reply    string                `json:"reply"`
	Tools    []abbot.AuditEnvelope `json:"tools_used,omitempty"`
	Context  []ragContextItem      `json:"context,omitempty"`
	Provider string                `json:"provider,omitempty"`
	Degraded bool                  `json:"degraded,omitempty"`
}

type ragContextItem struct {
	Kind  string `json:"kind"`
	ID    string `json:"id"`
	Title string `json:"title"`
}

// Query is the user-facing entry. Returns 503 with degrade hint if AI is disabled.
func (a *AI) Query(w http.ResponseWriter, r *http.Request) {
	subj, ok := SubjectFrom(r.Context())
	if !ok {
		jsonError(w, http.StatusUnauthorized, "no subject")
		return
	}

	var aiEnabled bool
	if err := a.db.Pool().QueryRow(r.Context(),
		`SELECT ai_enabled FROM orgs WHERE id = $1`, subj.OrgID).Scan(&aiEnabled); err != nil {
		slog.WarnContext(r.Context(), "ai org check failed", slog.String("err", err.Error()))
	}
	if !aiEnabled {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error":   "ai disabled for org",
			"hint":    "ai is off-by-default; an org admin can enable Abbot in settings",
			"degrade": "true",
		})
		return
	}

	var req aiQueryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Prompt) == "" {
		jsonError(w, http.StatusBadRequest, "prompt required")
		return
	}

	// Audit the inbound query (prompt hashed, never logged plaintext).
	sum := sha256.Sum256([]byte(req.Prompt))
	uid, oid := subj.UserID, subj.OrgID
	if a.auditLog != nil {
		_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
			OrgID: &oid, ActorID: &uid, Action: "ai.query",
			TargetKind: "ai", TargetID: "query",
			After: map[string]string{"prompt_hash": hex.EncodeToString(sum[:]), "tool_hints": strings.Join(req.ToolHint, ",")},
		})
	}

	// Build the per-request tool registry, RBAC-scoped to the subject.
	registry := a.buildRegistry()

	// RAG step: surface the top-k findings + assets matched to the prompt (no embedding
	// at this layer; pgvector lookup degrades to keyword search when no embedding is set).
	contextItems := a.ragLookup(r.Context(), subj.OrgID, req.Prompt)

	// Forward to the Abbot service.
	abbotReq := abbot.QueryRequest{
		Prompt:       req.Prompt,
		OrgAIEnabled: aiEnabled,
		Subject:      a.subjectFor(subj),
		ToolCatalog:  registry.List(),
	}
	resp, err := a.client.Query(r.Context(), abbotReq)
	if err != nil {
		// Graceful degradation: Abbot service unreachable or off. Return a
		// keyword-search response so the frontend can render the degraded path.
		if errors.Is(err, abbot.ErrServiceUnreachable) || errors.Is(err, abbot.ErrDisabled) {
			writeJSON(w, http.StatusServiceUnavailable, aiQueryResponse{
				Reply:    fmt.Sprintf("Abbot is unavailable; falling back to keyword search. Found %d candidate result(s).", len(contextItems)),
				Context:  contextItems,
				Degraded: true,
			})
			return
		}
		slog.ErrorContext(r.Context(), "abbot query", slog.String("err", err.Error()))
		jsonError(w, http.StatusBadGateway, "abbot upstream error")
		return
	}

	// Replay tool envelopes through the local registry to enforce RBAC + audit each.
	envelopes := make([]abbot.AuditEnvelope, 0, len(resp.Tools))
	for _, env := range resp.Tools {
		if !registry.Has(env.ToolName) {
			continue
		}
		_, replay, err := registry.Invoke(r.Context(), env.ToolName, env.Args, abbotReq.Subject)
		if err != nil {
			slog.WarnContext(r.Context(), "tool replay failed", slog.String("tool", env.ToolName), slog.String("err", err.Error()))
		}
		envelopes = append(envelopes, replay)
		if a.auditLog != nil {
			_, _, _ = a.auditLog.Log(r.Context(), audit.Event{
				OrgID: &oid, ActorID: &uid, Action: "ai.tool",
				TargetKind: "ai_tool", TargetID: env.ToolName,
				After: map[string]any{"args": env.Args, "successful": replay.Successful},
			})
		}
	}

	writeJSON(w, http.StatusOK, aiQueryResponse{
		Reply:    resp.Reply,
		Tools:    envelopes,
		Context:  contextItems,
		Provider: resp.Provider,
	})
}

// subjectFor projects an HTTP subject into the abbot.Subject struct used by tool handlers.
func (a *AI) subjectFor(subj Subject) abbot.Subject {
	verbs := make([]string, 0, 8)
	seen := map[string]bool{}
	for _, asn := range subj.Assignments {
		for _, v := range rbac.VerbsForRole(asn.Role) {
			s := string(v)
			if !seen[s] {
				verbs = append(verbs, s)
				seen[s] = true
			}
		}
	}
	return abbot.Subject{
		UserID: subj.UserID.String(),
		OrgID:  subj.OrgID.String(),
		Email:  subj.Email,
		Verbs:  verbs,
	}
}

// ragLookup does a coarse keyword search over findings + assets so the response
// has grounded context. A real embedding-backed lookup wires the pgvector query here.
func (a *AI) ragLookup(ctx context.Context, orgID any, prompt string) []ragContextItem {
	out := []ragContextItem{}
	// Keyword substring (ILIKE) search across findings.title/description — graceful
	// fallback when embeddings are absent. This is plain case-insensitive substring
	// matching (not trigram-similarity fuzzy search); findings.title has no pg_trgm
	// index, so these clauses fall back to a sequential scan bounded by the LIMIT.
	rows, err := a.db.Pool().Query(ctx, `
SELECT id::text, title FROM findings
 WHERE org_id = $1
   AND (title ILIKE '%' || $2 || '%' OR description ILIKE '%' || $2 || '%')
 ORDER BY risk_score DESC NULLS LAST, last_seen_at DESC
 LIMIT 5`, orgID, prompt)
	if err != nil {
		slog.WarnContext(ctx, "rag findings lookup failed", slog.String("err", err.Error()))
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, title string
		if err := rows.Scan(&id, &title); err != nil {
			continue
		}
		out = append(out, ragContextItem{Kind: "finding", ID: id, Title: title})
	}
	return out
}

// buildRegistry assembles the per-request tool catalog. All tools are read-side and
// re-check the RBAC verb on invocation; the AI itself never writes through this surface.
func (a *AI) buildRegistry() *abbot.Registry {
	reg := abbot.NewRegistry()

	reg.Register(abbot.Tool{
		Name:        "list_findings",
		Description: "List the top N findings for the calling org, optionally filtered by severity.",
		Side:        "read",
		RBACVerb:    string(rbac.VerbReadFindings),
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"severity": map[string]any{"type": "string"},
				"limit":    map[string]any{"type": "integer", "default": 20},
			},
		},
		Handler: func(ctx context.Context, args map[string]any, subj abbot.Subject) (any, error) {
			limit := 20
			if v, ok := args["limit"].(float64); ok {
				limit = int(v)
			}
			sev, _ := args["severity"].(string)
			rows, err := a.db.Pool().Query(ctx, `
SELECT id::text, title, severity, risk_score, lifecycle
  FROM findings
 WHERE org_id = $1::uuid
   AND ($2::text = '' OR severity = $2)
 ORDER BY risk_score DESC NULLS LAST LIMIT $3`, subj.OrgID, sev, limit)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			type item struct {
				ID, Title, Severity, Lifecycle string
				RiskScore                      int
			}
			out := []item{}
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.ID, &it.Title, &it.Severity, &it.RiskScore, &it.Lifecycle); err != nil {
					return nil, err
				}
				out = append(out, it)
			}
			return out, rows.Err()
		},
	})

	reg.Register(abbot.Tool{
		Name:        "list_assets",
		Description: "List assets (images, repos, clouds) for the calling org.",
		Side:        "read",
		RBACVerb:    string(rbac.VerbReadFindings),
		Parameters: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"kind":  map[string]any{"type": "string"},
				"limit": map[string]any{"type": "integer", "default": 20},
			},
		},
		Handler: func(ctx context.Context, args map[string]any, subj abbot.Subject) (any, error) {
			limit := 20
			if v, ok := args["limit"].(float64); ok {
				limit = int(v)
			}
			kind, _ := args["kind"].(string)
			rows, err := a.db.Pool().Query(ctx, `
SELECT id::text, kind, name FROM assets
 WHERE org_id = $1::uuid AND ($2::text = '' OR kind = $2)
 ORDER BY name LIMIT $3`, subj.OrgID, kind, limit)
			if err != nil {
				return nil, err
			}
			defer rows.Close()
			type item struct{ ID, Kind, Name string }
			out := []item{}
			for rows.Next() {
				var it item
				if err := rows.Scan(&it.ID, &it.Kind, &it.Name); err != nil {
					return nil, err
				}
				out = append(out, it)
			}
			return out, rows.Err()
		},
	})

	return reg
}
