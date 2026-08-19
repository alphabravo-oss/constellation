// Package abbot is the in-product library that talks to the cross-product Abbot GenAI
// gateway. Per spec section "AI integration is via Abbot", every AI feature in
// Constellation goes through this library; the library handles RBAC, local audit writes,
// tool catalog registration, and graceful degradation when the Abbot service is
// unreachable. Provider protocol bridges (OpenAI Chat Completions / Responses,
// Anthropic Messages) live in the Abbot service, NOT here.
//
// At v1 the surface is the tool registry plus the envelope-over-HTTPS Query path. When
// the Abbot service URL is unset, the client returns ErrServiceUnreachable so the product
// can degrade to non-AI search without changing callers.
//
// Reference: docs/specs/abbot-architecture.md (Phase 5 spec, owned by the Abbot workstream).
package abbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// ErrDisabled is returned when AI is disabled for the calling org (org.ai_enabled = false).
var ErrDisabled = errors.New("abbot: AI is disabled for this org")

// ErrServiceUnreachable is returned when the Abbot service URL is unset or unreachable.
// Callers must degrade gracefully (the UI falls back to keyword search etc.).
var ErrServiceUnreachable = errors.New("abbot: service unreachable; degrade to non-AI path")

// Tool is one capability the product exposes to the AI. Tool schemas are JSON-Schema-like.
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"` // JSON Schema
	RBACVerb    string                 `json:"rbac_verb,omitempty"`
	Side        string                 `json:"side"` // "read" | "write"

	// Handler is invoked by the library when the AI emits a tool-call for this tool.
	// Returns a result that's marshaled back to the AI + a synthesized audit event.
	Handler func(ctx context.Context, args map[string]interface{}, subject Subject) (interface{}, error) `json:"-"`
}

// Subject is the calling user's identity, propagated so tool handlers can re-check RBAC.
type Subject struct {
	UserID string
	OrgID  string
	Email  string
	Verbs  []string // RBAC verbs the subject holds in this scope
}

// Registry is the per-process tool catalog. The API server constructs one at startup and
// passes it to the /api/v1/ai/query handler.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]Tool
}

// NewRegistry constructs an empty registry.
func NewRegistry() *Registry { return &Registry{tools: map[string]Tool{}} }

// Register adds a tool to the registry. Panics on duplicate name.
func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tools[t.Name]; exists {
		panic("abbot: duplicate tool registration: " + t.Name)
	}
	r.tools[t.Name] = t
}

// List returns the catalog sorted by name (stable across restarts so the Abbot service
// can detect catalog changes via diff).
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Has reports whether a tool is registered.
func (r *Registry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tools[name]
	return ok
}

// Invoke runs a registered tool's handler. Verifies RBAC verb match before invoking.
// All invocations are returned with a synthesized audit envelope the caller writes to
// the hash-chained audit log.
func (r *Registry) Invoke(ctx context.Context, name string, args map[string]interface{}, subj Subject) (interface{}, AuditEnvelope, error) {
	r.mu.RLock()
	t, ok := r.tools[name]
	r.mu.RUnlock()
	if !ok {
		return nil, AuditEnvelope{}, errors.New("abbot: unknown tool: " + name)
	}
	if t.RBACVerb != "" && !hasVerb(subj, t.RBACVerb) {
		return nil, AuditEnvelope{}, errors.New("abbot: subject lacks RBAC verb: " + t.RBACVerb)
	}
	result, err := t.Handler(ctx, args, subj)
	env := AuditEnvelope{
		ToolName:   t.Name,
		Args:       args,
		Subject:    subj,
		At:         time.Now().UTC(),
		Successful: err == nil,
	}
	return result, env, err
}

func hasVerb(s Subject, want string) bool {
	for _, v := range s.Verbs {
		if v == want {
			return true
		}
	}
	return false
}

// AuditEnvelope is the per-tool-call record the caller writes to the hash-chained audit log.
type AuditEnvelope struct {
	ToolName   string
	Args       map[string]interface{}
	Subject    Subject
	At         time.Time
	Successful bool
}

// Client talks to the Abbot service. When ServiceURL is empty, Query returns
// ErrServiceUnreachable so the caller can degrade.
type Client struct {
	ServiceURL string
	HTTP       *http.Client
}

// NewClient constructs a Client. ServiceURL="" disables AI at the wire level.
func NewClient(serviceURL string) *Client {
	return &Client{ServiceURL: serviceURL, HTTP: &http.Client{Timeout: 60 * time.Second}}
}

// Query is the entry point /api/v1/ai/query calls into. When ServiceURL is empty,
// unreachable, or the org has AI disabled, returns ErrServiceUnreachable / ErrDisabled
// so the UI can fall back to non-AI search.
func (c *Client) Query(ctx context.Context, req QueryRequest) (*QueryResponse, error) {
	if c == nil || c.ServiceURL == "" {
		return nil, ErrServiceUnreachable
	}
	if !req.OrgAIEnabled {
		return nil, ErrDisabled
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	url := strings.TrimRight(c.ServiceURL, "/") + "/api/v1/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrServiceUnreachable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusNotFound {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("%w: status %d: %s", ErrServiceUnreachable, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("abbot: status %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	var out QueryResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// QueryRequest is the input the /api/v1/ai/query handler forwards.
type QueryRequest struct {
	Prompt       string        `json:"prompt"`
	Subject      Subject       `json:"subject"`
	OrgAIEnabled bool          `json:"-"`
	ToolCatalog  []Tool        `json:"tool_catalog"`
	History      []ChatMessage `json:"history,omitempty"`
}

// ChatMessage is one turn in a conversation.
type ChatMessage struct {
	Role    string `json:"role"` // user | assistant | tool
	Content string `json:"content"`
}

// QueryResponse is the output. Tool calls happen via Callback inside Query; the response
// is the final assistant text + the audit envelopes for every tool call made.
type QueryResponse struct {
	Reply    string          `json:"reply"`
	Tools    []AuditEnvelope `json:"tools_used,omitempty"`
	Provider string          `json:"provider,omitempty"` // populated by Abbot service
}

// MarshalCatalog returns the JSON the Abbot service registers at startup.
func (r *Registry) MarshalCatalog() ([]byte, error) {
	return json.MarshalIndent(r.List(), "", "  ")
}
