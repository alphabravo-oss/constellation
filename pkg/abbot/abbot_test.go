package abbot

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegistry_RegisterAndList(t *testing.T) {
	r := NewRegistry()
	r.Register(Tool{Name: "list_findings", Side: "read",
		Handler: func(_ context.Context, _ map[string]interface{}, _ Subject) (interface{}, error) {
			return []string{"a", "b"}, nil
		}})
	r.Register(Tool{Name: "suppress_finding", Side: "write", RBACVerb: "suppress-findings",
		Handler: func(_ context.Context, _ map[string]interface{}, _ Subject) (interface{}, error) {
			return "ok", nil
		}})
	tools := r.List()
	if len(tools) != 2 {
		t.Fatalf("list: %d", len(tools))
	}
	if tools[0].Name != "list_findings" {
		t.Fatalf("sort order: %s", tools[0].Name)
	}
}

func TestRegistry_RBACEnforcement(t *testing.T) {
	r := NewRegistry()
	r.Register(Tool{Name: "suppress", Side: "write", RBACVerb: "suppress-findings",
		Handler: func(_ context.Context, _ map[string]interface{}, _ Subject) (interface{}, error) {
			return "ok", nil
		}})
	// User without the verb is denied.
	_, _, err := r.Invoke(context.Background(), "suppress", nil, Subject{Verbs: []string{"read-findings"}})
	if err == nil {
		t.Fatal("expected RBAC denial")
	}
	// User with the verb gets through.
	_, env, err := r.Invoke(context.Background(), "suppress", nil, Subject{Verbs: []string{"suppress-findings"}})
	if err != nil {
		t.Fatal(err)
	}
	if !env.Successful {
		t.Fatal("audit envelope should mark success")
	}
}

func TestClient_DisabledWhenServiceURLEmpty(t *testing.T) {
	c := NewClient("")
	_, err := c.Query(context.Background(), QueryRequest{Prompt: "hi", OrgAIEnabled: true})
	if !errors.Is(err, ErrServiceUnreachable) {
		t.Fatalf("expected ErrServiceUnreachable, got %v", err)
	}
}

func TestClient_RejectsDisabledOrg(t *testing.T) {
	c := NewClient("https://abbot.example/test")
	_, err := c.Query(context.Background(), QueryRequest{Prompt: "hi", OrgAIEnabled: false})
	if !errors.Is(err, ErrDisabled) {
		t.Fatalf("expected ErrDisabled, got %v", err)
	}
}

func TestClient_QueryPostsEnvelope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/chat" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		var req QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Prompt != "show critical findings" || req.Subject.Email != "admin@example.test" || len(req.ToolCatalog) != 1 {
			t.Fatalf("request = %+v", req)
		}
		_ = json.NewEncoder(w).Encode(QueryResponse{
			Reply:    "critical findings summarized",
			Provider: "test-abbot",
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	c.HTTP = srv.Client()
	resp, err := c.Query(context.Background(), QueryRequest{
		Prompt:       "show critical findings",
		OrgAIEnabled: true,
		Subject:      Subject{Email: "admin@example.test"},
		ToolCatalog:  []Tool{{Name: "list_findings", Side: "read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Reply != "critical findings summarized" || resp.Provider != "test-abbot" {
		t.Fatalf("response = %+v", resp)
	}
}

func TestClient_QueryUnavailableDegrades(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "offline", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	c.HTTP = srv.Client()
	_, err := c.Query(context.Background(), QueryRequest{Prompt: "hi", OrgAIEnabled: true})
	if !errors.Is(err, ErrServiceUnreachable) {
		t.Fatalf("expected ErrServiceUnreachable, got %v", err)
	}
}

func TestRegistry_MarshalCatalog(t *testing.T) {
	r := NewRegistry()
	r.Register(Tool{Name: "x", Side: "read"})
	b, err := r.MarshalCatalog()
	if err != nil {
		t.Fatal(err)
	}
	var doc []map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc[0]["name"] != "x" {
		t.Fatalf("catalog: %+v", doc)
	}
}
