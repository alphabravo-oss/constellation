//go:build integration

package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// TestRoutePolicyTableIsCurrent extracts the static route -> verb map from the
// live router (guide ch.06: a static route-to-role map the Connect authz
// interceptor can reuse) by probing every registered route with a subject
// whose token carries no scopes: requireVerb and its variants answer 403
// naming the verb before any handler runs, so the verb is read off the wire
// and no handler executes. Routes that answer anything else are "public" and
// must be listed explicitly. The result is committed as routepolicy.json;
// UPDATE_ROUTE_POLICY=1 rewrites it.
func TestRoutePolicyTableIsCurrent(t *testing.T) {
	srv, _, _, _, userID, _, orgID := newSysConfigTestServer(t)
	router := srv.buildRouter()
	probe := authctx.Subject{UserID: userID, OrgID: orgID, TokenScopes: []rbac.Verb{"probe:none"}}
	got := map[string]string{}
	err := chi.Walk(router, func(method, route string, h http.Handler, mws ...func(http.Handler) http.Handler) error {
		if method == "*" || strings.HasPrefix(route, "/__") {
			return nil
		}
		key := method + " " + route
		path := strings.NewReplacer("{", "", "}", "", "*", "x").Replace(route)
		// 1. The verb gate wraps the handler itself: call it with the probe subject.
		rec := serve(h, httptest.NewRequest(method, path, nil).WithContext(authctx.WithSubject(context.Background(), probe)))
		var body struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if os.Getenv("ROUTE_POLICY_DEBUG") != "" {
			t.Logf("%s -> %d %s", key, rec.Code, strings.TrimSpace(rec.Body.String()))
		}
		if rec.Code == http.StatusForbidden && strings.HasPrefix(body.Error.Message, "forbidden: token lacks scope ") {
			got[key] = strings.TrimPrefix(body.Error.Message, "forbidden: token lacks scope ")
			return nil
		}
		// 2. No verb gate: is the route at least behind the group's authn middleware?
		wrapped := h
		for i := len(mws) - 1; i >= 0; i-- {
			wrapped = mws[i](wrapped)
		}
		if rec := serve(wrapped, httptest.NewRequest(method, path, nil)); rec.Code == http.StatusUnauthorized {
			got[key] = "authn"
			return nil
		}
		got[key] = "public"
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("UPDATE_ROUTE_POLICY") == "1" {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ordered := make(map[string]string, len(got))
		for _, k := range keys {
			ordered[k] = got[k]
		}
		b, _ := json.MarshalIndent(ordered, "", "  ")
		if err := os.WriteFile("routepolicy.json", append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote routepolicy.json with %d routes", len(got))
	}
	want := RoutePolicy()
	var drift []string
	for k, v := range got {
		if want[k] != v {
			drift = append(drift, k+": table="+want[k]+" router="+v)
		}
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			drift = append(drift, k+": in table, not registered")
		}
	}
	if len(drift) > 0 {
		sort.Strings(drift)
		t.Fatalf("routepolicy.json is stale (%d routes); run with UPDATE_ROUTE_POLICY=1:\n%s", len(drift), strings.Join(drift, "\n"))
	}
	_ = uuid.Nil
}

// serve runs h against req, turning a handler panic (a probe reaching real
// code with synthetic ids) into a 599 so the walk continues.
func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	func() {
		defer func() {
			if r := recover(); r != nil {
				rec.Code = 599
			}
		}()
		h.ServeHTTP(rec, req)
	}()
	return rec
}
