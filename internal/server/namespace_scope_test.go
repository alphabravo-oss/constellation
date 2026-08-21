package server

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

// RBAC-NS-24: requireVerb must derive the namespace a request targets so a
// namespace-scoped grant authorizes. Route param wins over the ?namespace= query;
// an unfiltered request yields "" (deny-closed for a namespace-scoped subject).
func TestNamespaceScopeFromRequest(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		routeNS  string // {namespace} route param
		routeNs2 string // {ns} route param
		want     string
	}{
		{"query only", "?namespace=prod", "", "", "prod"},
		{"query trimmed", "?namespace=%20prod%20", "", "", "prod"},
		{"route {namespace} wins over query", "?namespace=dev", "prod", "", "prod"},
		{"route {ns} fallback", "", "", "kube-system", "kube-system"},
		{"none → empty (unfiltered list)", "", "", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/x"+tc.query, nil)
			rctx := chi.NewRouteContext()
			if tc.routeNS != "" {
				rctx.URLParams.Add("namespace", tc.routeNS)
			}
			if tc.routeNs2 != "" {
				rctx.URLParams.Add("ns", tc.routeNs2)
			}
			r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
			if got := namespaceScopeFromRequest(r); got != tc.want {
				t.Fatalf("namespaceScopeFromRequest = %q, want %q", got, tc.want)
			}
		})
	}
}
