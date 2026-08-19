package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/cors"
)

// TestCORSAllowedOrigins_NeverWildcardsWithCredentials asserts the A8 invariant: because the
// router sets AllowCredentials:true, the CORS allow-list must never contain a wildcard "*"
// origin (the Fetch spec forbids credentialed wildcard responses, and go-chi/cors would either
// reflect every origin or panic). corsAllowedOrigins strips "*"/empty entries; a configured
// wildcard collapses to an empty list (same-origin only), never to a reflected wildcard.
func TestCORSAllowedOrigins_NeverWildcardsWithCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"wildcard dropped", []string{"*"}, []string{}},
		{"wildcard mixed", []string{"*", "https://app.example.com"}, []string{"https://app.example.com"}},
		{"empty and whitespace dropped", []string{"", "  ", "https://a.test"}, []string{"https://a.test"}},
		{"trimmed", []string{"  https://b.test  "}, []string{"https://b.test"}},
		{"nil", nil, []string{}},
		{"all explicit kept", []string{"https://a.test", "https://b.test"}, []string{"https://a.test", "https://b.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := corsAllowedOrigins(tc.in)
			for _, o := range got {
				if o == "*" || o == "" {
					t.Fatalf("corsAllowedOrigins(%v) leaked wildcard/empty origin %q", tc.in, o)
				}
			}
			if len(got) != len(tc.want) {
				t.Fatalf("corsAllowedOrigins(%v) = %v, want %v", tc.in, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("corsAllowedOrigins(%v) = %v, want %v", tc.in, got, tc.want)
				}
			}
		})
	}
}

// TestCORSEmptyAllowListDeniesCrossOrigin locks the L4 fix: when the sanitized allow-list is
// empty, buildRouter must pair it with a deny-all AllowOriginFunc. go-chi/cors treats an empty
// AllowedOrigins with a nil AllowOriginFunc as "allow all" and reflects a wildcard
// Access-Control-Allow-Origin — the opposite of the same-origin-only intent. The first case
// proves that dangerous default still exists in the pinned library (so the guard stays load-
// bearing); the second proves our deny-all func suppresses any cross-origin reflection.
func TestCORSEmptyAllowListDeniesCrossOrigin(t *testing.T) {
	preflight := func(h http.Handler) string {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/findings", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header().Get("Access-Control-Allow-Origin")
	}

	// Baseline: empty list + nil func => go-chi wildcards. This documents why the guard exists.
	unguarded := cors.Handler(cors.Options{
		AllowedOrigins:   corsAllowedOrigins([]string{"*"}),
		AllowCredentials: true,
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if got := preflight(unguarded); got != "*" {
		t.Fatalf("pinned go-chi/cors changed: empty AllowedOrigins yielded ACAO %q, want wildcard", got)
	}

	// Guarded: empty list + deny-all func (as buildRouter installs) => no reflection.
	opts := cors.Options{
		AllowedOrigins:   corsAllowedOrigins([]string{"*"}),
		AllowCredentials: true,
	}
	if len(opts.AllowedOrigins) == 0 {
		opts.AllowOriginFunc = func(*http.Request, string) bool { return false }
	}
	guarded := cors.Handler(opts)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	if got := preflight(guarded); got != "" {
		t.Fatalf("deny-all CORS still reflected origin: ACAO %q, want empty", got)
	}
}
