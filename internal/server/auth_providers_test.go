package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthProvidersIsAnonymous(t *testing.T) {
	s, err := newSpecServer()
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/auth/providers", nil))
	if w.Code != http.StatusOK || w.Body.String() != "{\"oidc\":false,\"saml\":false}\n" {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}
