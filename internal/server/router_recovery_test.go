package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
)

// TestRecovererConvertsPanicTo500 is the D3 panic-recovery guard. It exercises the same
// chi Recoverer middleware buildRouter() installs (server.go) and asserts an unexpected
// panic on the request path is converted to a 500 instead of crashing the process.
//
// We build the router locally (rather than via New, which needs a live DB) so the test
// runs without DATABASE_URL — the middleware behavior is identical.
func TestRecovererConvertsPanicTo500(t *testing.T) {
	r := chi.NewRouter()
	r.Use(chimw.Recoverer)
	r.Get("/boom", func(http.ResponseWriter, *http.Request) {
		panic("simulated request-path panic")
	})
	r.Get("/ok", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(r)
	defer ts.Close()

	// Panicking route: recovered -> 500, server still serving.
	resp, err := http.Get(ts.URL + "/boom")
	if err != nil {
		t.Fatalf("GET /boom: %v", err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("GET /boom status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
	_ = resp.Body.Close()

	// Process survived the panic: a subsequent request still succeeds.
	resp, err = http.Get(ts.URL + "/ok")
	if err != nil {
		t.Fatalf("GET /ok after panic: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /ok status = %d, want 200 (server should survive the prior panic)", resp.StatusCode)
	}
	_ = resp.Body.Close()
}
