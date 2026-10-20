//go:build integration

package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/api/apiutil"
)

// Runtime half of the error contract (guide ch.03): every 4xx/5xx the server
// produces — router 404/405, authn 401, authz 403, bad JSON 400, panic 500 —
// carries {"error":{"code","message"}} and a 500 never leaks the cause.
func TestErrorContractEveryStatusIsTheStandardShape(t *testing.T) {
	srv, ts, _, signer, userID, _, orgID := newSysConfigTestServer(t)
	router := srv.buildRouter()
	router.Get("/__panic", func(http.ResponseWriter, *http.Request) { panic("db password=hunter2") })
	local := httptest.NewServer(router)
	t.Cleanup(local.Close)
	admin := issueFor(t, signer, userID, orgID, 0)

	cases := []struct {
		name, method, url, bearer, body string
		status                          int
		code                            apiutil.Code
	}{
		{"router 404", http.MethodGet, ts.URL + "/api/v1/definitely-not-a-route", admin, "", 404, apiutil.CodeNotFound},
		{"router 405", http.MethodDelete, ts.URL + "/healthz", admin, "", 405, apiutil.CodeUnimplemented},
		{"authn 401", http.MethodGet, ts.URL + "/api/v1/clusters", "", "", 401, apiutil.CodeUnauthenticated},
		{"authn 401 bad token", http.MethodGet, ts.URL + "/api/v1/clusters", "not-a-jwt", "", 401, apiutil.CodeUnauthenticated},
		{"bad json 400", http.MethodPatch, ts.URL + "/api/v1/system/config", admin, "{not json", 400, apiutil.CodeInvalidArgument},
		{"resource 404", http.MethodGet, ts.URL + "/api/v1/clusters/00000000-0000-0000-0000-000000000000", admin, "", 404, apiutil.CodeNotFound},
		{"panic 500", http.MethodGet, local.URL + "/__panic", "", "", 500, apiutil.CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, tc.url, bytes.NewBufferString(tc.body))
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d, want %d: %s", resp.StatusCode, tc.status, raw)
			}
			var b apiutil.Body
			if err := json.Unmarshal(raw, &b); err != nil || b.Error.Code == "" || b.Error.Message == "" {
				t.Fatalf("body is not {\"error\":{\"code\",\"message\"}}: %s (%v)", raw, err)
			}
			if rid := resp.Header.Get("X-Request-ID"); rid == "" || b.Error.RequestID != rid {
				t.Fatalf("error body request_id %q does not match X-Request-ID header %q", b.Error.RequestID, rid)
			}
			if b.Error.Code != tc.code {
				t.Fatalf("code %s, want %s: %s", b.Error.Code, tc.code, raw)
			}
			if resp.StatusCode >= 500 && (b.Error.Message != apiutil.InternalMessage || strings.Contains(string(raw), "hunter2")) {
				t.Fatalf("500 leaked detail: %s", raw)
			}
			var generic map[string]any
			_ = json.Unmarshal(raw, &generic)
			if len(generic) != 1 {
				t.Fatalf("extra top-level keys in error body: %s", raw)
			}
		})
	}
}
