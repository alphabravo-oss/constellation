//go:build integration

package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestSystemConfigConditionalEditsRejectStaleAndConcurrentWriters(t *testing.T) {
	_, ts, pool, signer, adminID, _, orgID := newSysConfigTestServer(t)
	token := issueFor(t, signer, adminID, orgID, 0)
	status, initial := doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", token, nil)
	if status != 200 {
		t.Fatalf("initial GET: %d", status)
	}
	rev := int64(initial["revision"].(float64))
	patch := func(match string, days int) conditionalConfigResult {
		return patchConditionalConfig(t.Context(), ts.Client(), ts.URL+"/api/v1/system/config", token, match, days)
	}
	assertConcurrentConfigEdits(t, patch, rev)
	r := patch(fmt.Sprintf(`"%d"`, rev), 99)
	if r.err != nil || r.status != 412 {
		t.Fatalf("stale editor accepted: %+v", r)
	}
	for _, invalid := range []string{"", "*", "1", `W/"1"`, `"1","2"`, `"-1"`, `"+1"`, `"9223372036854775808"`} {
		if r := patch(invalid, 99); r.err != nil || r.status != 400 {
			t.Fatalf("invalid precondition %q: %+v", invalid, r)
		}
	}
	status, current := doJSON(t, http.MethodGet, ts.URL+"/api/v1/system/config", token, nil)
	if status != 200 || int64(current["revision"].(float64)) != rev+1 {
		t.Fatal("rejected updates changed revision")
	}
	days := current["config"].(map[string]any)["network_flow_retention_days"].(float64)
	if days != 21 && days != 45 {
		t.Fatalf("stale update escaped: %v", days)
	}
	var writes int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND action='system.config.update'`, orgID).Scan(&writes); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("rejected updates emitted success audit receipts: %d", writes)
	}
	// Older clients retain compatible merge semantics without a precondition.
	if status, _ := doJSON(t, http.MethodPatch, ts.URL+"/api/v1/system/config", token, map[string]any{"network_flow_retention_days": 30}); status != 200 {
		t.Fatalf("legacy PATCH failed: %d", status)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodOptions, ts.URL+"/api/v1/system/config", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "PATCH")
	req.Header.Set("Access-Control-Request-Headers", "If-Match, Content-Type")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if !strings.Contains(strings.ToLower(resp.Header.Get("Access-Control-Allow-Headers")), "if-match") {
		t.Fatal("CORS does not allow conditional editor requests")
	}
}

type conditionalConfigResult struct {
	status int
	etag   string
	err    error
}

func patchConditionalConfig(ctx context.Context, client *http.Client, endpoint, token, match string, days int) conditionalConfigResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, strings.NewReader(fmt.Sprintf(`{"network_flow_retention_days":%d}`, days)))
	if err != nil {
		return conditionalConfigResult{err: err}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", match)
	resp, err := client.Do(req)
	if err != nil {
		return conditionalConfigResult{err: err}
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return conditionalConfigResult{status: resp.StatusCode, etag: resp.Header.Get("ETag"), err: errors.Join(err, resp.Body.Close())}
}

func assertConcurrentConfigEdits(t *testing.T, patch func(string, int) conditionalConfigResult, rev int64) {
	t.Helper()
	results := make(chan conditionalConfigResult, 2)
	for _, days := range []int{21, 45} {
		go func(days int) { results <- patch(fmt.Sprintf(`"%d"`, rev), days) }(days)
	}
	successes, rejected := 0, 0
	for i := 0; i < 2; i++ {
		r := <-results
		if r.err != nil {
			t.Fatal(r.err)
		}
		switch r.status {
		case http.StatusOK:
			successes++
			if r.etag != fmt.Sprintf(`"%d"`, rev+1) {
				t.Fatalf("new ETag=%q", r.etag)
			}
		case http.StatusPreconditionFailed:
			rejected++
		default:
			t.Fatalf("unexpected status %d", r.status)
		}
	}
	if successes != 1 || rejected != 1 {
		t.Fatalf("concurrent edits: %d succeeded, %d rejected", successes, rejected)
	}
}
