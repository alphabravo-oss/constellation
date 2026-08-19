package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

// recordingJoint is a mock joint API: it captures the last request it saw (method, path,
// Authorization header, body) and returns a fixed 200 body.
type recordingJoint struct {
	method string
	path   string
	auth   string
	body   string
	hits   int
}

func newRecordingJoint(t *testing.T, rec *recordingJoint) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.hits++
		rec.method = r.Method
		rec.path = r.URL.Path
		rec.auth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		rec.body = string(b)
		w.Header().Set("X-Joint", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"from":"joint"}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

func forwardReq(t *testing.T, h *FedProxy, subj Subject, method, clusterID, subPath, query, body string) *httptest.ResponseRecorder {
	t.Helper()
	url := "/api/v1/federation/clusters/" + clusterID + "/" + subPath
	if query != "" {
		url += "?" + query
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, url, rdr)
	// Simulate a leaked inbound user credential the proxy must NOT forward to the joint.
	r.Header.Set("Authorization", "Bearer USER-JWT-SECRET")
	r.Header.Set("Cookie", "session=abc")
	r = r.WithContext(WithSubject(r.Context(), subj))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", clusterID)
	rctx.URLParams.Add("*", subPath)
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Forward(w, r)
	return w
}

func adminSubject(orgID, userID uuid.UUID) Subject {
	return Subject{UserID: userID, OrgID: orgID,
		Assignments: []rbac.RoleAssignment{{Role: rbac.RoleGlobalAdmin, Scope: rbac.Scope{OrgID: orgID}}}}
}

func readerSubject(orgID, userID uuid.UUID) Subject {
	return Subject{UserID: userID, OrgID: orgID,
		Assignments: []rbac.RoleAssignment{{Role: rbac.RoleAuditor, Scope: rbac.Scope{OrgID: orgID}}}}
}

// TestFedProxy_AdminForwardsGet covers the D3 acceptance check: an admin drives a joint's API
// through the master. The mock joint receives the forwarded GET (method+path preserved) and the
// master's fed credential — NOT the caller's inbound Authorization (no credential leak).
func TestFedProxy_AdminForwardsGet(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}

	var rec recordingJoint
	ts := newRecordingJoint(t, &rec)
	clusterID := insertMember(t, ctx, d, orgID, ts.URL)

	h := NewFedProxy(d, audit.New(pool))
	w := forwardReq(t, h, adminSubject(orgID, userID), http.MethodGet, clusterID, "findings", "severity=high", "")

	if w.Code != http.StatusOK {
		t.Fatalf("admin GET status: %d body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"from":"joint"`) {
		t.Fatalf("response not streamed from joint: %s", w.Body.String())
	}
	if w.Header().Get("X-Joint") != "1" {
		t.Fatalf("upstream response header not propagated")
	}
	if rec.hits != 1 || rec.method != http.MethodGet {
		t.Fatalf("joint saw hits=%d method=%q", rec.hits, rec.method)
	}
	if rec.path != "/api/v1/findings" {
		t.Fatalf("joint path: want /api/v1/findings, got %q", rec.path)
	}
	// The inbound user credential must never reach the joint.
	if strings.Contains(rec.auth, "USER-JWT-SECRET") {
		t.Fatalf("inbound Authorization leaked to joint: %q", rec.auth)
	}
}

// TestFedProxy_FedCredentialAttached asserts that when the master holds a fed signer it attaches
// a valid fed sync ticket (not the caller's token) as the outbound Authorization.
func TestFedProxy_FedCredentialAttached(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}
	signer := fedTestSigner(t, ctx, pool)

	var rec recordingJoint
	ts := newRecordingJoint(t, &rec)
	clusterID := insertMember(t, ctx, d, orgID, ts.URL)

	h := NewFedProxy(d, audit.New(pool)).WithFedCredentials(signer, nil)
	w := forwardReq(t, h, adminSubject(orgID, userID), http.MethodGet, clusterID, "findings", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status: %d body: %s", w.Code, w.Body.String())
	}
	tok := strings.TrimPrefix(rec.auth, "Bearer ")
	if tok == "" || tok == "USER-JWT-SECRET" {
		t.Fatalf("no fed credential attached, auth=%q", rec.auth)
	}
	claims, err := signer.VerifySyncTicket(tok)
	if err != nil {
		t.Fatalf("attached credential is not a valid fed sync ticket: %v", err)
	}
	if claims.ClusterID != clusterID || claims.OrgID != orgID {
		t.Fatalf("fed ticket scoped wrong: org=%s cluster=%s", claims.OrgID, claims.ClusterID)
	}
}

// TestFedProxy_NonAdminReadAllowlist covers the second acceptance check: a non-admin is limited
// to the read allowlist — an allowlisted GET is forwarded, a non-allowlisted GET is 403, and any
// mutating verb is 403.
func TestFedProxy_NonAdminReadAllowlist(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}

	var rec recordingJoint
	ts := newRecordingJoint(t, &rec)
	clusterID := insertMember(t, ctx, d, orgID, ts.URL)
	h := NewFedProxy(d, audit.New(pool))
	reader := readerSubject(orgID, userID)

	// Allowlisted read -> forwarded.
	if w := forwardReq(t, h, reader, http.MethodGet, clusterID, "findings", "", ""); w.Code != http.StatusOK {
		t.Fatalf("non-admin allowlisted GET: want 200, got %d body %s", w.Code, w.Body.String())
	}
	// Non-allowlisted read -> 403, never forwarded.
	before := rec.hits
	if w := forwardReq(t, h, reader, http.MethodGet, clusterID, "users", "", ""); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin non-allowlisted GET: want 403, got %d", w.Code)
	}
	if rec.hits != before {
		t.Fatalf("non-allowlisted GET was forwarded to joint")
	}
	// Mutating verb -> 403 (read-only for non-admins), never forwarded.
	before = rec.hits
	if w := forwardReq(t, h, reader, http.MethodPost, clusterID, "findings", "", `{"x":1}`); w.Code != http.StatusForbidden {
		t.Fatalf("non-admin POST: want 403, got %d", w.Code)
	}
	if rec.hits != before {
		t.Fatalf("non-admin POST was forwarded to joint")
	}
}

// TestFedProxy_UnregisteredClusterIs404 covers the SSRF guard: forwarding to a cluster id with
// no membership row is 404 and never dials out.
func TestFedProxy_UnregisteredClusterIs404(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}
	if !fedMembersPresent(t, ctx, d) {
		t.Skip("skipping: fed_members schema not applied")
	}

	h := NewFedProxy(d, audit.New(pool))
	// Even an admin cannot proxy to an unknown cluster id.
	w := forwardReq(t, h, adminSubject(orgID, userID), http.MethodGet, "no-such-cluster-"+uuid.NewString(), "findings", "", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("unregistered cluster: want 404, got %d body %s", w.Code, w.Body.String())
	}
}

// fedMembersPresent reports whether the fed_members table exists.
func fedMembersPresent(t *testing.T, ctx context.Context, d *db.DB) bool {
	t.Helper()
	var rc string
	_ = d.Pool().QueryRow(ctx, `SELECT COALESCE(to_regclass('public.fed_members')::text,'')`).Scan(&rc)
	return rc != ""
}

// insertMember registers an active fed member for org at endpoint and returns its cluster id.
func insertMember(t *testing.T, ctx context.Context, d *db.DB, orgID uuid.UUID, endpoint string) string {
	t.Helper()
	clusterID := "d3-joint-" + uuid.NewString()
	t.Cleanup(func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	})
	if _, err := d.Pool().Exec(ctx, `
INSERT INTO fed_members (org_id, cluster_id, name, role, endpoint, status, revision)
VALUES ($1,$2,$3,'joint',$4,'active',0)`, orgID, clusterID, "d3-joint", endpoint); err != nil {
		t.Fatalf("seed member: %v", err)
	}
	return clusterID
}
