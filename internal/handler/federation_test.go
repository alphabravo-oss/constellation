package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/federation"
)

// TestFederationMemberLifecycle exercises ENT-3: a sync poll from a joint stamps
// last_sync_at and flips status pending->active; ListMembers reports stale once the
// heartbeat ages past the freshness window; Kick revokes the member so a subsequent
// sync poll is rejected.
func TestFederationMemberLifecycle(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()

	ctx := t.Context()
	pool := d.Pool()

	var orgID, userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("skipping: no seed org (%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT id FROM users WHERE org_id=$1 LIMIT 1`, orgID).Scan(&userID); err != nil {
		t.Skipf("skipping: no seed user (%v)", err)
	}

	clusterID := "ent3-joint-" + uuid.NewString()
	_, _ = pool.Exec(ctx, `DELETE FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM fed_members WHERE org_id=$1 AND cluster_id=$2`, orgID, clusterID)
	})

	h := NewFederation(d, audit.New(pool))
	subj := Subject{UserID: userID, OrgID: orgID}

	// Seed a pending member directly (mirrors AddMember's upsert).
	var memberID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO fed_members (org_id, cluster_id, name, role, status, revision)
VALUES ($1,$2,'ent3-joint','joint','pending',0) RETURNING id`,
		orgID, clusterID).Scan(&memberID); err != nil {
		t.Fatalf("seed member: %v", err)
	}

	// 1) A sync poll identifying the joint stamps last_sync_at and activates it.
	r := httptest.NewRequest("GET", "/api/v1/federation/sync?since=0&cluster_id="+clusterID, nil)
	r = r.WithContext(WithSubject(r.Context(), subj))
	w := httptest.NewRecorder()
	h.Sync(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("sync status: %d body: %s", w.Code, w.Body.String())
	}
	var stored string
	var lastSync *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, last_sync_at FROM fed_members WHERE id=$1`, memberID).
		Scan(&stored, &lastSync); err != nil {
		t.Fatal(err)
	}
	if stored != "active" {
		t.Fatalf("after sync want stored status active, got %q", stored)
	}
	if lastSync == nil {
		t.Fatal("after sync last_sync_at not stamped")
	}

	// 2) ListMembers reports a live status. Fresh poll => active.
	if got := listMemberStatus(t, h, subj, clusterID); got != federation.MemberStatusActive {
		t.Fatalf("fresh member: want active, got %q", got)
	}
	// Age the heartbeat past the stale threshold (>1 interval, <=3 intervals).
	if _, err := pool.Exec(ctx,
		`UPDATE fed_members SET last_sync_at=NOW() - INTERVAL '90 seconds' WHERE id=$1`, memberID); err != nil {
		t.Fatal(err)
	}
	if got := listMemberStatus(t, h, subj, clusterID); got != federation.MemberStatusStale {
		t.Fatalf("aged member: want stale, got %q", got)
	}

	// 3) Kick revokes the member.
	r = httptest.NewRequest("DELETE", "/api/v1/federation/members/"+memberID.String(), nil)
	r = r.WithContext(WithSubject(r.Context(), subj))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", memberID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
	w = httptest.NewRecorder()
	h.KickMember(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("kick status: %d body: %s", w.Code, w.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM fed_members WHERE id=$1`, memberID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != federation.MemberStatusKicked {
		t.Fatalf("after kick want kicked, got %q", stored)
	}

	// 4) A subsequent sync poll from the kicked joint is rejected (403) and does not
	//    re-activate the member.
	r = httptest.NewRequest("GET", "/api/v1/federation/sync?since=0&cluster_id="+clusterID, nil)
	r = r.WithContext(WithSubject(r.Context(), subj))
	w = httptest.NewRecorder()
	h.Sync(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("kicked sync status: want 403, got %d body: %s", w.Code, w.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT status FROM fed_members WHERE id=$1`, memberID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != federation.MemberStatusKicked {
		t.Fatalf("kicked member self-reactivated: status %q", stored)
	}
}

func listMemberStatus(t *testing.T, h *Federation, subj Subject, clusterID string) string {
	t.Helper()
	r := httptest.NewRequest("GET", "/api/v1/federation/members", nil)
	r = r.WithContext(WithSubject(r.Context(), subj))
	w := httptest.NewRecorder()
	h.ListMembers(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("list members status: %d body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Members []federation.Member `json:"members"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for _, m := range resp.Members {
		if m.ClusterID == clusterID {
			return m.Status
		}
	}
	t.Fatalf("member %s not in list", clusterID)
	return ""
}
