//go:build integration

package identity

import (
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/rbac"
)

func TestOIDCFirstSessionUsesCurrentEpoch(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	store := Store{Pool: pool}
	service := &Service{store: store}
	ctx := t.Context()
	principal := &Principal{Subject: "first-login", Email: "first-login@example.test", Roles: []string{rbac.RoleAnalyst}}
	subject, epoch, err := store.resolve(ctx, "demo", "https://issuer.example.test", principal)
	if err != nil {
		t.Fatal(err)
	}
	login := func(epoch int64) (string, error) {
		return store.startSession(ctx, subject, epoch, principal.Roles, "oidc", time.Now().Add(time.Hour), audit.New(pool))
	}
	raw, err := login(epoch)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RefreshSessions(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := service.Authenticate(ctx, raw)
	if err != nil || got.UserID != subject.UserID || len(got.Assignments) != 1 || got.Assignments[0].Role != rbac.RoleAnalyst {
		t.Fatalf("first login session unusable: subject=%+v err=%v", got, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET session_epoch=session_epoch+1 WHERE id=$1`, subject.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := login(epoch); err == nil {
		t.Fatal("login accepted an epoch revoked after identity resolution")
	}
	var sessions int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM identity_sessions WHERE user_id=$1`, subject.UserID).Scan(&sessions); err != nil || sessions != 1 {
		t.Fatalf("rejected login persisted a session: count=%d err=%v", sessions, err)
	}
	if err := service.RefreshSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, raw); err == nil {
		t.Fatal("revoked prior session remained usable")
	}
	resolved, current, err := store.resolve(ctx, "demo", "https://issuer.example.test", principal)
	if err != nil || resolved.UserID != subject.UserID || current != epoch+1 {
		t.Fatalf("identity did not retain current epoch: %+v epoch=%d err=%v", resolved, current, err)
	}
	raw, err = login(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RefreshSessions(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Authenticate(ctx, raw); err != nil {
		t.Fatalf("fresh login after revocation failed: %v", err)
	}
}
