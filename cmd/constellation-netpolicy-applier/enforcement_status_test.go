//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/netpolicyapply"

	"github.com/google/uuid"
)

func TestEnforcementStatusCannotOverwriteNewerIntent(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pool := pgtest.Pool(t)
	org, cluster, id := uuid.New(), uuid.New(), uuid.New()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'status')`, org, org.String())
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM network_enforcement_actions WHERE org_id=$1`, org)
		_, _ = pool.Exec(ctx, `DELETE FROM orgs WHERE id=$1`, org)
	}()
	exec(`INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'status')`, cluster, org)
	exec(`INSERT INTO network_enforcement_actions(id,org_id,cluster_id,kind,target,manifest_flavor,manifest,state) VALUES($1,$2,$3,'isolate','team/api','native','{}','lifting')`, id, org, cluster)
	assert := func(wantState, wantStatus, wantError string, applied, deleted bool) {
		t.Helper()
		var state, status, message string
		var gotApplied, gotDeleted bool
		if err := pool.QueryRow(ctx, `SELECT state,last_status,last_error,last_applied_at IS NOT NULL,last_deleted_at IS NOT NULL FROM network_enforcement_actions WHERE id=$1`, id).Scan(&state, &status, &message, &gotApplied, &gotDeleted); err != nil {
			t.Fatal(err)
		}
		if state != wantState || status != wantStatus || message != wantError || gotApplied != applied || gotDeleted != deleted {
			t.Fatalf("state/status/error=%s/%s/%s timestamps=%v/%v", state, status, message, gotApplied, gotDeleted)
		}
	}
	// The applier read active, then the user requested removal before it reported.
	updateEnforcementStatus(ctx, pool, id.String(), "active", "ok", "", "")
	assert("lifting", "", "", false, false)
	updateEnforcementStatus(ctx, pool, id.String(), "active", "error", "old apply failure", "")
	assert("lifting", "", "", false, false)
	updateEnforcementStatus(ctx, pool, id.String(), "lifting", "error", "delete forbidden", "")
	assert("lifting", "error", "delete forbidden", false, false)
	updateEnforcementStatus(ctx, pool, id.String(), "lifting", "ok", "", "removed")
	assert("removed", "ok", "", false, true)
	// A delayed failure from an older reconcile cannot revive a removed action.
	updateEnforcementStatus(ctx, pool, id.String(), "lifting", "error", "late failure", "")
	assert("removed", "ok", "", false, true)
	client := &statusTestClient{verifyLock: func() {
		var state string
		err := pool.QueryRow(ctx, `SELECT state FROM network_enforcement_actions WHERE id=$1 FOR UPDATE NOWAIT`, id).Scan(&state)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "55P03" {
			t.Fatalf("Kubernetes operation executed without intent lock: %v", err)
		}
	}}
	manifest := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolation
  namespace: team
spec: {}`
	if err := reconcileEnforcementAction(ctx, pool, client, id.String(), "native", manifest, "active"); err != nil {
		t.Fatal(err)
	}
	if client.applies != 0 || client.deletes != 0 {
		t.Fatal("stale active snapshot recreated removed policy")
	}
	exec(`UPDATE network_enforcement_actions SET state='active',last_status='',last_error='' WHERE id=$1`, id)
	if err := reconcileEnforcementAction(ctx, pool, client, id.String(), "native", manifest, "active"); err != nil {
		t.Fatal(err)
	}
	assert("active", "ok", "", true, true)
	exec(`UPDATE network_enforcement_actions SET state='lifting',last_status='',last_error='' WHERE id=$1`, id)
	client.err = fmt.Errorf("delete forbidden")
	if err := reconcileEnforcementAction(ctx, pool, client, id.String(), "native", manifest, "lifting"); err != nil {
		t.Fatal(err)
	}
	assert("lifting", "error", "delete forbidden", true, true)
	client.err = nil
	if err := reconcileEnforcementAction(ctx, pool, client, id.String(), "native", manifest, "lifting"); err != nil {
		t.Fatal(err)
	}
	assert("removed", "ok", "", true, true)
	if client.applies != 1 || client.deletes != 2 {
		t.Fatalf("operation counts %d/%d", client.applies, client.deletes)
	}
}

type statusTestClient struct {
	verifyLock       func()
	applies, deletes int
	err              error
}

func (c *statusTestClient) Apply(context.Context, netpolicyapply.ManifestResource, []byte) error {
	if c.verifyLock != nil {
		c.verifyLock()
	}
	c.applies++
	return c.err
}
func (c *statusTestClient) Delete(context.Context, netpolicyapply.ManifestResource) error {
	if c.verifyLock != nil {
		c.verifyLock()
	}
	c.deletes++
	return c.err
}
