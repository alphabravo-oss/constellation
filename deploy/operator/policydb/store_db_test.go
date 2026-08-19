package policydb

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/responserule"
)

// openTestPool connects to the test DB, skipping when unreachable. It provisions the schema
// the store needs (orgs + policies + response_rules) and ensures the source provenance column,
// so the test is self-contained against a bare or fully-migrated database.
func openTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		url = os.Getenv("CONSTELLATION_TEST_DATABASE_URL")
	}
	if url == "" {
		url = "postgres://constellation:constellation@localhost:15433/constellation_test?sslmode=disable"
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Skipf("skipping: cannot reach test DB (%v)", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("skipping: cannot ping test DB (%v)", err)
	}
	stmts := []string{
		`CREATE EXTENSION IF NOT EXISTS pgcrypto`,
		`CREATE TABLE IF NOT EXISTS orgs (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT UNIQUE NOT NULL,
			display_name TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS policies (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			description TEXT,
			engine TEXT NOT NULL,
			category TEXT NOT NULL,
			spec_yaml TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT FALSE,
			mode TEXT NOT NULL DEFAULT 'monitor',
			version INTEGER NOT NULL DEFAULT 1,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (org_id, name, version))`,
		`CREATE TABLE IF NOT EXISTS response_rules (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			priority INTEGER NOT NULL DEFAULT 1000,
			event_type TEXT NOT NULL,
			conditions JSONB NOT NULL DEFAULT '[]'::jsonb,
			actions JSONB NOT NULL DEFAULT '[]'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (org_id, name))`,
		// Provenance column (migration 027 for policies, migration 108 for response_rules).
		// Idempotent: a no-op when the fully-migrated tables already carry it.
		`ALTER TABLE policies ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'imperative'`,
		`ALTER TABLE response_rules ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'imperative'`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			pool.Close()
			t.Skipf("skipping: cannot provision schema (%v)", err)
		}
	}
	return pool
}

func seedOrg(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	org := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1,$2,'Op B2b')`,
		org, "b2b-"+org.String()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org) })
	return org
}

func TestStore_AdmissionUpsertIdempotentDeleteScoped(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	org := seedOrg(t, pool)
	ctx := context.Background()
	s := New(pool)

	row := AdmissionRuleRow{OrgID: org, Name: "no-privileged", Engine: "kyverno", Mode: "enforce", Enabled: true, SpecYAML: "a: 1"}
	if err := s.UpsertAdmissionRule(ctx, row); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// Re-upsert with a changed field corrects drift on the same single row.
	row.Mode = "monitor"
	row.Enabled = false
	if err := s.UpsertAdmissionRule(ctx, row); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var count int
	var mode, source string
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT count(*), max(mode), bool_or(enabled), max(source) FROM policies WHERE org_id=$1 AND name=$2`,
		org, row.Name).Scan(&count, &mode, &enabled, &source); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 || mode != "monitor" || enabled || source != SourceDeclarative {
		t.Fatalf("row state count=%d mode=%s enabled=%v source=%s", count, mode, enabled, source)
	}

	// A REST-authored row with a different name must survive the operator's delete.
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id, name, engine, category, spec_yaml, enabled, mode) VALUES ($1,'rest-rule','kyverno','admission','x: 1',true,'enforce')`, org); err != nil {
		t.Fatalf("seed rest row: %v", err)
	}
	deleted, err := s.DeleteAdmissionRule(ctx, org, row.Name)
	if err != nil || !deleted {
		t.Fatalf("delete operator row: deleted=%v err=%v", deleted, err)
	}
	deleted, err = s.DeleteAdmissionRule(ctx, org, row.Name)
	if err != nil || deleted {
		t.Fatalf("second delete should be no-op: deleted=%v err=%v", deleted, err)
	}
	// Operator delete must not touch the REST row even if names matched (source guard).
	deleted, _ = s.DeleteAdmissionRule(ctx, org, "rest-rule")
	if deleted {
		t.Fatalf("operator delete removed a REST-authored row")
	}
	var restRemaining int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM policies WHERE org_id=$1 AND name='rest-rule'`, org).Scan(&restRemaining)
	if restRemaining != 1 {
		t.Fatalf("rest row missing after operator delete")
	}
}

// TestStore_UpsertRefusesImperativeClobber proves the upsert conflict path is source-guarded: a CR
// whose (org, name) collides with a pre-existing imperative (REST/UI-authored) row must NOT overwrite
// or relabel it — the upsert returns ErrImperativeConflict and the imperative row is left intact.
func TestStore_UpsertRefusesImperativeClobber(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	org := seedOrg(t, pool)
	ctx := context.Background()
	s := New(pool)

	// Seed an imperative admission policy at version=1 (the version the operator owns).
	if _, err := pool.Exec(ctx, `INSERT INTO policies (org_id, name, engine, category, spec_yaml, enabled, mode, version, source)
		VALUES ($1,'shared','kyverno','admission','rest: 1',true,'enforce',1,'imperative')`, org); err != nil {
		t.Fatalf("seed imperative policy: %v", err)
	}
	err := s.UpsertAdmissionRule(ctx, AdmissionRuleRow{
		OrgID: org, Name: "shared", Engine: "kyverno", Mode: "monitor", Enabled: false, SpecYAML: "cr: 1"})
	if !errors.Is(err, ErrImperativeConflict) {
		t.Fatalf("upsert over imperative row: want ErrImperativeConflict, got %v", err)
	}
	var mode, spec, source string
	var enabled bool
	if err := pool.QueryRow(ctx, `SELECT mode, enabled, spec_yaml, source FROM policies WHERE org_id=$1 AND name='shared'`,
		org).Scan(&mode, &enabled, &spec, &source); err != nil {
		t.Fatalf("query: %v", err)
	}
	if mode != "enforce" || !enabled || spec != "rest: 1" || source != "imperative" {
		t.Fatalf("imperative policy clobbered: mode=%s enabled=%v spec=%s source=%s", mode, enabled, spec, source)
	}

	// Same guard on response rules.
	if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, actions, source)
		VALUES ($1,'shared-rr','process','[{"type":"tag"}]'::jsonb,'imperative')`, org); err != nil {
		t.Fatalf("seed imperative rr: %v", err)
	}
	rerr := s.UpsertResponseRule(ctx, responserule.ResponseRule{
		OrgID: org, Name: "shared-rr", Enabled: false, Priority: 1, EventType: responserule.EventProcess,
		Actions: []responserule.Action{{Type: responserule.ActionQuarantine}}})
	if !errors.Is(rerr, ErrImperativeConflict) {
		t.Fatalf("upsert over imperative rr: want ErrImperativeConflict, got %v", rerr)
	}
	var rsource string
	if err := pool.QueryRow(ctx, `SELECT source FROM response_rules WHERE org_id=$1 AND name='shared-rr'`,
		org).Scan(&rsource); err != nil {
		t.Fatalf("query rr: %v", err)
	}
	if rsource != "imperative" {
		t.Fatalf("imperative rr clobbered: source=%s", rsource)
	}
}

func TestStore_ResponseUpsertIdempotentDeleteScoped(t *testing.T) {
	pool := openTestPool(t)
	defer pool.Close()
	org := seedOrg(t, pool)
	ctx := context.Background()
	s := New(pool)

	rule := responserule.ResponseRule{
		OrgID: org, Name: "curl-quarantine", Enabled: true, Priority: 10, EventType: responserule.EventProcess,
		Conditions: []responserule.Condition{{Field: "process_name", Op: responserule.OpContains, Value: "curl"}},
		Actions:    []responserule.Action{{Type: responserule.ActionQuarantine}},
	}
	if err := s.UpsertResponseRule(ctx, rule); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	rule.Priority = 5
	if err := s.UpsertResponseRule(ctx, rule); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	var count, prio int
	var source string
	if err := pool.QueryRow(ctx, `SELECT count(*), max(priority), max(source) FROM response_rules WHERE org_id=$1 AND name=$2`,
		org, rule.Name).Scan(&count, &prio, &source); err != nil {
		t.Fatalf("query: %v", err)
	}
	if count != 1 || prio != 5 || source != SourceDeclarative {
		t.Fatalf("row state count=%d prio=%d source=%s", count, prio, source)
	}

	// REST-authored response rule must survive the operator's delete (source guard).
	if _, err := pool.Exec(ctx, `INSERT INTO response_rules (org_id, name, event_type, actions) VALUES ($1,'rest-rr','process','[{"type":"tag"}]'::jsonb)`, org); err != nil {
		t.Fatalf("seed rest rr: %v", err)
	}
	deleted, err := s.DeleteResponseRule(ctx, org, rule.Name)
	if err != nil || !deleted {
		t.Fatalf("delete operator rr: deleted=%v err=%v", deleted, err)
	}
	deleted, _ = s.DeleteResponseRule(ctx, org, "rest-rr")
	if deleted {
		t.Fatalf("operator delete removed a REST-authored response rule")
	}
}
