//go:build integration

package storagehealth

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func TestAuditSourceIsolationAndFreshness(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	org := uuid.New()
	cfg := Config{AuditSources: AuditSources{MaxGap: 15 * time.Minute}}
	now := time.Now().UTC().Truncate(time.Second)
	for range 6 {
		cfg.AuditSources.Sources = append(cfg.AuditSources.Sources, AuditSource{OrgID: org, ClusterID: uuid.New()})
	}
	// Source zero has only another tenant's event. It must remain missing.
	execSQL(t, pool, `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,at,reported_at) VALUES($1,$2,'get',$3,$3)`, uuid.New(), cfg.AuditSources.Sources[0].ClusterID, now)
	for index, clocks := range []struct{ at, reported any }{
		{now.Add(-20 * time.Minute), now.Add(-20 * time.Minute)},
		{now, now},
		{now, now.Add(-time.Hour)},
		{now, nil},
		{now, now.Add(time.Hour)},
	} {
		execSQL(t, pool, `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,at,reported_at) VALUES($1,$2,'get',$3,$4)`, org, cfg.AuditSources.Sources[index+1].ClusterID, clocks.at, clocks.reported)
	}
	s, err := readSnapshot(t.Context(), pool, cfg)
	want := auditSourceHealth{Expected: 6, Missing: 1, Stale: 1, Delayed: 1, UnknownReported: 1, FutureReported: 1, OldestReceipt: epoch(now.Add(-20 * time.Minute))}
	if err != nil || s.AuditSources != want {
		t.Fatalf("source coverage=%+v want=%+v err=%v", s.AuditSources, want, err)
	}
	collector := New(pool, cfg, nil)
	// Mutating the caller's slice must not alter registered source expectations.
	cfg.AuditSources.Sources[1].OrgID = uuid.New()
	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(collector)
	metrics := gather(t, reg)
	if gauge(metrics, "k8s_audit_expected_sources") != 6 || gauge(metrics, "k8s_audit_missing_sources") != 1 || gauge(metrics, "k8s_audit_stale_sources") != 1 {
		t.Fatal("source metrics do not match snapshot")
	}
	cfg.AuditSources.Sources[1].OrgID = org
	// Historical presence never enables observation implicitly.
	if disabled := read(t, pool, ""); disabled.AuditSources != (auditSourceHealth{}) {
		t.Fatalf("inferred expected sources: %+v", disabled.AuditSources)
	}
	for _, source := range cfg.AuditSources.Sources {
		execSQL(t, pool, `INSERT INTO k8s_audit_events(org_id,cluster_id,verb,at,reported_at) VALUES($1,$2,'get',$3,$3)`, org, source.ClusterID, now.Add(time.Second))
	}
	s, err = readSnapshot(t.Context(), pool, cfg)
	want = auditSourceHealth{Expected: 6, OldestReceipt: epoch(now.Add(time.Second))}
	if err != nil || s.AuditSources != want {
		t.Fatalf("source recovery=%+v want=%+v err=%v", s.AuditSources, want, err)
	}
	var count int
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM k8s_audit_events`).Scan(&count); err != nil || count != 12 {
		t.Fatalf("observation changed evidence: count=%d err=%v", count, err)
	}
}
