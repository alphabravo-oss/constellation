//go:build integration

package syscfg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/testutil/pgfixture"
)

func TestRetentionDefaultsPreserveStoredHolds(t *testing.T) {
	cfg := Default()
	if cfg.EventsRetentionDays != 30 || cfg.NetworkFlowRetentionDays != 14 || cfg.ScanJobRetentionDays != 7 {
		t.Fatalf("unbounded new install: %+v", cfg)
	}
	for _, raw := range []string{`{}`, `{"events_retention_days":0,"network_flow_retention_days":0,"scan_job_retention_days":0}`} {
		stored, err := unmarshalStoredConfig(json.RawMessage(raw))
		if err != nil {
			t.Fatal(err)
		}
		if stored.EventsRetentionDays != 0 || stored.NetworkFlowRetentionDays != 0 || stored.ScanJobRetentionDays != 0 {
			t.Fatal("existing hold replaced by defaults")
		}
	}
	cfg.EventsRetentionDays = 0
	blob, err := marshalStoredConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := unmarshalStoredConfig(blob)
	if err != nil || stored.EventsRetentionDays != 0 || stored.NetworkFlowRetentionDays != 14 {
		t.Fatalf("hold roundtrip: %+v %v", stored, err)
	}
}

func TestRetentionFirstBootSeedPreservesExistingPolicy(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	ctx := t.Context()
	var org uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs WHERE name='demo'`).Scan(&org); err != nil {
		t.Fatal(err)
	}
	fresh, revision, err := Seed(ctx, pool, org, Default())
	if err != nil || revision != 1 || fresh.EventsRetentionDays != 30 || fresh.NetworkFlowRetentionDays != 14 || fresh.ScanJobRetentionDays != 7 {
		t.Fatalf("fresh persisted defaults: %+v revision=%d err=%v", fresh, revision, err)
	}
	fresh.EventsRetentionDays, fresh.NetworkFlowRetentionDays, fresh.ScanJobRetentionDays = 0, 60, 0
	revision, err = Save(ctx, pool, org, fresh, revision, nil)
	if err != nil {
		t.Fatal(err)
	}
	stored, gotRevision, err := Seed(ctx, pool, org, Default())
	if err != nil || gotRevision != revision || stored.EventsRetentionDays != 0 || stored.NetworkFlowRetentionDays != 60 || stored.ScanJobRetentionDays != 0 {
		t.Fatalf("repeat bootstrap overwrote holds/custom policy: %+v revision=%d err=%v", stored, gotRevision, err)
	}
}

func TestEffectiveRetentionKeepsFamilyHoldsIndependent(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	ctx := t.Context()
	var first, second uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs WHERE name='demo'`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO orgs(name,display_name) VALUES('retention-second','Retention second') RETURNING id`).Scan(&second); err != nil {
		t.Fatal(err)
	}
	a, b := Default(), Default()
	a.EventsRetentionDays, a.NetworkFlowRetentionDays, a.ScanJobRetentionDays = 7, 60, 30
	b.EventsRetentionDays, b.NetworkFlowRetentionDays, b.ScanJobRetentionDays = 90, 14, 7
	var revisionA, revisionB int64
	for _, phase := range []string{"longest", "event hold", "flow hold"} {
		if phase == "event hold" {
			a.EventsRetentionDays = 0
		}
		if phase == "flow hold" {
			b.NetworkFlowRetentionDays = 0
		}
		var err error
		if revisionA, err = Save(ctx, pool, first, a, revisionA, nil); err != nil {
			t.Fatal(err)
		}
		if revisionB, err = Save(ctx, pool, second, b, revisionB, nil); err != nil {
			t.Fatal(err)
		}
		events, flows := 90, 60
		if phase != "longest" {
			events = 0
		}
		if phase == "flow hold" {
			flows = 0
		}
		for _, family := range []struct {
			name string
			pick func(Config) int
			want int
		}{
			{"events", func(c Config) int { return c.EventsRetentionDays }, events},
			{"flows", func(c Config) int { return c.NetworkFlowRetentionDays }, flows},
			{"jobs", func(c Config) int { return c.ScanJobRetentionDays }, 30},
		} {
			if got, err := EffectiveRetentionDays(ctx, pool, family.pick); err != nil || got != family.want {
				t.Fatalf("%s / %s: got=%d want=%d err=%v", phase, family.name, got, family.want, err)
			}
		}
	}
}

func TestEffectiveRetentionRespectsEveryOrgAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	database := db.NewFromPool(pgtest.Pool(t))
	pool := pgfixture.Schema(t, database.Pool())
	if _, err := pool.Exec(ctx, `CREATE TABLE orgs(id int PRIMARY KEY); CREATE TABLE system_config(org_id int PRIMARY KEY,config jsonb); INSERT INTO orgs VALUES(1),(2); INSERT INTO system_config VALUES (1,'{"events_retention_days":7}'),(2,'{"events_retention_days":90}');`); err != nil {
		t.Fatal(err)
	}
	pick := func(c Config) int { return c.EventsRetentionDays }
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err != nil || got != 90 {
		t.Fatalf("longest org: %d %v", got, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE system_config SET config='{"events_retention_days":0}' WHERE org_id=1`); err != nil {
		t.Fatal(err)
	}
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err != nil || got != 0 {
		t.Fatalf("hold: %d %v", got, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE system_config SET config='{}' WHERE org_id=1`); err != nil {
		t.Fatal(err)
	}
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err != nil || got != 0 {
		t.Fatalf("legacy hold: %d %v", got, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE system_config SET config='{"events_retention_days":-1}' WHERE org_id=1`); err != nil {
		t.Fatal(err)
	}
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err == nil || got != 0 {
		t.Fatalf("invalid config: %d %v", got, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM system_config`); err != nil {
		t.Fatal(err)
	}
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err != nil || got != 30 {
		t.Fatalf("new orgs: %d %v", got, err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE system_config`); err != nil {
		t.Fatal(err)
	}
	if got, err := EffectiveRetentionDays(ctx, pool, pick); err == nil || got != 0 {
		t.Fatalf("read failure: %d %v", got, err)
	}
}
