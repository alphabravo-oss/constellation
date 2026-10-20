//go:build integration

package syscfg

import (
	"context"
	"encoding/json"
	"testing"

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
