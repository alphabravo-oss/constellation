//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestAuditVerifyChainNullableMetadata(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"null-request", "null-targets", "tampered-request"} {
		t.Run(kind, func(t *testing.T) {
			// Never truncate or append synthetic test content to the real global chain.
			admin := pgtest.Pool(t)
			schema := "audit_nullable_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			quoted := pgx.Identifier{schema}.Sanitize()
			if _, err := admin.Exec(t.Context(), "CREATE SCHEMA "+quoted); err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE") }()
			if _, err := admin.Exec(t.Context(), "CREATE TABLE "+quoted+".audit_events (LIKE public.audit_events INCLUDING ALL); CREATE SEQUENCE "+quoted+".audit_events_id_seq START WITH 2; ALTER TABLE "+quoted+".audit_events ALTER COLUMN id SET DEFAULT nextval('"+schema+".audit_events_id_seq')"); err != nil {
				t.Fatal(err)
			}
			config := admin.Config()
			config.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
			pool, err := pgxpool.NewWithConfig(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			at := time.Date(2026, 10, 13, 3, 0, 0, 123456000, time.UTC)
			event := Event{Action: "test.nullable", TargetKind: "workload", TargetID: "team/api", At: at}
			var targetKind, targetID any = event.TargetKind, event.TargetID
			if kind == "null-targets" {
				event.TargetKind = ""
				event.TargetID = ""
				targetKind = nil
				targetID = nil
			}
			if kind == "tampered-request" {
				event.RequestID = "different-canonical-request"
			}
			before, _ := json.Marshal(event.Before)
			after, _ := json.Marshal(event.After)
			hash := computeChainHash(GenesisHash, event, before, after, at)
			if _, err := pool.Exec(t.Context(), `INSERT INTO audit_events(id,action,target_kind,target_id,before,after,prev_hash,chain_hash,request_id,at) VALUES(1,$1,$2,$3,$4,$5,$6,$7,NULL,$8)`, event.Action, targetKind, targetID, before, after, GenesisHash, hash, at); err != nil {
				t.Fatal(err)
			}
			if _, _, err := New(pool).Log(t.Context(), Event{Action: "test.after_nullable", RequestID: "nonempty-request"}); err != nil {
				t.Fatal(err)
			}
			broken, err := VerifyChain(t.Context(), pool)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "tampered-request" {
				if broken == nil || broken.ID != 1 || broken.Reason != "row hash mismatch" {
					t.Fatalf("nullable corruption silently accepted: %v", broken)
				}
			} else if broken != nil {
				t.Fatalf("valid nullable chain rejected: %v", broken)
			}
		})
	}
}
