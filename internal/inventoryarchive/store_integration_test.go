//go:build integration

package inventoryarchive

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/server/database"
	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"
)

func seedTarget(t *testing.T, pool *pgxpool.Pool, identity targetIdentity) (uuid.UUID, uuid.UUID) {
	t.Helper()
	var org, target uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO orgs(name,display_name) VALUES($1,$1) RETURNING id`, uuid.NewString()).Scan(&org); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(t.Context(), `INSERT INTO scan_targets(org_id,type,ref,source_type,source_ref) VALUES($1,$2,$3,$4,$5) RETURNING id`, org, identity.Type, identity.Ref, identity.SourceType, identity.SourceRef).Scan(&target); err != nil {
		t.Fatal(err)
	}
	return org, target
}

func TestInventoryIndependentRestore(t *testing.T) {
	t.Parallel()
	source := pgtest.Pool(t)
	private, public := keys(t)
	row, identity := fixture()
	row.OrgID, row.TargetID = seedTarget(t, source, identity)
	raw, _ := json.Marshal(row)
	if _, err := source.Exec(t.Context(), `INSERT INTO scan_evidence SELECT * FROM jsonb_populate_record(NULL::scan_evidence,$1::jsonb)`, raw); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Export(t.Context(), source, uuid.New(), row.ID, private, public); err == nil {
		t.Fatal("cross-organization export succeeded")
	}
	data, report, err := Export(t.Context(), source, row.OrgID, row.ID, private, public)
	if err != nil {
		t.Fatal(err)
	}
	var unchanged bool
	if err = source.QueryRow(t.Context(), `SELECT to_jsonb(e)=to_jsonb(jsonb_populate_record(NULL::scan_evidence,$2::jsonb)) FROM scan_evidence e WHERE id=$1`, row.ID, raw).Scan(&unchanged); err != nil || !unchanged {
		t.Fatalf("export changed source: %v", err)
	}
	source.Close()
	dest, err := pgxpool.New(t.Context(), pgtest.FreshURL(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dest.Close)
	if _, err = database.MigratePool(t.Context(), dest, slog.Default()); err != nil {
		t.Fatal(err)
	}
	org, target := seedTarget(t, dest, identity)
	if _, err = Restore(t.Context(), dest, bytes.NewReader(data), public, uuid.New(), target); err == nil {
		t.Fatal("foreign target accepted")
	}
	badIdentity := identity
	badIdentity.Ref = "different-target"
	badOrg, badTarget := seedTarget(t, dest, badIdentity)
	if _, err = Restore(t.Context(), dest, bytes.NewReader(data), public, badOrg, badTarget); err == nil {
		t.Fatal("different target accepted")
	}
	_, wrong := keys(t)
	if _, err = Restore(t.Context(), dest, bytes.NewReader(data), wrong, org, target); err == nil {
		t.Fatal("wrong key accepted")
	}
	for i := 0; i < 2; i++ {
		got, err := Restore(t.Context(), dest, bytes.NewReader(data), public, org, target)
		if err != nil || got.Inserted != (i == 0) || got.Report != report {
			t.Fatalf("restore %d: %+v %v", i, got, err)
		}
	}
	var inventories, receipts int
	var payloadSame bool
	if err = dest.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM scan_evidence),(SELECT count(*) FROM audit_events WHERE action='scan.evidence.restore'),(SELECT payload=$2::jsonb FROM scan_evidence WHERE id=$1 AND org_id=$3 AND scan_target_id=$4)`, row.ID, row.Payload, org, target).Scan(&inventories, &receipts, &payloadSame); err != nil {
		t.Fatal(err)
	}
	if inventories != 1 || receipts != 1 || !payloadSame {
		t.Fatalf("incorrect restored evidence: %d %d %v", inventories, receipts, payloadSame)
	}
	if _, err = dest.Exec(t.Context(), `UPDATE scan_evidence SET payload='{"changed":true}' WHERE id=$1`, row.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(t.Context(), dest, bytes.NewReader(data), public, org, target); err == nil {
		t.Fatal("conflicting evidence overwritten")
	}
}

func TestInventoryAuditFailureRollsBack(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := keys(t)
	row, identity := fixture()
	org, target := seedTarget(t, pool, identity)
	data, _, err := encode(t.Context(), row, identity, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(t.Context(), `CREATE FUNCTION reject_inventory_receipt() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture audit unavailable'; END $$;
 CREATE TRIGGER reject_inventory_receipt BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_inventory_receipt()`); err != nil {
		t.Fatal(err)
	}
	if _, err = Restore(t.Context(), pool, bytes.NewReader(data), public, org, target); err == nil {
		t.Fatal("restore committed without audit receipt")
	}
	var count int
	if err = pool.QueryRow(t.Context(), `SELECT count(*) FROM scan_evidence WHERE id=$1`, row.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rollback failed: %d %v", count, err)
	}
}

func TestRestoreRejectsForeignTargetCluster(t *testing.T) {
	t.Parallel()
	pool := pgtest.Pool(t)
	private, public := keys(t)
	row, identity := fixture()
	org, target := seedTarget(t, pool, identity)
	foreign, _ := seedTarget(t, pool, identity)
	var cluster uuid.UUID
	if err := pool.QueryRow(t.Context(), `INSERT INTO clusters(org_id,name) VALUES($1,'foreign-cluster') RETURNING id`, foreign).Scan(&cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE scan_targets SET cluster_id=$2 WHERE id=$1`, target, cluster); err != nil {
		t.Fatal(err)
	}
	data, _, err := encode(t.Context(), row, identity, private, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(t.Context(), pool, bytes.NewReader(data), public, org, target); err == nil {
		t.Fatal("foreign cluster binding accepted")
	}
	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM scan_evidence WHERE id=$1`, row.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("foreign evidence inserted: %d %v", count, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE clusters SET org_id=$2 WHERE id=$1`, cluster, org); err != nil {
		t.Fatal(err)
	}
	if result, err := Restore(t.Context(), pool, bytes.NewReader(data), public, org, target); err != nil || !result.Inserted {
		t.Fatalf("valid cluster mapping failed: %+v %v", result, err)
	}
}
