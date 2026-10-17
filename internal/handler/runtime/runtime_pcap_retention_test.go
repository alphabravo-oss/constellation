package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func expirePcap(t *testing.T, f *pcapFilesFixture, id uuid.UUID) {
	t.Helper()
	if _, err := f.d.Pool().Exec(t.Context(), `UPDATE runtime_pcap_captures SET expires_at=now()-interval '1 hour' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
}
func requirePcapReceiptCount(t *testing.T, f *pcapFilesFixture, id uuid.UUID, want int) {
	t.Helper()
	var got int
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT count(*) FROM runtime_pcap_captures WHERE id=$1`, id).Scan(&got); err != nil || got != want {
		t.Fatalf("receipt count=%d want%d err=%v", got, want, err)
	}
}
func retainedPcapFile(t *testing.T, f *pcapFilesFixture, id uuid.UUID) {
	t.Helper()
	file, err := f.root.OpenFile(pcapFileName(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(file, "synthetic private capture")
	if err = errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
}
func TestPcapRetentionGlobalOwnedRowsAndNoOrphanGuessing(t *testing.T) {
	f := pcapFilesDB(t)
	first, second, unexpired := f.capture(t, "completed"), f.capture(t, "failed"), f.capture(t, "completed")
	orphan := uuid.New()
	for _, id := range []uuid.UUID{first, second, unexpired, orphan} {
		retainedPcapFile(t, f, id)
	}
	// Global trusted maintenance must expire both organizations, but only by UUID.
	if _, err := f.d.Pool().Exec(t.Context(), `UPDATE runtime_pcap_captures SET org_id=$2,cluster_id=$3 WHERE id=$1`, second, uuid.New(), uuid.New()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.d.Pool().Exec(context.WithoutCancel(t.Context()), `DELETE FROM runtime_pcap_captures WHERE id=$1`, second)
	})
	outside := filepath.Join(t.TempDir(), "preserved.pcap")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Pool().Exec(t.Context(), `UPDATE runtime_pcap_captures SET file_path=$2 WHERE id=$1`, first, outside); err != nil {
		t.Fatal(err)
	}
	expirePcap(t, f, first)
	expirePcap(t, f, second)
	n, err := f.h.SweepExpired(t.Context(), nil)
	if err != nil || n != 2 {
		t.Fatalf("sweep=%d err=%v", n, err)
	}
	for _, id := range []uuid.UUID{first, second} {
		requirePcapReceiptCount(t, f, id, 0)
		if _, err = f.root.Stat(pcapFileName(id)); !os.IsNotExist(err) {
			t.Fatal("expired file remains")
		}
	}
	requirePcapReceiptCount(t, f, unexpired, 1)
	for _, id := range []uuid.UUID{unexpired, orphan} {
		requirePcapBody(t, f.root, pcapFileName(id), "synthetic private capture")
	}
	raw, err := readPcapFixture(t, outside)
	if err != nil || string(raw) != "outside" {
		t.Fatal("used DB-authored arbitrary path")
	}
}
func TestPcapRetentionRemovalFailureRetainsReceiptAndRetries(t *testing.T) {
	f := pcapFilesDB(t)
	failed, healthy := f.capture(t, "completed"), f.capture(t, "completed")
	expirePcap(t, f, failed)
	expirePcap(t, f, healthy)
	retainedPcapFile(t, f, healthy)
	// A nonregular UUID entry is never recursively removed, nor does it block others.
	if err := f.root.Mkdir(pcapFileName(failed), 0o700); err != nil {
		t.Fatal(err)
	}
	n, err := f.h.SweepExpired(t.Context(), nil)
	if n != 1 || err == nil {
		t.Fatalf("failure sweep=%d err=%v", n, err)
	}
	requirePcapReceiptCount(t, f, failed, 1)
	requirePcapReceiptCount(t, f, healthy, 0)
	if err = f.root.Remove(pcapFileName(failed)); err != nil {
		t.Fatal(err)
	}
	retainedPcapFile(t, f, failed)
	if n, err = f.h.SweepExpired(t.Context(), nil); n != 1 || err != nil {
		t.Fatalf("retry=%d err=%v", n, err)
	}
	requirePcapReceiptCount(t, f, failed, 0)
}
func TestPcapRetentionSymlinkedRootPreservesOutsideAndReceipt(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "completed")
	expirePcap(t, f, id)
	outside := t.TempDir()
	outsideInfo, err := os.Stat(outside)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(outside, pcapFileName(id))
	if err := os.WriteFile(path, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	original := pcapDataDir()
	if err := os.Rename(original, original+"-preserved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, original); err != nil {
		t.Fatal(err)
	}
	n, err := f.h.SweepExpired(t.Context(), nil)
	if n != 0 || err == nil {
		t.Fatalf("symlink accepted %d %v", n, err)
	}
	requirePcapReceiptCount(t, f, id, 1)
	raw, err := readPcapFixture(t, path)
	if err != nil || string(raw) != "outside" {
		t.Fatal("outside changed")
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != outsideInfo.Mode().Perm() {
		t.Fatal("outside mode changed")
	}
	if err = os.Remove(original); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(original+"-preserved", original); err != nil {
		t.Fatal(err)
	}
	if n, err = f.h.SweepExpired(t.Context(), nil); n != 1 || err != nil {
		t.Fatalf("repaired retry=%d %v", n, err)
	}
}
func TestPcapRetentionBoundedBatchAndExpiryRecheck(t *testing.T) {
	f := pcapFilesDB(t)
	if _, err := f.d.Pool().Exec(t.Context(), `INSERT INTO runtime_pcap_captures(org_id,cluster_id,workload,namespace,requested_by,expires_at) SELECT $1,$2,'prod/api','prod',$3,now()-interval '1 day' FROM generate_series(1,105)`, f.org, f.cluster, f.user); err != nil {
		t.Fatal(err)
	}
	n, err := f.h.SweepExpired(t.Context(), nil)
	if n != pcapRetentionBatch || err != nil {
		t.Fatalf("batch=%d %v", n, err)
	}
	n, err = f.h.SweepExpired(t.Context(), nil)
	if n != 5 || err != nil {
		t.Fatalf("next batch=%d %v", n, err)
	}
	id := f.capture(t, "completed")
	retainedPcapFile(t, f, id)
	// A candidate whose expiry was renewed or whose identity no longer matches is skipped.
	for _, c := range []expiredPcap{{id, f.org, f.cluster}, {id, uuid.New(), f.cluster}} {
		n, err := f.h.removeExpiredPcap(t.Context(), c, f.root)
		if n || err != nil {
			t.Fatalf("stale candidate removed: %v %v", n, err)
		}
	}
	requirePcapReceiptCount(t, f, id, 1)
	requirePcapBody(t, f.root, pcapFileName(id), "synthetic private capture")
}
func TestPcapRetentionDatabaseDeleteFailureRetriesAbsentFile(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "completed")
	expirePcap(t, f, id)
	retainedPcapFile(t, f, id)
	name := "pcap_retention_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	q := `CREATE FUNCTION ` + name + `() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id='` + id.String() + `'::uuid THEN RAISE EXCEPTION 'injected retention failure'; END IF; RETURN OLD; END $$; CREATE TRIGGER ` + name + ` BEFORE DELETE ON runtime_pcap_captures FOR EACH ROW EXECUTE FUNCTION ` + name + `() `
	if _, err := f.d.Pool().Exec(t.Context(), q); err != nil {
		t.Fatal(err)
	}
	drop := func() {
		_, err := f.d.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+name+` ON runtime_pcap_captures; DROP FUNCTION IF EXISTS `+name+`() `)
		if err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(drop)
	n, err := f.h.SweepExpired(t.Context(), nil)
	if n != 0 || err == nil {
		t.Fatalf("delete failure=%d %v", n, err)
	}
	requirePcapReceiptCount(t, f, id, 1)
	if _, err = f.root.Stat(pcapFileName(id)); !os.IsNotExist(err) {
		t.Fatal("expired file not removed before delete")
	}
	drop()
	if n, err = f.h.SweepExpired(t.Context(), nil); n != 1 || err != nil {
		t.Fatalf("retry missing file=%d %v", n, err)
	}
}
func TestPcapRetentionLoopRetriesAndCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var calls atomic.Int32
	done := make(chan struct{})
	entered := make(chan struct{})
	go func() {
		defer close(done)
		runPcapRetention(ctx, nil, time.Millisecond, func(ctx context.Context, _ *slog.Logger) (int, error) {
			if _, ok := ctx.Deadline(); !ok {
				t.Error("sweep has no bounded deadline")
			}
			if calls.Add(1) == 1 {
				return 0, errors.New("retry me")
			}
			close(entered)
			<-ctx.Done()
			return 0, ctx.Err()
		})
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("failed sweep never retried")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not cancel in-flight sweep")
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected repeated cycle after cancellation")
	}
	alreadyCanceled, stop := context.WithCancel(t.Context())
	stop()
	runPcapRetention(alreadyCanceled, nil, time.Minute, func(context.Context, *slog.Logger) (int, error) { t.Error("started canceled sweep"); return 0, nil })
}

func fairPcapCandidates(t *testing.T, f *pcapFilesFixture) (uuid.UUID, uuid.UUID) {
	t.Helper()
	first := uuid.MustParse("00000000-0000-4000-8000-000000000001")
	healthy := uuid.MustParse("ffffffff-ffff-4fff-bfff-ffffffffffff")
	if _, err := f.d.Pool().Exec(t.Context(), `INSERT INTO runtime_pcap_captures(id,org_id,cluster_id,workload,namespace,requested_by,expires_at) SELECT ('00000000-0000-4000-8000-'||lpad(i::text,12,'0'))::uuid,$1,$2,'prod/api','prod',$3,now()-interval '1 day' FROM generate_series(1,105) i`, f.org, f.cluster, f.user); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.Pool().Exec(t.Context(), `INSERT INTO runtime_pcap_captures(id,org_id,cluster_id,workload,namespace,requested_by,expires_at) VALUES($1,$2,$3,'prod/api','prod',$4,now()-interval '1 hour')`, healthy, uuid.New(), uuid.New(), f.user); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.d.Pool().Exec(context.WithoutCancel(t.Context()), `DELETE FROM runtime_pcap_captures WHERE id=$1`, healthy)
	})
	retainedPcapFile(t, f, healthy)
	return first, healthy
}
func TestPcapRetentionFairCyclePastMoreThan100Failures(t *testing.T) {
	f := pcapFilesDB(t)
	first, healthy := fairPcapCandidates(t, f)
	for i := 1; i <= 105; i++ {
		id := uuid.MustParse("00000000-0000-4000-8000-" + fmt.Sprintf("%012d", i))
		if err := f.root.Mkdir(pcapFileName(id), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 0 || err == nil {
		t.Fatalf("first failures=%d %v", n, err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 1 || err == nil {
		t.Fatalf("later tenant starved=%d %v", n, err)
	}
	requirePcapReceiptCount(t, f, healthy, 0)
	requirePcapReceiptCount(t, f, first, 1)
	if err := f.root.Remove(pcapFileName(first)); err != nil {
		t.Fatal(err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 1 || err == nil {
		t.Fatalf("failed receipt not revisited after wrap=%d %v", n, err)
	}
	requirePcapReceiptCount(t, f, first, 0)
}
func TestPcapRetentionFairCyclePastMoreThan100LockedRows(t *testing.T) {
	f := pcapFilesDB(t)
	first, healthy := fairPcapCandidates(t, f)
	tx, err := f.d.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(t.Context())) }()
	if _, err = tx.Exec(t.Context(), `SELECT id FROM runtime_pcap_captures WHERE org_id=$1 FOR UPDATE`, f.org); err != nil {
		t.Fatal(err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 0 || err != nil {
		t.Fatalf("locked page=%d %v", n, err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 1 || err != nil {
		t.Fatalf("later tenant starved=%d %v", n, err)
	}
	requirePcapReceiptCount(t, f, healthy, 0)
	requirePcapReceiptCount(t, f, first, 1)
	if err = tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 100 || err != nil {
		t.Fatalf("unlocked wrap=%d %v", n, err)
	}
	if n, err := f.h.SweepExpired(t.Context(), nil); n != 5 || err != nil {
		t.Fatalf("unlocked remainder=%d %v", n, err)
	}
}
func TestPcapRetentionDaemonRequiresExplicitStorageConfirmation(t *testing.T) {
	// These must return without querying even a nil DB: old local/ephemeral stores
	// are not silently treated as a shared global artifact inventory.
	t.Setenv("CONSTELLATION_DATA_DIR", t.TempDir())
	t.Setenv("CONSTELLATION_PCAP_RETENTION_ENABLED", "")
	RunPcapRetention(t.Context(), nil, nil)
	t.Setenv("CONSTELLATION_PCAP_RETENTION_ENABLED", "true")
	t.Setenv("CONSTELLATION_DATA_DIR", "")
	RunPcapRetention(t.Context(), nil, nil)
}

func TestPcapRetentionPinnedRootSwapKeepsReceiptAndBothArtifacts(t *testing.T) {
	f := pcapFilesDB(t)
	id := f.capture(t, "completed")
	expirePcap(t, f, id)
	retainedPcapFile(t, f, id)
	original := pcapDataDir()
	if err := os.Rename(original, original+"-preserved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0o700); err != nil {
		t.Fatal(err)
	}
	replacement, err := os.OpenRoot(original)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = replacement.Close() }()
	file, err := replacement.OpenFile(pcapFileName(id), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(file, "replacement artifact")
	if err = errors.Join(writeErr, file.Close()); err != nil {
		t.Fatal(err)
	}
	if n, err := f.h.sweepExpired(t.Context(), nil, f.root); n != 0 || err == nil {
		t.Fatalf("root swap not rejected=%d %v", n, err)
	}
	requirePcapReceiptCount(t, f, id, 1)
	requirePcapBody(t, f.root, pcapFileName(id), "synthetic private capture")
	requirePcapBody(t, replacement, pcapFileName(id), "replacement artifact")
}
