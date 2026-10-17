package quarantine

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func privateQuarantine(t *testing.T, dir string, cols CollectorSet) *Quarantine {
	t.Helper()
	q, err := New(Options{OutputDir: dir, DryRun: true}, cols)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := q.Close(); err != nil {
			t.Error(err)
		}
	})
	return q
}

func TestSnapshotOutputIsPrivateAndSizeIsActualArchiveSize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snapshots")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	q := privateQuarantine(t, dir, CollectorSet{Proc: func(context.Context, int) (map[string][]byte, error) {
		return map[string][]byte{"environ": []byte("OWNED_PRIVATE_FIXTURE=value")}, nil
	}})
	result, err := q.Execute(t.Context(), Target{PID: 1, WorkloadID: "owned/workload"}, Trigger{})
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Stat(dir)
	if err != nil || directory.Mode().Perm() != 0o700 {
		t.Fatal("snapshot directory is not private")
	}
	file, err := os.Stat(result.TarballPath)
	if err != nil || file.Mode().Perm() != 0o600 || file.Size() != result.Bytes {
		t.Fatal("snapshot file permissions/size are incorrect")
	}
	parts, _, err := Restore(result.TarballPath)
	if err != nil || string(parts["proc/environ"]) != "OWNED_PRIVATE_FIXTURE=value" {
		t.Fatal("private snapshot lost original evidence")
	}
}

func TestSnapshotRejectsReplacedRootBeforeCollection(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "snapshots")
	var calls atomic.Int32
	q := privateQuarantine(t, dir, CollectorSet{Logs: func(context.Context, string, string, int) (map[string][]string, error) {
		calls.Add(1)
		return nil, nil
	}})
	moved := filepath.Join(parent, "retained")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, dir); err != nil {
		t.Fatal(err)
	}
	result, err := q.Execute(t.Context(), Target{}, Trigger{})
	if err == nil || result != nil || calls.Load() != 0 {
		t.Fatal("replaced root was accepted or collectors ran")
	}
	for _, path := range []string{outside, moved} {
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatal("root substitution wrote evidence")
		}
	}
}

func TestSnapshotRootSubstitutionRetainsOnlyPrivateCompleteArtifact(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "snapshots")
	moved := filepath.Join(parent, "retained")
	outside := t.TempDir()
	q := privateQuarantine(t, dir, CollectorSet{Proc: func(context.Context, int) (map[string][]byte, error) {
		if err := os.Rename(dir, moved); err != nil {
			return nil, err
		}
		if err := os.Symlink(outside, dir); err != nil {
			return nil, err
		}
		return map[string][]byte{"environ": []byte("owned private evidence")}, nil
	}})
	result, err := q.Execute(t.Context(), Target{PID: 1}, Trigger{})
	if err == nil || result != nil {
		t.Fatal("changed configured pathname reported as current")
	}
	entries, readErr := os.ReadDir(outside)
	if readErr != nil || len(entries) != 0 {
		t.Fatal("snapshot escaped pinned root")
	}
	entries, readErr = os.ReadDir(moved)
	if readErr != nil || len(entries) != 1 {
		t.Fatal("complete private artifact not retained")
	}
	path := filepath.Join(moved, entries[0].Name())
	parts, _, restoreErr := Restore(path)
	if restoreErr != nil || string(parts["proc/environ"]) != "owned private evidence" {
		t.Fatal("retained artifact was partial or lost evidence")
	}
}

type rejectingArchiveWriter struct{ failure error }

func (w rejectingArchiveWriter) Write([]byte) (int, error) { return 0, w.failure }

type archiveClosingFailureWriter struct {
	failure error
	calls   int
}

func (w *archiveClosingFailureWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls == 1 {
		return len(p), nil // Accept gzip header; fail its buffered close output.
	}
	return 0, w.failure
}

func TestArchiveFinalizationErrorPreventsPublication(t *testing.T) {
	failure := errors.New("owned writer failure")
	if err := encodeTarball(t.Context(), rejectingArchiveWriter{failure}, map[string][]byte{"entry": []byte("body")}); !errors.Is(err, failure) {
		t.Fatal("gzip/tar output failure hidden")
	}
	closingWriter := &archiveClosingFailureWriter{failure: failure}
	if err := encodeTarball(t.Context(), closingWriter, map[string][]byte{"entry": []byte("body")}); !errors.Is(err, failure) || closingWriter.calls < 2 {
		t.Fatal("buffered gzip finalization failure hidden")
	}
	dir := filepath.Join(t.TempDir(), "snapshots")
	q := privateQuarantine(t, dir, CollectorSet{})
	closedRoot := q.outputRoot
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := writeTarball(t.Context(), closedRoot, "failed.tar.gz", nil); err == nil {
		t.Fatal("closed destination reported successful archive")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed finalization published a partial archive")
	}
}

func TestCancelledSnapshotNeverPublishes(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	dir := filepath.Join(t.TempDir(), "snapshots")
	q := privateQuarantine(t, dir, CollectorSet{Logs: func(context.Context, string, string, int) (map[string][]string, error) {
		cancel()
		return map[string][]string{"container": {"owned log"}}, nil
	}})
	if result, err := q.Execute(ctx, Target{}, Trigger{}); result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collection reported a successful snapshot")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("cancelled snapshot left a published/pending artifact")
	}
}

func TestCloseWaitsForExecuteAndPreventsLaterCollection(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	q := privateQuarantine(t, filepath.Join(t.TempDir(), "snapshots"), CollectorSet{Logs: func(context.Context, string, string, int) (map[string][]string, error) {
		calls.Add(1)
		close(entered)
		<-release
		return nil, nil
	}})
	executed, closed := make(chan error, 1), make(chan error, 1)
	go func() { _, err := q.Execute(t.Context(), Target{}, Trigger{}); executed <- err }()
	<-entered
	go func() { closed <- q.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned before active Execute completed: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-executed; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if result, err := q.Execute(t.Context(), Target{}, Trigger{}); result != nil || err == nil || calls.Load() != 1 {
		t.Fatal("closed quarantine accepted execution")
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

var _ io.Writer = rejectingArchiveWriter{}

func TestCollectorFailuresKeepExistingBestEffortSnapshot(t *testing.T) {
	failure := errors.New("owned collector failure")
	q, err := New(Options{OutputDir: filepath.Join(t.TempDir(), "snapshots")}, CollectorSet{
		Cordon: func(context.Context, Target) (string, error) { return "partial policy", failure },
		PCAP: func(context.Context, string, time.Duration, int64) ([]byte, error) {
			return []byte("partial capture"), failure
		},
		Proc: func(context.Context, int) (map[string][]byte, error) {
			return map[string][]byte{"environ": []byte("partial private evidence")}, failure
		},
		Logs: func(context.Context, string, string, int) (map[string][]string, error) {
			return map[string][]string{"container": {"partial log"}}, failure
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := q.Close(); err != nil {
			t.Error(err)
		}
	})
	result, err := q.Execute(t.Context(), Target{PID: 1, Veth: "owned-fixture"}, Trigger{})
	if err != nil {
		t.Fatal(err)
	}
	parts, _, err := Restore(result.TarballPath)
	if err != nil || len(parts) != 1 || parts["manifest.json"] == nil || len(result.Components) != 0 || result.NetPolicy != "" {
		t.Fatal("failed collectors contributed partial evidence or stopped the existing manifest-only fallback")
	}
}
