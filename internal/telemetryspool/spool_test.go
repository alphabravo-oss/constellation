package telemetryspool

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRestartAndReplay(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir, "cluster-a/events", 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	producer := q.Producer()
	if err = q.Enqueue([]byte(`[{"kind":"exec"}]`), 1); err != nil {
		t.Fatal(err)
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(dir, "cluster-a/events", 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if q.Producer() != producer {
		t.Fatal("producer changed across restart")
	}
	b, err := q.Peek()
	if err != nil || b == nil || b.Sequence != 1 {
		t.Fatalf("batch=%+v err=%v", b, err)
	}
	if err = q.Ack(2); err == nil {
		t.Fatal("out of order acknowledgement accepted")
	}
	if err = q.Ack(1); err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue([]byte(`[2]`), 1); err != nil {
		t.Fatal(err)
	}
	b, err = q.Peek()
	if err != nil || b.Sequence != 2 {
		t.Fatalf("sequence reused: %+v %v", b, err)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state permissions: %v %v", info, err)
	}
}

func TestBoundedQueueRetainsOldest(t *testing.T) {
	for _, limits := range []struct {
		bytes int64
		files int
	}{{1 << 20, 1}, {60, 10}} {
		q, err := Open(t.TempDir(), "target", limits.bytes, limits.files)
		if err != nil {
			t.Fatal(err)
		}
		if err = q.Enqueue([]byte(`[1]`), 1); err != nil {
			t.Fatal(err)
		}
		if err = q.Enqueue([]byte(`[2]`), 1); !errors.Is(err, ErrFull) {
			t.Fatalf("expected overflow: %v", err)
		}
		b, err := q.Peek()
		if err != nil || string(b.Body) != `[1]` {
			t.Fatalf("oldest overwritten: %+v %v", b, err)
		}
		q.Close()
	}
}

func TestExclusiveOwnerAndDestination(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir, "a", 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if other, err := Open(dir, "a", 1000, 10); err == nil {
		other.Close()
		t.Fatal("two writers acquired queue")
	}
	q.Close()
	if other, err := Open(dir, "b", 1000, 10); err == nil {
		other.Close()
		t.Fatal("destination rebound")
	}
}

func TestCrashBetweenBatchAndState(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir, "a", 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	state, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue([]byte(`[1]`), 1); err != nil {
		t.Fatal(err)
	}
	q.Close()
	if err = os.WriteFile(filepath.Join(dir, "state.json"), state, 0600); err != nil {
		t.Fatal(err)
	}
	q, err = Open(dir, "a", 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err = q.Ack(1); err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue([]byte(`[2]`), 1); err != nil {
		t.Fatal(err)
	}
	b, err := q.Peek()
	if err != nil || b.Sequence != 2 {
		t.Fatalf("reused crash sequence: %+v %v", b, err)
	}
}

func TestMissingIdentityNeverResetsPendingData(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(dir, "a", 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue([]byte(`[1]`), 1); err != nil {
		t.Fatal(err)
	}
	q.Close()
	if err = os.Remove(filepath.Join(dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	if q, err = Open(dir, "a", 1000, 10); err == nil {
		q.Close()
		t.Fatal("lost producer identity was regenerated")
	}
}
