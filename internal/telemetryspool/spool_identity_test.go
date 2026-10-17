package telemetryspool

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func openTestQueue(t *testing.T, dir string) *Queue {
	t.Helper()
	queue, err := Open(dir, "target", 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	return queue
}

func enqueueTestBatch(t *testing.T, queue *Queue) {
	t.Helper()
	if err := queue.Enqueue([]byte(`[1]`), 1); err != nil {
		t.Fatal(err)
	}
}

func TestClosedQueueCannotAffectNewOwner(t *testing.T) {
	dir := t.TempDir()
	old := openTestQueue(t, dir)
	enqueueTestBatch(t, old)
	producer := old.Producer()
	closeQueue(t, old)
	current := openTestQueue(t, dir)
	defer closeQueue(t, current)
	enqueueTestBatch(t, current)
	if err := old.Enqueue([]byte(`[2]`), 1); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed enqueue: %v", err)
	}
	if _, err := old.Peek(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed peek: %v", err)
	}
	if err := old.Ack(1); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed acknowledgement: %v", err)
	}
	if err := old.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("repeated close: %v", err)
	}
	if old.Producer() != producer || current.Producer() != producer {
		t.Fatal("close changed producer identity")
	}
	assertOldest(t, current, 1, 2)
}

func assertOldest(t *testing.T, queue *Queue, sequence int64, count int) {
	t.Helper()
	batch, err := queue.Peek()
	if err != nil || batch == nil || batch.Sequence != sequence {
		t.Fatalf("oldest batch: %+v, %v", batch, err)
	}
	files, bytes := queue.Stats()
	if files != count || bytes <= 0 {
		t.Fatalf("retained batches: %d bytes: %d", files, bytes)
	}
}

func TestDirectoryReplacementCannotRedirectQueue(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "queue")
	moved := filepath.Join(parent, "original")
	queue := openTestQueue(t, dir)
	defer closeQueue(t, queue)
	enqueueTestBatch(t, queue)
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	replacement := openTestQueue(t, dir)
	enqueueTestBatch(t, replacement)
	assertRejectedQueue(t, queue)
	assertOldest(t, replacement, 1, 1)
	closeQueue(t, replacement)
	if err := os.Rename(dir, filepath.Join(parent, "replacement")); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(moved, dir); err != nil {
		t.Fatal(err)
	}
	// Detected ownership loss is sticky even when the original path returns.
	assertRejectedQueue(t, queue)
}

func TestLockReplacementCannotShareQueue(t *testing.T) {
	dir := t.TempDir()
	queue := openTestQueue(t, dir)
	enqueueTestBatch(t, queue)
	if err := os.Rename(filepath.Join(dir, "lock"), filepath.Join(dir, "old-lock")); err != nil {
		t.Fatal(err)
	}
	assertSecondOwnerRejected(t, dir)
	assertRejectedQueue(t, queue)
	closeQueue(t, queue)
	replacement := openTestQueue(t, dir)
	defer closeQueue(t, replacement)
	assertOldest(t, replacement, 1, 1)
	enqueueTestBatch(t, replacement)
	assertOldest(t, replacement, 1, 2)
}

func assertSecondOwnerRejected(t *testing.T, dir string) {
	t.Helper()
	if other, err := Open(dir, "target", 1<<20, 100); err == nil {
		closeQueue(t, other)
		t.Fatal("second updated queue acquired replaced lock while directory owner remains open")
	}
}

func assertRejectedQueue(t *testing.T, queue *Queue) {
	t.Helper()
	if err := queue.Enqueue([]byte(`[2]`), 1); err == nil {
		t.Fatal("queue accepted write after ownership loss")
	}
	if _, err := queue.Peek(); err == nil {
		t.Fatal("queue read evidence after ownership loss")
	}
	if err := queue.Ack(1); err == nil {
		t.Fatal("queue acknowledged after ownership loss")
	}
}

func TestOpenRejectsLinkedRootAndLock(t *testing.T) {
	for _, kind := range []string{"root-symlink", "lock-symlink", "lock-hardlink", "lock-directory"} {
		t.Run(kind, func(t *testing.T) { assertRejectedLink(t, kind) })
	}
}

func assertRejectedLink(t *testing.T, kind string) {
	t.Helper()
	parent := t.TempDir()
	dir := filepath.Join(parent, "queue")
	victim := filepath.Join(parent, "victim")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(victim, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	var err error
	switch kind {
	case "root-symlink":
		dir = filepath.Join(parent, "link")
		err = os.Symlink(parent, dir)
	case "lock-symlink":
		err = os.Symlink(victim, filepath.Join(dir, "lock"))
	case "lock-hardlink":
		err = os.Link(victim, filepath.Join(dir, "lock"))
	case "lock-directory":
		err = os.Mkdir(filepath.Join(dir, "lock"), 0o700)
	}
	if err != nil {
		t.Fatal(err)
	}
	if queue, err := Open(dir, "target", 1000, 10); err == nil {
		closeQueue(t, queue)
		t.Fatal("linked or nonregular spool identity accepted")
	}
	data, err := openTestRoot(t, parent).ReadFile("victim")
	if err != nil || string(data) != "unchanged" {
		t.Fatalf("unrelated file changed: %q %v", data, err)
	}
}

func TestConcurrentClosePreservesPublishedBatches(t *testing.T) {
	dir := t.TempDir()
	queue := openTestQueue(t, dir)
	var workers sync.WaitGroup
	start := make(chan struct{})
	results := make(chan error, 32)
	for range 32 {
		workers.Go(func() {
			<-start
			results <- queue.Enqueue([]byte(`[1]`), 1)
		})
	}
	close(start)
	closeQueue(t, queue)
	workers.Wait()
	close(results)
	published := 0
	for err := range results {
		if err == nil {
			published++
		} else if !errors.Is(err, os.ErrClosed) {
			t.Fatalf("concurrent enqueue: %v", err)
		}
	}
	files, _ := queue.Stats()
	if files != published {
		t.Fatalf("closed stats=%d successful writes=%d", files, published)
	}
	reopened := openTestQueue(t, dir)
	defer closeQueue(t, reopened)
	for sequence := int64(1); sequence <= int64(published); sequence++ {
		assertOldest(t, reopened, sequence, published-int(sequence)+1)
		if err := reopened.Ack(sequence); err != nil {
			t.Fatal(err)
		}
	}
	batch, err := reopened.Peek()
	if err != nil || batch != nil {
		t.Fatalf("unexpected remaining batch: %+v %v", batch, err)
	}
}

func TestRecoveryRemovesOnlyUnpublishedRegularFiles(t *testing.T) {
	dir := t.TempDir()
	queue := openTestQueue(t, dir)
	enqueueTestBatch(t, queue)
	closeQueue(t, queue)
	pending := filepath.Join(dir, ".pending-interrupted")
	if err := os.WriteFile(pending, []byte("incomplete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("state.json", filepath.Join(dir, ".pending-link")); err != nil {
		t.Fatal(err)
	}
	queue = openTestQueue(t, dir)
	defer closeQueue(t, queue)
	assertOldest(t, queue, 1, 1)
	if _, err := os.Lstat(pending); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unpublished temporary remains: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(dir, ".pending-link")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("nonregular pending entry changed: %v %v", info, err)
	}
}

func TestRecoveryRejectsLinkedStateWithoutChangingIdentity(t *testing.T) {
	dir := t.TempDir()
	queue := openTestQueue(t, dir)
	enqueueTestBatch(t, queue)
	closeQueue(t, queue)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	original, err := root.ReadFile("state.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("state.json", "original-state.json"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("original-state.json", "state.json"); err != nil {
		t.Fatal(err)
	}
	if reopened, err := Open(dir, "target", 1<<20, 100); err == nil {
		closeQueue(t, reopened)
		t.Fatal("linked metadata accepted")
	}
	retained, err := root.ReadFile("original-state.json")
	if err != nil || string(retained) != string(original) {
		t.Fatalf("retained identity changed: %v", err)
	}
	if err := root.Remove("state.json"); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("original-state.json", "state.json"); err != nil {
		t.Fatal(err)
	}
	queue = openTestQueue(t, dir)
	defer closeQueue(t, queue)
	assertOldest(t, queue, 1, 1)
}

func TestInFlightEnqueueLockReplacementRetainsExclusiveDirectory(t *testing.T) {
	assertInFlightReplacement(t, false)
}

func TestInFlightAckLockReplacementRetainsExclusiveDirectory(t *testing.T) {
	assertInFlightReplacement(t, true)
}

func assertInFlightReplacement(t *testing.T, acknowledge bool) {
	t.Helper()
	dir := t.TempDir()
	queue := openTestQueue(t, dir)
	if acknowledge {
		enqueueTestBatch(t, queue)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	resume := sync.OnceFunc(func() { close(release) })
	done := make(chan error, 1)
	if acknowledge {
		remove := queue.removeFile
		queue.removeFile = func(name string) error {
			close(entered)
			<-release
			return remove(name)
		}
	} else {
		write := queue.writeFile
		queue.writeFile = func(name string, body []byte) error {
			if strings.HasSuffix(name, ".batch") {
				close(entered)
				<-release
			}
			return write(name, body)
		}
	}
	// Always release/join before cleanup closes the queue, including failures.
	defer closeQueue(t, queue)
	defer resume()
	go func() {
		if acknowledge {
			done <- queue.Ack(1)
		} else {
			done <- queue.Enqueue([]byte(`["original-owner"]`), 1)
		}
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("operation never reached post-ownership-check mutation barrier")
	}
	if err := os.Rename(filepath.Join(dir, "lock"), filepath.Join(dir, "original-lock")); err != nil {
		t.Fatal(err)
	}
	// The operation already passed available(), and the legacy file lock now
	// has another name. A second updated queue must fail on the directory inode
	// before it can read Next or publish/delete any shared batch.
	assertSecondOwnerRejected(t, dir)
	resume()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("operation did not report the replaced lock identity")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not finish after barrier release")
	}
	assertSecondOwnerRejected(t, dir)
}

func TestDirectoryAndLegacyFileLocksBothRemainEffective(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	legacy, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := legacy.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := exclusiveLock(legacy); err != nil {
		t.Fatal(err)
	}
	// A legacy owner holds only lock-file flock; updated Open must honor it
	// and must release its directory lock when the second lock cannot acquire.
	assertSecondOwnerRejected(t, dir)
	if err := unlockLegacyTestFile(legacy); err != nil {
		t.Fatal(err)
	}
	queue := openTestQueue(t, dir)
	if err := exclusiveLock(legacy); err == nil {
		closeQueue(t, queue)
		t.Fatal("updated owner did not exclude the ordinary legacy file lock")
	}
	closeQueue(t, queue)
	if err := exclusiveLock(legacy); err != nil {
		t.Fatalf("Close did not release legacy lock: %v", err)
	}
}

func unlockLegacyTestFile(file *os.File) error {
	fd := file.Fd()
	if fd > math.MaxInt {
		return errors.New("test lock descriptor out of range")
	}
	return unix.Flock(int(fd), unix.LOCK_UN)
}
