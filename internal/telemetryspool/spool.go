// Package telemetryspool provides a bounded, single-process disk queue. A batch
// is durable after its file and directory have been synced. Capture buffers
// upstream of Enqueue are still volatile; this is not a lossless kernel tap.
package telemetryspool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

var ErrFull = errors.New("telemetry spool capacity exceeded")

type Batch struct {
	Sequence int64           `json:"sequence"`
	Count    int             `json:"count"`
	Body     json.RawMessage `json:"body"`
}

type metadata struct {
	Producer string `json:"producer"`
	Target   string `json:"target"`
	Next     int64  `json:"next"`
}

type entry struct{ sequence, bytes int64 }

type Queue struct {
	mu            sync.Mutex
	dir           string
	lock          *os.File
	directoryLock *os.File
	writeFile     func(string, []byte) error
	removeFile    func(string) error
	root          *os.Root
	directory     os.FileInfo
	closed        bool
	meta          metadata
	entries       []entry
	bytes, limit  int64
	maxFiles      int
	failed        error
}

// Open never silently resets an unreadable queue or rebinds data to another
// destination. The directory is private and must reside on persistent storage.
// Cooperating updated queues lock both the pinned directory inode and legacy
// lock file for their lifetime. The file lock preserves ordinary old-version
// exclusion, but old versions ignore the directory lock after lock replacement.
func Open(dir, target string, limit int64, maxFiles int) (*Queue, error) {
	if limit <= 0 || maxFiles <= 0 {
		return nil, errors.New("invalid spool limits")
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := securefiles.OpenPrivateDir(absolute)
	if err != nil {
		return nil, err
	}
	q := &Queue{dir: absolute, root: root, limit: limit, maxFiles: maxFiles}
	q.writeFile = func(name string, data []byte) error { return securefiles.WriteFile(root, name, data, 0o600) }
	q.removeFile = root.Remove
	if err = q.openLock(); err != nil {
		return nil, errors.Join(err, q.Close())
	}
	if err = q.load(target); err != nil {
		return nil, errors.Join(err, q.Close())
	}
	return q, nil
}

func (q *Queue) openLock() error {
	var err error
	q.directoryLock, err = q.root.Open(".")
	if err != nil {
		return err
	}
	q.directory, err = q.directoryLock.Stat()
	if err != nil {
		return err
	}
	// Keep the same directory inode exclusively owned even if "lock" is
	// renamed between an operation's identity check and publication/removal.
	if err = exclusiveLock(q.directoryLock); err != nil {
		return err
	}
	// Refuse links and special files before locking or changing permissions.
	q.lock, err = q.root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	info, err := q.lock.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || stat.Nlink != 1 {
		return errors.New("spool lock must be a single regular file")
	}
	if err = q.lock.Chmod(0o600); err != nil {
		return err
	}
	if err = exclusiveLock(q.lock); err != nil {
		return err
	}
	return q.checkIdentity()
}

func exclusiveLock(file *os.File) error {
	fd := file.Fd()
	if fd > math.MaxInt {
		return errors.New("spool lock descriptor out of range")
	}
	return unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB)
}

// checkIdentity never reopens data by the public directory pathname. A replaced
// root or lock is a terminal failure, even if the original name later returns.
func (q *Queue) checkIdentity() error {
	current, err := os.Lstat(q.dir)
	if err != nil {
		return errors.New("spool directory identity unavailable")
	}
	if !os.SameFile(q.directory, current) || !current.IsDir() {
		return errors.New("spool directory identity changed")
	}
	locked, err := q.lock.Stat()
	if err != nil {
		return errors.New("spool lock identity unavailable")
	}
	current, err = q.root.Lstat("lock")
	if err != nil {
		return errors.New("spool lock identity unavailable")
	}
	if !current.Mode().IsRegular() || !os.SameFile(locked, current) {
		return errors.New("spool lock identity changed")
	}
	return nil
}

func (q *Queue) available() error {
	if q.closed {
		return os.ErrClosed
	}
	if q.failed == nil {
		q.failed = q.checkIdentity()
	}
	return q.failed
}

func (q *Queue) load(target string) error {
	if err := q.scanBatches(); err != nil {
		return err
	}
	if err := q.loadState(target); err != nil {
		return err
	}
	// A crash may leave the durable batch just ahead of the metadata update.
	if len(q.entries) > 0 && q.meta.Next <= q.entries[len(q.entries)-1].sequence {
		last := q.entries[len(q.entries)-1].sequence
		if last == math.MaxInt64 {
			return errors.New("spool sequence exhausted")
		}
		q.meta.Next = last + 1
	}
	return q.saveState()
}

func (q *Queue) scanBatches() error {
	directory, err := q.root.Open(".")
	if err != nil {
		return err
	}
	files, err := directory.ReadDir(-1)
	if err = errors.Join(err, directory.Close()); err != nil {
		return err
	}
	for _, file := range files {
		if err = q.scanFile(file); err != nil {
			return err
		}
	}
	sort.Slice(q.entries, func(i, j int) bool { return q.entries[i].sequence < q.entries[j].sequence })
	return nil
}

func (q *Queue) scanFile(file os.DirEntry) error {
	// Unrenamed temporary files were never offered for delivery. Recover
	// their space after a crash so repeated interrupted writes stay bounded.
	if strings.HasPrefix(file.Name(), ".pending-") && file.Type().IsRegular() {
		return q.root.Remove(file.Name())
	}
	if !strings.HasSuffix(file.Name(), ".batch") {
		return nil
	}
	sequence, err := strconv.ParseInt(strings.TrimSuffix(file.Name(), ".batch"), 10, 64)
	if err != nil || sequence <= 0 || file.Type()&os.ModeSymlink != 0 {
		return errors.New("invalid spool batch filename")
	}
	info, err := file.Info()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("invalid spool batch file")
	}
	q.entries = append(q.entries, entry{sequence, info.Size()})
	q.bytes += info.Size()
	return nil
}

func (q *Queue) loadState(target string) error {
	data, err := q.readFile("state.json")
	if errors.Is(err, os.ErrNotExist) {
		if len(q.entries) > 0 {
			return errors.New("spool identity missing with pending batches")
		}
		q.meta = metadata{Producer: uuid.NewString(), Target: target, Next: 1}
		return nil
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &q.meta); err != nil {
		return err
	}
	id, parseErr := uuid.Parse(q.meta.Producer)
	if parseErr != nil || id == uuid.Nil || q.meta.Next < 1 || q.meta.Target != target {
		return errors.New("invalid spool identity or changed destination")
	}
	return nil
}

func (q *Queue) Producer() string { return q.meta.Producer }

func (q *Queue) Enqueue(body []byte, count int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.available(); err != nil {
		return err
	}
	if count <= 0 || !json.Valid(body) {
		return errors.New("invalid spool batch")
	}
	if q.meta.Next == math.MaxInt64 {
		return errors.New("spool sequence exhausted")
	}
	b := Batch{Sequence: q.meta.Next, Count: count, Body: body}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	if q.bytes+int64(len(data)) > q.limit || len(q.entries) >= q.maxFiles {
		return ErrFull
	}
	if err = q.atomicWrite(q.batchPath(b.Sequence), data); err != nil {
		q.failed = err
		return err
	}
	q.entries = append(q.entries, entry{b.Sequence, int64(len(data))})
	q.bytes += int64(len(data))
	q.meta.Next++
	if err = q.saveState(); err != nil {
		q.failed = err
		return err
	}
	return nil
}

func (q *Queue) Peek() (*Batch, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.available(); err != nil {
		return nil, err
	}
	if len(q.entries) == 0 {
		return nil, nil
	}
	data, err := q.readFile(q.batchPath(q.entries[0].sequence))
	if err != nil {
		return nil, err
	}
	var b Batch
	if err = json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Sequence != q.entries[0].sequence || b.Count <= 0 || !json.Valid(b.Body) {
		return nil, errors.New("corrupt spool batch")
	}
	return &b, nil
}

// Ack is called only after the matching durable server acknowledgement.
func (q *Queue) Ack(sequence int64) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.available(); err != nil {
		return err
	}
	if len(q.entries) == 0 || q.entries[0].sequence != sequence {
		return errors.New("out of order spool acknowledgement")
	}
	if err := q.removeFile(q.batchPath(sequence)); err != nil {
		q.failed = err
		return err
	}
	if err := q.syncDir(); err != nil {
		q.failed = err
		return err
	}
	q.bytes -= q.entries[0].bytes
	q.entries = q.entries[1:]
	return nil
}

func (q *Queue) Stats() (int, int64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.entries), q.bytes
}

// Close waits for any active queue operation and releases its ownership lock.
// Enqueue, Peek and Ack reject subsequent use; Stats and Producer remain readable.
func (q *Queue) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return os.ErrClosed
	}
	q.closed = true
	var err error
	if q.lock != nil {
		err = q.lock.Close()
	}
	err = errors.Join(err, q.root.Close())
	if q.directoryLock != nil {
		err = errors.Join(err, q.directoryLock.Close())
	}
	return err
}

func (q *Queue) batchPath(sequence int64) string {
	return fmt.Sprintf("%020d.batch", sequence)
}

func (q *Queue) saveState() error {
	data, err := json.Marshal(q.meta)
	if err != nil {
		return err
	}
	return q.atomicWrite("state.json", data)
}

func (q *Queue) atomicWrite(name string, data []byte) error {
	if err := q.writeFile(name, data); err != nil {
		return err
	}
	return q.syncDir()
}

func (q *Queue) syncDir() error {
	directory, err := q.root.Open(".")
	if err != nil {
		return err
	}
	err = errors.Join(directory.Sync(), directory.Close())
	return errors.Join(err, q.checkIdentity())
}

func (q *Queue) readFile(name string) ([]byte, error) {
	file, err := q.root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("spool data must be a regular file"), err, file.Close())
	}
	data, err := io.ReadAll(file)
	identityErr := q.checkIdentity()
	if identityErr != nil {
		q.failed = identityErr
	}
	return data, errors.Join(err, file.Close(), identityErr)
}
