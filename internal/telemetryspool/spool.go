// Package telemetryspool provides a bounded, single-process disk queue. A batch
// is durable after its file and directory have been synced. Capture buffers
// upstream of Enqueue are still volatile; this is not a lossless kernel tap.
package telemetryspool

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
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
	mu           sync.Mutex
	dir          string
	lock         *os.File
	meta         metadata
	entries      []entry
	bytes, limit int64
	maxFiles     int
	failed       error
}

// Open never silently resets an unreadable queue or rebinds data to another
// destination. The directory is private and must reside on persistent storage.
func Open(dir, target string, limit int64, maxFiles int) (*Queue, error) {
	if limit <= 0 || maxFiles <= 0 {
		return nil, errors.New("invalid spool limits")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, err
	}
	q := &Queue{dir: dir, lock: lock, limit: limit, maxFiles: maxFiles}
	if err = q.load(target); err != nil {
		_ = q.Close()
		return nil, err
	}
	return q, nil
}

func (q *Queue) load(target string) error {
	files, err := os.ReadDir(q.dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		// Unrenamed temporary files were never offered for delivery. Recover
		// their space after a crash so repeated interrupted writes stay bounded.
		if strings.HasPrefix(f.Name(), ".pending-") && f.Type().IsRegular() {
			if err := os.Remove(filepath.Join(q.dir, f.Name())); err != nil {
				return err
			}
			continue
		}
		if !strings.HasSuffix(f.Name(), ".batch") {
			continue
		}
		seq, err := strconv.ParseInt(strings.TrimSuffix(f.Name(), ".batch"), 10, 64)
		if err != nil || seq <= 0 || f.Type()&os.ModeSymlink != 0 {
			return errors.New("invalid spool batch filename")
		}
		info, err := f.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("invalid spool batch file")
		}
		q.entries = append(q.entries, entry{seq, info.Size()})
		q.bytes += info.Size()
	}
	sort.Slice(q.entries, func(i, j int) bool { return q.entries[i].sequence < q.entries[j].sequence })
	data, err := os.ReadFile(filepath.Join(q.dir, "state.json"))
	switch {
	case errors.Is(err, os.ErrNotExist):
		if len(q.entries) > 0 {
			return errors.New("spool identity missing with pending batches")
		}
		q.meta = metadata{Producer: uuid.NewString(), Target: target, Next: 1}
	case err != nil:
		return err
	default:
		if err = json.Unmarshal(data, &q.meta); err != nil {
			return err
		}
		id, parseErr := uuid.Parse(q.meta.Producer)
		if parseErr != nil || id == uuid.Nil || q.meta.Next < 1 || q.meta.Target != target {
			return errors.New("invalid spool identity or changed destination")
		}
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

func (q *Queue) Producer() string { return q.meta.Producer }

func (q *Queue) Enqueue(body []byte, count int) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.failed != nil {
		return q.failed
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
	if q.failed != nil {
		return nil, q.failed
	}
	if len(q.entries) == 0 {
		return nil, nil
	}
	data, err := os.ReadFile(q.batchPath(q.entries[0].sequence))
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
	if q.failed != nil {
		return q.failed
	}
	if len(q.entries) == 0 || q.entries[0].sequence != sequence {
		return errors.New("out of order spool acknowledgement")
	}
	if err := os.Remove(q.batchPath(sequence)); err != nil {
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

func (q *Queue) Close() error { return q.lock.Close() }

func (q *Queue) batchPath(sequence int64) string {
	return filepath.Join(q.dir, fmt.Sprintf("%020d.batch", sequence))
}

func (q *Queue) saveState() error {
	data, err := json.Marshal(q.meta)
	if err != nil {
		return err
	}
	return q.atomicWrite(filepath.Join(q.dir, "state.json"), data)
}

func (q *Queue) atomicWrite(path string, data []byte) error {
	f, err := os.CreateTemp(q.dir, ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return q.syncDir()
}

func (q *Queue) syncDir() error {
	d, err := os.Open(q.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
