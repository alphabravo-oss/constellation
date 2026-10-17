package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"

	compliancepkg "github.com/alphabravocompany/constellation/pkg/compliance"
)

const executionSpoolMax = compliancepkg.BenchExecutionMaxReport + (64 << 10)

type executionSpoolEntry struct {
	Version int                                 `json:"version"`
	Scope   string                              `json:"scope"`
	Phase   string                              `json:"phase"`
	Claim   compliancepkg.BenchExecutionClaim   `json:"claim"`
	Request compliancepkg.BenchExecutionRequest `json:"request"`
	Result  compliancepkg.BenchExecutionResult  `json:"result"`
}

type executionSpool struct {
	root *os.Root
	lock *os.File
}

func openExecutionSpool(directory string) (*executionSpool, error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("benchmark spool requires an absolute persistent path")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, errors.New("benchmark spool unavailable")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("benchmark spool must be a private directory")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, errors.New("benchmark spool unavailable")
	}
	lock, err := root.OpenFile("worker.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err == nil {
		rawFD := lock.Fd()
		if rawFD > uintptr(math.MaxInt) {
			err = errors.New("invalid worker lock descriptor")
		} else {
			err = unix.Flock(int(rawFD), unix.LOCK_EX|unix.LOCK_NB)
		}
	}
	if err != nil {
		if lock != nil {
			_ = lock.Close()
		}
		_ = root.Close()
		return nil, errors.New("benchmark spool is unavailable or already in use")
	}
	return &executionSpool{root: root, lock: lock}, nil
}

func (s *executionSpool) close() {
	_ = s.lock.Close()
	_ = s.root.Close()
}

func executionScope(cfg config) string {
	digest := sha256.Sum256([]byte(cfg.apiURL + "\x00" + cfg.clusterID + "\x00" + cfg.profile + "\x00" + cfg.token))
	return hex.EncodeToString(digest[:])
}

func (s *executionSpool) load(scope string) (*executionSpoolEntry, error) {
	f, err := s.root.Open("execution.json")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, errors.New("benchmark spool unreadable")
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, executionSpoolMax+1))
	var entry executionSpoolEntry
	if err != nil || len(raw) > executionSpoolMax || json.Unmarshal(raw, &entry) != nil || entry.Version != 1 || entry.Scope != scope {
		return nil, errors.New("benchmark spool scope or data mismatch; review pending execution before changing scope or credential")
	}
	if entry.Phase != "claiming" && entry.Phase != "executing" && entry.Phase != "result" {
		return nil, errors.New("invalid benchmark spool phase")
	}
	return &entry, nil
}

func (s *executionSpool) save(entry *executionSpoolEntry) error {
	raw, err := encodeExecutionJSON(entry)
	if err != nil || len(raw) > executionSpoolMax {
		return errors.New("benchmark spool entry exceeds durable bound")
	}
	name := "pending-" + uuid.NewString()
	f, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("benchmark spool write failed")
	}
	defer func() { _ = s.root.Remove(name) }()
	_, writeErr := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("benchmark spool write failed")
	}
	if err := s.root.Rename(name, "execution.json"); err != nil {
		return errors.New("benchmark spool replace failed")
	}
	return s.syncDirectory()
}

func (s *executionSpool) forget() error {
	if err := s.root.Remove("execution.json"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("benchmark spool cleanup failed")
	}
	return s.syncDirectory()
}

func (s *executionSpool) reject() error {
	// Keep one private last rejected result for operator inspection, with a
	// bounded footprint. It is never replayed against a replacement attempt.
	if err := s.root.Rename("execution.json", "last-rejected.json"); err != nil {
		return errors.New("benchmark spool rejection could not be retained")
	}
	return s.syncDirectory()
}

func (s *executionSpool) syncDirectory() error {
	dir, err := s.root.Open(".")
	if err != nil {
		return errors.New("benchmark spool directory unavailable")
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return errors.New("benchmark spool directory sync failed")
	}
	return nil
}
