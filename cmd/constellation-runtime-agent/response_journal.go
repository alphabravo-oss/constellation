package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/alphabravocompany/constellation/internal/securefiles"
)

const responseJournalEntryLimit = 1 << 16

type responseJournalEntry struct {
	Action processActionV2  `json:"action"`
	Result *processResultV2 `json:"result,omitempty"`
}

type responseJournal struct {
	mu                   sync.Mutex
	root                 *os.Root
	lock                 *os.File
	entries              map[string]responseJournalEntry
	bytes                int
	maxEntries, maxBytes int
}

func openResponseJournal(dir, scope string) (*responseJournal, error) {
	root, err := securefiles.OpenPrivateDir(dir)
	if err != nil {
		return nil, err
	}
	j := &responseJournal{root: root, entries: map[string]responseJournalEntry{}, maxEntries: 1024, maxBytes: 4 << 20}
	if err = j.initialize(scope); err != nil {
		_ = j.Close()
		return nil, err
	}
	return j, nil
}

func (j *responseJournal) initialize(scope string) error {
	var err error
	j.lock, err = j.root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	rawFD := j.lock.Fd()
	if rawFD > uintptr(math.MaxInt) {
		return errors.New("invalid journal lock descriptor")
	}
	if err = unix.Flock(int(rawFD), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return errors.New("response journal is already in use")
	}
	if err := j.loadEntries(); err != nil {
		return err
	}
	missing, err := j.checkScope(scope)
	if err != nil {
		return err
	}
	if missing {
		if len(j.entries) > 0 {
			return errors.New("response journal scope missing with pending actions")
		}
		body, _ := json.Marshal(scope)
		return j.write("scope.json", body)
	}
	return nil
}

func (j *responseJournal) checkScope(scope string) (bool, error) {
	body, err := j.read("scope.json", 4096)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	var old string
	if json.Unmarshal(body, &old) != nil || old == "" {
		return false, errors.New("invalid response journal scope")
	}
	if old == scope {
		return false, nil
	}
	// Only credentials may rotate automatically, and only after every durable
	// intent/result has received its exact server acknowledgement and drained.
	oldParts, newParts := strings.Split(old, "|"), strings.Split(scope, "|")
	if len(j.entries) == 0 && len(oldParts) == 4 && len(newParts) == 4 && strings.Join(oldParts[:3], "|") == strings.Join(newParts[:3], "|") {
		return true, nil
	}
	return false, errors.New("response journal scope changed")
}

func (j *responseJournal) loadEntries() error {
	directory, err := j.root.Open(".")
	if err != nil {
		return err
	}
	files, readErr := directory.ReadDir(j.maxEntries + 16)
	closeErr := directory.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, file := range files {
		if file.Name() == "lock" || file.Name() == "scope.json" {
			continue
		}
		if strings.HasPrefix(file.Name(), ".pending-") {
			return errors.New("interrupted response journal write requires review")
		}
		if err := j.loadEntry(file.Name()); err != nil {
			return err
		}
	}
	if len(files) >= j.maxEntries+16 {
		return errors.New("response journal directory is too large")
	}

	return nil
}

func (j *responseJournal) read(name string, limit int64) ([]byte, error) {
	file, err := j.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid response journal file")
	}
	return io.ReadAll(io.LimitReader(file, limit+1))
}

func (j *responseJournal) loadEntry(name string) error {
	body, err := j.read(name, responseJournalEntryLimit)
	if err != nil {
		return err
	}
	var entry responseJournalEntry
	if json.Unmarshal(body, &entry) != nil || validateProcessAction(entry.Action) != nil || name != entry.Action.ID+".json" {
		return errors.New("invalid response journal entry")
	}
	if entry.Result != nil && !responseResultMatches(entry.Action, *entry.Result) {
		return errors.New("invalid response journal result")
	}
	j.entries[entry.Action.ID] = entry
	j.bytes += len(body)
	if len(j.entries) > j.maxEntries || j.bytes > j.maxBytes {
		return errors.New("response journal capacity exceeded")
	}
	return nil
}

func (j *responseJournal) write(name string, body []byte) error {
	if err := securefiles.WriteFile(j.root, name, body, 0600); err != nil {
		return err
	}
	dir, err := j.root.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	return errors.Join(err, closeErr)
}

func (j *responseJournal) persist(entry responseJournalEntry) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if len(body) > responseJournalEntryLimit {
		return errors.New("response journal entry exceeds size limit")
	}
	oldBody, _ := json.Marshal(j.entries[entry.Action.ID])
	oldSize := 0
	if _, exists := j.entries[entry.Action.ID]; exists {
		oldSize = len(oldBody)
	}
	if len(j.entries) >= j.maxEntries && oldSize == 0 || j.bytes-oldSize+len(body) > j.maxBytes {
		return errors.New("response journal capacity exceeded")
	}
	if err := j.write(entry.Action.ID+".json", body); err != nil {
		return err
	}
	j.entries[entry.Action.ID] = entry
	j.bytes += len(body) - oldSize
	return nil
}

func (j *responseJournal) Prepare(a processActionV2) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := validateProcessAction(a); err != nil {
		return false, err
	}
	if existing, ok := j.entries[a.ID]; ok {
		if existing.Action != a {
			return false, errors.New("process action changed after journal preparation")
		}
		return false, nil
	}
	return true, j.persist(responseJournalEntry{Action: a})
}

func responseResultMatches(a processActionV2, r processResultV2) bool {
	return len(r.Reason) <= 4096 && r.Version == 2 && r.ID == a.ID && r.ActionToken == a.ActionToken && r.Node == a.Node && r.Type == a.Type && !r.At.IsZero() && (r.Outcome == "applied" || r.Outcome == "refused" || r.Outcome == "uncertain")
}

func (j *responseJournal) Complete(a processActionV2, r processResultV2) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	existing, ok := j.entries[a.ID]
	if !ok || existing.Action != a || !responseResultMatches(a, r) {
		return errors.New("process result does not match prepared action")
	}
	if existing.Result != nil {
		return errors.New("process result already recorded")
	}
	return j.persist(responseJournalEntry{Action: a, Result: &r})
}

func (j *responseJournal) Entries() []responseJournalEntry {
	j.mu.Lock()
	defer j.mu.Unlock()
	entries := make([]responseJournalEntry, 0, len(j.entries))
	for _, entry := range j.entries {
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, k int) bool { return entries[i].Action.ID < entries[k].Action.ID })
	return entries
}

func (j *responseJournal) Forget(id string) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	entry, ok := j.entries[id]
	if !ok {
		return nil
	}
	if err := j.root.Remove(id + ".json"); err != nil && !os.IsNotExist(err) {
		return err
	}
	dir, err := j.root.Open(".")
	if err != nil {
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err = errors.Join(err, closeErr); err != nil {
		return fmt.Errorf("response receipt removal: %w", err)
	}
	body, _ := json.Marshal(entry)
	j.bytes -= len(body)
	delete(j.entries, id)
	return nil
}

func (j *responseJournal) Close() error {
	if j == nil {
		return nil
	}
	var err error
	if j.lock != nil {
		err = j.lock.Close()
	}
	return errors.Join(err, j.root.Close())
}
