package handler

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAuditReadRowsRejectsTerminalError(t *testing.T) {
	failure := errors.New("audit stream interrupted")
	for _, tc := range []struct {
		name                 string
		scanErr, terminalErr error
	}{
		{"terminal", nil, failure}, {"scan", failure, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := &auditTestRows{remaining: 1, scanErr: tc.scanErr, terminalErr: tc.terminalErr}
			got, err := readAuditListRows(rows, 100, false)
			if !errors.Is(err, failure) || got != nil {
				t.Fatalf("partial rows must be discarded on error: rows=%d err=%v", len(got), err)
			}
		})
	}
}

func TestAuditReadRowsControlsAndEmpty(t *testing.T) {
	rows := &auditTestRows{remaining: 1}
	got, err := readAuditListRows(rows, 1, true)
	if err != nil || len(got) != 1 || len(got[0].Controls) == 0 {
		t.Fatalf("controls lost: rows=%d err=%v", len(got), err)
	}
	got, err = readAuditListRows(&auditTestRows{}, 100, false)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("empty rows must remain a nonnil array: %v", err)
	}
}

func TestAuditClusterPageBoundSaturates(t *testing.T) {
	_, args := auditListQuery(uuid.New(), uuid.New(), "", nil, nil, nil, 101, math.MaxInt)
	if bound := args[4].(int64); bound != int64(math.MaxInt) && bound != math.MaxInt64 {
		t.Fatalf("page bound overflowed: %d", bound)
	}
}

type auditTestRows struct {
	remaining            int
	scanErr, terminalErr error
}

func (r *auditTestRows) Next() bool {
	if r.remaining == 0 {
		return false
	}
	r.remaining--
	return true
}
func (r *auditTestRows) Err() error { return r.terminalErr }
func (r *auditTestRows) Scan(values ...any) error {
	if r.scanErr != nil {
		return r.scanErr
	}
	*values[0].(*int64) = 1
	*values[3].(*string) = "auth.login.local"
	*values[8].(*time.Time) = time.Now()
	return nil
}
