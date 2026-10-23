package main

import (
	"testing"

	"github.com/alphabravocompany/constellation/pkg/backup"
)

func TestAuditArchiveHeartbeatSnapshotIsBounded(t *testing.T) {
	t.Parallel()
	state := &auditArchiveHeartbeatState{
		Bucket:        "sensitive-audit-bucket",
		Prefix:        "constellation/audit",
		DryRun:        true,
		SignMode:      string(backup.SignModeStaticKey),
		Stage:         "dry-run",
		RecordCount:   3,
		ArchiveKey:    "constellation/audit/window.jsonl.gz",
		ManifestKey:   "constellation/audit/window.manifest.json",
		Success:       true,
		LastErrorText: "previous failure",
	}
	got, ok := state.snapshot().(map[string]any)
	if !ok {
		t.Fatalf("snapshot type = %T", state.snapshot())
	}
	if got["bucket_configured"] != true || got["prefix"] != "constellation/audit" || got["record_count"] != int64(3) {
		t.Fatalf("snapshot = %+v", got)
	}
	if _, ok := got["bucket"]; ok {
		t.Fatalf("snapshot leaked bucket name: %+v", got)
	}
	if state.lastError() != "previous failure" {
		t.Fatalf("lastError = %q", state.lastError())
	}
}
