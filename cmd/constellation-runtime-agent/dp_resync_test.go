package main

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

type flagRoundTripper struct{ called *bool }

func (f flagRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	*f.called = true
	return nil, context.Canceled
}

// TestDPSyncGateAndReadinessSkip covers the two dp-lifecycle invariants the
// consumer sync workers rely on:
//  1. the pure gate skips while dp is not ready and forces a re-push once the
//     lifecycle generation advances (dp restarted) even when content is
//     unchanged;
//  2. a real (zero-value ⇒ not-ready) supervisor makes DLPSyncWorker.SyncOnce
//     bail before it ever touches the network or pushes config.
func TestDPSyncGateAndReadinessSkip(t *testing.T) {
	// (1) pure decision logic.
	if skip, force := dpSyncGate(false, 5, 3); !skip || force {
		t.Fatalf("not-ready must skip and not force, got skip=%v force=%v", skip, force)
	}
	if skip, force := dpSyncGate(true, 7, 3); skip || !force {
		t.Fatalf("ready + new generation must force a re-push, got skip=%v force=%v", skip, force)
	}
	if skip, force := dpSyncGate(true, 3, 3); skip || force {
		t.Fatalf("ready + same generation must neither skip nor force, got skip=%v force=%v", skip, force)
	}

	// (2) integration: a zero-value supervisor reports Ready()==false, so
	// SyncOnce must return before fetching or pushing.
	called := false
	w := NewDLPSyncWorker(DLPSyncConfig{
		ClusterID:  "c1",
		DPSup:      &dp.Supervisor{},
		HTTPClient: &http.Client{Timeout: time.Second, Transport: flagRoundTripper{called: &called}},
	})
	w.SyncOnce(context.Background())
	if called {
		t.Fatal("SyncOnce fetched despite dp not being ready")
	}
	if got := w.Snapshot().Pushes; got != 0 {
		t.Fatalf("SyncOnce pushed while dp not ready: pushes=%d", got)
	}
}
