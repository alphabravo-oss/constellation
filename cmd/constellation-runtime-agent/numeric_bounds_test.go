package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/telemetryspool"
)

func TestProcessPIDBoundsPreserveUnknownObservationOnly(t *testing.T) {
	for _, pid := range []int{-math.MaxInt32, -1, 0, 1, math.MaxInt32} {
		value, valid := processPID(pid)
		if valid != (pid > 0) || valid && int64(value) != int64(pid) {
			t.Fatalf("process pid=%d value=%d valid=%v", pid, value, valid)
		}
		observed, valid := processObservationPID(pid)
		if valid != (pid >= 0) || valid && int64(observed) != int64(pid) {
			t.Fatalf("observed pid=%d value=%d valid=%v", pid, observed, valid)
		}
	}
	maximum := int(math.MaxInt32)
	if maximum < math.MaxInt {
		for _, pid := range []int{maximum + 1, math.MaxInt} {
			if value, valid := processPID(pid); valid || value != 0 {
				t.Fatalf("overflow pid=%d became %d", pid, value)
			}
			if value, valid := processObservationPID(pid); valid || value != 0 {
				t.Fatalf("overflow observation=%d became %d", pid, value)
			}
		}
	}
}

func TestProcessEnforcerRejectsSpecialAndOverflowPIDsBeforeSignal(t *testing.T) {
	var signals, receipts atomic.Int32
	status := newProcessEnforcementStatusStore()
	enforcer := newProcessEnforcer(processEnforcerConfig{Status: status, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), OnKill: func(int, string, string, string, string, string) { receipts.Add(1) }})
	enforcer.signal = func(int, syscall.Signal) error { signals.Add(1); return nil }
	invalid := []int{-1, 0, 1}
	maximum := int(math.MaxInt32)
	if maximum < math.MaxInt {
		invalid = append(invalid, maximum+1, math.MaxInt)
	}
	var group sync.WaitGroup
	for _, pid := range invalid {
		group.Go(func() { enforcer.block(pid, "cid", "fixture", "/fixture", "ns/test", "baseline") })
	}
	group.Wait()
	if signals.Load() != 0 || receipts.Load() != 0 {
		t.Fatal("invalid numeric identity reached signal or success receipt")
	}
	if _, exists := status.Get("ns/test"); exists {
		t.Fatal("invalid PID recorded as enforced")
	}
	enforcer.signal = func(pid int, signal syscall.Signal) error {
		if pid != 42 || signal != syscall.SIGKILL {
			t.Errorf("signal target=%d signal=%v", pid, signal)
		}
		signals.Add(1)
		return nil
	}
	enforcer.block(42, "cid", "fixture", "/fixture", "ns/test", "baseline")
	if signals.Load() != 1 || receipts.Load() != 1 {
		t.Fatal("valid positive PID no longer reaches signal and receipt")
	}
}

func TestProcessMatchersRejectInvalidPIDBeforeProcReads(t *testing.T) {
	enforcer := newProcessEnforcer(processEnforcerConfig{Granular: true, ZeroDrift: "enforce"})
	for _, rawPID := range []int32{-1, 0} {
		pid := int(rawPID)
		if enforcer.baselineViolation(pid, "fixture", "/fixture", "ns/test") {
			t.Fatal("invalid PID classified as baseline violation")
		}
		if context := enforcer.execContext(pid, "fixture", "/fixture"); context != (processExecContext{}) {
			t.Fatalf("invalid PID produced proc context: %+v", context)
		}
		if drift, _ := enforcer.driftViolation(pid, "cid", "ns/test"); drift {
			t.Fatal("invalid PID classified as drift")
		}
		if drift, _ := execEnforcerZeroDriftDecision(fileProfileEnforcerConfig{}, fanotifyDecisionEvent{Pid: rawPID}); drift {
			t.Fatal("invalid fanotify PID classified as drift")
		}
	}
}

func TestMetricNegativeSourceCountIsUnavailableWithoutHidingOtherFields(t *testing.T) {
	var output strings.Builder
	emitNonNegativeGauge(&output, "healthy_count", "fixture", "node=\"fixture\"", 7)
	emitNonNegativeGauge(&output, "unknown_count", "fixture", "node=\"fixture\"", -1)
	emitNonNegativeGauge(&output, "empty_count", "fixture", "node=\"fixture\"", 0)
	emitNonNegativeGauge(&output, "large_count", "fixture", "node=\"fixture\"", math.MaxInt64)
	text := output.String()
	for _, expected := range []string{"healthy_count{node=\"fixture\"} 7", "empty_count{node=\"fixture\"} 0", "large_count{node=\"fixture\"} 9223372036854775807"} {
		if !strings.Contains(text, expected) {
			t.Fatalf("lost legitimate metric %q: %s", expected, text)
		}
	}
	if strings.Contains(text, "unknown_count") {
		t.Fatalf("negative metric fabricated a value: %s", text)
	}
}

func TestDurableTelemetryRejectsNegativeRetainedCountWithoutUploadOrAck(t *testing.T) {
	var calls, uploaded atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	queue, err := telemetryspool.Open(directory, "fixture", 1<<20, 10)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := queue.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := queue.Enqueue([]byte(`[{"kind":"exec"}]`), 1); err != nil {
		t.Fatal(err)
	}
	corruptRetainedTelemetryCount(t, directory)
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Millisecond)
	defer cancel()
	deliverTelemetry(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)), queue, server.URL, "fixture", &uploaded)
	if calls.Load() != 0 || uploaded.Load() != 0 {
		t.Fatal("invalid negative count uploaded or wrapped counter")
	}
	if pending, _ := queue.Stats(); pending != 1 {
		t.Fatal("invalid retained batch was acknowledged or discarded")
	}
}

func corruptRetainedTelemetryCount(t *testing.T, directory string) {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	names, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range names {
		if !strings.HasSuffix(entry.Name(), ".batch") {
			continue
		}
		body, err := root.ReadFile(entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		var batch telemetryspool.Batch
		if err := json.Unmarshal(body, &batch); err != nil {
			t.Fatal(err)
		}
		batch.Count = -1
		file, err := root.OpenFile(entry.Name(), os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		encodeErr := json.NewEncoder(file).Encode(batch)
		if err := errors.Join(encodeErr, file.Close()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatal("no retained fixture batch")
}
