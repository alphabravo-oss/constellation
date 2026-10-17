package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type responseWorkerFixture struct {
	worker               *processResponseWorker
	action               processActionV2
	directory, scope     string
	signals, reports     atomic.Int32
	terminal             atomic.Bool
	received             atomic.Value
	failFirst            bool
	loseFirstAck         bool
	closeJournalOnSignal bool
}

func newResponseWorkerFixture(t *testing.T) *responseWorkerFixture {
	t.Helper()
	f := &responseWorkerFixture{action: responseFixtureAction(), directory: t.TempDir(), scope: "exact-owner"}
	procRoot := t.TempDir()
	writeResponseIdentityFixture(t, procRoot, 4242, "1234")
	if err := os.WriteFile(filepath.Join(procRoot, "proc/4242/comm"), []byte("nginx\n"), 0600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	r := newResponder(responderConfig{Workloads: responseFixtureWorkloads(), Protected: newProtectedSet("platform", nil), currentProcessStart: func(uint32) (uint64, bool) { return 12349999999, true }, Node: "node-a", HostRoot: procRoot, KillProcessEnabled: true, Logger: logger, openProcess: func(int) (responseProcessHandle, error) {
		return &responseTestHandle{signal: func() error {
			f.signals.Add(1)
			if f.closeJournalOnSignal {
				_ = f.worker.Journal.root.Close()
			}
			return nil
		}}, nil
	}})
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.worker = &processResponseWorker{APIBaseURL: server.URL, Token: "fixture", ClusterID: responseFixtureBoot, Node: "node-a", Client: server.Client(), Logger: logger, Responder: r, Journal: mustOpenResponseJournal(t, f.directory, f.scope)}
	t.Cleanup(func() { _ = f.worker.Journal.Close() })
	return f
}

func (f *responseWorkerFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		actions := []processActionV2{}
		if !f.terminal.Load() {
			actions = append(actions, f.action)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol_version": 2, "cluster_id": responseFixtureBoot, "node": "node-a", "actions": actions})
		return
	}
	attempt := f.reports.Add(1)
	var result processResultV2
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		http.Error(w, "invalid result", http.StatusBadRequest)
		return
	}
	f.received.Store(result)
	if f.failFirst && attempt == 1 {
		http.Error(w, "try later", http.StatusServiceUnavailable)
		return
	}
	f.terminal.Store(true)
	if f.loseFirstAck && attempt == 1 {
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
		return
	}
	state := "done"
	if result.Outcome == "uncertain" {
		state = "uncertain"
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true, "protocol_version": 2, "id": result.ID, "action_token": result.ActionToken, "node": result.Node, "outcome": result.Outcome, "state": state})
}

func TestProcessResponseWorkerRetriesReceiptWithoutRepeatingSignal(t *testing.T) {
	for _, mode := range []string{"report unavailable", "ack lost after commit"} {
		t.Run(mode, func(t *testing.T) {
			f := newResponseWorkerFixture(t)
			f.failFirst = mode == "report unavailable"
			f.loseFirstAck = mode == "ack lost after commit"
			f.worker.pollOnce(t.Context())
			if f.signals.Load() != 1 || len(f.worker.Journal.Entries()) != 1 {
				t.Fatal("initial effect/result was not retained")
			}
			if err := f.worker.Journal.Close(); err != nil {
				t.Fatal(err)
			}
			f.worker.Journal = mustOpenResponseJournal(t, f.directory, f.scope)
			f.worker.pollOnce(t.Context())
			if f.signals.Load() != 1 || f.reports.Load() != 2 || len(f.worker.Journal.Entries()) != 0 {
				t.Fatalf("retry repeated/lost effect: signals%d reports%d entries%d", f.signals.Load(), f.reports.Load(), len(f.worker.Journal.Entries()))
			}
		})
	}
}

func TestProcessResponseWorkerInterruptedIntentIsUncertain(t *testing.T) {
	for _, afterSignal := range []bool{false, true} {
		t.Run(map[bool]string{false: "before signal", true: "after signal before result sync"}[afterSignal], func(t *testing.T) {
			f := newResponseWorkerFixture(t)
			if afterSignal {
				f.closeJournalOnSignal = true
				f.worker.pollOnce(t.Context())
				f.closeJournalOnSignal = false
			} else {
				if _, err := f.worker.Journal.Prepare(f.action); err != nil {
					t.Fatal(err)
				}
			}
			_ = f.worker.Journal.Close()
			f.worker.Journal = mustOpenResponseJournal(t, f.directory, f.scope)
			f.worker.pollOnce(t.Context())
			expected := int32(0)
			if afterSignal {
				expected = 1
			}
			result, ok := f.received.Load().(processResultV2)
			if !ok || result.Outcome != "uncertain" || f.signals.Load() != expected || len(f.worker.Journal.Entries()) != 0 {
				t.Fatalf("interrupted intent was repeated/claimed successful: %+v signals%d", result, f.signals.Load())
			}
		})
	}
}

func TestProcessResponseWorkerFullJournalPreventsEffects(t *testing.T) {
	f := newResponseWorkerFixture(t)
	f.worker.Journal.maxBytes = 1
	f.worker.pollOnce(t.Context())
	if f.signals.Load() != 0 || f.reports.Load() != 0 {
		t.Fatal("effect ran without durable intent capacity")
	}
}

func TestProcessResponseWorkerRejectsForeignEnvelope(t *testing.T) {
	f := newResponseWorkerFixture(t)
	f.action.Node = "node-b"
	f.worker.pollOnce(t.Context())
	if f.signals.Load() != 0 || len(f.worker.Journal.Entries()) != 0 {
		t.Fatal("foreign node action reached executor")
	}
}

func TestProcessResponseWorkerLegacyProcessRefused(t *testing.T) {
	r := newResponder(responderConfig{KillProcessEnabled: true})
	res := r.Execute(context.Background(), responseAction{Type: "kill_process", PID: 4242, Comm: "nginx"})
	if res.Applied || res.Reason != "legacy process actions require exact V2 process identity" {
		t.Fatalf("legacy action executed: %+v", res)
	}
}

func TestProcessResponseWorkerControlPlaneOriginAndRedirects(t *testing.T) {
	for _, raw := range []string{"https://user:password@example.com", "https://example.com/path", "https://example.com?query=secret", "file:///tmp/control", "https://example.com#fragment"} {
		if _, err := processControlPlaneOrigin(raw); err == nil {
			t.Fatalf("unsafe configured origin accepted %q", raw)
		}
	}
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1); w.WriteHeader(http.StatusOK) }))
	defer other.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("configured origin lost authorization")
		}
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	worker := &processResponseWorker{APIBaseURL: origin.URL, Token: "fixture", Client: origin.Client()}
	result, err := worker.request(t.Context(), http.MethodPost, "/api/v1/runtime/response-actions/v2/result", []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = result.Body.Close() }()
	if result.StatusCode != http.StatusTemporaryRedirect || redirected.Load() != 0 {
		t.Fatal("process authorization followed redirect to a different origin")
	}
}

func TestProcessResponseWorkerRejectsTrailingAndOversizeResponse(t *testing.T) {
	for _, suffix := range []string{` {"actions":[]}`, strings.Repeat(" ", 1<<20)} {
		t.Run(fmt.Sprint(len(suffix)), func(t *testing.T) {
			f := newResponseWorkerFixture(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := json.Marshal(map[string]any{"protocol_version": 2, "cluster_id": responseFixtureBoot, "node": "node-a", "actions": []processActionV2{f.action}})
				_, _ = w.Write(append(body, []byte(suffix)...))
			}))
			defer server.Close()
			f.worker.APIBaseURL = server.URL
			f.worker.pollOnce(t.Context())
			if f.signals.Load() != 0 || len(f.worker.Journal.Entries()) != 0 {
				t.Fatal("ambiguous/unbounded response reached process executor")
			}
		})
	}
}

type responseCancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b responseCancelBody) Close() error { b.cancel(); return b.ReadCloser.Close() }

type responseCancelTransport struct {
	base   http.RoundTripper
	cancel context.CancelFunc
}

func (r responseCancelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := r.base.RoundTrip(req)
	if err == nil {
		resp.Body = responseCancelBody{ReadCloser: resp.Body, cancel: r.cancel}
	}
	return resp, err
}
func TestProcessResponseWorkerCancellationBeforeEffect(t *testing.T) {
	f := newResponseWorkerFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f.worker.Client.Transport = responseCancelTransport{base: http.DefaultTransport, cancel: cancel}
	f.worker.pollOnce(ctx)
	if f.signals.Load() != 0 || len(f.worker.Journal.Entries()) != 0 {
		t.Fatalf("canceled response prepared/signaled: signals%d entries%d", f.signals.Load(), len(f.worker.Journal.Entries()))
	}
}
