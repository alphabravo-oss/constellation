package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPostBatchRetriesServerErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer token" {
			t.Errorf("Authorization=%q want bearer token", got)
		}
		if attempts.Add(1) < 3 {
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := postBatch(ctx, srv.Client(), srv.URL, "token", []ingestEvent{{Kind: "process_exec", Node: "node-a"}})
	if err != nil {
		t.Fatalf("postBatch returned error: %v", err)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("attempts=%d want 3", got)
	}
}

func TestPostBatchDoesNotRetryClientErrors(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	err := postBatch(context.Background(), srv.Client(), srv.URL, "token", []ingestEvent{{Kind: "process_exec", Node: "node-a"}})
	if err == nil {
		t.Fatal("postBatch returned nil for 400 response")
	}
	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempts=%d want 1", got)
	}
}

func TestPostBatchReturnsContextErrorWhenAPIUnreachable(t *testing.T) {
	var attempts atomic.Int32
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts.Add(1)
			return nil, errors.New("connection refused")
		}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := postBatch(ctx, client, "http://constellation-api.invalid/api/v1/events:bulk", "token", []ingestEvent{{Kind: "process_exec", Node: "node-a"}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v want context deadline exceeded", err)
	}
	if got := attempts.Load(); got < 1 {
		t.Fatalf("attempts=%d want at least 1", got)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}
