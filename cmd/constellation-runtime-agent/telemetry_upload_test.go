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

func TestPostTelemetryRequiresMatchingDurableAck(t *testing.T) {
	for _, ack := range []string{"", "8", "7"} {
		t.Run("ack="+ack, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get(producerHeader) != "producer" || r.Header.Get(sequenceHeader) != "7" {
					t.Error("missing producer identity")
				}
				w.Header().Set(ackHeader, ack)
			}))
			defer server.Close()
			err := postTelemetry(context.Background(), server.Client(), server.URL, "test", []byte(`[]`), "producer", 7)
			if (err == nil) != (ack == "7") {
				t.Fatalf("ack=%q err=%v", ack, err)
			}
		})
	}
}

func TestRateLimitRetriesAndHonorsRetryAfter(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	err := postBatch(ctx, server.Client(), server.URL, "test", []ingestEvent{{Kind: "exec"}})
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 {
		t.Fatalf("retry ignored server delay: calls=%d err=%v", calls.Load(), err)
	}
}

func TestRetryAfterFormats(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	for value, want := range map[string]time.Duration{"12": 12 * time.Second, now.Add(time.Minute).Format(http.TimeFormat): time.Minute, "invalid": 0, "-1": 0, "9223372036854775807": 24 * time.Hour} {
		if got := retryAfter(value, now); got != want {
			t.Errorf("%q: got %v want %v", value, got, want)
		}
	}
}
