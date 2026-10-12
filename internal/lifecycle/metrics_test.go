package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCleanupMetricsPreserveFailuresAndPartialProgress(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewMetrics(registry)
	if err != nil {
		t.Fatal(err)
	}
	metrics.Record(SessionCleanup{RefreshTokens: 7}, time.Second, errors.New("test failure"))
	if testutil.ToFloat64(metrics.failures) != 1 || testutil.ToFloat64(metrics.lastSuccess) != 0 || testutil.ToFloat64(metrics.deleted.WithLabelValues("refresh_tokens")) != 7 {
		t.Fatal("failure/progress incorrectly recorded")
	}
	metrics.Record(SessionCleanup{UserSessions: 3}, 2*time.Second, nil)
	if testutil.ToFloat64(metrics.lastSuccess) <= 0 || testutil.ToFloat64(metrics.deleted.WithLabelValues("user_sessions")) != 3 {
		t.Fatal("success not recorded")
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 4 {
		t.Fatalf("metrics=%d err=%v", len(families), err)
	}
	if _, err := NewMetrics(registry); err == nil {
		t.Fatal("duplicate registration accepted")
	}
}

func TestCanceledSessionMonitorDoesNotTouchDatabase(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	metrics, err := NewMetrics(nil)
	if err != nil {
		t.Fatal(err)
	}
	RunSessionCleanup(ctx, nil, nil, metrics)
	if testutil.ToFloat64(metrics.lastSuccess) != 0 || testutil.ToFloat64(metrics.failures) != 0 {
		t.Fatal("canceled monitor ran cleanup")
	}
}
