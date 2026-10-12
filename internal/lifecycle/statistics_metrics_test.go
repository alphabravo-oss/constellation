package lifecycle

import (
	"errors"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestStatisticsMetricsDoNotCountFailedOrSkippedAnalysis(t *testing.T) {
	registry := prometheus.NewRegistry()
	metrics, err := NewStatisticsMetrics(registry)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1000, 0)
	metrics.Record(StatisticsRefresh{LastAnalyze: map[string]time.Time{"events": stamp}}, time.Second, nil)
	if got := testutil.ToFloat64(metrics.completed.WithLabelValues("events")); got != 0 {
		t.Fatalf("idle pass counted as analysis: %v", got)
	}
	metrics.Record(StatisticsRefresh{Analyzed: "events"}, time.Second, errors.New("commit failed"))
	if got := testutil.ToFloat64(metrics.completed.WithLabelValues("events")); got != 0 {
		t.Fatalf("failed pass counted as analysis: %v", got)
	}
	if got := testutil.ToFloat64(metrics.lastAnalyze.WithLabelValues("events")); got != 1000 {
		t.Fatalf("failure replaced prior database timestamp: %v", got)
	}
	metrics.Record(StatisticsRefresh{Analyzed: "events"}, time.Second, nil)
	if got := testutil.ToFloat64(metrics.completed.WithLabelValues("events")); got != 1 {
		t.Fatalf("completed count = %v", got)
	}
	if got := testutil.ToFloat64(metrics.failures); got != 1 {
		t.Fatalf("failure count = %v", got)
	}
	if _, err := NewStatisticsMetrics(registry); err == nil {
		t.Fatal("duplicate metrics must fail registration")
	}
}

func TestStatisticsMetricsKeepFixedTableLabels(t *testing.T) {
	metrics, err := NewStatisticsMetrics(nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics.Record(StatisticsRefresh{Analyzed: "tenant-controlled", LastAnalyze: map[string]time.Time{"tenant-controlled": time.Now()}}, time.Second, nil)
	if got := testutil.CollectAndCount(metrics.lastAnalyze); got != 3 {
		t.Fatalf("unexpected table label count: %d", got)
	}
	if got := testutil.CollectAndCount(metrics.completed); got != 3 {
		t.Fatalf("unexpected completed label count: %d", got)
	}
}
