package lifecycle

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type StatisticsMetrics struct {
	lastAnalyze *prometheus.GaugeVec
	completed   *prometheus.CounterVec
	failures    prometheus.Counter
	duration    prometheus.Histogram
}

func NewStatisticsMetrics(reg prometheus.Registerer) (*StatisticsMetrics, error) {
	m := &StatisticsMetrics{
		lastAnalyze: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "constellation_partition_statistics_last_analyze_timestamp_seconds", Help: "Last ANALYZE of each fixed partitioned parent; zero when never analyzed."}, []string{"table"}),
		completed:   prometheus.NewCounterVec(prometheus.CounterOpts{Name: "constellation_partition_statistics_completed_total", Help: "Committed parent statistics refreshes by this API process."}, []string{"table"}),
		failures:    prometheus.NewCounter(prometheus.CounterOpts{Name: "constellation_partition_statistics_failures_total", Help: "Failed partition statistics maintenance passes, including lock conflicts."}),
		duration:    prometheus.NewHistogram(prometheus.HistogramOpts{Name: "constellation_partition_statistics_duration_seconds", Help: "Partition statistics maintenance pass duration, including idle passes.", Buckets: []float64{0.01, 0.1, 1, 5, 10, 25, 30}}),
	}
	for _, table := range []string{"network_flows", "events", "findings"} {
		m.lastAnalyze.WithLabelValues(table).Set(0)
		m.completed.WithLabelValues(table).Add(0)
	}
	if reg != nil {
		if err := reg.Register(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *StatisticsMetrics) Describe(ch chan<- *prometheus.Desc) {
	m.lastAnalyze.Describe(ch)
	m.completed.Describe(ch)
	m.failures.Describe(ch)
	m.duration.Describe(ch)
}

func (m *StatisticsMetrics) Collect(ch chan<- prometheus.Metric) {
	m.lastAnalyze.Collect(ch)
	m.completed.Collect(ch)
	m.failures.Collect(ch)
	m.duration.Collect(ch)
}

func (m *StatisticsMetrics) Record(result StatisticsRefresh, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	for _, table := range []string{"network_flows", "events", "findings"} {
		if last, ok := result.LastAnalyze[table]; ok {
			stamp := float64(0)
			if !last.IsZero() {
				stamp = float64(last.Unix())
			}
			m.lastAnalyze.WithLabelValues(table).Set(stamp)
		}
		if err == nil && result.Analyzed == table {
			m.completed.WithLabelValues(table).Inc()
		}
	}
	m.duration.Observe(elapsed.Seconds())
	if err != nil {
		m.failures.Inc()
	}
}
