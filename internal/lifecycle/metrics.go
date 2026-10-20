package lifecycle

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics has fixed family labels: no user, node, cluster or token identifiers.
type Metrics struct {
	deleted     *prometheus.CounterVec
	failures    prometheus.Counter
	lastSuccess prometheus.Gauge
	duration    prometheus.Histogram
}

func NewMetrics(reg prometheus.Registerer) (*Metrics, error) {
	m := &Metrics{
		deleted:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "constellation_session_cleanup_deleted_total", Help: "Expired operational rows deleted, by fixed data family."}, []string{"family"}),
		failures:    prometheus.NewCounter(prometheus.CounterOpts{Name: "constellation_session_cleanup_failures_total", Help: "Failed operational session cleanup passes."}),
		lastSuccess: prometheus.NewGauge(prometheus.GaugeOpts{Name: "constellation_session_cleanup_last_success_timestamp_seconds", Help: "Unix time of the last complete successful cleanup pass; zero before first success."}),
		duration:    prometheus.NewHistogram(prometheus.HistogramOpts{Name: "constellation_session_cleanup_duration_seconds", Help: "Operational session cleanup pass duration.", Buckets: prometheus.DefBuckets}),
	}
	for _, family := range []string{"refresh_tokens", "user_sessions", "network_sessions", "kill_requests"} {
		m.deleted.WithLabelValues(family).Add(0)
	}
	if reg != nil {
		if err := reg.Register(m); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func (m *Metrics) Describe(ch chan<- *prometheus.Desc) {
	m.deleted.Describe(ch)
	m.failures.Describe(ch)
	m.lastSuccess.Describe(ch)
	m.duration.Describe(ch)
}

func (m *Metrics) Collect(ch chan<- prometheus.Metric) {
	m.deleted.Collect(ch)
	m.failures.Collect(ch)
	m.lastSuccess.Collect(ch)
	m.duration.Collect(ch)
}

func (m *Metrics) Record(result SessionCleanup, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	m.deleted.WithLabelValues("refresh_tokens").Add(float64(result.RefreshTokens))
	m.deleted.WithLabelValues("user_sessions").Add(float64(result.UserSessions))
	m.deleted.WithLabelValues("network_sessions").Add(float64(result.NetworkSessions))
	m.deleted.WithLabelValues("kill_requests").Add(float64(result.KillRequests))
	m.duration.Observe(elapsed.Seconds())
	if err != nil {
		m.failures.Inc()
		return
	}
	m.lastSuccess.SetToCurrentTime()
}
