// Package scannercache observes scanner-local filesystem capacity without
// opening cache contents, writing probes, creating directories or evicting data.
package scannercache

import (
	"errors"
	"math"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var cacheNames = [...]string{"xdg", "syft", "grype", "trivy"}

type Config struct {
	Paths   map[string]string
	Engines map[string]bool
	TTL     time.Duration
}

type observation struct {
	present                                 bool
	bytesKnown, inodesKnown                 bool
	capacity, available, inodes, freeInodes float64
}

type cacheState struct {
	name, path  string
	enabled     bool
	errors      float64
	lastSuccess time.Time
}

type Collector struct {
	mu        sync.Mutex
	ttl       time.Duration
	attempted time.Time
	states    []cacheState
	desc      map[string]*prometheus.Desc
	cached    []prometheus.Metric
}

func New(cfg Config) *Collector {
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Minute
	}
	c := &Collector{ttl: ttl, desc: map[string]*prometheus.Desc{}}
	for _, name := range cacheNames {
		c.states = append(c.states, cacheState{name: name, path: strings.TrimSpace(cfg.Paths[name]), enabled: name == "xdg" || cfg.Engines[name]})
	}
	for name, help := range map[string]string{
		"enabled":                        "Whether this process uses the cache family; disabled engines are not inspected.",
		"configured":                     "Whether a cache path is explicitly configured; paths are never labels.",
		"collection_success":             "Whether the last enabled/configured path observation succeeded, including a known missing directory.",
		"collection_errors_total":        "Failed path observations by this scanner process.",
		"last_success_timestamp_seconds": "Last successful path observation, retained across errors; zero before success.",
		"present":                        "Whether the configured path exists as a directory; absent on observation failure.",
		"capacity_known":                 "Whether filesystem byte counters are consistent and representable.",
		"capacity_bytes":                 "Total filesystem bytes, not a PVC quota or per-engine budget.",
		"available_bytes":                "Filesystem bytes available to an unprivileged process, excluding reserved blocks.",
		"inodes_known":                   "Whether the filesystem reports consistent, positive and representable inode capacity.",
		"capacity_inodes":                "Total filesystem inodes; do not sum across caches on the same filesystem.",
		"free_inodes":                    "Free filesystem inodes; zero is exhaustion when inodes_known is one.",
	} {
		c.desc[name] = prometheus.NewDesc("constellation_scanner_cache_"+name, help, []string{"cache"}, nil)
	}
	return c
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, desc := range c.desc {
		ch <- desc
	}
}

func (c *Collector) metric(name string, value float64, cache string) prometheus.Metric {
	kind := prometheus.GaugeValue
	if name == "collection_errors_total" {
		kind = prometheus.CounterValue
	}
	return prometheus.MustNewConstMetric(c.desc[name], kind, value, cache)
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	c.mu.Lock()
	if time.Since(c.attempted) >= c.ttl {
		c.refresh()
	}
	result := append([]prometheus.Metric(nil), c.cached...)
	c.mu.Unlock()
	for _, metric := range result {
		ch <- metric
	}
}

func (c *Collector) refresh() {
	c.cached = nil // A failed refresh must never retain a prior capacity sample.
	for i := range c.states {
		state := &c.states[i]
		add := func(name string, value float64) { c.cached = append(c.cached, c.metric(name, value, state.name)) }
		add("enabled", boolean(state.enabled))
		add("configured", boolean(state.path != ""))
		if !state.enabled || state.path == "" {
			continue
		}
		sample, err := inspect(state.path)
		add("collection_success", boolean(err == nil))
		if err != nil {
			state.errors++
		} else {
			state.lastSuccess = time.Now()
			c.cached = append(c.cached, c.encode(sample, state.name)...)
		}
		add("collection_errors_total", state.errors)
		timestamp := float64(0)
		if !state.lastSuccess.IsZero() {
			timestamp = float64(state.lastSuccess.Unix())
		}
		add("last_success_timestamp_seconds", timestamp)
	}
	c.attempted = time.Now() // Failure backoff is the same as successful sampling.
}

func (c *Collector) encode(sample observation, name string) []prometheus.Metric {
	result := []prometheus.Metric{c.metric("present", boolean(sample.present), name)}
	if !sample.present {
		return result
	}
	result = append(result, c.metric("capacity_known", boolean(sample.bytesKnown), name), c.metric("inodes_known", boolean(sample.inodesKnown), name))
	if sample.bytesKnown {
		result = append(result, c.metric("capacity_bytes", sample.capacity, name), c.metric("available_bytes", sample.available, name))
	}
	if sample.inodesKnown {
		result = append(result, c.metric("capacity_inodes", sample.inodes, name), c.metric("free_inodes", sample.freeInodes, name))
	}
	return result
}

func boolean(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func inspect(path string) (observation, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return observation{}, nil
	}
	if err != nil {
		return observation{}, err
	}
	if !info.IsDir() {
		return observation{}, errors.New("cache path is not a directory")
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return observation{}, err
	}
	return capacity(stat), nil
}

func capacity(stat syscall.Statfs_t) observation {
	out := observation{present: true}
	if stat.Blocks > 0 && stat.Bsize > 0 && stat.Bavail <= stat.Bfree && stat.Bfree <= stat.Blocks && stat.Blocks <= uint64(math.MaxInt64/stat.Bsize) {
		out.bytesKnown = true
		out.capacity = float64(int64(stat.Blocks) * stat.Bsize)
		out.available = float64(int64(stat.Bavail) * stat.Bsize)
	}
	if stat.Files > 0 && stat.Files <= math.MaxInt64 && stat.Ffree <= stat.Files {
		out.inodesKnown = true
		out.inodes = float64(stat.Files)
		out.freeInodes = float64(stat.Ffree)
	}
	return out
}
