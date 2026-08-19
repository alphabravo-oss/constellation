package admission

import (
	"testing"
	"time"
)

func TestParseReqImageName(t *testing.T) {
	cases := []struct {
		in              string
		registry, repo  string
		tag, digest     string
	}{
		{"ubuntu", "https://docker.io/", "library/ubuntu", "latest", ""},
		{"ubuntu:24.04", "https://docker.io/", "library/ubuntu", "24.04", ""},
		{"nvlab/iperf", "https://docker.io/", "nvlab/iperf", "latest", ""},
		{"docker.io/nvlab/iperf:1.2", "https://docker.io/", "nvlab/iperf", "1.2", ""},
		{"ghcr.io/foo/bar:v1", "https://ghcr.io/", "foo/bar", "v1", ""},
		{"localhost:5000/svc:dev", "https://localhost:5000/", "svc", "dev", ""},
		{"https://quay.io/redhat/ubi8:latest", "https://quay.io/", "redhat/ubi8", "latest", ""},
		{"ghcr.io/x/y@sha256:abc", "https://ghcr.io/", "x/y", "", "sha256:abc"},
		{"ghcr.io/x/y:v1@sha256:def", "https://ghcr.io/", "x/y", "v1", "sha256:def"},
	}
	for _, c := range cases {
		got := ParseReqImageName(c.in)
		if got.Registry != c.registry || got.Repo != c.repo || got.Tag != c.tag || got.Digest != c.digest {
			t.Errorf("Parse(%q) = %+v; want registry=%s repo=%s tag=%s digest=%s",
				c.in, got, c.registry, c.repo, c.tag, c.digest)
		}
	}
}

func TestAggregationCache_SuppressInsideWindow(t *testing.T) {
	c := NewAggregationCache(8 * time.Minute)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })

	first := c.Observe("owner-1", "sha256:abc", "img", "denied", "denied")
	if first == nil || first.Occurrences != 1 {
		t.Fatalf("first emit: want one-occurrence entry; got %+v", first)
	}
	// 5 min later — inside window
	now = now.Add(5 * time.Minute)
	if e := c.Observe("owner-1", "sha256:abc", "img", "denied", "denied"); e != nil {
		t.Fatalf("inside window: want suppress (nil); got %+v", e)
	}
	// 10 min later — outside window; previous flushes
	now = now.Add(10 * time.Minute)
	flushed := c.Observe("owner-1", "sha256:abc", "img", "denied", "denied")
	if flushed == nil || flushed.Occurrences != 2 {
		t.Fatalf("flush: want 2-occurrence entry; got %+v", flushed)
	}
}

func TestAggregationCache_Sweep(t *testing.T) {
	c := NewAggregationCache(time.Minute)
	now := time.Date(2026, 5, 12, 12, 0, 0, 0, time.UTC)
	c.SetClock(func() time.Time { return now })
	c.Observe("o", "d", "img", "reason", "denied")
	now = now.Add(2 * time.Minute)
	got := c.Sweep()
	if len(got) != 1 {
		t.Fatalf("sweep: want 1 entry; got %d", len(got))
	}
}
