package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDiscoveryOverrideCacheAndTTL(t *testing.T) {
	t.Parallel()
	calls := 0
	d := &Discovery{Service: "rustfs", Namespace: "ns", TTL: 50 * time.Millisecond,
		lookup: func(context.Context, string, string) (string, error) { calls++; return "rustfs.ns.svc:9000", nil }}
	for range 3 {
		if ep, err := d.Resolve(context.Background()); err != nil || ep != "rustfs.ns.svc:9000" {
			t.Fatalf("resolve: %q %v", ep, err)
		}
	}
	if calls != 1 {
		t.Fatalf("cache miss count %d, want 1", calls)
	}
	time.Sleep(60 * time.Millisecond)
	_, _ = d.Resolve(context.Background())
	if calls != 2 {
		t.Fatalf("TTL expiry should re-discover; calls=%d", calls)
	}
	d.Override = "override:9000"
	if ep, _ := d.Resolve(context.Background()); ep != "override:9000" || calls != 2 {
		t.Fatalf("override must win without a lookup: %q calls=%d", ep, calls)
	}
}

func TestDiscoveryFailsGracefullyAndBacksOff(t *testing.T) {
	t.Parallel()
	attempts := 0
	d := &Discovery{Service: "rustfs", lookup: func(context.Context, string, string) (string, error) {
		attempts++
		if attempts < 3 {
			return "", errors.New("not yet")
		}
		return "rustfs.default.svc:9000", nil
	}}
	if _, err := d.Resolve(context.Background()); !errors.Is(err, ErrDiscovery) {
		t.Fatalf("want ErrDiscovery, got %v", err)
	}
	ep, err := d.ResolveWithBackoff(context.Background(), 10*time.Second)
	if err != nil || ep != "rustfs.default.svc:9000" || attempts != 3 {
		t.Fatalf("backoff: %q %v attempts=%d", ep, err, attempts)
	}
}

func TestSplitScheme(t *testing.T) {
	t.Parallel()
	if h, ssl := splitScheme("https://s3.example:9000/", false); h != "s3.example:9000/" && !ssl {
		t.Fatalf("https: %q %v", h, ssl)
	}
	if h, ssl := splitScheme("rustfs:9000", true); h != "rustfs:9000" || !ssl {
		t.Fatalf("bare: %q %v", h, ssl)
	}
	if h, ssl := splitScheme("http://rustfs:9000", true); h != "rustfs:9000" || ssl {
		t.Fatalf("http: %q %v", h, ssl)
	}
}
