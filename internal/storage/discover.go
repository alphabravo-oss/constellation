package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Discovery locates the object store's in-cluster Service (guide ch.09: the
// Kubernetes API is the discovery surface; results are cached with a bounded
// TTL; an explicit override always wins).
type Discovery struct {
	// Override, when set, short-circuits discovery (operators use it during
	// incident response). The composition root fills it from STORAGE_ENDPOINT.
	Override string
	// Namespace/Service name the store is exposed as; PortName selects the
	// Service port ("s3" by default; falls back to the first port).
	Namespace string
	Service   string
	PortName  string
	// TTL bounds the cache (default 60s).
	TTL time.Duration

	mu       sync.Mutex
	cached   string
	cachedAt time.Time
	lookup   func(ctx context.Context, ns, name string) (string, error)
}

// ErrDiscovery wraps every discovery failure so callers can retry with backoff.
var ErrDiscovery = errors.New("storage: discovery failed")

// Resolve returns host:port for the store.
func (d *Discovery) Resolve(ctx context.Context) (string, error) {
	if ep := strings.TrimSpace(d.Override); ep != "" {
		return ep, nil
	}
	if d.Service == "" {
		return "", fmt.Errorf("%w: no Service configured", ErrDiscovery)
	}
	ttl := d.TTL
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cached != "" && time.Since(d.cachedAt) < ttl {
		return d.cached, nil
	}
	lookup := d.lookup
	if lookup == nil {
		lookup = d.kubeLookup
	}
	ns := d.Namespace
	if ns == "" {
		ns = currentNamespace()
	}
	ep, err := lookup(ctx, ns, d.Service)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrDiscovery, err)
	}
	d.cached, d.cachedAt = ep, time.Now()
	return ep, nil
}

func (d *Discovery) kubeLookup(ctx context.Context, ns, name string) (string, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return "", err
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return "", err
	}
	svc, err := cs.CoreV1().Services(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return "", err
	}
	if len(svc.Spec.Ports) == 0 {
		return "", fmt.Errorf("service %s/%s has no ports", ns, name)
	}
	port := svc.Spec.Ports[0].Port
	want := d.PortName
	if want == "" {
		want = "s3"
	}
	for _, p := range svc.Spec.Ports {
		if p.Name == want {
			port = p.Port
			break
		}
	}
	return fmt.Sprintf("%s.%s.svc:%d", name, ns, port), nil
}

func currentNamespace() string {
	if b, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace"); err == nil {
		return strings.TrimSpace(string(b))
	}
	if ns := os.Getenv("POD_NAMESPACE"); ns != "" {
		return ns
	}
	return "default"
}

// ResolveWithBackoff retries Resolve until it succeeds or ctx ends; use it at
// startup so a store that is still coming up degrades health instead of
// failing the boot.
func (d *Discovery) ResolveWithBackoff(ctx context.Context, maxWait time.Duration) (string, error) {
	deadline := time.Now().Add(maxWait)
	wait := 500 * time.Millisecond
	for {
		ep, err := d.Resolve(ctx)
		if err == nil {
			return ep, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(wait):
		}
		if wait < 10*time.Second {
			wait *= 2
		}
	}
}
