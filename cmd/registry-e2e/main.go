// registry-e2e exercises the registry connectors against a real registry.
//
// Usage:
//
//	go run ./cmd/registry-e2e --resolve ghcr.io/aquasecurity/trivy:0.49.1
//	go run ./cmd/registry-e2e --resolve docker.io/library/alpine:3.18
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/alphabravocompany/constellation/internal/registry"
)

func main() {
	resolve := flag.String("resolve", "", "Image ref to resolve to a digest-pinned reference")
	flag.Parse()
	if *resolve == "" {
		fmt.Fprintln(os.Stderr, "--resolve required")
		os.Exit(2)
	}
	ctx := context.Background()
	// Pick the right connector by host prefix.
	var conn registry.Connector
	switch {
	case has(*resolve, "ghcr.io/"):
		conn = registry.NewGHCR(registry.Config{})
	case has(*resolve, "docker.io/"):
		conn = registry.NewDockerHub(registry.Config{})
	default:
		// All other v2-compliant registries (zot, distribution, quay, etc.).
		conn = registry.NewGHCR(registry.Config{})
	}

	digestRef, err := conn.ResolveDigest(ctx, *resolve)
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAILED:", err)
		os.Exit(1)
	}
	fmt.Printf("RESOLVED  %s  →  %s\n", *resolve, digestRef)
}

func has(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
