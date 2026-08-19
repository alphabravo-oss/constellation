// Package netutil holds the small, dependency-free network-identity helpers
// shared between the network domain handlers (handler/network) and the network
// policy handlers that still live in internal/handler. Extracting them into a
// leaf package keeps both importers cycle-free (see docs/handler-split-plan.md,
// "Shared-helper extraction").
package netutil

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"strings"
)

// StableFlowID derives a short, deterministic identifier from the given parts.
func StableFlowID(parts ...any) string {
	h := sha1.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%v\x00", p)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// SplitWorkload splits a "namespace/name" workload id. A bare value (no slash)
// is treated as an external endpoint.
func SplitWorkload(id string) (string, string) {
	before, after, ok := strings.Cut(id, "/")
	if !ok {
		return "external", id
	}
	return before, after
}
