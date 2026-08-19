// Package sqlx holds the small, dependency-light cluster-scope and query-building
// helpers shared across the handler sub-packages. It is a leaf of the D2
// god-package split (see docs/handler-split-plan.md, "the enabling step"): the
// cluster-scoped list/detail handlers in every domain sub-package thread these
// helpers, so promoting them here lets those packages stop depending on
// internal/handler for SQL plumbing. Only deps: stdlib + uuid.
package sqlx

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ParseClusterIDParam reads an optional ?cluster_id=<uuid> query parameter and
// returns it as `any` suitable to pass into a pgx Query() $N::uuid placeholder.
// Empty string => nil (matches all clusters, by the ($N::uuid IS NULL OR ...)
// pattern used across the cluster-scoped handlers).
//
// This is the single source of truth for the cluster-first IA contract on the
// server side: every page under /clusters/:id/* threads `cluster_id` into its
// queries, and every list endpoint that supports cluster mode calls this to
// turn the param into a filter argument. Bad UUID => 400.
func ParseClusterIDParam(r *http.Request) (any, error) {
	raw := strings.TrimSpace(r.URL.Query().Get("cluster_id"))
	if raw == "" {
		return nil, nil
	}
	cid, err := uuid.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster_id")
	}
	return cid, nil
}

// ShiftPlaceholders rewrites $N placeholders in a SQL fragment, adding `off`
// to each index. Used when a precompiled fragment from pkg/search/dsl is
// appended to a query that already has its own $1.., $N placeholders.
func ShiftPlaceholders(where string, off int) string {
	if off == 0 {
		return where
	}
	var b strings.Builder
	b.Grow(len(where) + 8)
	i := 0
	for i < len(where) {
		c := where[i]
		if c == '$' && i+1 < len(where) && where[i+1] >= '0' && where[i+1] <= '9' {
			j := i + 1
			for j < len(where) && where[j] >= '0' && where[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(where[i+1 : j])
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n + off))
			i = j
			continue
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}
