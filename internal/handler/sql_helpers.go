package handler

import (
	"net/http"
	"strconv"

	"github.com/alphabravocompany/constellation/internal/handler/sqlx"
)

// The generic cluster-scope / placeholder-shifting helpers now live in the
// dependency-light leaf package internal/handler/sqlx (the "enabling step" of the
// D2 god-package split, see docs/handler-split-plan.md). sqlx is the source of
// truth; the thin wrappers below keep the many unqualified in-package callers
// (parseClusterIDParam, shiftPlaceholders) compiling without a repo-wide rename.

// parseClusterIDParam delegates to sqlx.ParseClusterIDParam. See that package for
// the cluster-first IA contract this enforces.
func parseClusterIDParam(r *http.Request) (any, error) { return sqlx.ParseClusterIDParam(r) }

// shiftPlaceholders delegates to sqlx.ShiftPlaceholders.
func shiftPlaceholders(where string, off int) string { return sqlx.ShiftPlaceholders(where, off) }

// itoa is strconv.Itoa with a shorter call site for inline placeholder building.
func itoa(n int) string { return strconv.Itoa(n) }
