// Package handler holds the HTTP handler implementations for the constellation-api server.
package handler

import (
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

// The auth-context seam now lives in the dependency-light leaf package
// internal/handler/authctx (the "enabling step" of the D2 god-package split, see
// docs/handler-split-plan.md). authctx is the source of truth; the aliases below
// keep the many unqualified in-package callers (Subject{...}, SubjectFrom(...),
// WithSubject(...)) compiling without a repo-wide churn through collision-prone
// identifiers (abbot.Subject, pkix.Name{Subject:...}, claims.Subject, ...).

// Subject is an alias for authctx.Subject.
type Subject = authctx.Subject

// WithSubject is an alias for authctx.WithSubject.
var WithSubject = authctx.WithSubject

// SubjectFrom is an alias for authctx.SubjectFrom.
var SubjectFrom = authctx.SubjectFrom

// NamespaceFilterFrom is an alias for authctx.NamespaceFilterFrom (RBAC-NS-24 row filter).
var NamespaceFilterFrom = authctx.NamespaceFilterFrom
