// Package authctx holds the request auth-context seam shared across the handler
// sub-packages: the authenticated Subject and the context plumbing for attaching
// and retrieving it. It is a dependency-light leaf of the D2 god-package split
// (see docs/handler-split-plan.md, "the enabling step"): every domain
// sub-package (handler/network, handler/scanning, ...) needs Subject/SubjectFrom,
// so promoting them here is what lets those packages stop depending on
// internal/handler for auth context. Only deps: uuid, pkg/rbac.
package authctx

import (
	"context"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/pkg/rbac"
)

type subjectKey struct{}

// Subject is the authenticated principal attached to a request context.
//
// TokenScopes, when non-nil, narrows the effective verb set granted by Assignments:
// a verb authorizes a request iff it appears in BOTH the underlying role assignments
// AND in TokenScopes. This is how API-token (PAT) requests get a strict subset of the
// minting user's privileges without weakening the role-based path (where TokenScopes
// is nil and any role-granted verb passes).
type Subject struct {
	UserID      uuid.UUID
	OrgID       uuid.UUID
	Email       string
	Assignments []rbac.RoleAssignment
	TokenScopes []rbac.Verb
	// TokenID is the api_tokens.id when the request was authenticated via an API token.
	// Empty otherwise. Used by audit log emission so token operations can be tied back
	// to the originating credential.
	TokenID string
}

// HasTokenScope reports whether v is within the subject's API-token scope envelope. If
// TokenScopes is nil (i.e. a user JWT), every verb passes through here.
func (s Subject) HasTokenScope(v rbac.Verb) bool {
	if s.TokenScopes == nil {
		return true
	}
	for _, t := range s.TokenScopes {
		if t == v {
			return true
		}
	}
	return false
}

// WithSubject attaches s to ctx.
func WithSubject(ctx context.Context, s Subject) context.Context {
	return context.WithValue(ctx, subjectKey{}, s)
}

// SubjectFrom returns the Subject attached to ctx, if any.
func SubjectFrom(ctx context.Context) (Subject, bool) {
	s, ok := ctx.Value(subjectKey{}).(Subject)
	return s, ok
}

type nsFilterKey struct{}

// WithNamespaceFilter attaches the set of namespaces a namespace-restricted subject
// may see (RBAC-NS-24 row filtering). Set by requireVerbNS on an unfiltered list when
// the subject has only namespace-scoped grants; a filter-aware list handler MUST read
// it via NamespaceFilterFrom and constrain its query. Absent = no restriction.
func WithNamespaceFilter(ctx context.Context, namespaces []string) context.Context {
	return context.WithValue(ctx, nsFilterKey{}, namespaces)
}

// NamespaceFilterFrom returns the namespace allow-list attached by WithNamespaceFilter.
// ok is true only when a non-empty restriction is present.
func NamespaceFilterFrom(ctx context.Context) (namespaces []string, ok bool) {
	ns, _ := ctx.Value(nsFilterKey{}).([]string)
	return ns, len(ns) > 0
}
