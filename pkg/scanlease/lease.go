// Package scanlease carries the identity of one scan-job claim across requests.
// A lease ID is a fencing identifier, not a substitute for scanner authentication.
package scanlease

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

const Header = "X-Constellation-Scan-Lease"

type contextKey struct{}

func WithContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, contextKey{}, id)
}

func Attach(req *http.Request) {
	if id, ok := req.Context().Value(contextKey{}).(string); ok && id != "" {
		req.Header.Set(Header, id)
	}
}

// FromRequest preserves an absent ID for pre-upgrade claims. Such requests may
// only operate on a row whose lease_id is NULL and whose lease is still active.
func FromRequest(req *http.Request) (*uuid.UUID, error) {
	raw := strings.TrimSpace(req.Header.Get(Header))
	if raw == "" {
		return nil, nil
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return nil, fmt.Errorf("invalid scan lease ID")
	}
	return &id, nil
}
