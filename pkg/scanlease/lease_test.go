package scanlease

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestLeaseHeaderRoundTripAndValidation(t *testing.T) {
	id := uuid.NewString()
	req := httptest.NewRequest("POST", "/", nil).WithContext(WithContext(context.Background(), id))
	Attach(req)
	parsed, err := FromRequest(req)
	if err != nil || parsed == nil || parsed.String() != id {
		t.Fatalf("round trip: %v %v", parsed, err)
	}
	for _, value := range []string{"bad", uuid.Nil.String()} {
		req.Header.Set(Header, value)
		if _, err := FromRequest(req); err == nil {
			t.Fatalf("accepted invalid lease %q", value)
		}
	}
	req.Header.Del(Header)
	if parsed, err := FromRequest(req); err != nil || parsed != nil {
		t.Fatalf("absent legacy lease: %v %v", parsed, err)
	}
}
