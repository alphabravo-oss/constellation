package authctx

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestSlotObservesSubjectAttachedDownstream(t *testing.T) {
	t.Parallel()
	ctx, slot := WithSlot(context.Background())
	if _, ok := slot.Subject(); ok {
		t.Fatal("empty slot reported a subject")
	}
	user := uuid.New()
	_ = WithSubject(context.WithValue(ctx, struct{}{}, 1), Subject{UserID: user})
	got, ok := slot.Subject()
	if !ok || got.UserID != user {
		t.Fatalf("slot did not observe the downstream subject: %v %v", got, ok)
	}
}
