package apiutil

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func decode(t *testing.T, rec *httptest.ResponseRecorder) Body {
	t.Helper()
	var b Body
	if err := json.NewDecoder(rec.Body).Decode(&b); err != nil {
		t.Fatalf("body is not the error shape: %q: %v", rec.Body.String(), err)
	}
	if rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
	return b
}

func TestWriteErrorMapsSentinelsAndScrubsInternal(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err     error
		status  int
		code    Code
		message string
	}{
		{fmt.Errorf("lookup: %w", ErrNotFound), 404, CodeNotFound, "not found"},
		{pgx.ErrNoRows, 404, CodeNotFound, "not found"},
		{fmt.Errorf("name: %w", ErrInvalid), 400, CodeInvalidArgument, "name: invalid argument"},
		{Invalid("bad json"), 400, CodeInvalidArgument, "bad json"},
		{Forbidden("nope"), 403, CodePermissionDenied, "nope"},
		{ErrUnauthenticated, 401, CodeUnauthenticated, "unauthenticated"},
		{Conflict("exists"), 409, CodeAlreadyExists, "exists"},
		{ErrResourceExhausted, 429, CodeResourceExhausted, "resource exhausted"},
		{context.DeadlineExceeded, 504, CodeDeadlineExceeded, "context deadline exceeded"},
		{errors.New("pq: connection refused password=hunter2"), 500, CodeInternal, InternalMessage},
		{Wrap(errors.New("secret detail"), CodeInternal, "ignored"), 500, CodeInternal, InternalMessage},
	}
	for _, tc := range cases {
		t.Run(string(tc.code), func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			WriteError(context.Background(), rec, tc.err)
			b := decode(t, rec)
			if rec.Code != tc.status || b.Error.Code != tc.code || b.Error.Message != tc.message {
				t.Fatalf("got %d %s %q, want %d %s %q", rec.Code, b.Error.Code, b.Error.Message, tc.status, tc.code, tc.message)
			}
			if b.Error.Code == CodeInternal && (b.Error.Message != InternalMessage || containsAny(rec.Body.String(), "hunter2", "secret detail")) {
				t.Fatalf("500 leaked the cause: %s", rec.Body.String())
			}
		})
	}
}

func TestWriteStatusKeepsStatusAndScrubs5xx(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	WriteStatus(context.Background(), rec, http.StatusUnprocessableEntity, "field x required")
	if b := decode(t, rec); rec.Code != 422 || b.Error.Code != CodeInvalidArgument || b.Error.Message != "field x required" {
		t.Fatalf("422: %d %+v", rec.Code, b)
	}
	rec = httptest.NewRecorder()
	WriteStatus(context.Background(), rec, http.StatusInternalServerError, "db: password=hunter2")
	if b := decode(t, rec); rec.Code != 500 || b.Error.Code != CodeInternal || b.Error.Message != InternalMessage {
		t.Fatalf("500: %d %+v", rec.Code, b)
	}
}

func TestToConnectTable(t *testing.T) {
	t.Parallel()
	if c, m := ToConnect(NotFound("cluster")); c != ConnectNotFound || m != "cluster not found" {
		t.Fatalf("not found: %d %q", c, m)
	}
	if c, m := ToConnect(errors.New("boom")); c != ConnectInternal || m != InternalMessage {
		t.Fatalf("internal: %d %q", c, m)
	}
	for code, cc := range connectCodes {
		if HTTPStatus(code) == 0 || cc == 0 {
			t.Fatalf("table gap for %s", code)
		}
	}
}

func TestCursorRoundTripAndPageBounds(t *testing.T) {
	t.Parallel()
	c := Cursor{CreatedAt: time.Date(2026, 10, 20, 1, 2, 3, 456000, time.UTC), ID: uuid.New()}
	got, ok, err := DecodeCursor(c.Encode())
	if err != nil || !ok || !got.CreatedAt.Equal(c.CreatedAt) || got.ID != c.ID {
		t.Fatalf("round trip: %+v %v %v", got, ok, err)
	}
	if _, _, err := DecodeCursor("not-base64!!"); CodeOf(err) != CodeInvalidArgument {
		t.Fatalf("bad token should be invalid_argument, got %v", err)
	}
	p, err := ParsePageValues("9999", "", DefaultPageSize, MaxPageSize)
	if err != nil || p.Size != MaxPageSize || p.HasCursor {
		t.Fatalf("cap: %+v %v", p, err)
	}
	if _, err := ParsePageValues("-1", "", 10, 100); err == nil {
		t.Fatal("negative page_size accepted")
	}
	tok, n := NextToken(11, 10, func() Cursor { return c })
	if tok == "" || n != 10 {
		t.Fatalf("next token: %q %d", tok, n)
	}
	if tok, n := NextToken(7, 10, nil); tok != "" || n != 7 {
		t.Fatalf("last page: %q %d", tok, n)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) && contains(s, sub) {
			return true
		}
	}
	return false
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
