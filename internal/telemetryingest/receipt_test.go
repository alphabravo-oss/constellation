//go:build integration

package telemetryingest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/testutil/pgtest"

	"github.com/google/uuid"
)

func TestReceiptConcurrentReplayRollbackAndScope(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool := pgtest.Pool(t)
	org, cluster := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES ($1,$2,$2)`, org, "receipt-"+org.String()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, org) }()
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES ($1,$2,'receipt')`, cluster, org); err != nil {
		t.Fatal(err)
	}
	producer := uuid.New()
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM telemetry_producers WHERE producer_id=$1`, producer)
	}()
	request := func(seq int64) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), "POST", "/", nil)
		r.Header.Set(ProducerHeader, producer.String())
		r.Header.Set(SequenceHeader, strconv.FormatInt(seq, 10))
		return r
	}
	// A rolled-back batch must not advance the durable cursor.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, "SET LOCAL synchronous_commit = 'off'"); err != nil {
		t.Fatal(err)
	}
	receipt, _, err := Begin(ctx, tx, request(1), org, cluster, "events", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	var commitMode string
	if err = tx.QueryRow(ctx, "SHOW synchronous_commit").Scan(&commitMode); err != nil || commitMode != "on" {
		t.Fatalf("durable receipt inherited asynchronous commit: %q %v", commitMode, err)
	}
	if err = receipt.Complete(ctx, tx, map[string]int{"accepted": 1}); err != nil {
		t.Fatal(err)
	}
	if err = tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var writes atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			defer tx.Rollback(ctx)
			receipt, replay, err := Begin(ctx, tx, request(1), org, cluster, "events", []int{1})
			if err != nil {
				t.Error(err)
				return
			}
			if replay != nil {
				return
			}
			if err = receipt.Complete(ctx, tx, map[string]int{"accepted": 1}); err != nil {
				t.Error(err)
				return
			}
			if err = tx.Commit(ctx); err != nil {
				t.Error(err)
				return
			}
			writes.Add(1)
		}()
	}
	wg.Wait()
	if writes.Load() != 1 {
		t.Fatalf("committed %d copies of same batch", writes.Load())
	}
	for _, tc := range []struct {
		stream           string
		seq              int64
		payload          int
		replay, conflict bool
	}{
		{"events", 1, 1, true, false}, {"events", 1, 9, false, true},
		{"flows", 1, 1, false, false}, {"events", 2, 2, false, false},
		{"events", 1, 1, false, true},
	} {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		receipt, replay, err := Begin(ctx, tx, request(tc.seq), org, cluster, tc.stream, []int{tc.payload})
		if tc.conflict {
			if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrStale) {
				t.Errorf("expected payload conflict, got %v", err)
			}
		} else if err != nil {
			t.Error(err)
		} else {
			if (replay != nil) != tc.replay {
				t.Errorf("case %+v replay=%s", tc, replay)
			}
			if replay == nil {
				if err = receipt.Complete(ctx, tx, map[string]int{"accepted": 1}); err != nil {
					t.Error(err)
				}
			}
			if err = tx.Commit(ctx); err != nil {
				t.Error(err)
			}
		}
		_ = tx.Rollback(ctx)
	}
}

func TestAdmissionIsolatesBusyCluster(t *testing.T) {
	t.Parallel()
	org, a, b := uuid.New(), uuid.New(), uuid.New()
	one, ok := Admit(httptest.NewRecorder(), org, a)
	if !ok {
		t.Fatal("first rejected")
	}
	defer one()
	two, ok := Admit(httptest.NewRecorder(), org, a)
	if !ok {
		t.Fatal("second rejected")
	}
	defer two()
	w := httptest.NewRecorder()
	if release, ok := Admit(w, org, a); ok {
		release()
		t.Fatal("cluster exceeded cap")
	}
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing retry contract")
	}
	other, ok := Admit(httptest.NewRecorder(), org, b)
	if !ok {
		t.Fatal("noisy cluster blocked another cluster")
	}
	other()
}
