package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/pkg/notify"
)

// DefaultAdmissionNotifyInterval is the poll cadence for the admission-deny notify
// dispatcher when the caller passes a non-positive interval.
const DefaultAdmissionNotifyInterval = 10 * time.Second

// admissionNotifyBatch caps how many new admission.deny rows one sweep dispatches, so a
// backlog (e.g. after downtime) drains in bounded chunks instead of one huge burst.
const admissionNotifyBatch = 256

// RunAdmissionNotifyDispatcher polls audit_events for 'admission.deny' rows and fans each
// one out through the notify.Dispatcher, so org webhook receivers and the syslog/SIEM
// mirror actually see Constellation's own admission denies (NeuVector EventAdmCtrl ->
// webhookAudit + logAudit parity).
//
// This closes the gap where the constellation-admission webhook pod writes admission.deny
// audit rows directly to the DB but has no dispatcher of its own, so a rule "webhook on
// admission deny" was accepted and audit-logged as fired while the webhook never sent. The
// API is the only process that owns a dispatcher (with the live syslog target wired), so it
// re-delivers the denies here.
//
// Leader-gated (started from startSingletonLoops): a durable single-row cursor
// (admission_notify_state.last_dispatched_id) makes delivery exactly-once and survives
// restarts. Only enforce denies notify — 'admission.monitor' rows are observe-only and are
// intentionally skipped, matching the webhook pod's own monitor semantics.
func RunAdmissionNotifyDispatcher(ctx context.Context, pool *pgxpool.Pool, dispatcher *notify.Dispatcher, interval time.Duration, logger *slog.Logger) {
	if pool == nil || dispatcher == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultAdmissionNotifyInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := sweepAdmissionNotifyOnce(ctx, pool, dispatcher, admissionNotifyBatch); err != nil {
				if logger != nil {
					logger.Warn("admission notify dispatch failed", slog.String("err", err.Error()))
				}
			} else if n > 0 && logger != nil {
				logger.Info("admission notify dispatched", slog.Int("denies", n))
			}
		}
	}
}

// sweepAdmissionNotifyOnce advances the cursor over new admission.deny rows and dispatches
// each. It reads and updates admission_notify_state.last_dispatched_id inside a transaction
// that holds a row lock (FOR UPDATE), so concurrent sweeps (belt-and-suspenders even though
// the loop is leader-gated) never double-dispatch. Returns the count dispatched this pass.
func sweepAdmissionNotifyOnce(ctx context.Context, pool *pgxpool.Pool, dispatcher *notify.Dispatcher, limit int) (int, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, fmt.Errorf("admission notify: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lazily create + lock the singleton cursor row. Seeded at max(id) so a fresh install
	// never replays historical denies (the migration also seeds it).
	var cursor int64
	err = tx.QueryRow(ctx, `SELECT last_dispatched_id FROM admission_notify_state WHERE id = true FOR UPDATE`).Scan(&cursor)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("admission notify: read cursor: %w", err)
		}
		if err := tx.QueryRow(ctx, `
INSERT INTO admission_notify_state (id, last_dispatched_id)
VALUES (true, COALESCE((SELECT max(id) FROM audit_events), 0))
ON CONFLICT (id) DO UPDATE SET last_dispatched_id = admission_notify_state.last_dispatched_id
RETURNING last_dispatched_id`).Scan(&cursor); err != nil {
			return 0, fmt.Errorf("admission notify: seed cursor: %w", err)
		}
	}

	rows, err := tx.Query(ctx, `
SELECT id, org_id, target_id, after, at
  FROM audit_events
 WHERE action = 'admission.deny'
   AND id > $1
 ORDER BY id ASC
 LIMIT $2`, cursor, limit)
	if err != nil {
		return 0, fmt.Errorf("admission notify: query denies: %w", err)
	}
	type denyRow struct {
		id     int64
		orgID  *uuid.UUID
		target string
		after  map[string]any
		at     time.Time
	}
	var denies []denyRow
	for rows.Next() {
		var (
			id        int64
			orgID     *uuid.UUID
			target    string
			afterJSON []byte
			at        time.Time
		)
		if err := rows.Scan(&id, &orgID, &target, &afterJSON, &at); err != nil {
			rows.Close()
			return 0, fmt.Errorf("admission notify: scan: %w", err)
		}
		var after map[string]any
		_ = json.Unmarshal(afterJSON, &after)
		denies = append(denies, denyRow{id: id, orgID: orgID, target: target, after: after, at: at})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("admission notify: rows: %w", err)
	}
	if len(denies) == 0 {
		return 0, nil
	}

	// Advance the cursor to the highest id in this batch and commit BEFORE dispatching.
	// The dispatcher persists its own delivery rows + retries, so a crash after commit at
	// worst drops the in-flight fan-out for a few denies rather than re-notifying every
	// delivered one on restart. Advancing over the whole scanned batch (not just rows with
	// an org) guarantees forward progress past org-less/system rows.
	maxID := denies[len(denies)-1].id
	if _, err := tx.Exec(ctx, `UPDATE admission_notify_state SET last_dispatched_id = $1, updated_at = now() WHERE id = true`, maxID); err != nil {
		return 0, fmt.Errorf("admission notify: advance cursor: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("admission notify: commit: %w", err)
	}

	dispatched := 0
	for _, d := range denies {
		if d.orgID == nil || *d.orgID == uuid.Nil {
			continue // org-less/system rows can't route to a receiver
		}
		_, _ = dispatcher.Dispatch(ctx, admissionDenyNotifyEvent(*d.orgID, d.target, d.after, d.at))
		dispatched++
	}
	return dispatched, nil
}

// admissionDenyNotifyEvent folds an admission.deny audit row into the notify.Event the
// dispatcher fans out. The "admission.deny" kind matches receivers subscribed to
// "admission" (prefix routing) and is what the syslog mirror stamps. Pure — no I/O — so the
// mapping is unit-testable without a DB.
func admissionDenyNotifyEvent(orgID uuid.UUID, targetID string, after map[string]any, at time.Time) notify.Event {
	reason := afterString(after, "reason")
	namespace := afterString(after, "namespace")
	pod := afterString(after, "pod")
	ev := notify.Event{
		Kind:     "admission.deny",
		OrgID:    orgID,
		Severity: "high",
		Title:    admissionDenyTitle(targetID, reason),
		Cluster:  afterString(after, "cluster_id"),
		Workload: targetID,
		URL:      "/admission/events",
		Labels: map[string]string{
			"namespace": namespace,
			"pod":       pod,
			"rule_id":   afterString(after, "rule_id"),
			"operation": afterString(after, "operation"),
		},
		Payload: after,
		FiredAt: at,
	}
	return ev
}

// admissionDenyTitle builds the one-line subject: "Admission denied: <workload> (<reason>)".
func admissionDenyTitle(targetID, reason string) string {
	target := strings.TrimSpace(targetID)
	if target == "" {
		target = "workload"
	}
	title := "Admission denied: " + target
	if r := strings.TrimSpace(reason); r != "" {
		title += " (" + r + ")"
	}
	return title
}

// afterString reads a string field from the decoded audit `after` map, tolerating a nil map
// or non-string value.
func afterString(after map[string]any, key string) string {
	if after == nil {
		return ""
	}
	if v, ok := after[key].(string); ok {
		return v
	}
	return ""
}
