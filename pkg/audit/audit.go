// Package audit implements the hash-chained, append-only audit log writer + chain verifier.
//
// Each row's chain_hash = sha256(prev_chain_hash || canonical(row content excluding hash fields)).
// Tamper detection: replay the chain and assert each row's chain_hash matches the computed value.
// Postgres triggers (see migration 007) forbid UPDATE/DELETE on the table at the engine level.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GenesisHash is the prev_hash of the first row in the chain. Constant so a fresh DB
// can be verified end-to-end.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// chainAdvisoryLockKey is the fixed key all audit writers contend on via
// pg_advisory_xact_lock so concurrent Log() calls serialize before reading the chain head.
//
// The chain is GLOBAL — VerifyChain walks the entire table by id ASC and Log() reads the
// single newest row (no org filter) as prev_hash — so a single fixed key (not a per-org key)
// is required. A per-org lock would let two writers from different orgs read the same global
// head concurrently and insert divergent prev_hash values, the exact corruption H9 describes.
//
// This replaces the previous `SELECT ... ORDER BY id DESC LIMIT 1 FOR UPDATE`, which did NOT
// serialize: after a FOR UPDATE wait, Postgres EvalPlanQual re-checks only the originally
// locked tuple, not the ORDER BY/LIMIT, so a blocked writer would insert with a stale
// prev_hash and miss the row that committed while it waited. The advisory lock is held for the
// life of the transaction and released automatically on commit or rollback.
const chainAdvisoryLockKey int64 = 0x636e7374656c6175 // "cnstelau" (constellation audit)

// Event is one audit row as the application sees it (without the hash fields, which the
// Logger computes).
type Event struct {
	OrgID      *uuid.UUID
	ActorID    *uuid.UUID
	ActorIP    net.IP
	Action     string // "finding.suppress", "policy.update", ...
	TargetKind string
	TargetID   string
	Before     any
	After      any
	RequestID  string
	At         time.Time // optional; defaults to NOW() if zero
}

// Logger writes hash-chained audit events. Construct one per process; Log is safe to call
// concurrently because every writer serializes on a fixed transaction-scoped advisory lock
// (chainAdvisoryLockKey) taken before reading the chain head, so concurrent writers queue and
// each reads the true committed head.
type Logger struct {
	pool *pgxpool.Pool
}

// New returns a Logger writing to the given pool.
func New(pool *pgxpool.Pool) *Logger { return &Logger{pool: pool} }

// Log appends one event to the chain. Returns the row id and the chain_hash of the new row.
func (l *Logger) Log(ctx context.Context, ev Event) (id int64, chainHash string, err error) {
	tx, err := l.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return 0, "", fmt.Errorf("audit: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize all chain writers on a fixed transaction-scoped advisory lock BEFORE reading the
	// head, so a concurrent writer queues here and reads the true (committed) head once it acquires
	// the lock — instead of racing on a "moving head" row under READ COMMITTED. See
	// chainAdvisoryLockKey for why this must be a single global key, not per-org.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, chainAdvisoryLockKey); err != nil {
		return 0, "", fmt.Errorf("audit: acquire chain lock: %w", err)
	}

	// Read the current chain head. The advisory lock above guarantees no other writer can
	// insert between this read and our INSERT, so prev is always the genuine head.
	// On a fresh chain there is no row, in which case prev_hash = GenesisHash.
	var prev string
	row := tx.QueryRow(ctx, `SELECT chain_hash FROM audit_events ORDER BY id DESC LIMIT 1`)
	if err := row.Scan(&prev); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			prev = GenesisHash
		} else {
			return 0, "", fmt.Errorf("audit: read prev hash: %w", err)
		}
	}

	beforeJSON, err := json.Marshal(ev.Before)
	if err != nil {
		return 0, "", fmt.Errorf("audit: marshal before: %w", err)
	}
	afterJSON, err := json.Marshal(ev.After)
	if err != nil {
		return 0, "", fmt.Errorf("audit: marshal after: %w", err)
	}

	at := ev.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	// Postgres TIMESTAMPTZ has microsecond precision; truncating here ensures the hash we
	// store is computed over the same value that a later VerifyChain reads back. Without
	// this, an in-memory time.Time with nanosecond precision would be hashed on write but
	// the µs-truncated round-trip value would be hashed on verify, breaking every chain.
	at = at.Truncate(time.Microsecond)

	rowHash := computeChainHash(prev, ev, beforeJSON, afterJSON, at)

	var actorIP *string
	if ev.ActorIP != nil {
		s := ev.ActorIP.String()
		actorIP = &s
	}

	insertSQL := `
INSERT INTO audit_events (org_id, actor_id, actor_ip, action, target_kind, target_id,
                          before, after, prev_hash, chain_hash, request_id, at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING id`
	if err := tx.QueryRow(ctx, insertSQL,
		ev.OrgID, ev.ActorID, actorIP, ev.Action, ev.TargetKind, ev.TargetID,
		beforeJSON, afterJSON, prev, rowHash, ev.RequestID, at,
	).Scan(&id); err != nil {
		return 0, "", fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, "", fmt.Errorf("audit: commit: %w", err)
	}
	return id, rowHash, nil
}

// canonicalContent is the deterministic bytes hashed for this row.
// Field order is intentionally fixed; changing it would invalidate every existing chain.
func canonicalContent(ev Event, beforeJSON, afterJSON []byte, at time.Time) []byte {
	type c struct {
		OrgID      string          `json:"org_id"`
		ActorID    string          `json:"actor_id"`
		ActorIP    string          `json:"actor_ip"`
		Action     string          `json:"action"`
		TargetKind string          `json:"target_kind"`
		TargetID   string          `json:"target_id"`
		Before     json.RawMessage `json:"before"`
		After      json.RawMessage `json:"after"`
		RequestID  string          `json:"request_id"`
		AtUnixNano int64           `json:"at"`
	}
	out := c{
		Action:     ev.Action,
		TargetKind: ev.TargetKind,
		TargetID:   ev.TargetID,
		Before:     canonicalJSON(beforeJSON),
		After:      canonicalJSON(afterJSON),
		RequestID:  ev.RequestID,
		AtUnixNano: at.UTC().UnixNano(),
	}
	if ev.OrgID != nil {
		out.OrgID = ev.OrgID.String()
	}
	if ev.ActorID != nil {
		out.ActorID = ev.ActorID.String()
	}
	if ev.ActorIP != nil {
		out.ActorIP = ev.ActorIP.String()
	}
	b, _ := json.Marshal(out)
	return b
}

func canonicalJSON(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("null")
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return json.RawMessage(raw)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(raw)
	}
	return b
}

func computeChainHash(prev string, ev Event, beforeJSON, afterJSON []byte, at time.Time) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(canonicalContent(ev, beforeJSON, afterJSON, at))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyChain walks the entire audit_events table from id ASC and returns the first row at
// which the recomputed chain hash does not match the stored hash. nil means the chain is intact.
func VerifyChain(ctx context.Context, pool *pgxpool.Pool) (*ChainBreak, error) {
	// NB: use host(actor_ip) to strip the inet/cidr mask. Postgres renders
	// `inet::text` as `<addr>/<bits>` (e.g. "::1/128", "10.0.0.1/32"), which
	// fails to round-trip through net.ParseIP and silently breaks the chain
	// for every row that carries a non-NULL actor IP. host() returns just the
	// address portion ("::1", "10.0.0.1") — matching what Logger stored at
	// write time via net.IP.String().
	rows, err := pool.Query(ctx, `
SELECT id, org_id, actor_id, host(actor_ip), action, target_kind, target_id,
       before, after, prev_hash, chain_hash, request_id, at
  FROM audit_events ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("audit: query chain: %w", err)
	}
	defer rows.Close()

	expectedPrev := GenesisHash
	for rows.Next() {
		var (
			id         int64
			orgID      *uuid.UUID
			actorID    *uuid.UUID
			actorIP    *string
			action     string
			targetKind string
			targetID   string
			beforeJSON []byte
			afterJSON  []byte
			prev       string
			stored     string
			requestID  string
			at         time.Time
		)
		if err := rows.Scan(&id, &orgID, &actorID, &actorIP, &action, &targetKind, &targetID,
			&beforeJSON, &afterJSON, &prev, &stored, &requestID, &at); err != nil {
			return nil, fmt.Errorf("audit: scan: %w", err)
		}
		if prev != expectedPrev {
			return &ChainBreak{ID: id, Reason: "prev_hash mismatch", Expected: expectedPrev, Found: prev}, nil
		}
		ev := Event{
			OrgID:      orgID,
			ActorID:    actorID,
			Action:     action,
			TargetKind: targetKind,
			TargetID:   targetID,
			RequestID:  requestID,
			At:         at,
		}
		if actorIP != nil {
			ev.ActorIP = net.ParseIP(*actorIP)
		}
		computed := computeChainHash(prev, ev, beforeJSON, afterJSON, at)
		if computed != stored {
			return &ChainBreak{ID: id, Reason: "row hash mismatch", Expected: computed, Found: stored}, nil
		}
		expectedPrev = stored
	}
	return nil, rows.Err()
}

// ChainBreak describes the first integrity failure encountered while walking the chain.
type ChainBreak struct {
	ID       int64
	Reason   string
	Expected string
	Found    string
}

func (cb *ChainBreak) Error() string {
	return fmt.Sprintf("audit chain broken at id=%d: %s (expected=%s found=%s)", cb.ID, cb.Reason, cb.Expected, cb.Found)
}
