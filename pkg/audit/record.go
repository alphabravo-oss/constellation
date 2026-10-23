package audit

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
)

// Record is the portable JSONL representation of an audit row. ActorIP is a
// host address (Postgres host(actor_ip)), never an inet CIDR expression.
type Record struct {
	ID         int64           `json:"id"`
	OrgID      *uuid.UUID      `json:"org_id"`
	ActorID    *uuid.UUID      `json:"actor_id"`
	ActorIP    *string         `json:"actor_ip"`
	Action     string          `json:"action"`
	TargetKind string          `json:"target_kind"`
	TargetID   string          `json:"target_id"`
	Before     json.RawMessage `json:"before"`
	After      json.RawMessage `json:"after"`
	PrevHash   string          `json:"prev_hash"`
	ChainHash  string          `json:"chain_hash"`
	RequestID  string          `json:"request_id"`
	At         time.Time       `json:"at"`
}

// VerifyRecord replays the exact database writer's canonical hash algorithm.
// Callers also enforce increasing IDs; sequence gaps alone are not corruption.
func VerifyRecord(r Record, expectedPrev string) error {
	if r.PrevHash != expectedPrev {
		return &ChainBreak{ID: r.ID, Reason: "prev_hash mismatch", Expected: expectedPrev, Found: r.PrevHash}
	}
	ev := Event{OrgID: r.OrgID, ActorID: r.ActorID, Action: r.Action, TargetKind: r.TargetKind,
		TargetID: r.TargetID, RequestID: r.RequestID, At: r.At}
	if r.ActorIP != nil {
		ev.ActorIP = net.ParseIP(*r.ActorIP)
		if ev.ActorIP == nil {
			return fmt.Errorf("audit: invalid actor IP at id=%d", r.ID)
		}
	}
	computed := computeChainHash(r.PrevHash, ev, r.Before, r.After, r.At)
	if computed != r.ChainHash {
		return &ChainBreak{ID: r.ID, Reason: "row hash mismatch", Expected: computed, Found: r.ChainHash}
	}
	return nil
}
