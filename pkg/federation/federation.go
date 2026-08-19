// Package federation implements Constellation's NeuVector-style multi-cluster
// federation primitives: state machine + member registry + a since-version
// rule-sync log used to ship policy / group changes from a master to its joints.
//
// Scope: policies, groups, admission policies, and response-rule overrides.
// Runtime data (events, flows) stays per-cluster.
package federation

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// State is the federation role of this controller.
type State string

const (
	StateStandalone State = "standalone"
	StateMaster     State = "master"
	StateJoint      State = "joint"
)

// Membership is the federation header for an org.
type Membership struct {
	State       State     `json:"state"`
	MasterID    string    `json:"master_id,omitempty"`
	ClusterName string    `json:"cluster_name,omitempty"`
	Revision    int64     `json:"revision"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// Member is one federated cluster.
type Member struct {
	ID         string    `json:"id,omitempty"`
	ClusterID  string    `json:"cluster_id"`
	Name       string    `json:"name"`
	Role       string    `json:"role"` // master | joint
	Endpoint   string    `json:"endpoint"`
	Status     string    `json:"status"`
	LastSyncAt time.Time `json:"last_sync_at,omitempty"`
	Revision   int64     `json:"revision"`
}

// RuleRevision is one entry in the modified-rules log.
type RuleRevision struct {
	ID        string    `json:"id,omitempty"`
	Kind      string    `json:"kind"` // policy | group | admission_policy | response_rule (+ *_delete tombstones)
	RuleID    string    `json:"rule_id"`
	Revision  int64     `json:"revision"`
	Payload   []byte    `json:"payload"`
	UpdatedAt time.Time `json:"updated_at"`
}

// State machine transitions.
//
//	standalone → master  (Promote)
//	standalone → joint   (Join)
//	master     → standalone (Demote)
//	joint      → standalone (Leave)
//
// Returns the next state or an error when the transition is invalid.
func Promote(cur Membership) (Membership, error) {
	if cur.State != StateStandalone {
		return cur, fmt.Errorf("federation: cannot promote from %s", cur.State)
	}
	cur.State = StateMaster
	cur.Revision = 1
	cur.UpdatedAt = time.Now().UTC()
	return cur, nil
}

func Join(cur Membership, masterID, clusterName string) (Membership, error) {
	if cur.State != StateStandalone {
		return cur, fmt.Errorf("federation: cannot join from %s", cur.State)
	}
	if strings.TrimSpace(masterID) == "" {
		return cur, fmt.Errorf("federation: master_id required")
	}
	cur.State = StateJoint
	cur.MasterID = masterID
	cur.ClusterName = clusterName
	cur.Revision = 0
	cur.UpdatedAt = time.Now().UTC()
	return cur, nil
}

func Demote(cur Membership) (Membership, error) {
	if cur.State != StateMaster {
		return cur, fmt.Errorf("federation: cannot demote from %s", cur.State)
	}
	cur.State = StateStandalone
	cur.MasterID = ""
	cur.UpdatedAt = time.Now().UTC()
	return cur, nil
}

func Leave(cur Membership) (Membership, error) {
	if cur.State != StateJoint {
		return cur, fmt.Errorf("federation: cannot leave from %s", cur.State)
	}
	cur.State = StateStandalone
	cur.MasterID = ""
	cur.UpdatedAt = time.Now().UTC()
	return cur, nil
}

// Member liveness statuses derived from last_sync_at age (ListMembers) and the
// terminal membership states recorded in fed_members.status.
const (
	MemberStatusPending = "pending" // added, has not yet polled the master
	MemberStatusActive  = "active"  // polled within the freshness window
	MemberStatusStale   = "stale"   // polled, but not within the freshness window
	MemberStatusOffline = "offline" // polled long ago / well past the window
	MemberStatusKicked  = "kicked"  // ejected by the master; future polls rejected
)

// Kick is the master-side eject transition for a joint member. It mirrors
// NeuVector's CLUSEvFedKick: the master revokes a joint so its subsequent polls
// are rejected. Unlike Leave (joint-initiated, self-demotes to standalone), Kick
// is applied to a member row by the master and is only valid for a member that is
// not already kicked.
func Kick(status string) (string, error) {
	if status == MemberStatusKicked {
		return status, fmt.Errorf("federation: member already kicked")
	}
	return MemberStatusKicked, nil
}

// DeriveStatus maps a member's last_sync_at age onto a liveness status, leaving
// terminal states (pending with no sync, kicked) untouched. interval is the joint
// poll cadence; a member is active within one interval, stale within three, and
// offline beyond that.
//
// ponytail: the freshness multipliers are fixed (1x/3x); a per-federation
// configurable threshold is the upgrade path.
func DeriveStatus(stored string, lastSync time.Time, now time.Time, interval time.Duration) string {
	if stored == MemberStatusKicked {
		return MemberStatusKicked
	}
	if lastSync.IsZero() {
		return MemberStatusPending
	}
	if interval <= 0 {
		interval = time.Minute
	}
	age := now.Sub(lastSync)
	switch {
	case age <= interval:
		return MemberStatusActive
	case age <= 3*interval:
		return MemberStatusStale
	default:
		return MemberStatusOffline
	}
}

// FilterSince returns the subset of revisions strictly greater than `since`, sorted
// ascending. Used by joints polling the master's /sync endpoint.
func FilterSince(revisions []RuleRevision, since int64) []RuleRevision {
	out := make([]RuleRevision, 0, len(revisions))
	for _, r := range revisions {
		if r.Revision > since {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision < out[j].Revision })
	return out
}

// NextRevision returns max(known)+1 — used by the master when recording a change.
func NextRevision(known []RuleRevision) int64 {
	var max int64
	for _, r := range known {
		if r.Revision > max {
			max = r.Revision
		}
	}
	return max + 1
}

// Validate returns an error if m is malformed.
func (m *Member) Validate() error {
	if strings.TrimSpace(m.ClusterID) == "" {
		return fmt.Errorf("federation: cluster_id required")
	}
	if m.Role != "master" && m.Role != "joint" {
		return fmt.Errorf("federation: invalid role %q", m.Role)
	}
	return nil
}
