package dp

import "time"

// EventKind tags a decoded notification by message type. Consumers switch on
// this to pick the right payload field.
type EventKind int

const (
	// EventConnection — one bucket of per-(EPMAC, 5-tuple, policy_id) aggregated
	// traffic. Conn is non-nil. Multiple ConnectionEvents arrive per dp emit;
	// see NeuVector dp/ctrl.c:2787 (CONNECTS_PER_MSG packing).
	EventConnection EventKind = iota
	// EventThreat — one threat detection. Threat is non-nil. Carries the
	// captured packet bytes for forensics.
	EventThreat
	// EventKeepAlive — dp said hi. No payload. Useful for liveness telemetry.
	EventKeepAlive
	// EventSession — one DPMsgSession from a ctrl_list_session response.
	// Wave C1. Sessions is non-nil with N entries per emitted datagram.
	EventSession
	// EventOther — a notification we don't yet promote to a typed payload
	// (DP_KIND_APP_UPDATE, FQDN updates, etc.). Kind carries the raw DP_KIND_*
	// so observability counters can break down what's flowing.
	EventOther
)

// Event is the tagged union surfaced to consumers via Supervisor.Events().
// Exactly one of the typed payload pointers (Conn, Threat, Sessions) is
// non-nil for EventConnection / EventThreat / EventSession. EventOther
// sets RawKind to the DP_KIND_*.
type Event struct {
	Kind     EventKind
	At       time.Time
	Conn     *Connection
	Threat   *ThreatLog
	Sessions []*Session // EventSession: dp emits a batch per datagram
	RawKind  uint8      // for EventOther — the DP_KIND_* observed
}
