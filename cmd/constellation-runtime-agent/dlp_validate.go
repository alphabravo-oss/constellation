// NET-41: agent-side precision gate for the built-in PII DLP patterns.
//
// dp matches credit-card / SSN patterns on structure alone and cannot compute a
// Luhn checksum or apply the SSA sentinel exclusions, so it fires on plenty of
// non-PII digit runs. The validators that filter those (Luhn, SSN sentinels)
// live in internal/runtime/dlp but nothing on the live dp path invoked them —
// they only ran inside the agent-side dlp.Engine, which sees no traffic. This
// file wires them into the one live seam that CAN re-validate: the dp threat
// emit path. When dp reports a hit for a built-in PII rule, we re-scan the
// reported packet; if it holds no checksum-valid PII we drop the false positive
// before it reaches the control plane.
//
// GAP (reported): the built-in PII pack flattens several patterns (CC + SSN +
// national ids) into ONE dp rule, so a hit's sig id names the pack, not the
// pattern; and dp copies only a bounded packet prefix. We therefore gate
// conservatively — suppress only when the captured payload proves NO valid PII
// is present, so a real leak (or a payload dp truncated) is always kept.
package main

import (
	"strings"
	"sync/atomic"

	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// validatedPIIPackMarker identifies the seeded built-in DLP pack whose patterns
// (credit-card, US-SSN) match on structure only and thus benefit from Luhn /
// sentinel re-validation. The handler seeds it as "builtin-dlp-federal-pii".
const validatedPIIPackMarker = "federal-pii"

// validatedThreatIDs holds the dp sig ids of the built-in PII DLP rules in the
// current bundle. dp reports a DLP hit by sig id (threat_id); the IPC reader
// consults this set to decide whether a hit is a re-validation candidate. Behind
// an atomic pointer so the dlp-sync writer and the reader never race on a map.
var validatedThreatIDs atomic.Pointer[map[uint32]struct{}]

// setValidatedThreatIDs recomputes the validated-PII sig-id set from the current
// bundle. Called on every dlp sync so the set tracks rule create/delete. dp
// derives a rule's threat_id from its dp_rule_id via DLPSigID — the same mapping
// planDLPPushes uses to push the rule — so the ids line up with reported hits.
func setValidatedThreatIDs(rules []dlpRuleWire) {
	m := map[uint32]struct{}{}
	for _, r := range rules {
		if strings.Contains(r.Name, validatedPIIPackMarker) {
			m[dp.DLPSigID(uint32(r.DPRuleID))] = struct{}{}
		}
	}
	validatedThreatIDs.Store(&m)
}

// suppressDLPFalsePositive reports whether a dp threat row is a built-in PII DLP
// hit whose captured payload carries NO checksum-valid credit card and no
// issuable SSN — a structural false positive dp fired on. Such rows are dropped
// before upload. It suppresses ONLY when it can prove the payload has no valid
// PII: an unregistered sig id or an empty/absent packet leaves the row untouched
// (fail-open — a genuine alert is never hidden).
func suppressDLPFalsePositive(row threatIngestRow) bool {
	if len(row.Packet) == 0 {
		return false
	}
	set := validatedThreatIDs.Load()
	if set == nil {
		return false
	}
	if _, ok := (*set)[row.ThreatID]; !ok {
		return false
	}
	return !dlp.PayloadHasValidPII(row.Packet)
}
