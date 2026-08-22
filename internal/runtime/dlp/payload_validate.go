package dlp

import "regexp"

// NET-41: the built-in credit-card / SSN DLP patterns match on structure alone,
// so dp (which runs raw PCRE and cannot compute a Luhn checksum) fires on any
// 13-19 digit run or NNN-NN-NNNN string — order numbers, phone strings, tracking
// ids all trip it. The Luhn / sentinel validators below already existed
// (BuiltinSensor wires them into the agent-side dlp.Engine) but nothing on the
// live dp path called them. These exported helpers let the runtime-agent
// re-validate a reported DLP hit's payload at emit time and suppress the false
// positives dp cannot filter itself. They only ever REJECT a match that has no
// checksum-valid value in it, so a genuine leak is never hidden.

// ccCandidate finds credit-card-shaped runs: 13-19 digits, optionally split by a
// single space or dash between digits. Matches the built-in CC sensor's shape.
var ccCandidate = regexp.MustCompile(`[0-9](?:[ -]?[0-9]){12,18}`)

// ssnCandidate finds US-SSN-shaped strings (NNN-NN-NNNN).
var ssnCandidate = regexp.MustCompile(`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`)

// LuhnValid reports whether a string of digits passes the Luhn checksum (and is a
// plausible PAN length, 13-19 digits). Exported wrapper over the internal check.
func LuhnValid(digits string) bool { return luhnValid(digits) }

// ValidSSN reports whether s (NNN-NN-NNNN) is an SSN the SSA can actually issue —
// it rejects the 000/666/9xx area, 00 group, and 0000 serial sentinels. Exported
// wrapper over the internal check.
func ValidSSN(s string) bool { return validSSN(s) }

// PayloadHasValidCreditCard reports whether payload contains at least one
// credit-card-shaped run that passes the Luhn checksum.
func PayloadHasValidCreditCard(payload []byte) bool {
	for _, m := range ccCandidate.FindAll(payload, -1) {
		if luhnValid(stripNonDigits(string(m))) {
			return true
		}
	}
	return false
}

// PayloadHasValidSSN reports whether payload contains at least one SSN-shaped
// string that passes the sentinel-exclusion check.
func PayloadHasValidSSN(payload []byte) bool {
	for _, m := range ssnCandidate.FindAll(payload, -1) {
		if validSSN(string(m)) {
			return true
		}
	}
	return false
}

// PayloadHasValidPII reports whether payload carries a checksum-valid credit-card
// number OR an issuable SSN. The runtime-agent uses this to decide whether a
// built-in PII DLP hit is a real leak (keep it) or a structural false positive dp
// could not filter (drop it). Returns false for an empty payload so a hit whose
// packet dp did not capture is never suppressed (fail-open — keep the alert).
func PayloadHasValidPII(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	return PayloadHasValidCreditCard(payload) || PayloadHasValidSSN(payload)
}
