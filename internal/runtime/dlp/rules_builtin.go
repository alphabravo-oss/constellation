package dlp

import (
	"regexp"
	"strings"
)

// BuiltinSensor returns the v1 Constellation default DLP sensor: credit-card numbers
// (with Luhn validation), US SSNs, AWS access keys, GitHub PATs, Slack tokens, and
// Stripe live/test keys.
//
// Targets are the L7-wide ones — REQUEST_URI/ARGS/REQUEST_BODY/REQUEST_HEADERS/QUERY
// — so the same patterns catch leaks in HTTP, gRPC, SQL, and Redis simultaneously.
func BuiltinSensor() Sensor {
	defaultTargets := []string{"REQUEST_URI", "REQUEST_BODY", "REQUEST_HEADERS", "QUERY", "REDIS_ARGS"}
	return Sensor{
		Name:    "constellation-default-dlp",
		Group:   "constellation-default",
		Type:    CfgPredefined,
		Comment: "Constellation default DLP signature pack.",
		Patterns: []Pattern{
			{
				ID: 1001, Msg: "Credit card number (Luhn-valid)",
				Severity: SevCritical, Action: "block",
				Regex:    `\b(?:\d[ -]*?){13,19}\b`,
				Validator: func(s string) bool {
					return luhnValid(stripNonDigits(s))
				},
				Targets: defaultTargets,
			},
			{
				ID: 1002, Msg: "US Social Security Number",
				Severity: SevCritical, Action: "block",
				// RE2 has no negative lookaheads; we validate exclusions in code.
				Regex:   `\b\d{3}-\d{2}-\d{4}\b`,
				Validator: validSSN,
				Targets: defaultTargets,
			},
			{
				ID: 1003, Msg: "AWS Access Key ID",
				Severity: SevCritical, Action: "block",
				Regex:   `\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`,
				Targets: defaultTargets,
			},
			{
				ID: 1004, Msg: "AWS Secret Access Key (heuristic)",
				Severity: SevError, Action: "alert",
				// 40 base64-ish chars near a `aws_secret_access_key` marker.
				Regex:   `(?i)aws_secret_access_key["'= :]+[A-Za-z0-9/+]{40}`,
				Targets: defaultTargets,
			},
			{
				ID: 1005, Msg: "GitHub Personal Access Token",
				Severity: SevCritical, Action: "block",
				Regex:   `\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghu_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b|\bghr_[A-Za-z0-9]{36}\b`,
				Targets: defaultTargets,
			},
			{
				ID: 1006, Msg: "Slack Bot/User token",
				Severity: SevCritical, Action: "block",
				Regex:   `\bxox[abps]-[A-Za-z0-9-]{10,48}\b`,
				Targets: defaultTargets,
			},
			{
				ID: 1007, Msg: "Stripe live secret key",
				Severity: SevCritical, Action: "block",
				Regex:   `\bsk_live_[A-Za-z0-9]{24,}\b`,
				Targets: defaultTargets,
			},
			{
				ID: 1008, Msg: "Stripe test secret key",
				Severity: SevWarning, Action: "alert",
				Regex:   `\bsk_test_[A-Za-z0-9]{24,}\b`,
				Targets: defaultTargets,
			},
			{
				ID: 1009, Msg: "Generic high-entropy bearer token",
				Severity: SevError, Action: "alert",
				Regex:   `(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}`,
				Targets: []string{"REQUEST_HEADERS"},
			},
			{
				ID: 1010, Msg: "EU IBAN",
				Severity: SevWarning, Action: "alert",
				Regex:   `\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`,
				Validator: func(s string) bool {
					s = strings.ToUpper(stripNonAlnum(s))
					return looksLikeIBAN(s)
				},
				Targets: defaultTargets,
			},
		},
	}
}

// validSSN rejects sentinel SSNs the SSA never issues (000/666/9xx area; 00 group;
// 0000 serial). See: https://www.ssa.gov/employer/randomization.html
func validSSN(s string) bool {
	if len(s) != 11 || s[3] != '-' || s[6] != '-' {
		return false
	}
	area := s[0:3]
	group := s[4:6]
	serial := s[7:11]
	switch {
	case area == "000" || area == "666":
		return false
	case area[0] == '9':
		return false
	case group == "00":
		return false
	case serial == "0000":
		return false
	}
	return true
}

// luhnValid runs the Luhn check on a string of digits.
func luhnValid(digits string) bool {
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	var sum int
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func stripNonAlnum(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= '0' && r <= '9') || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// looksLikeIBAN runs the IBAN mod-97 check. We're lenient — letters map to two-digit
// values, then the whole string is interpreted as a giant decimal mod 97 = 1.
func looksLikeIBAN(s string) bool {
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	// Move first 4 chars to end.
	rearranged := s[4:] + s[:4]
	var digits strings.Builder
	for _, r := range rearranged {
		switch {
		case r >= '0' && r <= '9':
			digits.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			digits.WriteString(itoa(int(r - 'A' + 10)))
		default:
			return false
		}
	}
	// Compute mod 97 incrementally.
	mod := 0
	for _, r := range digits.String() {
		mod = (mod*10 + int(r-'0')) % 97
	}
	return mod == 1
}

func itoa(n int) string {
	if n < 10 {
		return string('0' + rune(n))
	}
	return string('0'+rune(n/10)) + string('0'+rune(n%10))
}

// rxStripBlanks deletes whitespace + dashes (used by Luhn pre-check).
var rxStripBlanks = regexp.MustCompile(`[\s-]+`)

func init() { _ = rxStripBlanks }
