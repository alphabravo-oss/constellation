package dp

import "strings"

// dp validates every rule's sig_id and name before compiling it (dpi_sig.c
// dpi_dlp_parse_opts_routine + dpi_sigopt_basic.c dpi_sigopt_name_parser):
//   - sig_id MUST fall in 20000-29999 (user), 30000-39999 (pre-user), or
//     40000-49999 (WAF); anything else is rejected.
//   - name MUST contain no whitespace/delimiter and no leading/trailing space,
//     or it is rejected as INVALID_SIG_NAME.
// A rejected rule is dropped (and, combined with a bad build/cfg, was part of
// what crashed dp). These helpers keep our rule metadata inside dp's grammar.

// WAF/user sig-id range bounds, mirrored from dp/dpi/sig/dpi_sig.h.
const (
	dpMinWAFSigID  uint32 = 40000
	dpWAFSigSpan   uint32 = 10000 // 40000-49999
	dpMinUserSigID uint32 = 20000
	dpUserSigSpan  uint32 = 10000 // 20000-29999
)

// WAFSigID maps a 0-based built-in WAF rule index into dp's WAF sig-id range
// (40000-49999). Built-in packs are a small fixed list, so a sequential index
// is stable and collision-free.
func WAFSigID(index int) uint32 {
	return dpMinWAFSigID + uint32(index)%dpWAFSigSpan
}

// DLPSigID maps a DB dp_rule_id into dp's user sig-id range (20000-29999).
// ponytail: modulo 10000 — collides only if two ids differ by exactly 10000;
// fine for the built-ins and typical custom-rule counts. Fix the dp_id sequence
// (start at 20000) if custom DLP rules ever approach 10000.
func DLPSigID(dbID uint32) uint32 {
	return dpMinUserSigID + dbID%dpUserSigSpan
}

// SanitizeSigName rewrites a rule name into a token dp's name parser accepts:
// every byte outside [A-Za-z0-9_-] (crucially whitespace, which dp treats as an
// option delimiter) becomes '_'. Leading/trailing '_' is trimmed and the result
// is capped well under dp's MAX_SIG_NAME_LEN. Empty input yields "rule".
func SanitizeSigName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "rule"
	}
	if len(out) > 60 {
		out = strings.Trim(out[:60], "_")
	}
	return out
}
