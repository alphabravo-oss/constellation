package dp

import "strings"

// dp's DLP/WAF engine does NOT accept a raw regex. dp copies each pattern we
// push verbatim into a signature as `pcre <pattern>;` (dp/dpi/sig/dpi_sig.c),
// str-splits that on ';', then dpi_sigopt_pcre_parser (dp/dpi/sig/dpi_sigopt_pcre.c)
// parses the "pcre" option value as a Snort-style pcre literal: it demands a
// leading delimiter ('/', or 'm<delim>', optionally negated with '!'). A value
// that does not start that way is rejected with "invalid option(pcre : <regex>)".
//
// CRUCIALLY, dp also needs a "context" option per pattern. Without one, the pcre
// pattern lands in dp's packet_opts build path (dpi_sigopt_pcre.c:528 defaults
// class=PACKET) — and building the hyperscan detect tree over that path SEGFAULTS.
// NeuVector's own agent never hits it because it ALWAYS appends "; context <ctx>"
// (default "body") and always wraps with the "is" flags — see
// neuvector/agent/system.go:1024-1030. We mirror that exact format:
//
//	[!]/<regex>/is; context <ctx>
//
// dp receives `pcre /<regex>/is; context <ctx>;`, splits on ';' into a "pcre"
// option (value "/<regex>/is") and a "context" option (value "<ctx>"), so the
// pattern is placed in body_opts and the tree build is the exercised, safe path.
//
// pcreFlagChars are the trailing flag letters dp accepts after the closing
// delimiter (dpi_sigopt_pcre.c lines 468-490): i m s x A E G. dp locates the
// closing delimiter with strrchr — the LAST '/' — so interior '/' (including
// "://") is preserved as long as only flag letters follow the final '/'.
const pcreFlagChars = "imsxAEG"

// defaultDLPContext is dp's default match context. dp REQUIRES a context option
// per pattern (a context-less pattern crashes the tree build); "body" mirrors
// neuvector share.DlpPatternContextDefault.
const defaultDLPContext = "body"

// NormalizePCREPattern rewrites a raw regex into the full dp pcre value form
// NeuVector's agent uses: "[!]/<regex>/is; context <ctx>". dp prepends the
// "pcre " keyword and a trailing ";" itself, so we supply only this value.
//
//   - Empty / whitespace-only input returns "" (callers skip it — never panics).
//   - A pattern that already carries a "; context <ctx>" clause is returned
//     unchanged, so the function is idempotent (f(f(x)) == f(x)) and never
//     double-wraps our own output or a fully-formed literal.
//   - A leading "!" (negate) is preserved ahead of the delimiter, matching dp's
//     dpi_sigopt_pcre.c:434 and NeuVector's CriteriaOpNotRegex handling.
//   - A now-redundant leading "(?i)" is stripped (the "i" flag covers it).
//   - Interior "/" is preserved: dp finds the closing delimiter via strrchr, so
//     slashes inside the regex (e.g. the Log4Shell "://") stay intact.
func NormalizePCREPattern(raw string) string {
	return normalizePCREWithContext(raw, defaultDLPContext)
}

// normalizePCREWithContext is NormalizePCREPattern with an explicit dp context
// (WAF patterns carry a per-pattern context; DLP uses the "body" default). ctx
// must be a value dp's dpi_sigopt_context_parser accepts: url, header, body,
// packet, or sql_query — an unknown context makes dp reject the whole rule.
func normalizePCREWithContext(raw, ctx string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// Idempotent / already-formed: our own output (and any dp-ready literal)
	// carries a "; context <ctx>" clause — leave it untouched.
	if strings.Contains(s, "; context ") {
		return s
	}
	neg := ""
	if strings.HasPrefix(s, "!") {
		neg = "!"
		s = strings.TrimSpace(s[1:])
	}
	body := s
	if !isDelimitedForm(s) {
		// Raw regex → wrap NeuVector-style "/regex/is" (i=caseless, s=dotall).
		// Strip a now-redundant leading (?i).
		inner := strings.TrimPrefix(s, "(?i)")
		if strings.TrimSpace(inner) == "" {
			return ""
		}
		// dp splits the signature text on ';' (its option separator), so a literal
		// ';' inside the regex (shell-metachar rules: "(;|&&|...)", "id\s*;") would
		// truncate the pcre value and make pcre2 reject it. Escape it as \x3b, which
		// pcre2/hyperscan compile back to ';'. Do this BEFORE appending the real
		// "; context" separator below.
		inner = strings.ReplaceAll(inner, ";", `\x3b`)
		body = "/" + inner + "/is"
	}
	return neg + body + "; context " + ctx
}

// isDelimitedForm reports whether s is already a Snort pcre literal in
// "/regex/flags" or "m<delim>regex<delim>flags" form (with a distinct closing
// delimiter after a non-empty body and only valid dp flag letters trailing).
// When true, NormalizePCREPattern keeps the caller's delimiters/flags and only
// appends the required context. None of our built-ins start with a delimiter, so
// this branch is a defensive passthrough for pre-wrapped user literals.

// isDelimitedForm reports whether s is a Snort pcre literal in "/regex/flags" or
// "m<delim>regex<delim>flags" form, with a distinct closing delimiter after a
// non-empty body. The bare '/' form is deliberately tight (flag tail must be one
// we ourselves emit) so a raw regex that merely resembles a literal is wrapped
// rather than silently mis-shipped; the m<delim> form accepts any dp flag.
func isDelimitedForm(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case 'm':
		// m<delim><regex><delim><flags>: the char after 'm' is the delimiter and
		// must be punctuation (a real regex like "mail@" has an alnum there); a
		// distinct closing delimiter must follow a NON-EMPTY body (inner is s[2:i],
		// so require i > 2 — "m##", "m@" are raw, not literals). The explicit m
		// form is the escape hatch for authoring a literal with any dp flag.
		if len(s) < 3 || !isDelimByte(s[1]) {
			return false
		}
		i := strings.LastIndexByte(s, s[1])
		return i > 2 && validFlags(s[i+1:])
	case '/':
		// /<regex>/<flags>: needs a distinct closing '/' after a NON-EMPTY body
		// (i > 1, so "//" is wrapped, not shipped as an empty regex) and a valid
		// dp flag tail. Our own output carries a "; context " clause and is caught
		// by the idempotency check before reaching here, so this only classifies
		// pre-wrapped user literals lacking a context.
		i := strings.LastIndexByte(s, '/')
		return i > 1 && validFlags(s[i+1:])
	}
	return false
}

// isDelimByte reports whether b can serve as a pcre delimiter (any punctuation;
// never alphanumeric or backslash).
func isDelimByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= 'A' && b <= 'Z', b >= '0' && b <= '9', b == '\\':
		return false
	default:
		return true
	}
}

// validFlags reports whether every byte of s is a pcre flag letter (empty is
// valid — a flagless "/.../" is fine).
func validFlags(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(pcreFlagChars, s[i]) < 0 {
			return false
		}
	}
	return true
}

// normalizePCREList maps NormalizePCREPattern over a string slice, dropping any
// pattern that normalizes to empty. Returns nil for a nil input so an unset
// pattern list stays unset on the wire.
func normalizePCREList(pats []string) []string {
	if pats == nil {
		return nil
	}
	out := make([]string, 0, len(pats))
	for _, p := range pats {
		if n := NormalizePCREPattern(p); n != "" {
			out = append(out, n)
		}
	}
	return out
}
