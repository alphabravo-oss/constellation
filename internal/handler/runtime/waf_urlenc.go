package runtime

import "strings"

// urlEncodeTolerant rewrites a PCRE authored for URL-DECODED text into one that
// ALSO matches the single-percent-encoded form seen on the wire.
//
// Why this exists: dp scans the RAW request URI (DPI_SIG_CONTEXT_TYPE_URI_ORIGIN)
// and does NOT url-decode; query-string special chars are always percent-encoded
// on the wire (a raw space terminates the URI), so a CRS pattern like
// `\bunion\b.+\bselect\b` — written against decoded text — can essentially never
// match a real URL attack (`UNION%20SELECT`: the trailing `0` of `%20` defeats
// the `\b` before `union`). We can't fix dp (third_party, read-only) and its
// hyperscan has no lookaround, so we widen the PATTERN instead.
//
// The rewrite is a small tokenizer that, OUTSIDE character classes and group
// openers, replaces boundary/whitespace/literal tokens with an alternation of
// the original AND its percent-encoding:
//   - `\b`            -> (?:\b|%[0-9A-Fa-f]{2})   (a preceding %XX satisfies the boundary)
//   - `\s`            -> (?:\s|%09|%0[AaCcDd]|%20|\+)
//   - escaped `\. \/ \\ \|` and the literal set (' " < > : ; / ` = & , space)
//     -> (?:orig|%HH)
// Character classes are augmented (not skipped) with the encodings of their
// encodable members so e.g. `[\s>]` also matches `%3E`. Group openers ((?:, (?i),
// (?i:, (?<name>, lookaround) and quantifier braces are copied verbatim so their
// structural chars are never rewritten.
//
// ponytail: single-encoding only. Double-encoding (%2520) and mixed-case exotic
// evasions are a documented residual — the real fix would be url-decoding in dp,
// which is out of reach. Widen here only for the always-on single-encoding case.
func urlEncodeTolerant(pcre string) string {
	var b strings.Builder
	s := pcre
	n := len(s)
	for i := 0; i < n; {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= n {
				b.WriteByte(c)
				i++
				continue
			}
			switch s[i+1] {
			case 'b':
				b.WriteString(bAlt)
			case 's':
				b.WriteString(wsAlt)
			case '.':
				b.WriteString(`(?:\.|%2[Ee])`)
			case '/':
				b.WriteString(`(?:/|%2[Ff])`)
			case '\\':
				b.WriteString(`(?:\\|%5[Cc])`)
			case '|':
				b.WriteString(`(?:\||%7[Cc])`)
			default:
				b.WriteByte(c)
				b.WriteByte(s[i+1])
			}
			i += 2
		case c == '[':
			j := classEnd(s, i)
			b.WriteString(augmentClass(s[i:j]))
			i = j
		case c == '(':
			j := groupOpenerEnd(s, i)
			b.WriteString(s[i:j])
			i = j
		case c == '{':
			j := i + 1
			for j < n && s[j] != '}' {
				j++
			}
			if j < n {
				j++
			}
			b.WriteString(s[i:j])
			i = j
		default:
			if repl, ok := literalAlt[c]; ok {
				b.WriteString(repl)
			} else {
				b.WriteByte(c)
			}
			i++
		}
	}
	return b.String()
}

// wsAlt matches a decoded whitespace char OR its percent-encoding (tab/LF/FF/CR/
// space) OR the `+` form used in query strings.
const wsAlt = `(?:\s|%09|%0[AaCcDd]|%20|\+)`

// bAlt replaces a word boundary `\b`. Besides a real boundary it accepts a bare
// hex char OR a full %XX. Rationale: a keyword is often preceded by an encoded
// separator like `%20`; a preceding `.+`/`.{m,n}` consumes most of it, leaving
// only the final hex char (`0` of `%20`) adjacent to the keyword — which a plain
// `\b` rejects (digit→letter is no boundary). The bare `[0-9A-Fa-f]` alt absorbs
// that trailing hex char so the keyword still anchors, while a leading LETTER
// (e.g. the `m` of "communion") is still rejected — hex letters a–f are the only
// FP surface (a keyword directly preceded by a lone a–f/0–9 char), which is
// contrived enough to accept. `\b` is tried first so decoded input is unaffected.
const bAlt = `(?:\b|[0-9A-Fa-f]|%[0-9A-Fa-f]{2})`

// literalAlt maps an UNESCAPED literal char (never a regex metacharacter) to an
// alternation of itself and its percent-encoding. Regex metacharacters
// (. * + ? { } ( ) [ ] ^ $ |) are absent and thus copied verbatim; ( [ { are
// handled by dedicated cases before this map is consulted.
var literalAlt = map[byte]string{
	'\'': `(?:'|%27)`,
	'"':  `(?:"|%22)`,
	'<':  `(?:<|%3C)`,
	'>':  `(?:>|%3E)`,
	':':  `(?::|%3A)`,
	';':  `(?:;|%3B)`,
	'/':  `(?:/|%2[Ff])`,
	'`':  "(?:`|%60)",
	'=':  `(?:=|%3D)`,
	'&':  `(?:&|%26)`,
	',':  `(?:,|%2C)`,
	' ':  wsAlt,
}

// classEnd returns the index just past the closing ] of the character class
// starting at s[i]=='['. Respects a leading ^ and a leading ] (literal member)
// and escaped \].
func classEnd(s string, i int) int {
	n := len(s)
	j := i + 1
	if j < n && s[j] == '^' {
		j++
	}
	if j < n && s[j] == ']' {
		j++
	}
	for j < n {
		if s[j] == '\\' {
			j += 2
			continue
		}
		if s[j] == ']' {
			return j + 1
		}
		j++
	}
	return n
}

// groupOpenerEnd returns the index just past the group-opener prefix starting at
// s[i]=='('. Handles bare (, (?:, inline/scoped flags ((?i) / (?i:), named
// groups ((?<name> / (?P<name>) and lookaround ((?= (?! (?<= (?<!). The opener
// prefix is copied verbatim so its structural chars (the : of (?:, the > of a
// named group) are never rewritten.
func groupOpenerEnd(s string, i int) int {
	n := len(s)
	if i+1 >= n || s[i+1] != '?' {
		return i + 1 // bare (
	}
	j := i + 2 // past "(?"
	if j >= n {
		return j
	}
	switch s[j] {
	case ':':
		return j + 1
	case '=', '!':
		return j + 1
	case '<':
		if j+1 < n && (s[j+1] == '=' || s[j+1] == '!') {
			return j + 2 // (?<= (?<!
		}
		for j < n && s[j] != '>' {
			j++
		}
		if j < n {
			j++
		}
		return j
	case 'P':
		for j < n && s[j] != '>' && s[j] != ')' {
			j++
		}
		if j < n {
			j++
		}
		return j
	default:
		// flags: [a-zA-Z-]* terminated by ':' (scoped) or ')' (inline)
		for j < n && s[j] != ':' && s[j] != ')' {
			j++
		}
		if j < n {
			j++
		}
		return j
	}
}

// classEncode maps a char-class member to the percent-encoding alternative(s) to
// add. `\s` expands to the whitespace forms. Returns nil for members without a
// percent form (ranges, \w, \d, plain letters/digits).
var classEncode = map[byte]string{
	'>':  `%3E`,
	'<':  `%3C`,
	'\'': `%27`,
	'"':  `%22`,
	':':  `%3A`,
	';':  `%3B`,
	'/':  `%2[Ff]`,
	'`':  `%60`,
	'=':  `%3D`,
	'&':  `%26`,
	',':  `%2C`,
	'.':  `%2[Ee]`,
}

// augmentClass returns the character class widened with the percent-encodings of
// its encodable members, as (?:[orig]|%HH|...). A char class matches exactly one
// char, so an encoded member (3 bytes) cannot match inside it — we lift the class
// into an alternation instead. Verbatim when no member is encodable.
//
// ponytail: an encoded alt consumes 3 bytes where the class consumed 1, so this
// is only correct when the class is not immediately followed by another anchored
// token. Fine for the CRS pack (the only augmented class, [\s>], is a trailing
// token). Revisit if a mid-pattern class needs encoding.
func augmentClass(class string) string {
	// inner = between [ and ]
	inner := class[1 : len(class)-1]
	extras := make([]string, 0, 4)
	seen := map[string]bool{}
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			extras = append(extras, v)
		}
	}
	for k := 0; k < len(inner); k++ {
		ch := inner[k]
		if ch == '\\' && k+1 < len(inner) {
			if inner[k+1] == 's' {
				add(`%09`)
				add(`%0[AaCcDd]`)
				add(`%20`)
				add(`\+`)
			}
			k++
			continue
		}
		// skip ranges like a-z (member '-' between two chars)
		if k+2 < len(inner) && inner[k+1] == '-' {
			k += 2
			continue
		}
		if enc, ok := classEncode[ch]; ok {
			add(enc)
		}
	}
	if len(extras) == 0 {
		return class
	}
	return "(?:" + class + "|" + strings.Join(extras, "|") + ")"
}

// hasTransform reports whether the CRS transformation list contains name.
func hasTransform(transforms []string, name string) bool {
	for _, t := range transforms {
		if t == name {
			return true
		}
	}
	return false
}
