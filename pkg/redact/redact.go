// Package redact is the write-side PII redactor.
//
// Per spec FR-32 + NFR-14: configurable regex set (CC, US SSN, EU national IDs, email,
// IP) applied to findings.detail_json + audit_events.payload BEFORE persistence. The
// redacted value is replaced with a `<REDACTED:KIND>` placeholder; the original is
// optionally retained encrypted with a per-org KEK held in KMS (KEK encryption is a
// separate concern handled at the persistence boundary).
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Pattern is one redaction rule.
type Pattern struct {
	Name string // CC | US_SSN | EU_NATIONAL_ID | EMAIL | IP | CUSTOM
	Re   *regexp.Regexp
}

// DefaultPatterns are the spec's curated defaults. Compiled once at package init.
var DefaultPatterns = []Pattern{
	// Visa / MC / Amex / Discover / Diners — 13-19 digits with optional separators.
	// We require word boundaries to avoid clobbering long IDs that happen to start with digits.
	{Name: "CC", Re: regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`)},
	{Name: "US_SSN", Re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	// French INSEE 13-digit national ID (sample of EU coverage; expandable).
	{Name: "EU_NATIONAL_ID", Re: regexp.MustCompile(`\b\d{13}\b`)},
	{Name: "EMAIL", Re: regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)},
	{Name: "IP_V4", Re: regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)},
}

// Redactor applies a pattern set to byte strings and JSON values.
type Redactor struct {
	Patterns []Pattern
}

// New returns a Redactor with the supplied patterns; pass DefaultPatterns to use the
// spec's curated set.
func New(p []Pattern) *Redactor { return &Redactor{Patterns: p} }

// NewDefault returns a Redactor using DefaultPatterns.
func NewDefault() *Redactor { return New(DefaultPatterns) }

// String returns s with all matches replaced by "<REDACTED:KIND>". The first matching
// pattern wins per byte offset (longest-prefix semantics are NOT used — patterns should
// not overlap).
func (r *Redactor) String(s string) string {
	for _, p := range r.Patterns {
		s = p.Re.ReplaceAllString(s, "<REDACTED:"+p.Name+">")
	}
	return s
}

// JSON walks a json.RawMessage and recursively redacts string values. Arrays and objects
// are descended; numbers + booleans + nulls are preserved.
func (r *Redactor) JSON(raw json.RawMessage) (json.RawMessage, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw, err
	}
	out := r.walk(v)
	b, err := json.Marshal(out)
	return b, err
}

func (r *Redactor) walk(v any) any {
	switch x := v.(type) {
	case string:
		return r.String(x)
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = r.walk(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = r.walk(val)
		}
		return out
	}
	return v
}

// Compile turns a list of custom regex source strings into Patterns. Bad regexes are
// silently dropped; the error is returned via the second return value so the caller can
// log / surface to the user.
func Compile(custom map[string]string) ([]Pattern, []error) {
	out := []Pattern{}
	errs := []error{}
	for name, src := range custom {
		re, err := regexp.Compile(src)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, Pattern{Name: strings.ToUpper(name), Re: re})
	}
	return out, errs
}

// Compose returns a Redactor combining the default + custom patterns. Custom patterns
// run after defaults so customer-specific data wins over generic email/IP captures.
func Compose(custom map[string]string) (*Redactor, []error) {
	customPatterns, errs := Compile(custom)
	all := append([]Pattern(nil), DefaultPatterns...)
	all = append(all, customPatterns...)
	return New(all), errs
}
