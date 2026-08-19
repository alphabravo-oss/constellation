package runtime

import (
	"testing"

	"github.com/alphabravocompany/constellation/internal/runtime/dp"
)

// Self-check for the ModSecurity-target -> dp-context mapping (FIX 2). dp scans
// HTTP into separate buffers and a rule only matches the buffer its context
// names, so ARGS/URI targets MUST land in "url", header/cookie targets in "head",
// and body/POST-arg targets in "body". Collapsing everything but REQUEST_BODY into
// HEAD (the old bug) made every URL/query attack miss.
func TestWAFTargetContextMapping(t *testing.T) {
	cases := []struct {
		target string
		want   string
	}{
		{"ARGS", dp.WAFCtxURL},
		{"ARGS_GET", dp.WAFCtxURL},
		{"ARGS_NAMES", dp.WAFCtxURL},
		{"QUERY_STRING", dp.WAFCtxURL},
		{"REQUEST_URI", dp.WAFCtxURL},
		{"REQUEST_URI_RAW", dp.WAFCtxURL},
		{"REQUEST_FILENAME", dp.WAFCtxURL},
		{"REQUEST_LINE", dp.WAFCtxURL},
		{"REQUEST_METHOD", dp.WAFCtxURL},
		{"REQUEST_HEADERS:User-Agent", dp.WAFCtxHead},
		{"REQUEST_HEADERS", dp.WAFCtxHead},
		{"REQUEST_COOKIES", dp.WAFCtxHead},
		{"REQUEST_BODY", dp.WAFCtxBody},
		{"ARGS_POST", dp.WAFCtxBody},
		{"XML", dp.WAFCtxBody},
		{"JSON", dp.WAFCtxBody},
		{"", dp.WAFCtxHead}, // unknown -> conservative HEAD default
	}
	for _, c := range cases {
		if got := wafTargetContext(c.target); got != c.want {
			t.Errorf("wafTargetContext(%q) = %q, want %q", c.target, got, c.want)
		}
	}
}
