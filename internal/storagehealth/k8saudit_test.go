package storagehealth

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestParseAuditSources(t *testing.T) {
	t.Parallel()
	pair := uuid.NewString() + "/" + uuid.NewString()
	for _, tc := range []struct {
		name, raw, gap string
		want           int
		valid          bool
	}{
		{"disabled", "", "", 0, true},
		{"explicit", pair, "2h", 1, true},
		{"deduplicate", " " + pair + "," + pair + " ", "", 1, true},
		{"invalid pair", "invalid", "", 0, false},
		{"trailing comma", pair + ",", "", 0, false},
		{"zero org", uuid.Nil.String() + "/" + uuid.NewString(), "", 0, false},
		{"zero cluster", uuid.NewString() + "/" + uuid.Nil.String(), "", 0, false},
		{"invalid org", "bad/" + uuid.NewString(), "", 0, false},
		{"oversized", strings.Repeat(pair+",", 1000) + pair, "", 0, false},
		{"zero gap", pair, "0s", 0, false},
		{"large gap", pair, "721h", 0, false},
		{"invalid gap", "", "oops", 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseAuditSources(tc.raw, tc.gap)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
			if tc.valid && (len(got.Sources) != tc.want || got.MaxGap < time.Second) {
				t.Fatalf("unexpected configuration: %+v", got)
			}
		})
	}
}
