package dp

import "testing"

func TestSigIDAndName(t *testing.T) {
	// WAF ids land in 40000-49999.
	for i := 0; i < 12; i++ {
		if id := WAFSigID(i); id < 40000 || id > 49999 {
			t.Fatalf("WAFSigID(%d)=%d out of WAF range", i, id)
		}
	}
	// DLP ids land in 20000-29999 (dp_rule_id starts at 9000).
	for _, dbID := range []uint32{9000, 9001, 9010, 15000} {
		if id := DLPSigID(dbID); id < 20000 || id > 29999 {
			t.Fatalf("DLPSigID(%d)=%d out of user range", dbID, id)
		}
	}
	// Names: no whitespace/delimiter survives (dp would reject).
	for _, tc := range []struct{ in, want string }{
		{"SQL Injection Attempt (UNION SELECT)", "SQL_Injection_Attempt__UNION_SELECT"},
		{"builtin-dlp-federal-pii", "builtin-dlp-federal-pii"},
		{"  ", "rule"},
		{"", "rule"},
	} {
		got := SanitizeSigName(tc.in)
		if got != tc.want {
			t.Fatalf("SanitizeSigName(%q)=%q want %q", tc.in, got, tc.want)
		}
		for _, r := range got {
			if r == ' ' || r == '\t' {
				t.Fatalf("SanitizeSigName(%q)=%q still has whitespace", tc.in, got)
			}
		}
	}
}
