package notify

import (
	"strings"
	"testing"
)

func TestParseEmailRecipients(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want []string
	}{
		{"array", `{"to":["a@x.com","b@y.com"]}`, []string{"a@x.com", "b@y.com"}},
		{"comma-string", `{"to":"a@x.com, b@y.com"}`, []string{"a@x.com", "b@y.com"}},
		{"trims-blanks", `{"to":["a@x.com","  ",""]}`, []string{"a@x.com"}},
		{"missing", `{"other":1}`, nil},
		{"empty", ``, nil},
	}
	for _, c := range cases {
		got := parseEmailRecipients([]byte(c.cfg))
		if len(got) != len(c.want) {
			t.Fatalf("%s: got %v want %v", c.name, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("%s: got %v want %v", c.name, got, c.want)
			}
		}
	}
}

// A crafted subject must not be able to inject extra SMTP headers (CRLF injection).
func TestBuildMessageHeaderInjection(t *testing.T) {
	msg := string(buildMessage("from@x.com", []string{"to@y.com"},
		"Hi\r\nBcc: evil@z.com", "body"))
	// The injected header line must be neutralized, not present as its own header.
	if strings.Contains(msg, "\r\nBcc: evil@z.com") {
		t.Fatalf("header injection not sanitized:\n%s", msg)
	}
	if !strings.HasPrefix(msg, "From: from@x.com\r\n") {
		t.Fatalf("unexpected message start:\n%s", msg)
	}
	// Body dot-stuffing: a line starting with "." is escaped so it can't end DATA.
	msg2 := string(buildMessage("f@x", []string{"t@y"}, "s", "line1\r\n.\r\nline2"))
	if !strings.Contains(msg2, "\r\n..\r\n") {
		t.Fatalf("body not dot-stuffed:\n%s", msg2)
	}
}
