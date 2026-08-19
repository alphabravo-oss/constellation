package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestString_RedactsAllPatterns(t *testing.T) {
	r := NewDefault()
	cases := []struct {
		in, want string
	}{
		{"My SSN is 123-45-6789.", "My SSN is <REDACTED:US_SSN>."},
		{"Contact: alice@example.com please", "Contact: <REDACTED:EMAIL> please"},
		{"Connect from 10.0.0.5", "Connect from <REDACTED:IP_V4>"},
		{"Card 4111 1111 1111 1111 charged", "Card <REDACTED:CC> charged"},
	}
	for _, c := range cases {
		got := r.String(c.in)
		if got != c.want {
			t.Fatalf("redact(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestJSON_RedactsNestedStrings(t *testing.T) {
	r := NewDefault()
	in := json.RawMessage(`{"email":"alice@example.com","tags":["safe","bob@example.com"],"meta":{"ip":"10.0.0.5","ok":true,"n":42}}`)
	out, err := r.JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	// json.Marshal HTML-escapes <>, so check on the parsed structure rather than the bytes.
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["email"] != "<REDACTED:EMAIL>" {
		t.Fatalf("email: %v", doc["email"])
	}
	meta := doc["meta"].(map[string]any)
	if meta["ip"] != "<REDACTED:IP_V4>" {
		t.Fatalf("ip: %v", meta["ip"])
	}
	if meta["ok"] != true {
		t.Fatalf("ok bool lost: %v", meta["ok"])
	}
	if meta["n"].(float64) != 42 {
		t.Fatalf("number lost: %v", meta["n"])
	}
	_ = strings.Contains // keep import
}

func TestCompose_AppliesCustomAfterDefault(t *testing.T) {
	r, errs := Compose(map[string]string{"GITHUB_TOKEN": `ghp_[A-Za-z0-9]{20,}`})
	if len(errs) > 0 {
		t.Fatal(errs[0])
	}
	got := r.String("token=ghp_abcdef0123456789abcd")
	if !strings.Contains(got, "<REDACTED:GITHUB_TOKEN>") {
		t.Fatalf("custom pattern not applied: %s", got)
	}
}

func TestCompile_RejectsBadRegex(t *testing.T) {
	_, errs := Compile(map[string]string{"bad": "(*"})
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %d", len(errs))
	}
}
