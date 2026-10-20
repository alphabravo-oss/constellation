package dsl

import (
	"reflect"
	"strings"
	"testing"
)

func TestDefaultFieldAndLeadingNegation(t *testing.T) {
	t.Parallel()
	schema := Schema{DefaultField: "text", Fields: map[string]Field{"text": {Column: "document", Type: FieldString}, "status": {Column: "lifecycle", Type: FieldString}}}
	for _, tc := range []struct {
		query     string
		args      []any
		negations int
	}{
		{"openssl !status:resolved", []any{"%openssl%", "%resolved%"}, 1},
		{"!openssl status:!resolved", []any{"%openssl%", "%resolved%"}, 2},
		{`"exact phrase" OR status:open`, []any{"exact phrase", "%open%"}, 0},
		{"!status:!resolved", []any{"%resolved%"}, 0},
	} {
		got, err := Compile(tc.query, schema)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got.Args, tc.args) || strings.Count(got.Where, "NOT ") != tc.negations {
			t.Fatalf("%s => %+v", tc.query, got)
		}
	}
	if _, err := Compile("bare", Schema{Fields: schema.Fields}); err == nil {
		t.Fatal("schema without a default accepted bare text")
	}
	if _, err := Compile("typo:value", schema); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestColonValuesAndStrictBooleans(t *testing.T) {
	t.Parallel()
	s := Schema{Fields: map[string]Field{"purl": {Column: "purl", Type: FieldString}, "seen": {Column: "seen_at", Type: FieldTime}, "kev": {Column: "kev", Type: FieldBool}}}
	got, err := Compile("purl:pkg:npm/example kev:true seen:2026-01-01T12:34:56Z", s)
	if err != nil || len(got.Args) != 3 || got.Args[0] != "%pkg:npm/example%" || got.Args[1] != true {
		t.Fatalf("colon values: %+v %v", got, err)
	}
	for _, q := range []string{"kev:garbage", "purl:pkg:"} {
		if _, err := Compile(q, s); err == nil {
			t.Fatalf("accepted %s", q)
		}
	}
	for _, q := range []string{"kev:false", "kev:0", "kev:TRUE", "kev:1"} {
		if _, err := Compile(q, s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiteralSubstrings(t *testing.T) {
	t.Parallel()
	s := Schema{DefaultField: "text", LiteralSubstrings: true, Fields: map[string]Field{"text": {Column: "document", Type: FieldString}}}
	got, err := Compile(`foo_bar% text:g/foo*`, s)
	if err != nil || !reflect.DeepEqual(got.Args, []any{`%foo\_bar\%%`, "foo%"}) {
		t.Fatalf("literal substring %+v %v", got, err)
	}
}
