package dsl

import (
	"strings"
	"testing"
)

func testSchema() Schema {
	return Schema{Fields: map[string]Field{
		"severity":      {Column: "f.severity", Type: FieldString},
		"kind":          {Column: "f.kind", Type: FieldString},
		"risk":          {Column: "f.risk_score", Type: FieldInt},
		"last_seen":     {Column: "f.last_seen_at", Type: FieldTime},
		"title":         {Column: "f.title", Type: FieldString},
	}}
}

func TestCompileEmpty(t *testing.T) {
	c, err := Compile("", testSchema())
	if err != nil || !c.Empty() {
		t.Fatalf("expected empty compile, got %+v err=%v", c, err)
	}
}

func TestCompileSimple(t *testing.T) {
	c, err := Compile("severity:high", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "f.severity ILIKE") {
		t.Fatalf("unexpected where: %q", c.Where)
	}
	if len(c.Args) != 1 {
		t.Fatalf("expected 1 arg: %v", c.Args)
	}
}

func TestCompileRegexAndOr(t *testing.T) {
	c, err := Compile("kind:vulnerability OR title:r/^CVE-2024", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "OR") || !strings.Contains(c.Where, "~*") {
		t.Fatalf("expected OR + regex: %q", c.Where)
	}
}

func TestCompileNegate(t *testing.T) {
	c, err := Compile("kind:!iac severity:high", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "NOT") || !strings.Contains(c.Where, "AND") {
		t.Fatalf("unexpected: %q", c.Where)
	}
}

func TestCompileTimeRange(t *testing.T) {
	c, err := Compile("last_seen:tr/[2026-01-01,2026-02-01]", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, ">=") || !strings.Contains(c.Where, "<") {
		t.Fatalf("unexpected: %q", c.Where)
	}
	if len(c.Args) != 2 {
		t.Fatalf("expected 2 args: %v", c.Args)
	}
}

func TestCompileUnknownField(t *testing.T) {
	if _, err := Compile("nope:value", testSchema()); err == nil {
		t.Fatalf("expected error")
	}
}

func TestCompileInt(t *testing.T) {
	c, err := Compile("risk:80", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "f.risk_score =") {
		t.Fatalf("unexpected: %q", c.Where)
	}
	if got, ok := c.Args[0].(int64); !ok || got != 80 {
		t.Fatalf("expected int64 80: %#v", c.Args[0])
	}
}

func TestCompileGlob(t *testing.T) {
	c, err := Compile("title:g/CVE-2024-*", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "ILIKE") {
		t.Fatalf("unexpected: %q", c.Where)
	}
	v, _ := c.Args[0].(string)
	if !strings.Contains(v, "%") {
		t.Fatalf("expected glob converted to ILIKE pattern: %q", v)
	}
}

func TestCompileParens(t *testing.T) {
	c, err := Compile("(severity:high OR severity:critical) kind:vulnerability", testSchema())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(c.Where, "AND") || !strings.Contains(c.Where, "OR") {
		t.Fatalf("expected AND+OR: %q", c.Where)
	}
}
