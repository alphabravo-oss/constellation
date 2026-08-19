// Package dsl implements the Constellation search query DSL.
//
// Inspired by StackRox's pkg/search/query_builder.go and general_query_parser.go,
// re-implemented from scratch in idiomatic Go. The syntax is intentionally similar
// so users coming from StackRox have minimal learning curve:
//
//	field:value                  -> exact equals
//	field:"exact phrase"         -> exact phrase
//	field:r/regex                -> POSIX regex (ILIKE-not-supported, mapped to ~*)
//	field:c/case-sensitive       -> case-sensitive equality
//	field:!negate                -> NOT field:negate
//	field:g/glob                 -> glob with * and ? (mapped to ILIKE)
//	field:tr/[2026-01-01,2026-02-01] -> time range
//
//	Multiple terms are AND-combined by default. Use the bare keyword OR (uppercase)
//	between terms to switch to OR. Parentheses group sub-expressions.
//
// Compile() builds a SQL WHERE fragment + arg list for parameterised queries.
// The caller supplies a Schema describing which top-level fields are allowed and
// which SQL column each maps to — unknown fields produce an error so a typo can't
// leak unfiltered data.
package dsl

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schema maps user-visible field names (e.g. "severity") to SQL column expressions
// (e.g. "f.severity"). Field names are matched case-insensitively. Type hints let
// the compiler emit the right operator (e.g. timestamps need ::timestamptz casts).
type Schema struct {
	Fields map[string]Field
}

// FieldType controls how values are compared in SQL.
type FieldType string

const (
	FieldString  FieldType = "string"
	FieldInt     FieldType = "int"
	FieldFloat   FieldType = "float"
	FieldTime    FieldType = "time"
	FieldBool    FieldType = "bool"
)

type Field struct {
	Column string
	Type   FieldType
}

// Compiled is the result of parsing + compiling a query string against a schema.
type Compiled struct {
	Where string
	Args  []any
}

// Empty reports whether the compiled fragment is a no-op.
func (c Compiled) Empty() bool { return c.Where == "" }

// Compile parses q and produces a SQL WHERE fragment (without the leading WHERE
// keyword). Returns Compiled{} for an empty query. Returns an error on syntax
// errors or unknown fields.
func Compile(q string, s Schema) (Compiled, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return Compiled{}, nil
	}
	p := newParser(q)
	ast, err := p.parseExpr()
	if err != nil {
		return Compiled{}, err
	}
	if p.pos < len(p.tokens) {
		return Compiled{}, fmt.Errorf("search: unexpected token %q at pos %d", p.tokens[p.pos].val, p.pos)
	}
	var args []any
	where, err := emit(ast, s, &args)
	if err != nil {
		return Compiled{}, err
	}
	return Compiled{Where: where, Args: args}, nil
}

// ---- AST ----

type node interface{ isNode() }

type termNode struct {
	field string
	val   string
}

func (termNode) isNode() {}

type binaryNode struct {
	op       string // AND, OR
	lhs, rhs node
}

func (binaryNode) isNode() {}

type unaryNode struct{ inner node }

func (unaryNode) isNode() {}

// ---- lexer ----

type token struct {
	kind string // ident, colon, lparen, rparen, or
	val  string
}

type parser struct {
	tokens []token
	pos    int
}

func newParser(q string) *parser {
	return &parser{tokens: tokenize(q)}
}

func tokenize(q string) []token {
	var out []token
	i := 0
	for i < len(q) {
		c := q[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '(':
			out = append(out, token{kind: "lparen", val: "("})
			i++
		case c == ')':
			out = append(out, token{kind: "rparen", val: ")"})
			i++
		case c == ':':
			out = append(out, token{kind: "colon", val: ":"})
			i++
		case c == '"':
			j := i + 1
			for j < len(q) && q[j] != '"' {
				j++
			}
			out = append(out, token{kind: "ident", val: q[i : minInt(j+1, len(q))]})
			i = j + 1
		default:
			j := i
			depth := 0
			for j < len(q) {
				c := q[j]
				if c == '[' {
					depth++
				} else if c == ']' {
					depth--
				}
				if depth == 0 && (c == ' ' || c == '\t' || c == ':' || c == '(' || c == ')') {
					break
				}
				j++
			}
			val := q[i:j]
			if strings.EqualFold(val, "OR") {
				out = append(out, token{kind: "or", val: "OR"})
			} else if strings.EqualFold(val, "AND") {
				// AND is the implicit default, ignore
			} else {
				out = append(out, token{kind: "ident", val: val})
			}
			i = j
		}
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- parser ----

func (p *parser) peek() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	return &p.tokens[p.pos]
}

func (p *parser) eat() *token {
	if p.pos >= len(p.tokens) {
		return nil
	}
	t := &p.tokens[p.pos]
	p.pos++
	return t
}

func (p *parser) parseExpr() (node, error) {
	lhs, err := p.parseTerm()
	if err != nil {
		return nil, err
	}
	for {
		t := p.peek()
		if t == nil || t.kind == "rparen" {
			return lhs, nil
		}
		op := "AND"
		if t.kind == "or" {
			op = "OR"
			p.eat()
		}
		rhs, err := p.parseTerm()
		if err != nil {
			return nil, err
		}
		lhs = binaryNode{op: op, lhs: lhs, rhs: rhs}
	}
}

func (p *parser) parseTerm() (node, error) {
	t := p.peek()
	if t == nil {
		return nil, errors.New("search: unexpected end of input")
	}
	if t.kind == "lparen" {
		p.eat()
		inner, err := p.parseExpr()
		if err != nil {
			return nil, err
		}
		close := p.eat()
		if close == nil || close.kind != "rparen" {
			return nil, errors.New("search: missing closing paren")
		}
		return inner, nil
	}
	if t.kind != "ident" {
		return nil, fmt.Errorf("search: expected field, got %q", t.val)
	}
	field := p.eat().val
	if c := p.peek(); c == nil || c.kind != "colon" {
		return nil, fmt.Errorf("search: expected colon after field %q", field)
	}
	p.eat() // consume colon
	v := p.peek()
	if v == nil || v.kind != "ident" {
		return nil, fmt.Errorf("search: expected value after %q:", field)
	}
	val := p.eat().val
	if strings.HasPrefix(val, "!") {
		return unaryNode{inner: termNode{field: field, val: strings.TrimPrefix(val, "!")}}, nil
	}
	return termNode{field: field, val: val}, nil
}

// ---- emit (SQL) ----

func emit(n node, s Schema, args *[]any) (string, error) {
	switch v := n.(type) {
	case termNode:
		return emitTerm(v, s, args)
	case unaryNode:
		inner, err := emit(v.inner, s, args)
		if err != nil {
			return "", err
		}
		return "(NOT " + inner + ")", nil
	case binaryNode:
		l, err := emit(v.lhs, s, args)
		if err != nil {
			return "", err
		}
		r, err := emit(v.rhs, s, args)
		if err != nil {
			return "", err
		}
		return "(" + l + " " + v.op + " " + r + ")", nil
	}
	return "", errors.New("search: bad ast")
}

func emitTerm(t termNode, s Schema, args *[]any) (string, error) {
	fieldKey := strings.ToLower(t.field)
	f, ok := lookupField(s, fieldKey)
	if !ok {
		return "", fmt.Errorf("search: unknown field %q", t.field)
	}
	val := t.val
	switch {
	case strings.HasPrefix(val, "r/"):
		*args = append(*args, strings.TrimPrefix(val, "r/"))
		return fmt.Sprintf("%s ~* $%d", f.Column, len(*args)), nil
	case strings.HasPrefix(val, "c/"):
		*args = append(*args, strings.TrimPrefix(val, "c/"))
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	case strings.HasPrefix(val, "g/"):
		g := strings.TrimPrefix(val, "g/")
		// glob -> ILIKE pattern
		like := strings.NewReplacer("*", "%", "?", "_").Replace(g)
		*args = append(*args, like)
		return fmt.Sprintf("%s ILIKE $%d", f.Column, len(*args)), nil
	case strings.HasPrefix(val, "tr/"):
		start, end, err := parseTimeRange(strings.TrimPrefix(val, "tr/"))
		if err != nil {
			return "", err
		}
		*args = append(*args, start, end)
		return fmt.Sprintf("(%s >= $%d AND %s < $%d)", f.Column, len(*args)-1, f.Column, len(*args)), nil
	case strings.HasPrefix(val, "\"") && strings.HasSuffix(val, "\""):
		v := strings.Trim(val, "\"")
		*args = append(*args, v)
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	}
	// Default: case-insensitive equality / ILIKE substring on strings.
	switch f.Type {
	case FieldInt:
		i, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return "", fmt.Errorf("search: field %q expects int, got %q", t.field, val)
		}
		*args = append(*args, i)
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	case FieldFloat:
		fl, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return "", fmt.Errorf("search: field %q expects float, got %q", t.field, val)
		}
		*args = append(*args, fl)
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	case FieldBool:
		b := strings.EqualFold(val, "true") || val == "1"
		*args = append(*args, b)
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	case FieldTime:
		t, err := time.Parse(time.RFC3339, val)
		if err != nil {
			return "", fmt.Errorf("search: field %q expects RFC3339 time, got %q", t.Format(time.RFC3339), val)
		}
		*args = append(*args, t)
		return fmt.Sprintf("%s = $%d", f.Column, len(*args)), nil
	}
	*args = append(*args, "%"+val+"%")
	return fmt.Sprintf("%s ILIKE $%d", f.Column, len(*args)), nil
}

func parseTimeRange(in string) (time.Time, time.Time, error) {
	in = strings.TrimPrefix(in, "[")
	in = strings.TrimSuffix(in, "]")
	parts := strings.SplitN(in, ",", 2)
	if len(parts) != 2 {
		return time.Time{}, time.Time{}, fmt.Errorf("search: bad time range %q", in)
	}
	a, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[0]))
	if err != nil {
		// Try date-only form
		if a2, err2 := time.Parse("2006-01-02", strings.TrimSpace(parts[0])); err2 == nil {
			a = a2
		} else {
			return time.Time{}, time.Time{}, err
		}
	}
	b, err := time.Parse(time.RFC3339, strings.TrimSpace(parts[1]))
	if err != nil {
		if b2, err2 := time.Parse("2006-01-02", strings.TrimSpace(parts[1])); err2 == nil {
			b = b2
		} else {
			return time.Time{}, time.Time{}, err
		}
	}
	return a, b, nil
}

func lookupField(s Schema, key string) (Field, bool) {
	if f, ok := s.Fields[key]; ok {
		return f, true
	}
	for k, f := range s.Fields {
		if strings.EqualFold(k, key) {
			return f, true
		}
	}
	return Field{}, false
}
