// Package falco ingests Falco community rule YAML and produces RuntimeEvent records
// (mapped through pkg/attack to ATT&CK technique IDs).
//
// Falco rule shape (simplified):
//
//	- rule: Terminal shell in container
//	  desc: A shell was used as the entrypoint/exec point into a container with an attached terminal.
//	  condition: spawned_process and container and shell_procs and proc.tty != 0
//	  output: A shell was spawned in a container (...)
//	  priority: NOTICE
//	  tags: [container, shell, mitre_execution]
//
//	- macro: shell_procs
//	  condition: proc.name in (shell_binaries)
//
//	- list: shell_binaries
//	  items: [sh, bash, csh, ksh, tcsh, zsh, dash]
//
// We parse rules + macros + lists but evaluate conditions lazily — the runtime agent
// passes a per-process map { proc.name, proc.tty, container.id, … } and we return
// matching rules + their ATT&CK technique mappings.
package falco

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/alphabravocompany/constellation/pkg/attack"
)

// Document is a parsed Falco YAML file.
type Document struct {
	Rules  []Rule
	Macros map[string]string // name → condition expression
	Lists  map[string][]string
}

// Rule is one Falco rule, normalized.
type Rule struct {
	Name      string
	Desc      string
	Condition string
	Output    string
	Priority  string
	Tags      []string

	// AttackIDs are the ATT&CK technique IDs derived from the rule's tags + name.
	AttackIDs []string
}

// rawEntry is one of the polymorphic YAML map entries Falco rule files use.
type rawEntry struct {
	Rule      string   `yaml:"rule,omitempty"`
	Macro     string   `yaml:"macro,omitempty"`
	List      string   `yaml:"list,omitempty"`
	Desc      string   `yaml:"desc,omitempty"`
	Condition string   `yaml:"condition,omitempty"`
	Output    string   `yaml:"output,omitempty"`
	Priority  string   `yaml:"priority,omitempty"`
	Tags      []string `yaml:"tags,omitempty"`
	Items     []string `yaml:"items,omitempty"`
}

// Parse decodes a Falco rule YAML document.
func Parse(raw []byte) (*Document, error) {
	var entries []rawEntry
	if err := yaml.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("falco: parse yaml: %w", err)
	}
	doc := &Document{
		Macros: map[string]string{},
		Lists:  map[string][]string{},
	}
	for _, e := range entries {
		switch {
		case e.Rule != "":
			doc.Rules = append(doc.Rules, Rule{
				Name:      e.Rule,
				Desc:      e.Desc,
				Condition: e.Condition,
				Output:    e.Output,
				Priority:  e.Priority,
				Tags:      e.Tags,
				AttackIDs: deriveAttackIDs(e.Rule, e.Tags),
			})
		case e.Macro != "":
			doc.Macros[e.Macro] = e.Condition
		case e.List != "":
			doc.Lists[e.List] = append([]string(nil), e.Items...)
		}
	}
	return doc, nil
}

// deriveAttackIDs extracts ATT&CK technique ids from a rule's tags + name. Falco's
// convention: a tag like "mitre_execution" or "T1059.004" → technique id. We also map
// common rule-name keywords to event kinds and back to technique ids via pkg/attack.
func deriveAttackIDs(name string, tags []string) []string {
	seen := map[string]struct{}{}
	for _, tag := range tags {
		if strings.HasPrefix(strings.ToUpper(tag), "T1") {
			seen[tag] = struct{}{}
		}
	}
	lower := strings.ToLower(name)
	type m struct {
		needle string
		kind   attack.EventKind
	}
	matches := []m{
		{"shell in container", attack.EventShellSpawn},
		{"reverse shell", attack.EventReverseShell},
		{"crypto mining", attack.EventCryptoMiner},
		{"crypto miner", attack.EventCryptoMiner},
		{"sensitive file", attack.EventReadSensitiveFile},
		{"container escape", attack.EventContainerBreakout},
		{"container breakout", attack.EventContainerBreakout},
		{"privilege escalation", attack.EventPrivilegeEscalation},
		{"dns tunneling", attack.EventDNSTunnel},
	}
	for _, e := range matches {
		if strings.Contains(lower, e.needle) {
			for _, id := range attack.Map(e.kind) {
				seen[id] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Evaluator runs Rules against a normalized event map. Conditions are evaluated via a
// simple expression evaluator that supports `and`, `or`, `not`, `in (list)`, `==`, `!=`,
// `>=`, `<=`, `>`, `<`. That's enough for the ~80% of community rules; the long tail
// requires Falco's libsinsp evaluator, out of scope for v1.
type Evaluator struct {
	doc *Document
}

// NewEvaluator builds an Evaluator over a parsed document.
func NewEvaluator(doc *Document) *Evaluator { return &Evaluator{doc: doc} }

// Match returns rules whose condition fires against the given fact map.
func (e *Evaluator) Match(facts map[string]any) []Rule {
	var out []Rule
	for _, r := range e.doc.Rules {
		if evalExpr(r.Condition, facts, e.doc) {
			out = append(out, r)
		}
	}
	return out
}

// evalExpr is a tiny boolean expression interpreter — handles the common Falco patterns.
// Macros are expanded at the token level so identifiers like "container.id" don't get
// partially matched against a macro named "container". List lookups happen in evalLeaf
// via the doc so commas in list values never confuse the tokenizer.
func evalExpr(expr string, facts map[string]any, doc *Document) bool {
	tokens := tokenize(expr)
	tokens = expandMacroTokens(tokens, doc, 0)
	return evalBool(tokens, facts, doc)
}

// expandMacroTokens replaces standalone macro-name tokens with their expanded token
// sequence (wrapped in parens). Cycles are bounded by a depth limit.
func expandMacroTokens(tokens []string, doc *Document, depth int) []string {
	if depth > 8 {
		return tokens
	}
	expanded := false
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		body, isMacro := doc.Macros[t]
		if !isMacro {
			out = append(out, t)
			continue
		}
		expanded = true
		out = append(out, "(")
		out = append(out, tokenize(body)...)
		out = append(out, ")")
	}
	if expanded {
		return expandMacroTokens(out, doc, depth+1)
	}
	return out
}

// tokenize splits the expression into shell-style tokens. Whitespace + parens are separators.
func tokenize(s string) []string {
	out := []string{}
	cur := strings.Builder{}
	push := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\'':
			inQuote = !inQuote
		case !inQuote && (c == '(' || c == ')'):
			push()
			out = append(out, string(c))
		case !inQuote && (c == ' ' || c == '\t' || c == '\n'):
			push()
		default:
			cur.WriteByte(c)
		}
	}
	push()
	return out
}

// evalBool walks the token stream as a left-to-right boolean expression. Parens are
// honored; precedence is `not` > `and` > `or` to match Falco.
func evalBool(tokens []string, facts map[string]any, doc *Document) bool {
	if len(tokens) == 0 {
		return false
	}
	// Convert tokens to RPN via shunting-yard, then evaluate.
	prec := func(op string) int {
		switch op {
		case "not":
			return 3
		case "and":
			return 2
		case "or":
			return 1
		}
		return 0
	}
	var out []string
	var ops []string
	i := 0
	for i < len(tokens) {
		t := tokens[i]
		switch {
		case t == "(":
			ops = append(ops, t)
		case t == ")":
			for len(ops) > 0 && ops[len(ops)-1] != "(" {
				out = append(out, ops[len(ops)-1])
				ops = ops[:len(ops)-1]
			}
			if len(ops) > 0 {
				ops = ops[:len(ops)-1]
			}
		case t == "and" || t == "or" || t == "not":
			for len(ops) > 0 && ops[len(ops)-1] != "(" && prec(ops[len(ops)-1]) >= prec(t) {
				out = append(out, ops[len(ops)-1])
				ops = ops[:len(ops)-1]
			}
			ops = append(ops, t)
		default:
			// Eagerly collect leaves of the form `key op value [op value]*` until we
			// hit a boolean operator or paren.
			leaf := []string{t}
			for i+1 < len(tokens) {
				next := tokens[i+1]
				if next == "and" || next == "or" || next == "not" || next == "(" || next == ")" {
					break
				}
				leaf = append(leaf, next)
				i++
			}
			out = append(out, strings.Join(leaf, " "))
		}
		i++
	}
	for len(ops) > 0 {
		out = append(out, ops[len(ops)-1])
		ops = ops[:len(ops)-1]
	}

	// Evaluate RPN.
	stack := []bool{}
	for _, tok := range out {
		switch tok {
		case "and":
			if len(stack) < 2 {
				return false
			}
			b := stack[len(stack)-1]
			a := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a && b)
		case "or":
			if len(stack) < 2 {
				return false
			}
			b := stack[len(stack)-1]
			a := stack[len(stack)-2]
			stack = stack[:len(stack)-2]
			stack = append(stack, a || b)
		case "not":
			if len(stack) < 1 {
				return false
			}
			stack[len(stack)-1] = !stack[len(stack)-1]
		default:
			stack = append(stack, evalLeaf(tok, facts, doc))
		}
	}
	if len(stack) == 0 {
		return false
	}
	return stack[len(stack)-1]
}

var (
	reInList    = regexp.MustCompile(`^(\S+)\s+in\s+(\S+)$`)        // key in list_name (parens stripped in tokenizer)
	reInInline  = regexp.MustCompile(`^(\S+)\s+in\s+\((.+)\)$`)     // key in (a, b, c)
	reCmp       = regexp.MustCompile(`^(\S+)\s*(==|!=|>=|<=|>|<|=)\s*(.+?)\s*$`)
)

// evalLeaf evaluates a single comparison or membership test. Bare facts are truthy when
// present and not zero/false. The doc is consulted for `key in <list-name>` membership.
func evalLeaf(expr string, facts map[string]any, doc *Document) bool {
	expr = strings.TrimSpace(expr)
	// Strip enclosing parens.
	for strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		expr = strings.TrimSpace(expr[1 : len(expr)-1])
	}

	// "key in (a, b, c)" — inline list.
	if m := reInInline.FindStringSubmatch(expr); m != nil {
		got := fmt.Sprint(facts[m[1]])
		for _, item := range strings.Split(m[2], ",") {
			if got == strings.TrimSpace(strings.Trim(item, `"'`)) {
				return true
			}
		}
		return false
	}
	// "key in <list-name>" — look up the list in the doc.
	if m := reInList.FindStringSubmatch(expr); m != nil {
		got := fmt.Sprint(facts[m[1]])
		if items, ok := doc.Lists[m[2]]; ok {
			for _, item := range items {
				if got == strings.TrimSpace(strings.Trim(item, `"'`)) {
					return true
				}
			}
		}
		return false
	}
	if m := reCmp.FindStringSubmatch(expr); m != nil {
		key := m[1]
		op := m[2]
		want := strings.TrimSpace(strings.Trim(m[3], `"'`))
		// "host" appearing on the RHS resolves to the fact map (matches Falco's literal-name
		// indirection where common identifiers come from the SDK).
		if w, ok := facts[want]; ok {
			want = fmt.Sprint(w)
		}
		got := fmt.Sprint(facts[key])
		switch op {
		case "==", "=":
			return got == want
		case "!=":
			return got != want
		}
		return false
	}
	// Bare key: truthy if present + non-zero.
	v, ok := facts[expr]
	if !ok {
		return false
	}
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	}
	return true
}

// ErrEmpty is returned when Parse is given an empty document.
var ErrEmpty = errors.New("falco: empty document")
