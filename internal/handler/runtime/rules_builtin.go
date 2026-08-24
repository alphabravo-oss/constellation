// P1-4 (seed default DLP) + P1-6 (WAF / Log4Shell / Spring4Shell).
//
// The pattern *content* for the built-in sensors already lives in
// internal/runtime/dlp (DefaultCatalog: Luhn CC, SSN, AWS/GitHub/Slack/Stripe
// secrets) and internal/runtime/waf (BuiltinCRS: SQLi/XSS/LFI/RCE). But the
// enforced runtime_dlp_rules table — the one the agent's dlp_sync poller reads
// and pushes to dp — shipped empty, so none of that content ever reached the
// dataplane.
//
// This file bridges the two: it renders the built-in sensors as
// runtime_dlp_rules rows and seeds them per (org, cluster) idempotently.
//
// SAFETY: every seeded row ships in MONITOR mode. They alert; they never drop.
// Promotion to enforce is a deliberate, audited operator action (and even then
// the agent's fleet-level CONSTELLATION_DLP_ENFORCE gate must be on before dp
// actually drops).
//
// WAF-as-a-concept: the CRS + Log4Shell/Spring4Shell packs are seeded as
// category='signature' rows, which is exactly what the runtime_signatures.go
// ("DPI Signatures") API surface serves. dp's hyperscan engine doesn't
// distinguish WAF from DLP — the category column is the UI framing — so seeding
// them here exposes them through the existing signatures list without a parallel
// table. Custom signatures continue to work via the same hyperscan path.
package runtime

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
)

// builtinPack is one seeded runtime_dlp_rules row: a named set of PCRE
// patterns dp compiles into hyperscan. Name is stable + prefixed so seeds
// never collide with user-authored rules and re-seeding is a no-op.
type builtinPack struct {
	Name     string
	Category DLPCategory
	ApplyDir int16 // 1=egress, 2=ingress, 3=both
	Severity int16 // 1..9
	Patterns []string
	// Contexts is the optional NET-40 index-aligned per-pattern match context
	// (uri|header|body|packet). When any entry is non-empty EnsureBuiltins seeds
	// the row's patterns in the {pattern, context} object form so dp scans each
	// pattern in its authored buffer; an all-empty/nil slice keeps the legacy
	// bare-string encoding (WAF packs, which fan across buffers).
	Contexts    []string
	Description string
}

// BuiltinDLPPacks renders the userspace DLP catalog (federal PII + modern
// secrets) as egress DLP rows. One row per sensor; the sensor's per-rule
// patterns are flattened into the row's pattern list (dp matches every
// pattern against the payload regardless).
func BuiltinDLPPacks() []builtinPack {
	out := []builtinPack{}
	for _, s := range dlp.DefaultCatalog() {
		pats := make([]string, 0, len(s.Rules))
		ctxs := make([]string, 0, len(s.Rules))
		for _, r := range s.Rules {
			if r.Pattern != "" {
				pats = append(pats, r.Pattern)
				// NET-40: carry each catalog rule's authored context through to
				// the seeded row instead of flattening it away — e.g. github-pat
				// scans "header", credit-card "body".
				ctxs = append(ctxs, catalogContext(r.Context))
			}
		}
		if len(pats) == 0 {
			continue
		}
		out = append(out, builtinPack{
			Name:        "builtin-dlp-" + s.Name,
			Category:    CategoryDLP,
			ApplyDir:    1, // egress: catch sensitive data leaving the workload
			Severity:    6,
			Patterns:    pats,
			Contexts:    ctxs,
			Description: "Built-in DLP sensor: " + s.Comment,
		})
	}
	return out
}

// BuiltinWAFPacks renders the WAF rule packs as bidirectional signature rows:
// the OWASP-CRS-flavored core pack plus a dedicated Log4Shell/Spring4Shell
// pack. These are the "WAF" concept surfaced alongside DLP.
func BuiltinWAFPacks() []builtinPack {
	crs := waf.BuiltinCRS()
	crsPats := make([]string, 0, len(crs.Rules))
	for _, r := range crs.Rules {
		if p := wafOpToPattern(r.Operator); p != "" {
			crsPats = append(crsPats, p)
		}
	}
	return []builtinPack{
		{
			Name:        "builtin-waf-owasp-crs-core",
			Category:    CategorySignature,
			ApplyDir:    3, // both: inbound attack or outbound C2
			Severity:    7,
			Patterns:    crsPats,
			Description: "Built-in WAF pack (OWASP-CRS subset): SQLi, XSS, path traversal, RCE.",
		},
		{
			Name:        "builtin-waf-log4shell-spring4shell",
			Category:    CategorySignature,
			ApplyDir:    3,
			Severity:    9,
			Patterns:    log4ShellSpring4ShellPatterns(),
			Description: "Built-in WAF pack: Log4Shell (CVE-2021-44228) JNDI + Spring4Shell (CVE-2022-22965) classLoader.",
		},
	}
}

// log4ShellSpring4ShellPatterns is the named Log4Shell/Spring4Shell signature
// set. Covers the raw JNDI lookup, the common lookup-obfuscation evasions
// (${lower:...}, ${env:...}, nested ${${...}}), and the Spring4Shell
// class.module.classLoader binding-path probe.
func log4ShellSpring4ShellPatterns() []string {
	return []string{
		// Log4Shell — direct JNDI lookup over any of the abused protocols.
		`(?i)\$\{jndi:(ldaps?|rmi|dns|nis|iiop|corba|nds|http)://`,
		// Log4Shell — lookup obfuscation used to smuggle "jndi" past filters.
		`(?i)\$\{(lower|upper|env|sys|date|main|java):`,
		// Log4Shell — nested lookups (${${...}}) that reassemble the keyword.
		`(?i)\$\{[^}]*\$\{`,
		// Spring4Shell — classLoader binding-path manipulation.
		`(?i)class\.module\.classloader`,
		`(?i)\bclass\.\[?['"]?module['"]?\]?\.\[?['"]?classloader`,
	}
}

// wafOpToPattern converts a WAF operator into a single PCRE string dp's
// hyperscan can compile. "rx" passes through; literal operators are quoted and
// anchored so they keep their original semantics as a regex.
func wafOpToPattern(op waf.MatchExpr) string {
	switch op.Type {
	case "rx":
		return op.Value
	case "contains":
		return regexp.QuoteMeta(op.Value)
	case "beginsWith":
		return "^" + regexp.QuoteMeta(op.Value)
	case "endsWith":
		return regexp.QuoteMeta(op.Value) + "$"
	case "streq":
		return "^" + regexp.QuoteMeta(op.Value) + "$"
	default:
		if op.Value == "" {
			return ""
		}
		return regexp.QuoteMeta(op.Value)
	}
}

// AllBuiltinPacks is the full seed set (DLP + WAF).
func AllBuiltinPacks() []builtinPack {
	return append(BuiltinDLPPacks(), BuiltinWAFPacks()...)
}

// catalogContext maps a dlp catalog rule Context (header/body/url) to the NET-40
// DLP schema context token (header/body/uri). An unrecognised context degrades
// to "" so the pattern uses dp's body default rather than seeding an invalid one.
func catalogContext(c dlp.Context) string {
	switch c {
	case dlp.ContextURL:
		return "uri"
	case dlp.ContextHeader:
		return "header"
	case dlp.ContextBody:
		return "body"
	default:
		return ""
	}
}

// builtinPackPatternsJSON renders a pack's patterns for the JSONB column. When
// any per-pattern context is set (NET-40) it emits the {pattern, context} object
// form so dp scans each pattern in its authored buffer; otherwise it emits the
// legacy bare-string array, keeping WAF-pack seed bytes byte-for-byte unchanged.
func builtinPackPatternsJSON(p builtinPack) any {
	hasCtx := false
	for _, c := range p.Contexts {
		if strings.TrimSpace(c) != "" {
			hasCtx = true
			break
		}
	}
	if !hasCtx {
		return p.Patterns
	}
	specs := make([]dlp.PatternSpec, len(p.Patterns))
	for i, pat := range p.Patterns {
		specs[i] = dlp.PatternSpec{Pattern: pat}
		if i < len(p.Contexts) {
			specs[i].Context = p.Contexts[i]
		}
	}
	return specs
}

// EnsureBuiltins idempotently seeds the built-in DLP + WAF packs for one
// (org, cluster) in MONITOR mode. Safe to call repeatedly: the UNIQUE
// (org_id, cluster_id, name) constraint + ON CONFLICT DO NOTHING makes
// re-seeds no-ops, and operator edits to a seeded row survive (we never
// UPDATE existing rows here). Returns the number of rows actually inserted.
func (s *RuntimeDLPStore) EnsureBuiltins(ctx context.Context, orgID, clusterID uuid.UUID) (int, error) {
	inserted := 0
	for _, p := range AllBuiltinPacks() {
		patterns, err := json.Marshal(builtinPackPatternsJSON(p))
		if err != nil {
			continue
		}
		tag, err := s.db.Pool().Exec(ctx, `
INSERT INTO runtime_dlp_rules
  (org_id, cluster_id, name, category, apply_dir, severity, mode, patterns, description, source, cfg_type)
VALUES ($1,$2,$3,$4,$5,$6,'monitor',$7::jsonb,$8,'builtin','predefined')
ON CONFLICT (org_id, cluster_id, name) DO NOTHING`,
			orgID, clusterID, p.Name, string(p.Category), p.ApplyDir, p.Severity,
			string(patterns), p.Description)
		if err != nil {
			return inserted, err
		}
		inserted += int(tag.RowsAffected())
	}
	return inserted, nil
}
