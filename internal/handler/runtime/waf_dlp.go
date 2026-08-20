package runtime

import (
	"strings"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
)

// WAF rule enforcement was removed (WS-G G1): the /waf/groups CRUD never had
// an agent bundle endpoint, a sync worker, or a DP consumer, so its rules
// never reached the dataplane. DPI Signatures (runtime_signatures.go, backed
// by runtime_dlp_rules + Supervisor.BuildDLPRules) are the single
// authoritative DPI/L7 ruleset that compiles to dp's hyperscan engine. The
// in-process L7 evaluator in internal/runtime/waf (Engine/BuiltinCRS) is kept
// for the runtime pipeline; only the orphan CRUD surface was deleted here.
//
// G2.2: the authored CRS pack (waf.BuiltinCRS — SQLi/XSS/LFI/RCE/scanner-UA)
// now DOES reach the dataplane through a dedicated WAF pattern table, distinct
// from DLP. WAFRuleTable renders the 12 CRS rules as dp.WAFRule entries (one
// PCRE per rule, tagged with its HTTP HEAD/BODY context), and PushWAFRules
// pushes them over dp's WAF RPCs (BuildWAFRules + ConfigureWAFRules → dp's
// ep->waf_cfg_map). Unlike the earlier rules_builtin.go path — which flattened
// WAF patterns into category='signature' DLP rows and so lost the WAF/DLP split
// and per-context matching — this keeps WAF in its own dp table with a
// WAF-flavoured enforce action (RESET), mirroring NeuVector's wafinside table.
//
// Mode parity with DLP: rules ship monitor-by-default; a rule only RESETs when
// the fleet enforce gate is on AND the authored rule's Action is "block".

// wafTargetContext maps a CRS rule's ModSecurity target to the dp WAF pattern
// context. dp scans HTTP into three separate buffers and a rule only matches the
// one its context names, so each target must land in the buffer it actually lives
// in (dpi_http.c): the request line/URL/query args -> "url" (WAFCtxURL); the header
// block and cookies -> "header" (WAFCtxHead); the entity body / POST args -> "body"
// (WAFCtxBody). The old code collapsed everything but REQUEST_BODY into HEAD, so
// ARGS/REQUEST_URI rules scanned the header buffer and missed all URL/query attacks.
//
// ModSec ARGS spans GET (url) + POST (body); we map it to url (GET). No current CRS
// rule targets POST args, so nothing is lost today; a POST-arg rule would need a
// second pattern in the body context.
func wafTargetContext(target string) string {
	switch {
	case target == "REQUEST_BODY" ||
		strings.HasPrefix(target, "ARGS_POST") ||
		strings.HasPrefix(target, "XML") ||
		strings.HasPrefix(target, "JSON"):
		return dp.WAFCtxBody
	case strings.HasPrefix(target, "REQUEST_HEADERS") ||
		strings.HasPrefix(target, "REQUEST_COOKIES"):
		return dp.WAFCtxHead
	case strings.HasPrefix(target, "ARGS") || // ARGS / ARGS_GET / ARGS_NAMES
		target == "QUERY_STRING" ||
		strings.HasPrefix(target, "REQUEST_URI") || // REQUEST_URI / REQUEST_URI_RAW
		target == "REQUEST_FILENAME" ||
		target == "REQUEST_BASENAME" ||
		target == "REQUEST_LINE" ||
		target == "REQUEST_METHOD" ||
		target == "REQUEST_PROTOCOL":
		return dp.WAFCtxURL
	default:
		return dp.WAFCtxHead
	}
}

// WAFRuleTable renders the built-in OWASP-CRS pack as dp WAF rules. Each CRS
// rule becomes one dp.WAFRule carrying a single PCRE pattern (reusing
// wafOpToPattern, the same operator→PCRE lowering the seed path uses) tagged
// with the rule's HTTP context and keyed by the CRS rule ID as the dp sigid.
//
// enforce gates the per-rule mode exactly like the DLP fleet gate: when false
// every rule is monitor (alert-only); when true a rule inherits "enforce" only
// if its authored Action is "block" (so alert-only CRS rules — comment-evasion
// SQLi, event-handler XSS, scanner-UA — stay monitor even under enforce).
func WAFRuleTable(enforce bool) []*dp.WAFRule {
	crs := waf.BuiltinCRS()
	out := make([]*dp.WAFRule, 0, len(crs.Rules))
	for _, r := range crs.Rules {
		pcre := wafOpToPattern(r.Operator)
		if pcre == "" {
			continue
		}
		ctx := wafTargetContext(r.Target)
		// dp scans the raw percent-encoded URI and never url-decodes; widen
		// url-context patterns so single-encoded attacks (UNION%20SELECT) match.
		if ctx == dp.WAFCtxURL && hasTransform(r.Transformations, "urlDecode") {
			pcre = urlEncodeTolerant(pcre)
		}
		mode := "monitor"
		if enforce && r.Action == "block" {
			mode = "enforce"
		}
		// dp rejects names with spaces and sig ids outside 20000-49999
		// (dpi_sig.c / dpi_sigopt_basic.c). CRS names are human strings and CRS
		// ids (942100…) are far out of range, so sanitize the name and assign a
		// sequential in-range WAF sig id — stable across restarts (fixed list).
		out = append(out, &dp.WAFRule{
			Name: dp.SanitizeSigName(r.Msg),
			ID:   dp.WAFSigID(len(out)),
			Patterns: []dp.WAFPattern{{
				Context: ctx,
				Value:   pcre,
			}},
			Mode: mode,
		})
	}
	return out
}

// wafNameByID maps a dp WAF sig id (40000+) back to its human CRS rule message,
// reproducing WAFRuleTable's exact filter+order so id-40000 lines up with the rule
// dp actually matched. dp reports WAF hits as "WAF: id 40002"; this turns that into
// "SQL Injection Attempt (UNION SELECT)" the way NeuVector labels sensor hits.
var wafNameByID = func() map[uint32]string {
	m := map[uint32]string{}
	i := 0
	for _, r := range waf.BuiltinCRS().Rules {
		if wafOpToPattern(r.Operator) == "" {
			continue
		}
		m[dp.WAFSigID(i)] = r.Msg
		i++
	}
	return m
}()

// WAFThreatName returns the CRS rule message for a dp WAF sig id (40000-49999),
// or "" if the id isn't a known WAF rule.
func WAFThreatName(id uint32) string { return wafNameByID[id] }

// resolveThreatName labels a dp threat id: WAF sensor hits (40000-49999) get their
// CRS rule message; everything else falls back to the built-in DPI signature names.
func resolveThreatName(id uint32) string {
	if n := WAFThreatName(id); n != "" {
		return n
	}
	return handler.NeuVectorThreatName(id)
}

// PushWAFRules compiles the CRS pack into dp's hyperscan DB and binds it to the
// given workload MACs under the dedicated WAF table. It is the WAF analogue of
// the DLP sync worker's BuildDLPRules + ConfigureDLPRules pair: BuildWAFRules
// pushes the patterns, ConfigureWAFRules installs the per-rule action so
// enforce-mode rules actually RESET. WAF runs ingress by default (block inbound
// web attacks). No-op when there are no MACs to scan.
//
// STANDALONE ONLY. dp keeps ONE detector per endpoint, so a WAF-only
// ctrl_bld_dlp and a DLP-only ctrl_bld_dlp CLOBBER each other (the second
// build's dpi_dlp_detect_update destroys the first's patterns). The runtime
// agent therefore no longer calls this alongside a DLP build — it uses
// Supervisor.BuildDetector + ConfigureDetector to compile BOTH rule sets into
// one detector. Only use PushWAFRules where a workload has WAF rules and nothing
// else on the shared DLP/WAF detector.
func PushWAFRules(sup *dp.Supervisor, macs []string, enforce bool) error {
	if len(macs) == 0 {
		return nil
	}
	rules := WAFRuleTable(enforce)
	if err := sup.BuildWAFRules(rules, macs, nil, dp.ApplyDirIngress); err != nil {
		return err
	}
	return sup.ConfigureWAFRules(macs, rules)
}

// DLP sensors CRUD (the /dlp/sensors REST surface + ConstellationDLPSensor CRD)
// was removed following the WS-G G1 precedent: like the deleted /waf/groups CRUD,
// the dlp_sensors table it wrote never reached the dataplane — no agent bundle
// endpoint, no sync worker, and no dp consumer ever read it, so authored sensors
// enforced nothing. The authoritative enforced DLP path is runtime_dlp_rules
// (runtime_dlp.go, seeded from the code-level dlp.DefaultCatalog() in
// rules_builtin.go and served to agents via AgentBundle). See
// internal/handler/dlp_sensors_removed_test.go for the orphan-surface guard.
