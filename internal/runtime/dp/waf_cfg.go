package dp

import "fmt"

// ----- WAF -------------------------------------------------------------------
// The WAF engine reuses dp's DLP/hyperscan machinery but binds its matches to a
// DEDICATED per-endpoint table (ep->waf_cfg_map, keyed by the "wafinside" /
// "wafoutside" ruletype) rather than collapsing into the DLP table
// (ep->dlp_cfg_map). This mirrors NeuVector: one shared hyperscan build compiles
// every signature, then each endpoint's cfg binding decides whether a given
// sigid is checked as a DLP (payload-exfil, egress) or a WAF (inbound web-attack)
// rule. See third_party/neuvector dp/apis.h WAF_RULETYPE_INSIDE and dp/ctrl.c
// ep->waf_cfg_map / ep->waf_inside.
//
// Two coupled RPCs, exactly like DLP:
//   ctrl_bld_dlp: compile pattern definitions into dp's hyperscan database
//                 (shared with DLP — one detector holds every sigid).
//   ctrl_cfg_dlp: bind sigids → MACs, carrying wafruletype + the per-rule
//                 action dp stamps on a match.
//
// Keeping WAF in its own cfg table (not folding it into DLP) means a workload
// can run DLP egress rules and WAF ingress rules independently, each with its
// own action, which is exactly the split neuvector/dp/ctrl.c enforces.

// WAF cfg ruletype selectors, mirrored from third_party/neuvector/dp/apis.h
// WAF_RULETYPE_INSIDE / WAF_RULETYPE_OUTSIDE. "inside" scopes the rule to
// traffic within the mesh boundary; "outside" to traffic crossing it. Inbound
// web-attack rules default to inside (the common case), matching DLP's default.
const (
	WAFRuleTypeInside  = "wafinside"
	WAFRuleTypeOutside = "wafoutside"
)

// DLP ruletype selectors, mirrored from third_party/neuvector/dp/apis.h
// DLP_RULETYPE_INSIDE / _OUTSIDE. dp's dp_ctrl_cfg_dlp strcmp's "ruletype"
// against these — the value must be "inside"/"outside", NOT "dlp".
const (
	DLPRuleTypeInside  = "inside"
	DLPRuleTypeOutside = "outside"
)

// defaultSessionRID is dp's implicit/unmatched network-policy id. dp gates DLP/WAF
// detection on the SESSION'S policy id (key.rid = sess->policy_desc.id), NOT on the
// signature id — see dpi_search.c dpi_waf_ep_policy_check :777-785 / dpi_dlp_ep_policy_check
// :844-852. Every default east-west session to a tapped workload (host->pod, pod->pod,
// any tuple with no positive pushed rule, regardless of the default action) carries
// sess->policy_desc.id==0 (dpi_policy.c). We therefore run the cfg in OUTSIDE ruletype —
// whose branch has NO east-west exclusion and scans iff rcu_map_lookup(rid_map,{rid:0})
// hits — and bind exactly {0}. ctrl.c inserts key{rid:0} verbatim (0 is not skipped), so
// the lookup hits and dpi_process_detector runs. (Sending the sigids here — as the old
// INSIDE path did — was the bug: sigids never match a session's policy id; DLP INSIDE
// additionally INVERTS the map, exempting id 0.)
//
// Coverage gap: OUTSIDE scans only ids present in the map, so a session matching a
// positive pushed rule (nonzero DPPolicyID) is not scanned with only {0} bound. The
// id==0 default bulk (the goal traffic) is fully covered; append pushed ids here if
// positive-rule sessions must be inspected later.
const defaultSessionRID uint32 = 0

// defaultSessionRIDs is the rid set bound into ep->{dlp,waf}_rid_map so OUTSIDE-mode
// detection fires on default (policy id 0) sessions. Returns a fresh slice per call.
func defaultSessionRIDs() []uint32 { return []uint32{defaultSessionRID} }

// sessionRIDs returns the rid set to bind into ep->{dlp,waf}_rid_map: always the
// default session id 0 (east-west / unmatched traffic) PLUS every nonzero pushed
// network-policy rule id. dp's OUTSIDE branch keys the rid_map lookup on the
// session's policy id (sess->policy_desc.id — dpi_search.c :778/:845), so binding
// only {0} scans just default sessions and misses every session that matched a
// positive pushed rule (nonzero DPPolicyID). Feeding those rule ids here closes
// that coverage gap. A redundant 0 and duplicates are dropped; 0 stays first.
func sessionRIDs(policyRIDs []uint32) []uint32 {
	out := []uint32{defaultSessionRID}
	seen := map[uint32]struct{}{defaultSessionRID: {}}
	for _, r := range policyRIDs {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		out = append(out, r)
	}
	return out
}

// WAF pattern context selects which slice of the HTTP message a pattern is
// matched against, mirroring dpi_sig_context_class_t
// (third_party/neuvector/dp/dpi/sig/dpi_sig.h): HEAD covers the request line +
// URI + headers, BODY the entity body. Keeping them separate lets dp skip body
// reassembly for head-only rules (scanner User-Agent, path traversal) and
// avoids header noise for body-only rules.
// dp scans HTTP into distinct per-context buffers (dpi_http.c): the request line
// (method + URL + query args) lands in the URI_ORIGIN buffer dp names "url"; the
// header block in "header"; the entity body in "body". A rule only ever matches the
// buffer its context selects, so ARGS/URI rules MUST target URL and header rules
// MUST target HEAD — collapsing both into "header" (the old behaviour) made every
// URL/query attack miss.
const (
	WAFCtxURL  = "url"
	WAFCtxHead = "head"
	WAFCtxBody = "body"
)

// WAFPattern is one PCRE matched in a named HTTP context.
type WAFPattern struct {
	Context string `json:"context"` // WAFCtxURL | WAFCtxHead | WAFCtxBody
	Value   string `json:"pattern"` // PCRE; dp's hyperscan validates on compile
}

// WAFRule is one named pattern set dp compiles into hyperscan and binds to the
// waf_cfg_map. Analogous to DLPRule, but each pattern carries an HTTP context
// and the enforce action is RESET (tear the offending session down) rather than
// the silent DROP DLP uses for egress exfil.
type WAFRule struct {
	Name     string       `json:"name"`
	ID       uint32       `json:"id"`
	Patterns []WAFPattern `json:"patterns"`

	// Mode is agent-side only ("monitor" | "enforce"); it drives the
	// ctrl_cfg_dlp action binding, not the ctrl_bld_dlp compile message, hence
	// json:"-". BuildWAFRules ignores it; ConfigureWAFRules reads it to decide
	// DPIActionReset vs DPIActionAllow.
	Mode string `json:"-"`
}

// wafBuildRuleWire is the on-the-wire shape of one rule in ctrl_bld_dlp. dp
// (dp/ctrl.c:2170-2189 dp_ctrl_bld_dlp) reads each rule as {name, id, patterns}
// where patterns is an array of STRINGS — it calls json_string_value on each
// element and strlcpy's it. A per-pattern context is NOT a wire field; it is
// folded into the pattern string as "...; context <ctx>" (dp splits it back out).
// WAFPattern is a struct, so serializing []WAFPattern directly produces JSON
// OBJECTS and json_string_value returns NULL → dp segfaults. Hence this flat
// []string wire form, identical to the DLP build's DLPRule.
type wafBuildRuleWire struct {
	Name     string   `json:"name"`
	ID       uint32   `json:"id"`
	Patterns []string `json:"patterns"`
}

// wafBuildPayload reuses the ctrl_bld_dlp wire shape: the hyperscan detector is
// shared between DLP and WAF, so WAF patterns are compiled through the same
// "dlp_rules" build array. The DLP-vs-WAF split happens later, at cfg time.
type wafBuildPayload struct {
	Flag        uint                `json:"flag"`
	ApplyDir    int                 `json:"dir"`
	WafRules    []*wafBuildRuleWire `json:"dlp_rules"`
	WorkloadMac []string            `json:"mac"`
	DelMac      []string            `json:"delmac,omitempty"`
}

type wafBuildReq struct {
	Build *wafBuildPayload `json:"ctrl_bld_dlp"`
}

// BuildWAFRules pushes the WAF pattern database to dp. Single-shot, like
// BuildDLPRules: dp's hyperscan compile is atomic at the workload level. macs
// is the set of workloads scanned with this rule set; delMacs the revoke list.
// applyDir uses the ApplyDir* constants — WAF commonly runs ingress (block
// inbound web attacks) rather than DLP's egress default.
func (s *Supervisor) BuildWAFRules(rules []*WAFRule, macs, delMacs []string, applyDir int) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp waf: supervisor not started")
	}
	return s.client.sendOneway(&wafBuildReq{Build: &wafBuildPayload{
		Flag:        MsgStart | MsgEnd,
		ApplyDir:    applyDir,
		WafRules:    wafRulesToWire(rules),
		WorkloadMac: macs,
		DelMac:      delMacs,
	}})
}

// wafRulesToWire flattens each WAFRule into dp's ctrl_bld_dlp wire form: a rule
// with a patterns array of STRINGS. Each WAFPattern becomes a single dp pattern
// string "[!]/regex/is; context <dpctx>" — its Value normalized and its Context
// folded in (a struct pattern would serialize as a JSON object dp can't read,
// which is exactly what segfaulted dp at ctrl.c:2184). Patterns that normalize
// to empty are dropped; nil rules are skipped.
func wafRulesToWire(rules []*WAFRule) []*wafBuildRuleWire {
	if rules == nil {
		return nil
	}
	out := make([]*wafBuildRuleWire, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			continue
		}
		w := &wafBuildRuleWire{Name: r.Name, ID: r.ID}
		for _, p := range r.Patterns {
			s := normalizePCREWithContext(p.Value, dpWAFContext(p.Context))
			if s == "" {
				continue
			}
			w.Patterns = append(w.Patterns, s)
		}
		out = append(out, w)
	}
	return out
}

// dpWAFContext maps a WAFPattern context token to a context value dp accepts
// (dpi_sigopt_context_parser: url|header|body|packet|sql_query). "url" selects dp's
// URI_ORIGIN buffer (request line + URL + query args); "head" the header block
// ("header"); everything else the entity body ("body"). An unmapped/unknown context
// would make dp reject the rule.
func dpWAFContext(ctx string) string {
	switch ctx {
	case WAFCtxURL:
		return "url"
	case WAFCtxHead:
		return "header"
	default:
		return "body"
	}
}

// WAFModeAction maps a WAF rule's mode to the dp DPI action its ctrl_cfg_dlp
// binding carries. A WAF hit is an inbound L7 web attack, so enforce escalates
// to RESET (EnforceAction(HitThreat) == DPIActionReset): dp NF_DROPs the packet
// AND injects a TCP RST so the offending HTTP session tears down immediately,
// giving the client an explicit connection-reset instead of a hang. Anything
// but "enforce" stays alert-only (DPIActionAllow) — the same monitor-by-default
// safety contract DLPModeAction has.
func WAFModeAction(mode string) uint8 {
	if mode == "enforce" {
		return EnforceAction(HitThreat) // DPIActionReset
	}
	return DPIActionAllow
}

// wafRidSetting binds one built WAF rule (by dp sigid) to a per-workload action.
// Mirrors dlpRidSetting: {id, action}.
type wafRidSetting struct {
	ID     uint32 `json:"id"`
	Action uint8  `json:"action"` // DPIAction* — RESET only for enforce-mode rules
}

// wafCfgPayload is the WAF variant of the ctrl_cfg_dlp binding. It writes the
// waf_rule_names / waf_rule_ids / wafruletype keys neuvector/dp/ctrl.c reads
// into ep->waf_cfg_map (dedicated table), leaving the DLP keys untouched.
// dp's dp_ctrl_cfg_dlp strcmp's BOTH "ruletype" and "wafruletype" unconditionally
// (ctrl.c:1832-1846), so a WAF-only cfg must ALSO carry a non-null "ruletype" or
// dp NULL-derefs. RuleType is a present-but-unused DLP selector here.
type wafCfgPayload struct {
	Flag         uint             `json:"flag"`
	WorkloadMac  []string         `json:"mac"`
	RuleType     string           `json:"ruletype"` // present (no DLP rules bound here) so dp's strcmp doesn't NULL-deref
	WafRuleNames []*wafRidSetting `json:"waf_rule_names"`
	WafRuleIds   []uint32         `json:"waf_rule_ids"`
	WafRuleType  string           `json:"wafruletype"`
}

type wafCfgReq struct {
	Cfg *wafCfgPayload `json:"ctrl_cfg_dlp"`
}

// ConfigureWAFRules issues the ctrl_cfg_dlp binding that makes an enforce-mode
// WAF rule actually RESET. BuildWAFRules only compiles the pattern database;
// without this binding dp has no per-MAC WAF action table and treats every
// match as alert-only. For each rule we derive DPIActionReset (enforce) or
// DPIActionAllow (monitor) from its Mode and bind it to the given MACs under
// the wafinside ruletype.
//
// SAFETY: rules default to DPIActionAllow — a rule RESETs only when its Mode is
// explicitly "enforce". Callers gate fleet-wide enforcement upstream, exactly
// as ConfigureDLPRules does.
//
// ponytail: like the DLP cfg path, the vendored dp isn't exercised in CI, so
// this drop/reset path is wired to the IPC seam but not integration-tested here.
func (s *Supervisor) ConfigureWAFRules(macs []string, rules []*WAFRule) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp waf: supervisor not started")
	}
	if len(macs) == 0 || len(rules) == 0 {
		return nil // nothing to bind
	}
	bindings := make([]*wafRidSetting, 0, len(rules))
	for _, r := range rules {
		bindings = append(bindings, &wafRidSetting{ID: r.ID, Action: WAFModeAction(r.Mode)})
	}
	return s.client.sendOneway(&wafCfgReq{Cfg: &wafCfgPayload{
		Flag:         MsgStart | MsgEnd,
		WorkloadMac:  macs,
		RuleType:     DLPRuleTypeOutside, // present (no DLP rules bound here) so dp's strcmp doesn't NULL-deref
		WafRuleNames: bindings,
		WafRuleIds:   defaultSessionRIDs(), // gate on the session's network-policy id (0 = default), NOT sigids
		WafRuleType:  WAFRuleTypeOutside,
	}})
}
