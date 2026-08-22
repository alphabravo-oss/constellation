// Wave A1: agent → dp policy push channel.
//
// dp's policy engine matches every observed session against a per-workload
// rule table. The agent installs/replaces/clears that table via the
// `ctrl_cfg_policy` JSON RPC; dp's table swap is atomic per (cmd, MSG_END)
// fragment boundary so we can ship policy without dropping packets.
//
// Wire format mirrors NeuVector's `neuvector/agent/dp/dp_apis.go`
// (DPWorkloadIPPolicy, DPPolicyIPRule, DPPolicyCfg). The Go-native shape
// is on top: callers build a single WorkloadPolicy; PushPolicy fragments
// at ~40 rules per message and writes each chunk via the existing
// dpClient.sendOneway primitive.
//
// Action vocabulary maps onto the existing PolicyAction* constants:
//
//	monitor mode  →  PolicyActionViolate (logged; packet still allowed)
//	enforce mode  →  PolicyActionDeny    (dropped; emits a threat row)
//	allow         →  PolicyActionAllow
//	learn         →  PolicyActionLearn   (recorded for auto-policy-gen)
//
// The agent's policy state machine (Wave A5) picks which action to stamp on
// rules before calling PushPolicy.
package dp

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// PolicyApp is one L7 application whitelist on a rule. dp's per-rule app
// match falls through every PolicyApp entry; the first match wins and the
// per-app Action overrides the rule's overall Action.
type PolicyApp struct {
	App    uint32 `json:"app"`    // dp APP_* id from third_party/neuvector/dp/apis.h
	Action uint8  `json:"action"` // PolicyAction*
	RuleID uint32 `json:"rid"`    // for audit-trail back to the source rule
}

// IP protocol numbers dp accepts in PolicyRule.IPProto. IPProtoAny (0) is
// dp's wildcard: on the dp side a proto-any rule fans out to TCP+UDP, and
// additionally to ICMP only when ICMP policy is enabled (see SetICMPPolicy).
// A non-zero proto is matched verbatim, so IPProtoICMP makes ICMP an
// expressible, per-rule protocol alongside TCP/UDP.
const (
	IPProtoAny  uint8 = 0 // dp wildcard: fans out to TCP+UDP (+ICMP if enabled)
	IPProtoICMP uint8 = 1
	IPProtoTCP  uint8 = 6
	IPProtoUDP  uint8 = 17
)

// PolicyRule is one row in dp's policy table.
type PolicyRule struct {
	ID      uint32 `json:"id"`  // dp's hash key — unique per workload
	SrcIP   net.IP `json:"sip"` // for ingress: peer IP; for egress: workload IP
	DstIP   net.IP `json:"dip"`
	SrcIPR  net.IP `json:"sipr,omitempty"` // optional upper bound for IP range
	DstIPR  net.IP `json:"dipr,omitempty"`
	Port    uint16 `json:"port"`           // dst port (lower bound when PortR set)
	PortR   uint16 `json:"portr"`          // dst port range upper bound; 0 if single port
	IPProto uint8  `json:"proto"`          // IPProto*: 1=ICMP, 6=TCP, 17=UDP, 0=any
	Action  uint8  `json:"action"`         // PolicyAction*
	Ingress bool   `json:"ingress"`        // true → ingress rule (peer→workload)
	Fqdn    string `json:"fqdn,omitempty"` // for FQDN-anchored rules (DNS lookup → IP)
	Vhost   bool   `json:"vhost,omitempty"`

	Apps []PolicyApp `json:"apps,omitempty"`
}

// WorkloadPolicy is the agent-side bundle: every rule for one workload,
// keyed by its MAC(s). dp matches incoming packets to workloads by MAC,
// then walks the per-workload rule table.
type WorkloadPolicy struct {
	WorkloadID string        // operator-friendly label, eg. "default/api"
	Mode       string        // "monitor" | "enforce" | "disabled" — agent-side only
	DefAction  uint8         // matched-no-rule fallback (default: PolicyActionAllow)
	ApplyDir   int           // ApplyDirEgress | ApplyDirIngress | ApplyDirBoth
	MACs       []string      // veth MACs of every pod replica of this workload
	Rules      []*PolicyRule // the actual rule table
}

// policyCfgPayload is the wire-level shape of `ctrl_cfg_policy`. Mirrors
// neuvector/agent/dp/dp_apis.go DPPolicyCfg. Sent inside a JSON envelope:
//
//	{"ctrl_cfg_policy": { ... policyCfgPayload ... }}
type policyCfgPayload struct {
	Cmd         uint          `json:"cmd"`  // CmdAdd | CmdModify | CmdDelete
	Flag        uint          `json:"flag"` // MsgStart | MsgEnd (set for first/last fragment)
	DefAction   uint8         `json:"defact"`
	ApplyDir    int           `json:"dir"`
	WorkloadMac []string      `json:"mac"`
	IPRules     []*PolicyRule `json:"rules"`
}

type policyCfgReq struct {
	Cfg *policyCfgPayload `json:"ctrl_cfg_policy"`
}

// maxPolicyMsgSize is dp's per-datagram cap minus envelope overhead. dp's
// listener buffer is DP_MSG_SIZE (8192); we leave 72 bytes for the JSON
// keys/punctuation of the envelope. Mirrors NeuVector's maxMsgSize = 8120.
const maxPolicyMsgSize = 8120

// initialRulesPerMsg is the first-pass estimate of how many rules fit in
// one datagram. NeuVector's agent starts here and adapts down if the
// marshalled payload exceeds maxPolicyMsgSize.
const initialRulesPerMsg = 40

// PushPolicy fragments a WorkloadPolicy across one or more `ctrl_cfg_policy`
// datagrams and sends them in order. `cmd` is CmdAdd, CmdModify, or
// CmdDelete; the MSG_START / MSG_END flag bits are managed automatically:
// MSG_START on the first datagram, MSG_END on the last, both on a single-
// message push.
//
// Empty WorkloadPolicy + cmd=CmdDelete clears the workload's table.
//
// Errors are conservative: a marshal failure or a per-datagram send error
// aborts the push (we don't half-install a policy). The caller's policy
// state machine should set the workload to a safe state on error.
func (s *Supervisor) PushPolicy(policy *WorkloadPolicy, cmd uint) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp policy: supervisor not started")
	}
	if policy == nil {
		return fmt.Errorf("dp policy: nil policy")
	}
	return s.client.pushPolicy(policy, cmd)
}

// pushPolicy is the inner implementation; takes a raw *dpClient so it's
// easy to unit-test without spinning up a real supervisor.
func (c *dpClient) pushPolicy(policy *WorkloadPolicy, cmd uint) error {
	if policy == nil {
		return fmt.Errorf("dp policy: nil policy")
	}
	rules := policy.Rules
	first := true
	rulesPerMsg := initialRulesPerMsg

	// One zero-rule send is required even when there are no rules — that's
	// how we communicate CmdDelete or "this workload has no rules now".
	if len(rules) == 0 {
		payload := &policyCfgPayload{
			Cmd:         cmd,
			Flag:        MsgStart | MsgEnd,
			DefAction:   policy.DefAction,
			ApplyDir:    policy.ApplyDir,
			WorkloadMac: policy.MACs,
			IPRules:     nil,
		}
		return c.sendOneway(&policyCfgReq{Cfg: payload})
	}

	for len(rules) > 0 || first {
		// Try the current rulesPerMsg estimate. Adapt down if the marshalled
		// payload exceeds maxPolicyMsgSize (mirrors NeuVector's retry loop).
		chunkLen := rulesPerMsg
		if chunkLen > len(rules) {
			chunkLen = len(rules)
		}
	retry:
		flag := uint(0)
		if first {
			flag |= MsgStart
		}
		isLast := chunkLen >= len(rules)
		if isLast {
			flag |= MsgEnd
		}
		payload := &policyCfgPayload{
			Cmd:         cmd,
			Flag:        flag,
			DefAction:   policy.DefAction,
			ApplyDir:    policy.ApplyDir,
			WorkloadMac: policy.MACs,
			IPRules:     rules[:chunkLen],
		}
		msg, err := json.Marshal(&policyCfgReq{Cfg: payload})
		if err != nil {
			return fmt.Errorf("dp policy: marshal: %w", err)
		}
		if len(msg) > maxPolicyMsgSize {
			// Adapt: per-rule size estimate plus 1 byte slack.
			perRule := (len(msg)/chunkLen + 1)
			newPerMsg := maxPolicyMsgSize / perRule
			if newPerMsg >= chunkLen {
				newPerMsg = chunkLen - 1
			}
			if newPerMsg <= 0 {
				return fmt.Errorf("dp policy: single rule too large (%d bytes > %d)", len(msg), maxPolicyMsgSize)
			}
			rulesPerMsg = newPerMsg
			chunkLen = newPerMsg
			goto retry
		}
		if err := c.sendOnewayRaw(msg); err != nil {
			return fmt.Errorf("dp policy: send fragment: %w", err)
		}
		rules = rules[chunkLen:]
		first = false
		if isLast {
			break
		}
	}
	return nil
}

// sendOnewayRaw writes pre-marshalled bytes. Same lifecycle as sendOneway
// (auto-connect, write-deadline, reset on err) but skips json.Marshal so
// we can re-use the same buffer for the size-adapt retry loop.
func (c *dpClient) sendOnewayRaw(msg []byte) error {
	if err := c.connect(); err != nil {
		return err
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("dp policy: no connection")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	if _, err := conn.Write(msg); err != nil {
		c.resetOnErr()
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// ----- ICMP policy gate ------------------------------------------------------
// dp keeps a single global (g_enable_icmp_policy, default 0) that decides how
// ICMP is treated by the policy engine — see neuvector/dp/dpi/dpi_policy.c.
// When OFF, IPProtoAny rules fan out to TCP+UDP only and dp installs a blanket
// allow-all-ICMP default, so ICMP is never policed. When ON, IPProtoAny rules
// also cover ICMP and the default allow is dropped, so IPProtoICMP rules are
// actually enforced. Mirrors NeuVector's EnableIcmpPolicy.

// icmpPolicyReq is the wire shape of dp's `ctrl_enable_icmp_policy` control
// message. Mirrors neuvector/dp/ctrl.c dp_ctrl_enable_icmp_policy, which reads
// a single "enable_icmp_policy" bool out of the message body.
type icmpPolicyReq struct {
	Cfg struct {
		Enable bool `json:"enable_icmp_policy"`
	} `json:"ctrl_enable_icmp_policy"`
}

// SetICMPPolicy toggles dp's ICMP policy enforcement. It is additive and OFF
// by default in dp: until this is called with enable=true, IPProtoAny rules
// fan out to TCP+UDP only and ICMP is blanket-allowed — i.e. the pre-existing
// 0-any behaviour is unchanged. Enabling it makes IPProtoAny rules also cover
// ICMP and lets IPProtoICMP rules take effect. Send it once before/with the
// PushPolicy that relies on it; dp holds the flag globally.
func (s *Supervisor) SetICMPPolicy(enable bool) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp policy: supervisor not started")
	}
	req := &icmpPolicyReq{}
	req.Cfg.Enable = enable
	return s.client.sendOneway(req)
}

// ----- DLP -------------------------------------------------------------------
// dp's DLP engine has two coupled RPCs:
//   ctrl_bld_dlp: push pattern definitions (name, ID, list of PCRE patterns).
//                 dp compiles these into its hyperscan database.
//   ctrl_cfg_dlp: bind rule names → MACs so dp knows which workloads to
//                 scan with which rule set.
// Wave A1 ships the first; Wave C4 surfaces the second alongside a UI.

// DPI action codes, mirrored from neuvector/defs.h (DPI_ACTION_*). dp's DLP
// engine reads the per-rule action out of the ctrl_cfg_dlp binding; a rule
// only DROPs when its binding carries DPIActionDrop. Pushing patterns via
// ctrl_bld_dlp alone leaves every match alert-only.
const (
	DPIActionNone   uint8 = 0
	DPIActionAllow  uint8 = 1 // alert / monitor: log the match, forward the packet
	DPIActionDrop   uint8 = 2 // enforce: silently NF_DROP the packet + emit a threat row
	DPIActionReset  uint8 = 3 // enforce: NF_DROP + inject a TCP RST so the session tears down now
	DPIActionBypass uint8 = 4 // stop inspecting this session, fast-path it (allow)
	DPIActionBlock  uint8 = 5 // enforce: DROP + blacklist the 5-tuple for the session's lifetime
)

// EnforceHit classifies why dp is about to enforce on a session, which decides
// how hard we tear it down.
type EnforceHit uint8

const (
	HitPolicyDeny EnforceHit = iota // a network-policy Deny rule matched
	HitThreat                       // an L7 inspection (IPS/IDS/WAF/anomaly) fired
)

// EnforceAction maps an enforce hit to the dp DPI action dp should stamp.
//
// A network-policy Deny stays a silent DROP (NF_DROP): that's the long-standing
// semantics of a Deny rule — the peer sees a black-hole with no RST, so a
// scanner can't fingerprint the policy boundary. A threat / L7 hit escalates to
// RESET: dp injects a TCP RST so the offending session tears down immediately
// (faster than waiting for a timeout) and the client gets an explicit
// connection-reset signal instead of hanging.
//
// ponytail: RESET is hard-picked for every threat hit rather than plumbed as a
// per-rule drop-vs-reset knob — no threat-rule DTO carries an action today, and
// RESET is the sensible default. Escalate to DPIActionBlock if we later want dp
// to also blacklist the 5-tuple for the rest of the session.
func EnforceAction(hit EnforceHit) uint8 {
	switch hit {
	case HitThreat:
		return DPIActionReset
	default:
		return DPIActionDrop
	}
}

// DLPModeAction maps a rule's operating mode to the dp DPI action its
// ctrl_cfg_dlp binding should carry. Mirrors neuvector/agent/system.go
// dlpModeToDefaultAction: only "enforce" drops; everything else alerts.
// SAFETY: any mode we don't recognise falls through to ALLOW (monitor).
func DLPModeAction(mode string) uint8 {
	if mode == "enforce" {
		return DPIActionDrop
	}
	return DPIActionAllow
}

// DLPRule is one named pattern set dp will compile into hyperscan.
type DLPRule struct {
	Name     string   `json:"name"`
	ID       uint32   `json:"id"`
	Patterns []string `json:"patterns"` // PCRE; dp's hyperscan validates on compile

	// Contexts is the optional index-aligned per-pattern match context
	// (NET-40): Contexts[i] scopes Patterns[i] to dp's uri/header/body/packet
	// buffer. It is agent-side only — normalizeDLPPatterns folds each context
	// INTO the pattern string ("...; context <ctx>") before the wire, so this
	// field is never serialized to dp (json:"-"). A nil/short slice, or an empty
	// entry, defaults that pattern to "body" — the pre-NET-40 behaviour, so
	// existing callers that leave it unset are unchanged.
	Contexts []string `json:"-"`

	// Mode is agent-side only ("monitor" | "enforce"); it drives the
	// ctrl_cfg_dlp action binding, not the ctrl_bld_dlp pattern-compile
	// message, hence json:"-". BuildDLPRules ignores it; ConfigureDLPRules
	// reads it to decide DPIActionDrop vs DPIActionAllow.
	Mode string `json:"-"`
}

type dlpBuildPayload struct {
	Flag        uint       `json:"flag"`
	ApplyDir    int        `json:"dir"`
	DlpRules    []*DLPRule `json:"dlp_rules"`
	WorkloadMac []string   `json:"mac"`
	DelMac      []string   `json:"delmac,omitempty"`
}

type dlpBuildReq struct {
	Build *dlpBuildPayload `json:"ctrl_bld_dlp"`
}

// BuildDLPRules pushes a pattern database to dp. Single-shot — dp's
// hyperscan compile is atomic at the workload level. macs is the set of
// workloads that should be scanned with this rule set; delMacs is the
// optional revoke list.
//
// applyDir uses the ApplyDir* constants (egress | ingress | both); DLP
// commonly runs on egress only to catch data exfiltration.
func (s *Supervisor) BuildDLPRules(rules []*DLPRule, macs, delMacs []string, applyDir int) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp dlp: supervisor not started")
	}
	return s.client.sendOneway(&dlpBuildReq{Build: &dlpBuildPayload{
		Flag:        MsgStart | MsgEnd,
		ApplyDir:    applyDir,
		DlpRules:    normalizeDLPPatterns(rules),
		WorkloadMac: macs,
		DelMac:      delMacs,
	}})
}

// normalizeDLPPatterns returns a shallow copy of rules with every pattern run
// through NormalizePCREPattern, so no push site can hand dp a raw (undelimited)
// regex. The caller's rules are left untouched (we copy each *DLPRule before
// rewriting its Patterns).
func normalizeDLPPatterns(rules []*DLPRule) []*DLPRule {
	if rules == nil {
		return nil
	}
	out := make([]*DLPRule, 0, len(rules))
	for _, r := range rules {
		if r == nil {
			out = append(out, r)
			continue
		}
		cp := *r
		cp.Patterns = normalizePCREListWithContexts(r.Patterns, r.Contexts)
		out = append(out, &cp)
	}
	return out
}

// dlpRidSetting binds one built DLP rule (by dp rule ID) to a per-workload
// action. Mirrors neuvector/agent/dp/dp_apis.go DPDlpRidSetting: {id, action}.
type dlpRidSetting struct {
	ID     uint32 `json:"id"`
	Action uint8  `json:"action"` // DPIAction* — DROP only for enforce-mode rules
}

// dlpCfgPayload is the wire shape of ctrl_cfg_dlp. Mirrors
// neuvector/agent/dp/dp_apis.go DPDlpCfg: it binds a set of already-built
// rule IDs to a set of workload MACs, each carrying the action dp applies on
// match.
//
// CRITICAL: dp's dp_ctrl_cfg_dlp (ctrl.c:1832-1846) reads BOTH "ruletype" AND
// "wafruletype" and strcmp's each UNCONDITIONALLY — a missing key is a NULL and
// strcmp(NULL) segfaults. So every ctrl_cfg_dlp message MUST carry both keys as
// non-null strings, even a DLP-only binding. RuleType must be dp's
// DLP_RULETYPE_INSIDE ("inside"), not "dlp".
type dlpCfgPayload struct {
	Flag         uint             `json:"flag"`
	WorkloadMac  []string         `json:"mac"`
	DlpRuleNames []*dlpRidSetting `json:"dlp_rule_names"`
	RuleIds      []uint32         `json:"rule_ids"`
	RuleType     string           `json:"ruletype"`
	WafRuleType  string           `json:"wafruletype"` // must be present or dp strcmp(NULL) crashes
}

type dlpCfgReq struct {
	Cfg *dlpCfgPayload `json:"ctrl_cfg_dlp"`
}

// ConfigureDLPRules issues the ctrl_cfg_dlp binding that makes an enforce-mode
// DLP rule actually DROP. BuildDLPRules only compiles the pattern database;
// without this binding dp has no per-MAC action table and treats every match
// as alert-only. For each rule we derive DPIActionDrop (enforce) or
// DPIActionAllow (monitor) from its Mode and bind it to the given MACs.
//
// SAFETY: rules default to DPIActionAllow — a rule DROPs only when its Mode is
// explicitly "enforce". Callers gate fleet-wide enforcement upstream.
//
// ponytail: the dp C binary must implement ctrl_cfg_dlp (it does — see
// neuvector/agent/dp DPDlpCfgReq / dpi_dlp.c) and honour the per-rule Action.
// The vendored dp in this tree isn't exercised in CI, so the drop path is
// wired to this IPC seam but not integration-tested here.
func (s *Supervisor) ConfigureDLPRules(macs []string, rules []*DLPRule) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp dlp: supervisor not started")
	}
	if len(macs) == 0 || len(rules) == 0 {
		return nil // nothing to bind
	}
	bindings := make([]*dlpRidSetting, 0, len(rules))
	for _, r := range rules {
		bindings = append(bindings, &dlpRidSetting{ID: r.ID, Action: DLPModeAction(r.Mode)})
	}
	return s.client.sendOneway(&dlpCfgReq{Cfg: &dlpCfgPayload{
		Flag:         MsgStart | MsgEnd,
		WorkloadMac:  macs,
		DlpRuleNames: bindings,
		RuleIds:      defaultSessionRIDs(), // gate on the network-policy id (0 = default session), NOT sigids
		RuleType:     DLPRuleTypeOutside,
		WafRuleType:  WAFRuleTypeOutside, // present (no WAF rules bound here) so dp's strcmp doesn't NULL-deref
	}})
}

// ----- Combined DLP+WAF detector (shared hyperscan build) --------------------
// dp compiles ONE detector per endpoint: dpi_sig.c's dpi_sig_bld uses a
// file-static dlpDetector per ctrl_bld_dlp, and at MSG_END dpi_dlp_detect_update
// REPLACES ep->dlp_detector and DESTROYS the previous one. So two separate
// ctrl_bld_dlp builds — one for DLP, one for WAF — clobber each other: the
// second build's detect_update throws away the first's patterns, leaving the ep
// with only the last build's DB (WAF sigids stay cfg-bound but their patterns
// are gone → WAF can never match). The fix is to carry BOTH rule sets in a
// SINGLE ctrl_bld_dlp so one detector holds every pattern; the DLP-vs-WAF split
// is then made entirely at cfg time (ep->dlp_cfg_map vs ep->waf_cfg_map). This
// mirrors NeuVector's agent, which issues exactly one DPCtrlBldDlp + one
// DPCtrlConfigDlp per workload even when it has both DLP sensors and WAF rules.
// (Q1/Q4)

// dpBuildRule is the flat ctrl_bld_dlp rule shape ({name,id,patterns[]string})
// dp reads in dp_ctrl_bld_dlp. dp keys each pattern into hyperscan by CONTEXT
// class (uri/header/body/packet), never by sig_id, and treats sig_id as an
// opaque integer with NO DLP-vs-WAF range check — so DLP (20000-29999) and WAF
// (40000-49999) rules compile into one detector when carried in one array. Both
// DLPRule and wafBuildRuleWire already serialize to this exact shape; this type
// just lets the two flow through one array without a mixed []any. (Q1)
type dpBuildRule struct {
	Name     string   `json:"name"`
	ID       uint32   `json:"id"`
	Patterns []string `json:"patterns"`
}

type detectorBuildPayload struct {
	Flag        uint           `json:"flag"`
	ApplyDir    int            `json:"dir"`
	DlpRules    []*dpBuildRule `json:"dlp_rules"`
	WorkloadMac []string       `json:"mac"`
	DelMac      []string       `json:"delmac,omitempty"`
}

type detectorBuildReq struct {
	Build *detectorBuildPayload `json:"ctrl_bld_dlp"`
}

// BuildDetector compiles BOTH the DLP and WAF pattern sets into ONE dp detector
// via a single ctrl_bld_dlp, so the ep ends up with every pattern instead of
// only the last build's (the shared-detector clobber above). DLP patterns are
// normalized via normalizeDLPPatterns and WAF patterns flattened to dp's
// "[!]/regex/is; context <ctx>" string form via wafRulesToWire — reusing the
// exact same normalization the standalone BuildDLPRules / BuildWAFRules use, so
// no pattern logic is duplicated. Either rule set may be empty (e.g. a WAF-only
// workload). applyDir should be ApplyDirBoth: one detector now serves DLP's
// egress east-west check and WAF's ingress path, and detector->dlp_apply_dir
// only gates the egress east-west special case (dpi_search.c reads it solely as
// `& DP_POLICY_APPLY_EGRESS`), so the EGRESS bit must stay set while the INGRESS
// bit is a harmless no-op there. (Q1)
func (s *Supervisor) BuildDetector(dlpRules []*DLPRule, wafRules []*WAFRule, macs, delMacs []string, applyDir int) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp dlp: supervisor not started")
	}
	rules := make([]*dpBuildRule, 0, len(dlpRules)+len(wafRules))
	for _, r := range normalizeDLPPatterns(dlpRules) {
		if r == nil {
			continue
		}
		rules = append(rules, &dpBuildRule{Name: r.Name, ID: r.ID, Patterns: r.Patterns})
	}
	for _, w := range wafRulesToWire(wafRules) {
		if w == nil {
			continue
		}
		rules = append(rules, &dpBuildRule{Name: w.Name, ID: w.ID, Patterns: w.Patterns})
	}
	return s.client.sendOneway(&detectorBuildReq{Build: &detectorBuildPayload{
		Flag:        MsgStart | MsgEnd,
		ApplyDir:    applyDir,
		DlpRules:    rules,
		WorkloadMac: macs,
		DelMac:      delMacs,
	}})
}

// detectorCfgPayload is the combined ctrl_cfg_dlp binding: it carries BOTH the
// DLP keys (dlp_rule_names/rule_ids/ruletype) AND the WAF keys
// (waf_rule_names/waf_rule_ids/wafruletype) in ONE message. dp's dp_ctrl_cfg_dlp
// processes the two independently — dlp_rule_names populate ep->dlp_cfg_map and
// waf_rule_names populate ep->waf_cfg_map, each cleared+repopulated under its own
// MSG_START guard (ctrl.c) — so one message binds both tables and neither
// clobbers the other. Both "ruletype" and "wafruletype" are strcmp'd
// unconditionally, so both MUST be present as non-null strings even when one
// side has no rules. (Q2/Q4)
type detectorCfgPayload struct {
	Flag         uint             `json:"flag"`
	WorkloadMac  []string         `json:"mac"`
	DlpRuleNames []*dlpRidSetting `json:"dlp_rule_names"`
	RuleIds      []uint32         `json:"rule_ids"`
	RuleType     string           `json:"ruletype"`
	WafRuleNames []*wafRidSetting `json:"waf_rule_names"`
	WafRuleIds   []uint32         `json:"waf_rule_ids"`
	WafRuleType  string           `json:"wafruletype"`
}

type detectorCfgReq struct {
	Cfg *detectorCfgPayload `json:"ctrl_cfg_dlp"`
}

// ConfigureDetector issues the single ctrl_cfg_dlp that binds the DLP rules into
// ep->dlp_cfg_map and the WAF rules into ep->waf_cfg_map for the given MACs,
// each with its per-rule action (DLP: DROP for enforce; WAF: RESET for enforce;
// ALLOW/alert otherwise). Companion to BuildDetector: the build compiles every
// pattern into one detector, this cfg decides which sigids fire as DLP vs WAF.
// Either rule set may be empty — the corresponding map is simply cleared for
// these MACs (e.g. a WAF-only workload gets an empty dlp_cfg_map). (Q2/Q4)
//
// policyRIDs are the nonzero network-policy rule ids (DPPolicyID) currently
// programmed into dp for these MACs. dp gates detection on the SESSION'S policy
// id, so these are bound into ep->{dlp,waf}_rid_map alongside the default id 0:
// without them, only default (id 0) east-west sessions are scanned and every
// session matching a positive pushed rule is missed (dpi_search.c OUTSIDE
// branch). Pass none (variadic) for the default-only {0} binding.
func (s *Supervisor) ConfigureDetector(macs []string, dlpRules []*DLPRule, wafRules []*WAFRule, policyRIDs ...uint32) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("dp dlp: supervisor not started")
	}
	if len(macs) == 0 {
		return nil
	}
	dlpBindings := make([]*dlpRidSetting, 0, len(dlpRules))
	for _, r := range dlpRules {
		dlpBindings = append(dlpBindings, &dlpRidSetting{ID: r.ID, Action: DLPModeAction(r.Mode)})
	}
	wafBindings := make([]*wafRidSetting, 0, len(wafRules))
	for _, r := range wafRules {
		wafBindings = append(wafBindings, &wafRidSetting{ID: r.ID, Action: WAFModeAction(r.Mode)})
	}
	// DLP gets full coverage: {0} + every pushed network-policy id, so exfil is
	// scanned on positive-policy sessions too (DLP legitimately inspects both
	// directions). WAF stays {0}-ONLY: the OUTSIDE branch has no apply_dir gate,
	// so binding policy ids to waf_rid_map would scan those sessions in BOTH
	// directions and re-open the DB-egress false positive on a WAF-opted web
	// workload. Widen WAF coverage only once dp's INSIDE + per-workload apply_dir
	// direction model lands (then ingress-only makes it safe). See sessionRIDs.
	dlpRIDs := sessionRIDs(policyRIDs)
	return s.client.sendOneway(&detectorCfgReq{Cfg: &detectorCfgPayload{
		Flag:         MsgStart | MsgEnd,
		WorkloadMac:  macs,
		DlpRuleNames: dlpBindings,
		RuleIds:      dlpRIDs,
		RuleType:     DLPRuleTypeOutside,
		WafRuleNames: wafBindings,
		WafRuleIds:   defaultSessionRIDs(),
		WafRuleType:  WAFRuleTypeOutside,
	}})
}
