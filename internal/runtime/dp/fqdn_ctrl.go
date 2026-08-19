// Task F1b: wire the FQDN resolver into the live dp control path.
//
// The resolver (fqdn.go) learns FQDN→IP mappings from snooped DNS responses.
// dp's policy engine matches FQDN-anchored rules by IP, so the agent has to
// program dp with the current IP set for every allowed name. NeuVector does
// this with the `ctrl_cfg_set_fqdn` JSON RPC, which carries the FULL current
// IP set for one name (re-sending the whole set on every change; an empty set
// clears the name). We mirror that exactly rather than inventing a per-IP
// delta protocol — see neuvector/agent/dp/ctrl.go DPCtrlSetFqdnIp.
//
// Flow in production (driven by the agent's DNS snoop + this Supervisor):
//
//	DNS response ─▶ Supervisor.FeedDNS ─▶ resolver.Observe ─▶ reconcile ─▶ ctrl_cfg_set_fqdn
//	Expire tick  ─▶ resolver.Expire    ─▶ reconcile ─▶ ctrl_cfg_set_fqdn (shrunk/empty set)
//	policy change─▶ Supervisor.SetAllowedFqdns ─▶ resolver.SetAllowed ─▶ reconcile
package dp

import (
	"context"
	"net"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
)

// defaultFqdnExpireInterval is how often the Supervisor drives TTL eviction
// (resolver.Expire) and reconciles the resulting IP sets into dp. Without this
// loop, learned IPs would never be released as DNS records rotate.
const defaultFqdnExpireInterval = 30 * time.Second

// dpFqdnIPs mirrors NeuVector's DPFqdnIps (agent/dp/dp_apis.go): the full IP
// set for one name. Sent inside the `ctrl_cfg_set_fqdn` envelope.
type dpFqdnIPs struct {
	FqdnName string   `json:"fqdn_name"`
	FqdnIPs  []net.IP `json:"fqdn_ips"`
}

type dpFqdnIPSetReq struct {
	Fqdns *dpFqdnIPs `json:"ctrl_cfg_set_fqdn"`
}

// setFqdnIPs programs dp with the complete IP set for `name`. An empty/nil
// `ips` clears the name's mapping. Mirrors NeuVector DPCtrlSetFqdnIp.
func (c *dpClient) setFqdnIPs(name string, ips []net.IP) error {
	return c.sendOneway(&dpFqdnIPSetReq{Fqdns: &dpFqdnIPs{FqdnName: name, FqdnIPs: ips}})
}

// Fqdns exposes the Supervisor's FQDN resolver so the agent can seed the
// allow-set and inspect learned mappings. Never nil after New.
func (s *Supervisor) Fqdns() *FqdnResolver { return s.fqdn }

// SetAllowedFqdns replaces the FQDN allow-set (the union of every workload's
// FQDN-anchored egress rules) and reconciles the change into dp — names that
// are no longer allowed have their dp mapping cleared immediately rather than
// lingering until TTL.
func (s *Supervisor) SetAllowedFqdns(allowed []string) {
	if s == nil || s.fqdn == nil {
		return
	}
	s.fqdn.SetAllowed(allowed)
	s.reconcileFqdn()
}

// FeedDNS hands a parsed DNS response to the resolver and reconciles any
// resulting IP-set change into dp. The agent's L7/DNS snoop calls this for
// every observed response; non-responses and non-allowed names are no-ops.
func (s *Supervisor) FeedDNS(evt *dpi.DNSEvent) {
	if s == nil || s.fqdn == nil {
		return
	}
	s.fqdn.FeedDNSResponse(evt, time.Now())
	s.reconcileFqdn()
}

// reconcileFqdn diffs the resolver's current name→IP table against the last
// set pushed to dp and emits a `ctrl_cfg_set_fqdn` for every name whose set
// changed (including names that disappeared, which get an empty set). The
// per-name pushed state only advances on a successful send so a transient dp
// outage is retried on the next reconcile.
func (s *Supervisor) reconcileFqdn() {
	if s == nil || s.fqdn == nil || s.client == nil {
		return
	}
	snap := s.fqdn.Snapshot()

	s.fqdnMu.Lock()
	defer s.fqdnMu.Unlock()
	if s.fqdnPushed == nil {
		s.fqdnPushed = map[string][]net.IP{}
	}
	// Names present now: push when their set changed.
	for name, ips := range snap {
		if ipsEqual(s.fqdnPushed[name], ips) {
			continue
		}
		if err := s.client.setFqdnIPs(name, ips); err != nil {
			// Warn, not Debug: a failed push means dp is enforcing a stale
			// (or empty) IP set for an allowed FQDN — egress that should be
			// permitted gets dropped, silently, until the next reconcile
			// retries. Surface it at prod log levels.
			s.logger.Warn("fqdn: set dp mapping failed", "fqdn", name, "err", err)
			continue
		}
		s.fqdnPushed[name] = ips
	}
	// Names that disappeared: clear their dp mapping.
	for name := range s.fqdnPushed {
		if _, ok := snap[name]; ok {
			continue
		}
		if err := s.client.setFqdnIPs(name, nil); err != nil {
			// Warn, not Debug: a failed clear leaves dp allowing IPs for a
			// name no rule references anymore — a silent over-permit that
			// persists until the next reconcile retries.
			s.logger.Warn("fqdn: clear dp mapping failed", "fqdn", name, "err", err)
			continue
		}
		delete(s.fqdnPushed, name)
	}
}

// fqdnExpireLoop drives TTL eviction on a fixed cadence and reconciles the
// shrunken IP sets into dp. Runs until ctx is canceled.
func (s *Supervisor) fqdnExpireLoop(ctx context.Context) {
	interval := s.opt.FqdnExpireInterval
	if interval <= 0 {
		interval = defaultFqdnExpireInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.fqdn.Expire(now)
			s.reconcileFqdn()
		}
	}
}

// FqdnAllowSet returns the de-duplicated union of every FQDN-anchored rule
// across `policies`. The agent's policy layer feeds this to SetAllowedFqdns so
// the resolver only learns IPs for names some active rule references — an
// unrelated DNS lookup never reaches dp's FQDN table.
func FqdnAllowSet(policies ...*WorkloadPolicy) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, p := range policies {
		if p == nil {
			continue
		}
		for _, r := range p.Rules {
			if r == nil || r.Fqdn == "" {
				continue
			}
			if _, ok := seen[r.Fqdn]; ok {
				continue
			}
			seen[r.Fqdn] = struct{}{}
			out = append(out, r.Fqdn)
		}
	}
	return out
}

// ipsEqual reports whether two sorted IP slices are identical. Snapshot()
// returns sorted slices, so a positional compare suffices.
func ipsEqual(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !a[i].Equal(b[i]) {
			return false
		}
	}
	return true
}
