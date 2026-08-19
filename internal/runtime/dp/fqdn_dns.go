// Task F1b: glue from the L7 DNS parser to the FQDN resolver.
//
// internal/runtime/dpi/dns.go decodes DNS responses (question + A/AAAA/CNAME
// answers). This adapter collects the answer IPs of a response and feeds them
// to the resolver under the query name, so an allowed FQDN's live IP set
// tracks what the workload actually resolved. Kept separate from fqdn.go so the
// resolver core carries no dpi dependency.
package dp

import (
	"net"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
)

// FeedDNSResponse extracts the A/AAAA answers from a parsed DNS response and
// records them against the response's query name. Returns the storage-update
// messages emitted (nil when evt is not a response, has no query name, or the
// name is not in the allow-set). CNAME-only / non-IP answers are ignored.
//
// Only A/AAAA records whose owner name is reachable from QName via the
// response's CNAME chain are learned. An off-path or compromised resolver can
// still answer for a name, but it can no longer smuggle arbitrary attacker IPs
// in under unrelated owner names alongside an allowed QName.
func (r *FqdnResolver) FeedDNSResponse(evt *dpi.DNSEvent, now time.Time) []IPFqdnStorageMsg {
	if evt == nil || !evt.Response || evt.QName == "" || len(evt.Answers) == 0 {
		return nil
	}
	valid := validOwnerNames(evt.QName, evt.Answers)
	ips := make([]ResolvedIP, 0, len(evt.Answers))
	for _, a := range evt.Answers {
		if !a.IP.IsValid() {
			continue
		}
		if !valid[normalizeFqdn(a.Name)] {
			continue // owner name not anchored to QName via the CNAME chain
		}
		ips = append(ips, ResolvedIP{IP: net.IP(a.IP.AsSlice()), TTL: a.TTL})
	}
	if len(ips) == 0 {
		return nil
	}
	return r.Observe(evt.QName, ips, now)
}

// validOwnerNames returns the set of owner names reachable from qname by
// following the response's CNAME chain (qname → CNAME target → ...). A/AAAA
// records are only trusted when their owner name is in this set. The chain is
// resolved to a fixed point so out-of-order CNAME records still link up.
func validOwnerNames(qname string, answers []dpi.DNSAnswer) map[string]bool {
	valid := map[string]bool{normalizeFqdn(qname): true}
	for added := true; added; {
		added = false
		for _, a := range answers {
			if a.Type != 5 || a.CNAME == "" { // 5 = CNAME
				continue
			}
			owner := normalizeFqdn(a.Name)
			target := normalizeFqdn(a.CNAME)
			if valid[owner] && !valid[target] {
				valid[target] = true
				added = true
			}
		}
	}
	return valid
}
