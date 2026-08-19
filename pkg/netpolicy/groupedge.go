// P1-1: group→group rule model + expansion to member rules.
//
// Today a network rule is keyed to a single workload (ultimately a MAC on the
// datapath). That means a rule authored for "frontend may talk to backend on
// 5432" has to be restated for every replica, and it goes stale the moment a
// pod is added or removed. NeuVector solves this by letting a rule be an EDGE
// between two GROUPS (CLUSPolicyRule.From/To are group names); membership is
// resolved live and the rule applies to all current + future members.
//
// This file is the control-plane model + the pure expansion: a GroupEdge plus
// the two groups' current member lists fan out to a set of member-to-member
// Flows. Those Flows feed the existing BuildDPRules / GenerateNative path
// unchanged, so an edge becomes concrete per-workload allow rules without any
// new datapath primitive. Re-running expansion after a group-sync membership
// change is how "applies to future members" is honoured.
package netpolicy

import (
	"sort"
	"strings"
)

// PortSpec is one L4 opening on an edge. Port 0 means "any port" for that proto.
type PortSpec struct {
	Protocol string `json:"protocol"` // TCP | UDP | SCTP | ICMP
	Port     int    `json:"port"`
}

// GroupEdge is a rule authored as a directed edge between two groups: members of
// FromGroup may initiate to members of ToGroup on Ports. Mode mirrors the
// per-group triad (discover|monitor|protect); it defaults to monitor so a newly
// authored edge never blocks live traffic (see Validate).
type GroupEdge struct {
	ID        string     `json:"id,omitempty"`
	FromGroup string     `json:"from_group"`
	ToGroup   string     `json:"to_group"`
	Ports     []PortSpec `json:"ports"`
	Mode      string     `json:"mode,omitempty"`
	Comment   string     `json:"comment,omitempty"`
}

// Validate normalises and checks an edge. An empty mode defaults to monitor
// (never block by default). Ports may be empty, meaning "all ports".
func (e *GroupEdge) Validate() error {
	if strings.TrimSpace(e.FromGroup) == "" || strings.TrimSpace(e.ToGroup) == "" {
		return errBadEdge("from_group and to_group are required")
	}
	if e.Mode == "" {
		e.Mode = "monitor"
	}
	switch e.Mode {
	case "discover", "monitor", "protect":
	default:
		return errBadEdge("invalid mode " + e.Mode)
	}
	for i := range e.Ports {
		p := &e.Ports[i]
		p.Protocol = strings.ToUpper(strings.TrimSpace(p.Protocol))
		if p.Protocol == "" {
			p.Protocol = "TCP"
		}
		if p.Port < 0 || p.Port > 65535 {
			return errBadEdge("port out of range")
		}
	}
	return nil
}

type errBadEdge string

func (e errBadEdge) Error() string { return string(e) }

// ExpandEdge fans a GroupEdge out to member-to-member Flows: for every
// (fromMember, toMember, port) triple it emits one Flow with the fromMember as
// source and the toMember as destination. Members are "namespace/name"
// workload ids. The resulting Flows are exactly the shape BuildDPRules and the
// YAML generators already consume, so an edge reduces to the same per-workload
// allow rules an observed flow would produce — no new datapath concept.
//
// Self-pairs (a member appearing in both groups) are skipped: a workload does
// not need a policy rule to talk to itself. Output is sorted for a stable,
// reviewable expansion.
func ExpandEdge(e GroupEdge, fromMembers, toMembers []string) []Flow {
	ports := e.Ports
	if len(ports) == 0 {
		ports = []PortSpec{{Protocol: "TCP", Port: 0}}
	}
	out := make([]Flow, 0, len(fromMembers)*len(toMembers)*len(ports))
	for _, from := range fromMembers {
		from = strings.TrimSpace(from)
		if from == "" {
			continue
		}
		for _, to := range toMembers {
			to = strings.TrimSpace(to)
			if to == "" || to == from {
				continue
			}
			for _, p := range ports {
				proto := strings.ToUpper(strings.TrimSpace(p.Protocol))
				if proto == "" {
					proto = "TCP"
				}
				out = append(out, Flow{
					SrcWorkload:  from,
					SrcNamespace: namespaceOfID(from),
					DstWorkload:  to,
					DstNamespace: namespaceOfID(to),
					Protocol:     proto,
					Port:         p.Port,
					Count:        1,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SrcWorkload != out[j].SrcWorkload {
			return out[i].SrcWorkload < out[j].SrcWorkload
		}
		if out[i].DstWorkload != out[j].DstWorkload {
			return out[i].DstWorkload < out[j].DstWorkload
		}
		if out[i].Protocol != out[j].Protocol {
			return out[i].Protocol < out[j].Protocol
		}
		return out[i].Port < out[j].Port
	})
	return out
}

func namespaceOfID(id string) string {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i]
	}
	return ""
}
