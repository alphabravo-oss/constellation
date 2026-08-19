// NET-3: Hubble ingest source for Cilium-eBPF clusters.
//
// On Cilium clusters the NeuVector dp / iptables-NFQUEUE datapath is
// structurally blind: Cilium's eBPF policy plane bypasses iptables entirely
// (internal/runtime/dp/cnidetect.go SafeForNFQUEUE()==false for cilium), so
// the agent's tap-based flow capture sees nothing. Cilium itself already
// observes every flow and exposes them via the Hubble relay observer API
// (github.com/cilium/cilium/api/v1/observer over gRPC). This file bridges
// that stream into the existing /api/v1/network-flows:bulk pipeline.
//
// Three pieces live here:
//
//  1. hubbleFlow — a minimal, dependency-free mirror of the fields we read
//     out of a cilium observer.Flow (source/destination identity, L4
//     port/proto, verdict, bytes). The real gRPC client populates this from
//     the wire type; the converter is unit-tested against it directly.
//
//  2. hubbleToFlowIngest — the pure converter: hubbleFlow -> flowIngestRow,
//     the same wire shape dpConnToFlowIngest produces (source="hubble").
//
//  3. hubbleObserver / hubbleStreamLoop — the integration seam. A small
//     client interface plus the stream->convert->upload loop, gated on
//     "Cilium detected AND a relay address configured". The real gRPC client
//     is a HEAVY dependency (pulls cilium's k8s API surface) and is NOT wired
//     here — see the DEPENDENCY CEILING note on hubbleObserver.
package main

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// hubbleFlow is the subset of a cilium observer.Flow we need to build a
// network_flows row. Field names mirror the protobuf message so the eventual
// gRPC client is a straight field copy.
//
// ponytail: this is a hand-rolled mirror of observer.Flow rather than the real
// generated type — ceiling: it tracks only the fields the converter reads
// (identity, L4, verdict, bytes). Upgrade path: when the cilium observer dep
// is added (see hubbleObserver), populate this from the wire Flow, or convert
// directly off the wire type and delete this struct.
type hubbleFlow struct {
	// Source / destination workload identity. Cilium's flow carries an
	// Endpoint{Namespace, PodName} for in-cluster peers and only an IP for
	// world/external peers; we accept both and let classify* decide the label.
	SrcNamespace string
	SrcPodName   string
	SrcIP        string
	DstNamespace string
	DstPodName   string
	DstIP        string

	// DstNames mirrors observer.Flow.destination_names (proto field 25): the
	// DNS names Cilium's FQDN cache associates with the destination IP, i.e.
	// the name(s) the source looked up before connecting. We anchor an
	// egress-to-external allow rule on the first one (F1). Empty for in-cluster
	// peers and for flows where Cilium observed no prior DNS lookup.
	DstNames []string

	// L4. Protocol is "TCP"/"UDP"/"ICMPv4"/"ICMPv6" (observer.Flow.l4); Port
	// is the destination port. SrcPort is the ephemeral source port.
	Protocol string
	SrcPort  int
	DstPort  int

	// Verdict is observer.Flow.verdict — "FORWARDED" (allow) or "DROPPED".
	Verdict string

	// Bytes, when present. Hubble flows from the L7/observer path can carry a
	// byte count; the L3/L4 datapath path often does not, in which case this
	// is 0 and the row lands with bytes unset (NULL), exactly like a legacy
	// bpf row.
	Bytes int64

	// Time is observer.Flow.time. Zero -> converter substitutes now().
	Time time.Time
}

// hubbleToFlowIngest converts a single Hubble observer flow into the
// flowIngestRow wire shape (source="hubble"). Pure function — no I/O — so it
// is fully unit-testable. `node` is the agent's CONSTELLATION_NODE_NAME, used
// only as a last-resort identity for peers with neither a name nor an IP.
//
// Identity rules mirror dp_flow.go's classifyPeer so the Network Map renders
// hubble flows the same as dp flows:
//   - In-cluster endpoint (namespace+pod known)  -> "<ns>/<pod>"
//   - Private/loopback IP only                    -> "cluster/<ip>" (server
//     resolves to <ns>/<deployment> via pod_ips)
//   - Any other IP                                -> "external/<ip>" (server
//     collapses to "external")
//   - Nothing at all                              -> "node/<name>"
func hubbleToFlowIngest(f hubbleFlow, node string) flowIngestRow {
	row := flowIngestRow{
		Protocol:    hubbleProtoToString(f.Protocol),
		Verdict:     hubbleVerdict(f.Verdict),
		SrcWorkload: hubbleWorkload(f.SrcNamespace, f.SrcPodName, f.SrcIP, node),
		DstWorkload: hubbleWorkload(f.DstNamespace, f.DstPodName, f.DstIP, node),
		SrcAddr:     f.SrcIP,
		DstAddr:     f.DstIP,
		SrcPort:     f.SrcPort,
		DstPort:     f.DstPort,
		Bytes:       f.Bytes,
		Source:      "hubble",
		At:          f.Time,
	}
	if row.At.IsZero() {
		row.At = time.Now().UTC()
	}
	// PolicyAction mirrors verdict so callers can filter by either, matching
	// the dp converter's contract.
	row.PolicyAction = row.Verdict

	// F1: anchor the egress allow rule on the destination DNS name, but ONLY
	// for egress to an EXTERNAL peer. hubbleWorkload labels external peers
	// "external/<ip>"; in-cluster peers ("<ns>/<pod>", "cluster/<ip>") and the
	// node-local fallback never carry an FQDN. This is a property of the
	// destination side only, so it can never be set on an ingress edge.
	if strings.HasPrefix(row.DstWorkload, "external/") {
		for _, name := range f.DstNames {
			if name = strings.TrimSpace(name); name != "" {
				row.Fqdn = name
				break
			}
		}
	}
	return row
}

// hubbleWorkload builds the stable workload label for one side of a flow.
func hubbleWorkload(ns, pod, ip, node string) string {
	if ns != "" && pod != "" {
		return ns + "/" + pod
	}
	if ip != "" {
		if addr, err := netip.ParseAddr(ip); err == nil && addr.IsValid() {
			if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
				return "cluster/" + ip
			}
			return "external/" + ip
		}
	}
	return "node/" + node
}

// hubbleProtoToString lowercases Cilium's L4 protocol name into the canonical
// labels the ingest handler and Network Map expect.
func hubbleProtoToString(p string) string {
	switch strings.ToUpper(strings.TrimSpace(p)) {
	case "TCP":
		return "tcp"
	case "UDP":
		return "udp"
	case "ICMPV4", "ICMP":
		return "icmp"
	case "ICMPV6":
		return "icmpv6"
	case "SCTP":
		return "sctp"
	case "":
		return ""
	default:
		return strings.ToLower(strings.TrimSpace(p))
	}
}

// hubbleVerdict maps Cilium's verdict enum names to Constellation's lowercase
// verdict labels. Anything other than an explicit drop is treated as allow —
// matching how the ingest handler defaults an empty verdict.
func hubbleVerdict(v string) string {
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DROPPED", "DROP":
		return "deny"
	case "ERROR":
		return "deny"
	case "FORWARDED", "TRANSLATED", "REDIRECTED", "":
		return "allow"
	default:
		return "allow"
	}
}

// ---------------------------------------------------------------------------
// Integration seam (Part 3)
//
// hubbleObserver is the minimal client surface hubbleStreamLoop needs. The
// real implementation dials the Hubble relay's observer gRPC API
// (github.com/cilium/cilium/api/v1/observer:ObserverClient.GetFlows) and
// translates each observer.Flow into a hubbleFlow.
//
// DEPENDENCY CEILING: the cilium observer client is a HEAVY dependency — it
// pulls cilium's full api/v1 + k8s client surface and risks conflicting with
// this repo's pinned k8s.io/* versions. Per the work item it is NOT vendored
// here. The converter + ingest above are complete and tested; the live
// "dial Hubble relay over gRPC + Cilium-cluster e2e" piece is the remaining
// work. To wire it: implement hubbleObserver against observer.ObserverClient,
// run `go mod tidy`, and confirm `go build ./...` stays green before keeping
// the dep.
type hubbleObserver interface {
	// Flows streams converted flows on the returned channel until ctx is
	// cancelled or the stream errors. The channel is closed on return.
	Flows(ctx context.Context) (<-chan hubbleFlow, error)
}

// hubbleStreamConfig holds the runtime gate for the Hubble lane.
type hubbleStreamConfig struct {
	// Enabled is the result of the "Cilium detected AND relay addr set" gate,
	// computed by hubbleEnabled below.
	Enabled bool
	// RelayAddr is the Hubble relay address (host:port), from
	// CONSTELLATION_HUBBLE_RELAY_ADDR. Empty disables the lane.
	RelayAddr string
}

// hubbleEnabled is the gate the agent applies before starting the Hubble lane:
// the lane runs only when the detected CNI is Cilium (where dp is blind) AND a
// relay address is configured. cniName comes from dp.DetectCNI(...).Name.
func hubbleEnabled(cniName, relayAddr string) hubbleStreamConfig {
	cfg := hubbleStreamConfig{RelayAddr: strings.TrimSpace(relayAddr)}
	cfg.Enabled = cfg.RelayAddr != "" && strings.EqualFold(cniName, "cilium")
	return cfg
}

// hubbleStreamLoop streams flows from obs through the converter and onto the
// existing flow-upload channel (flowOut), which flowUploadLoop drains to
// /api/v1/network-flows:bulk. Mirrors the dp lane's "convert then non-blocking
// send, count drops" pattern. Returns when ctx is cancelled.
//
// This is the seam exercised by the real client once it lands; with the
// converter and channel wiring done, the only remaining piece is a concrete
// hubbleObserver.
func hubbleStreamLoop(
	ctx context.Context,
	logger *slog.Logger,
	obs hubbleObserver,
	node string,
	flowOut chan<- flowIngestRow,
	uploaded, dropped *atomic.Uint64,
) {
	for {
		if ctx.Err() != nil {
			return
		}
		flows, err := obs.Flows(ctx)
		if err != nil {
			logger.Warn("hubble: observer stream failed; retrying",
				slog.String("err", err.Error()))
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}
		for f := range flows {
			row := hubbleToFlowIngest(f, node)
			select {
			case flowOut <- row:
				uploaded.Add(1)
			default:
				dropped.Add(1)
			}
		}
		// Stream ended (relay restart / EOF); loop and re-dial unless cancelled.
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
