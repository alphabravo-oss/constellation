// NET-3 (concrete): the live Hubble relay gRPC client.
//
// hubble_flow.go defines the seam — hubbleObserver, the hubbleFlow mirror, the
// pure hubbleToFlowIngest converter and hubbleStreamLoop. This file supplies the
// one piece that was missing: a concrete hubbleObserver that dials the Cilium
// Hubble relay's observer API (github.com/cilium/cilium/api/v1/observer) over
// gRPC, follows the live flow stream, and maps each wire *flow.Flow into the
// dependency-free hubbleFlow the converter consumes.
//
// Split of responsibility for testability:
//   - flowToHubble(*flow.Flow) hubbleFlow is a PURE mapping and is unit-tested
//     directly (hubble_client_test.go) with hand-built protobuf messages.
//   - hubbleRelayClient.Flows does the I/O (dial + stream) and is exercised only
//     against a real relay (Cilium cluster), not in unit tests.
package main

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// hubbleRelayClient is the concrete hubbleObserver. It dials the Hubble relay
// and streams converted flows. One client per relay address; Flows may be
// called repeatedly (hubbleStreamLoop re-dials after a stream ends), each call
// opens its own connection + stream and tears them down on return.
type hubbleRelayClient struct {
	addr   string
	logger *slog.Logger
}

// newHubbleRelayClient constructs a hubbleObserver for the given relay address
// (host:port, from CONSTELLATION_HUBBLE_RELAY_ADDR).
func newHubbleRelayClient(addr string, logger *slog.Logger) *hubbleRelayClient {
	return &hubbleRelayClient{addr: addr, logger: logger}
}

// Flows dials the relay, opens a following GetFlows stream, and returns a
// channel of converted flows. The channel is closed (and the gRPC conn torn
// down) when ctx is cancelled or Recv returns an error/EOF. An error is
// returned only if the initial dial / GetFlows call fails — once the stream is
// established, transient Recv errors just close the channel and hubbleStreamLoop
// re-dials.
func (c *hubbleRelayClient) Flows(ctx context.Context) (<-chan hubbleFlow, error) {
	// ponytail: plaintext to the relay. Hubble relay is typically reached
	// in-cluster over a ClusterIP without TLS, so we dial insecure. Upgrade
	// path: gate on a CONSTELLATION_HUBBLE_RELAY_TLS env var and swap in
	// credentials.NewClientTLSFromFile / a tls.Config here when the relay is
	// configured with mTLS.
	conn, err := grpc.NewClient(c.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}

	client := observer.NewObserverClient(conn)
	// Follow=true streams live flows indefinitely. Number/Whitelist are left
	// unset: we want every flow the relay will give us (the converter + the
	// server-side ingest do the filtering/classification), and Number is
	// incompatible with a follow stream's "tail forever" semantics.
	stream, err := client.GetFlows(ctx, &observer.GetFlowsRequest{Follow: true})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	out := make(chan hubbleFlow, 256)
	go func() {
		defer close(out)
		defer conn.Close()
		for {
			resp, err := stream.Recv()
			if err != nil {
				// ctx cancellation surfaces here as a status error too; in all
				// cases we stop and let hubbleStreamLoop decide whether to
				// re-dial (it checks ctx).
				if ctx.Err() == nil {
					c.logger.Warn("hubble: relay stream recv ended",
						slog.String("err", err.Error()))
				}
				return
			}
			f := resp.GetFlow()
			if f == nil {
				// Non-flow responses (NodeStatus, LostEvents) carry no flow.
				continue
			}
			select {
			case out <- flowToHubble(f):
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}

// flowToHubble maps a wire *flow.Flow into the dependency-free hubbleFlow the
// converter consumes. Pure — no I/O — so it is the unit-tested half of this
// file. All accesses go through the generated nil-safe getters, so a sparse
// flow (e.g. world peer with IP but no endpoint, or no L4) yields zero-valued
// fields rather than panicking.
func flowToHubble(f *flow.Flow) hubbleFlow {
	if f == nil {
		return hubbleFlow{}
	}

	hf := hubbleFlow{
		// Identity: Endpoint{Namespace, PodName} is present for in-cluster
		// peers and empty for world/external peers (IP only).
		SrcNamespace: f.GetSource().GetNamespace(),
		SrcPodName:   f.GetSource().GetPodName(),
		DstNamespace: f.GetDestination().GetNamespace(),
		DstPodName:   f.GetDestination().GetPodName(),

		// L3 addresses.
		SrcIP: f.GetIP().GetSource(),
		DstIP: f.GetIP().GetDestination(),

		// destination_names (field 25): the DNS names Cilium's FQDN cache knows
		// the destination IP by. Carried straight through; the converter anchors
		// an egress-to-external allow rule on the first one (F1).
		DstNames: f.GetDestinationNames(),

		// Verdict enum name ("FORWARDED"/"DROPPED"/...) — hubbleVerdict maps it.
		Verdict: f.GetVerdict().String(),
	}

	// L4: exactly one of TCP/UDP/ICMPv4/ICMPv6 is set (a protobuf oneof).
	if l4 := f.GetL4(); l4 != nil {
		switch {
		case l4.GetTCP() != nil:
			hf.Protocol = "TCP"
			hf.SrcPort = int(l4.GetTCP().GetSourcePort())
			hf.DstPort = int(l4.GetTCP().GetDestinationPort())
		case l4.GetUDP() != nil:
			hf.Protocol = "UDP"
			hf.SrcPort = int(l4.GetUDP().GetSourcePort())
			hf.DstPort = int(l4.GetUDP().GetDestinationPort())
		case l4.GetICMPv4() != nil:
			hf.Protocol = "ICMPv4"
		case l4.GetICMPv6() != nil:
			hf.Protocol = "ICMPv6"
		case l4.GetSCTP() != nil:
			hf.Protocol = "SCTP"
			hf.SrcPort = int(l4.GetSCTP().GetSourcePort())
			hf.DstPort = int(l4.GetSCTP().GetDestinationPort())
		}
	}

	// Time: protobuf Timestamp -> time.Time, guarding nil (GetTime() may be nil
	// on synthetic/sparse flows). Zero time -> converter substitutes now().
	if ts := f.GetTime(); ts != nil {
		hf.Time = ts.AsTime()
	}

	// Bytes: L3/L4 Hubble flows carry no byte count (only the L7/observer path
	// does, and not in flow.Flow's top-level fields), so this stays 0 and the
	// row lands with bytes unset — exactly like a legacy bpf row.

	return hf
}
