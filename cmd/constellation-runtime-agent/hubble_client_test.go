package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/cilium/cilium/api/v1/flow"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestFlowToHubble_InClusterTCP covers the common case: an in-cluster
// pod-to-pod TCP flow that was forwarded. Both peers carry an Endpoint
// (namespace+pod) and an IP; L4 is TCP with source/destination ports.
func TestFlowToHubble_InClusterTCP(t *testing.T) {
	at := time.Date(2026, 6, 25, 12, 0, 0, 0, time.UTC)
	f := &flow.Flow{
		Time:    timestamppb.New(at),
		Verdict: flow.Verdict_FORWARDED,
		Source: &flow.Endpoint{
			Namespace: "shop",
			PodName:   "frontend-abc",
		},
		Destination: &flow.Endpoint{
			Namespace: "shop",
			PodName:   "cart-xyz",
		},
		IP: &flow.IP{
			Source:      "10.0.1.5",
			Destination: "10.0.2.9",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_TCP{
				TCP: &flow.TCP{
					SourcePort:      54321,
					DestinationPort: 8080,
				},
			},
		},
	}

	got := flowToHubble(f)

	want := hubbleFlow{
		SrcNamespace: "shop",
		SrcPodName:   "frontend-abc",
		SrcIP:        "10.0.1.5",
		DstNamespace: "shop",
		DstPodName:   "cart-xyz",
		DstIP:        "10.0.2.9",
		Protocol:     "TCP",
		SrcPort:      54321,
		DstPort:      8080,
		Verdict:      "FORWARDED",
		Bytes:        0,
		Time:         at,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("flowToHubble mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestFlowToHubble_WorldUDPDropped covers an external/world peer (IP only, no
// Endpoint) over UDP that was dropped. Namespace/PodName must come back empty
// so hubbleWorkload falls through to the IP-based label, and the verdict must
// surface as the DROPPED enum name.
func TestFlowToHubble_WorldUDPDropped(t *testing.T) {
	f := &flow.Flow{
		Verdict: flow.Verdict_DROPPED,
		// No Source/Destination Endpoint: world peers carry IP only.
		IP: &flow.IP{
			Source:      "10.0.3.4",
			Destination: "8.8.8.8",
		},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_UDP{
				UDP: &flow.UDP{
					SourcePort:      33333,
					DestinationPort: 53,
				},
			},
		},
	}

	got := flowToHubble(f)

	if got.SrcNamespace != "" || got.SrcPodName != "" ||
		got.DstNamespace != "" || got.DstPodName != "" {
		t.Errorf("expected no endpoint identity for world flow, got %+v", got)
	}
	if got.SrcIP != "10.0.3.4" || got.DstIP != "8.8.8.8" {
		t.Errorf("IP mismatch: src=%q dst=%q", got.SrcIP, got.DstIP)
	}
	if got.Protocol != "UDP" || got.SrcPort != 33333 || got.DstPort != 53 {
		t.Errorf("L4 mismatch: proto=%q src=%d dst=%d", got.Protocol, got.SrcPort, got.DstPort)
	}
	if got.Verdict != "DROPPED" {
		t.Errorf("verdict = %q, want DROPPED", got.Verdict)
	}
	// No Time set -> zero; the converter (hubbleToFlowIngest) substitutes now().
	if !got.Time.IsZero() {
		t.Errorf("expected zero Time for flow without timestamp, got %v", got.Time)
	}
}

// TestFlowToHubble_ICMPv4 confirms a connectionless L4 (ICMPv4) maps protocol
// but leaves ports at zero.
func TestFlowToHubble_ICMPv4(t *testing.T) {
	f := &flow.Flow{
		Verdict: flow.Verdict_FORWARDED,
		IP:      &flow.IP{Source: "10.0.0.1", Destination: "10.0.0.2"},
		L4: &flow.Layer4{
			Protocol: &flow.Layer4_ICMPv4{ICMPv4: &flow.ICMPv4{Type: 8}},
		},
	}

	got := flowToHubble(f)

	if got.Protocol != "ICMPv4" {
		t.Errorf("protocol = %q, want ICMPv4", got.Protocol)
	}
	if got.SrcPort != 0 || got.DstPort != 0 {
		t.Errorf("expected zero ports for ICMP, got src=%d dst=%d", got.SrcPort, got.DstPort)
	}
}

// TestFlowToHubble_Nil guards the nil-flow path.
func TestFlowToHubble_Nil(t *testing.T) {
	if got := flowToHubble(nil); !reflect.DeepEqual(got, hubbleFlow{}) {
		t.Errorf("flowToHubble(nil) = %+v, want zero value", got)
	}
}
