package main

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestHubbleToFlowIngest covers NET-3 part 2: the pure Hubble observer.Flow ->
// flowIngestRow converter. It must produce correct rows for an ALLOW
// (FORWARDED) and a DROP (DROPPED) flow, map identity/proto/verdict, carry
// bytes when present, and always stamp source="hubble".
func TestHubbleToFlowIngest(t *testing.T) {
	at := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)

	t.Run("allow in-cluster pod-to-pod", func(t *testing.T) {
		row := hubbleToFlowIngest(hubbleFlow{
			SrcNamespace: "shop",
			SrcPodName:   "frontend-abc",
			SrcIP:        "10.42.0.5",
			DstNamespace: "shop",
			DstPodName:   "cart-xyz",
			DstIP:        "10.42.0.9",
			Protocol:     "TCP",
			SrcPort:      54321,
			DstPort:      8080,
			Verdict:      "FORWARDED",
			Bytes:        4096,
			Time:         at,
		}, "node-1")

		if row.Source != "hubble" {
			t.Errorf("source = %q want hubble", row.Source)
		}
		if row.SrcWorkload != "shop/frontend-abc" {
			t.Errorf("src_workload = %q want shop/frontend-abc", row.SrcWorkload)
		}
		if row.DstWorkload != "shop/cart-xyz" {
			t.Errorf("dst_workload = %q want shop/cart-xyz", row.DstWorkload)
		}
		if row.Protocol != "tcp" {
			t.Errorf("protocol = %q want tcp", row.Protocol)
		}
		if row.DstPort != 8080 || row.SrcPort != 54321 {
			t.Errorf("ports = (%d,%d) want (54321,8080)", row.SrcPort, row.DstPort)
		}
		if row.Verdict != "allow" {
			t.Errorf("verdict = %q want allow", row.Verdict)
		}
		if row.PolicyAction != "allow" {
			t.Errorf("policy_action = %q want allow", row.PolicyAction)
		}
		if row.Bytes != 4096 {
			t.Errorf("bytes = %d want 4096", row.Bytes)
		}
		if !row.At.Equal(at) {
			t.Errorf("at = %v want %v", row.At, at)
		}
	})

	t.Run("drop pod-to-external", func(t *testing.T) {
		row := hubbleToFlowIngest(hubbleFlow{
			SrcNamespace: "shop",
			SrcPodName:   "frontend-abc",
			SrcIP:        "10.42.0.5",
			// External peer: no namespace/pod, public IP only.
			DstIP:    "93.184.216.34",
			Protocol: "UDP",
			DstPort:  53,
			Verdict:  "DROPPED",
			// L3/L4 drop carries no byte count.
			Time: at,
		}, "node-1")

		if row.Source != "hubble" {
			t.Errorf("source = %q want hubble", row.Source)
		}
		if row.SrcWorkload != "shop/frontend-abc" {
			t.Errorf("src_workload = %q want shop/frontend-abc", row.SrcWorkload)
		}
		if row.DstWorkload != "external/93.184.216.34" {
			t.Errorf("dst_workload = %q want external/93.184.216.34", row.DstWorkload)
		}
		if row.Protocol != "udp" {
			t.Errorf("protocol = %q want udp", row.Protocol)
		}
		if row.Verdict != "deny" {
			t.Errorf("verdict = %q want deny", row.Verdict)
		}
		if row.Bytes != 0 {
			t.Errorf("bytes = %d want 0 (unset)", row.Bytes)
		}
	})

	t.Run("private-ip-only peer becomes cluster label", func(t *testing.T) {
		// No pod identity but a private IP -> "cluster/<ip>" so the server's
		// ipResolver can map it to <ns>/<deployment>.
		row := hubbleToFlowIngest(hubbleFlow{
			SrcIP:    "10.42.0.5",
			DstIP:    "10.43.0.10",
			Protocol: "TCP",
			DstPort:  443,
			Verdict:  "FORWARDED",
			Time:     at,
		}, "node-1")
		if row.SrcWorkload != "cluster/10.42.0.5" {
			t.Errorf("src_workload = %q want cluster/10.42.0.5", row.SrcWorkload)
		}
		if row.DstWorkload != "cluster/10.43.0.10" {
			t.Errorf("dst_workload = %q want cluster/10.43.0.10", row.DstWorkload)
		}
	})

	t.Run("zero time substitutes now", func(t *testing.T) {
		row := hubbleToFlowIngest(hubbleFlow{
			SrcNamespace: "a", SrcPodName: "b",
			DstNamespace: "c", DstPodName: "d",
			Protocol: "TCP", DstPort: 80, Verdict: "FORWARDED",
		}, "node-1")
		if row.At.IsZero() {
			t.Error("at should be substituted with now() when input is zero")
		}
	})
}

// TestHubbleEnabled covers the part-3 gate: the Hubble lane runs only when the
// CNI is Cilium AND a relay address is configured.
func TestHubbleEnabled(t *testing.T) {
	cases := []struct {
		cni, relay string
		want       bool
	}{
		{"cilium", "hubble-relay.kube-system:80", true},
		{"Cilium", "hubble-relay:80", true}, // case-insensitive CNI match
		{"cilium", "", false},               // no relay addr
		{"calico", "hubble-relay:80", false},// not cilium (dp is not blind)
		{"unknown", "", false},
	}
	for _, c := range cases {
		got := hubbleEnabled(c.cni, c.relay)
		if got.Enabled != c.want {
			t.Errorf("hubbleEnabled(%q,%q).Enabled = %v want %v", c.cni, c.relay, got.Enabled, c.want)
		}
	}
}

// fakeObserver is a one-shot hubbleObserver for exercising the stream seam.
type fakeObserver struct{ flows []hubbleFlow }

func (f *fakeObserver) Flows(ctx context.Context) (<-chan hubbleFlow, error) {
	ch := make(chan hubbleFlow, len(f.flows))
	for _, fl := range f.flows {
		ch <- fl
	}
	close(ch)
	return ch, nil
}

// TestHubbleStreamLoop confirms the seam converts streamed flows and pushes
// them onto the upload channel as hubble-sourced rows.
func TestHubbleStreamLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	obs := &fakeObserver{flows: []hubbleFlow{
		{SrcNamespace: "a", SrcPodName: "x", DstNamespace: "b", DstPodName: "y",
			Protocol: "TCP", DstPort: 80, Verdict: "FORWARDED"},
	}}
	flowOut := make(chan flowIngestRow, 4)
	var up, drop atomic.Uint64

	// Run one stream pass, then cancel so the re-dial loop exits.
	done := make(chan struct{})
	go func() {
		hubbleStreamLoop(ctx, discardLogger(), obs, "node-1", flowOut, &up, &drop)
		close(done)
	}()

	select {
	case row := <-flowOut:
		if row.Source != "hubble" || row.SrcWorkload != "a/x" {
			t.Errorf("unexpected row %+v", row)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no row produced by stream loop")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream loop did not exit after cancel")
	}
	if up.Load() < 1 {
		t.Errorf("uploaded = %d want >=1", up.Load())
	}
}
