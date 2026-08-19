package main

import (
	"os/exec"
	"testing"
)

// TestValidateBPFFilter — the trust-boundary validator for operator BPF
// filters. Injection / shell-metacharacter attempts must be rejected by
// the pure-Go character allowlist (before tcpdump is ever exec'd); a
// normal expression must be accepted (dry-compiled by `tcpdump -d`).
func TestValidateBPFFilter(t *testing.T) {
	// Each contains a metacharacter rejected by isBPFRune, so these fail
	// without needing tcpdump present.
	reject := []string{
		"tcp port 443; rm -rf /",   // ';'
		"tcp or `id`",              // backtick
		"tcp port $(whoami)",       // '$'
		"tcp and host \"evil\"",    // '"'
		`tcp and host 'x'`,         // '\''
		"tcp \\ndrop",              // '\\'
		"tcp port 443\n rm x",      // newline
	}
	for _, f := range reject {
		if err := validateBPFFilter(f, ""); err == nil {
			t.Errorf("expected rejection of %q, got nil", f)
		}
	}

	// The accept path needs a real tcpdump to dry-compile the expression.
	if _, err := exec.LookPath("tcpdump"); err != nil {
		t.Skip("tcpdump not installed; skipping accept assertion")
	}
	if err := validateBPFFilter("tcp port 443", "tcpdump"); err != nil {
		t.Errorf("valid filter %q rejected: %v", "tcp port 443", err)
	}
	// Malformed-but-clean (passes char check, fails tcpdump parse).
	if err := validateBPFFilter("tcp porrt 443", "tcpdump"); err == nil {
		t.Errorf("expected tcpdump to reject malformed filter")
	}
}

// TestBuildBPFFilter — the 5-tuple → tcpdump-filter assembly. Most of the
// PCAP worker's behavior lives behind a tcpdump subprocess and an HTTP
// transport; the BPF-filter builder is the bit that's pure-go testable.
func TestBuildBPFFilter(t *testing.T) {
	cases := []struct {
		name string
		cap  pcapCaptureWire
		want string
	}{
		{
			name: "full 5-tuple TCP",
			cap:  pcapCaptureWire{SrcIP: "10.0.0.5", DstIP: "1.1.1.1", DstPort: 443, Protocol: "tcp"},
			want: "host 10.0.0.5 and host 1.1.1.1 and port 443 and tcp",
		},
		{
			name: "only dst port + tcp",
			cap:  pcapCaptureWire{DstPort: 8080, Protocol: "tcp"},
			want: "port 8080 and tcp",
		},
		{
			name: "udp dns",
			cap:  pcapCaptureWire{DstPort: 53, Protocol: "udp"},
			want: "port 53 and udp",
		},
		{
			name: "icmp only",
			cap:  pcapCaptureWire{Protocol: "icmp"},
			want: "icmp",
		},
		{
			name: "junk IPs ignored",
			cap:  pcapCaptureWire{SrcIP: "not-an-ip", DstIP: "8.8.8.8", DstPort: 53},
			want: "host 8.8.8.8 and port 53",
		},
		{
			name: "out-of-range port ignored",
			cap:  pcapCaptureWire{DstPort: 99999, Protocol: "tcp"},
			want: "tcp",
		},
		{
			name: "empty 5-tuple = no filter",
			cap:  pcapCaptureWire{},
			want: "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildBPFFilter(&c.cap)
			if got != c.want {
				t.Errorf("filter = %q want %q", got, c.want)
			}
		})
	}
}
