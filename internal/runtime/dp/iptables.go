// Wave A3: iptables rule installer for NFQUEUE enforcement.
//
// When a host-side veth needs inline enforcement, we install one PREROUTING
// rule (ingress to the pod) and one POSTROUTING rule (egress from the pod)
// in the mangle table that redirects all traffic to the pod's assigned
// NFQUEUE. dp owns the queue; its verdict (ACCEPT or DROP) is what the
// kernel applies to each packet.
//
// The critical `--queue-bypass` flag means: if no userspace process is
// listening on the queue (dp died, dp is restarting, OS rebooted with
// our DaemonSet not yet scheduled), the kernel falls back to ACCEPT.
// Without this flag a dead dp would silently break every pod's networking.
//
// The runner abstraction (iptRunner) is faked in tests; production uses
// the real iptables binary in the runtime image (deploy/docker/
// Dockerfile.runtime-agent installs iptables in stage 4).
package dp

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// iptRunner is the small surface enforceManager needs. We split it out so
// tests can substitute a recording fake.
type iptRunner interface {
	// Run executes iptables with the given args; returns combined stdout/stderr
	// and the exit status as a Go error. The actual binary varies per CNI
	// (eg. iptables-legacy vs iptables-nft); the runner chooses at startup.
	//
	// netns is the network namespace to run in (e.g. /proc/<pid>/ns/net). It
	// MUST be the pod's netns: dp binds the NFQUEUE inside that netns (dp_data_add_nfq
	// enters it), and nf_queue is netns-scoped — a rule installed in the host root
	// netns queues to a handler that doesn't exist there, so the pod's packets are
	// never delivered to dp. Empty netns runs in the caller's current netns.
	Run(ctx context.Context, netns string, args ...string) (string, error)
}

// execIPTRunner is the production runner: shells out to /sbin/iptables (or
// /usr/sbin/iptables) via os/exec. The runtime image's PATH is set so
// "iptables" resolves correctly. When netns is set it wraps the call in
// `nsenter --net=<netns>` so the rule lands in the pod's netns (where dp
// bound the queue), not the agent's host netns.
type execIPTRunner struct{}

func (execIPTRunner) Run(ctx context.Context, netns string, args ...string) (string, error) {
	name, full := "iptables", args
	if netns != "" {
		name = "nsenter"
		full = append([]string{"--net=" + netns, "iptables"}, args...)
	}
	cmd := exec.CommandContext(ctx, name, full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w (output: %s)",
			name, strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ipt is the iptables binding the enforceManager uses. Each call shells out;
// we don't batch via iptables-restore today (would speed up bulk reconcile
// but adds parsing complexity — defer if observed in profiles).
type ipt struct {
	runner iptRunner
	chain  string // jump-target chain; "" → install directly to PREROUTING/POSTROUTING
}

// newIPT — production binding.
func newIPT() *ipt {
	return &ipt{runner: execIPTRunner{}, chain: ""}
}

// addRedirect installs the per-veth pair of NFQUEUE rules. Returns nil on
// success or already-exists (we use -C first to check; -I if missing). The
// "queue-bypass" flag means: if userspace isn't listening, ACCEPT.
//
// The rules go in the POD's netns (netns arg) on the pod-side iface (eth0),
// because dp binds the NFQUEUE inside that same netns (AddNfqPort → dp_data_add_nfq
// enters it) and nf_queue is netns-scoped. Direction convention there:
// PREROUTING `-i eth0` catches the pod's INGRESS (client→pod requests — what
// WAF inspects); POSTROUTING `-o eth0` catches the pod's EGRESS.
//
// dp tags each NFQUEUE packet with the workload's EPMAC (passed via
// AddNfqPort) so its policy engine matches the right rule table.
func (i *ipt) addRedirect(ctx context.Context, netns, iface string, qnum int) error {
	rules := i.redirectRules(iface, qnum)
	for _, r := range rules {
		// Check first (-C) so we don't double-insert on a tight reconcile loop.
		args := append([]string{"-t", "mangle", "-C"}, r...)
		if _, err := i.runner.Run(ctx, netns, args...); err == nil {
			continue // already present
		}
		args = append([]string{"-t", "mangle", "-I"}, r...)
		if _, err := i.runner.Run(ctx, netns, args...); err != nil {
			return err
		}
	}
	return nil
}

// removeRedirect undoes addRedirect. Idempotent — missing rules are OK.
func (i *ipt) removeRedirect(ctx context.Context, netns, iface string, qnum int) error {
	rules := i.redirectRules(iface, qnum)
	for _, r := range rules {
		args := append([]string{"-t", "mangle", "-D"}, r...)
		// Errors here mean "rule wasn't there" — log at debug elsewhere; not fatal.
		_, _ = i.runner.Run(ctx, netns, args...)
	}
	return nil
}

// redirectRules returns the two rule specs (PREROUTING + POSTROUTING)
// without the -C / -I / -D verb so addRedirect and removeRedirect can
// share the spec.
func (i *ipt) redirectRules(hostVeth string, qnum int) [][]string {
	qs := fmt.Sprintf("%d", qnum)
	// PREROUTING: catches packets arriving on the host stack from this veth.
	// POSTROUTING: catches packets about to be sent out via this veth.
	// `--queue-bypass` is the safety belt: if dp isn't listening, kernel ACCEPTs.
	return [][]string{
		{"PREROUTING", "-i", hostVeth, "-j", "NFQUEUE", "--queue-num", qs, "--queue-bypass"},
		{"POSTROUTING", "-o", hostVeth, "-j", "NFQUEUE", "--queue-num", qs, "--queue-bypass"},
	}
}
