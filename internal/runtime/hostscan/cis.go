// Host CIS benchmark runner (Slice E). A minimal in-tree set of
// CIS-style host checks that the runtime-agent runs periodically and
// POSTs to /api/v1/host-cis:report.
//
// We deliberately did NOT vendor NeuVector's agent/nvbench/*.tmpl
// shell templates: they're shell-script driven, need bash + lots of
// utilities, and tightly couple to NeuVector's report format. The
// checks here are native Go, no shell-out, and use stdlib only. The
// set is small but high-signal — exactly what an operator needs to
// flag a node as misconfigured against the CIS Distribution-Independent
// Linux Benchmark.
//
// Each check has:
//   - ID         e.g. "1.1.1.1" — maps to CIS section numbering
//   - Title      short human-readable name
//   - Result     pass | fail | warn | skip
//   - Detail     optional extra info shown in the UI
//
// Adding a check: append a CISCheck literal to defaultChecks (or
// inject via Options.Checks for tests).
package hostscan

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CISCheckResult is one finding row.
type CISCheckResult struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Result string `json:"result"` // pass | fail | warn | skip
	Detail string `json:"detail,omitempty"`
}

// CISReport is the wire shape POSTed by the agent.
type CISReport struct {
	Node       string           `json:"node"`
	ObservedAt time.Time        `json:"observed_at"`
	Profile    string           `json:"profile,omitempty"` // e.g. "cis-distro-linux-2.0.0"
	Passed     int              `json:"passed"`
	Failed     int              `json:"failed"`
	Warned     int              `json:"warned"`
	Skipped    int              `json:"skipped"`
	Checks     []CISCheckResult `json:"checks"`
}

// CISOptions controls the run.
type CISOptions struct {
	HostRoot string
	NodeName string
	Profile  string // defaults to "cis-distro-linux-min"
	Checks   []CISCheck
}

// CISCheck is one check definition.
type CISCheck struct {
	ID    string
	Title string
	// Run executes the check and returns (result, detail).
	Run func(hostRoot string) (string, string)
}

// RunCIS executes every configured check and returns a CISReport.
// Never returns an error: skipped checks for missing files are still
// runnable (they just emit result="skip").
func RunCIS(opts CISOptions) CISReport {
	if opts.Profile == "" {
		opts.Profile = "cis-distro-linux-min"
	}
	checks := opts.Checks
	if checks == nil {
		checks = defaultCISChecks()
	}
	r := CISReport{
		Node:       opts.NodeName,
		ObservedAt: time.Now().UTC(),
		Profile:    opts.Profile,
	}
	if r.Node == "" {
		if h, _ := os.Hostname(); h != "" {
			r.Node = h
		}
	}
	for _, c := range checks {
		result, detail := c.Run(opts.HostRoot)
		r.Checks = append(r.Checks, CISCheckResult{
			ID:     c.ID,
			Title:  c.Title,
			Result: result,
			Detail: detail,
		})
		switch result {
		case "pass":
			r.Passed++
		case "fail":
			r.Failed++
		case "warn":
			r.Warned++
		default:
			r.Skipped++
		}
	}
	return r
}

// defaultCISChecks is the in-tree minimum benchmark. Numbering loosely
// matches CIS Distribution-Independent Linux 2.0.0 sections.
func defaultCISChecks() []CISCheck {
	return []CISCheck{
		// 1.1 — filesystem configuration.
		{
			ID:    "1.1.1",
			Title: "Disable unused filesystems (cramfs)",
			Run: func(root string) (string, string) {
				return checkModuleDisabled(root, "cramfs")
			},
		},
		{
			ID:    "1.1.2",
			Title: "Disable unused filesystems (squashfs)",
			Run: func(root string) (string, string) {
				return checkModuleDisabled(root, "squashfs")
			},
		},

		// 3.x — network parameters.
		{
			ID:    "3.2.1",
			Title: "Source routed packets are not accepted (net.ipv4.conf.all.accept_source_route=0)",
			Run: func(root string) (string, string) {
				return checkSysctl(root, "net/ipv4/conf/all/accept_source_route", "0")
			},
		},
		{
			ID:    "3.2.2",
			Title: "ICMP redirects are not accepted (net.ipv4.conf.all.accept_redirects=0)",
			Run: func(root string) (string, string) {
				return checkSysctl(root, "net/ipv4/conf/all/accept_redirects", "0")
			},
		},
		{
			ID:    "3.2.3",
			Title: "IP forwarding policy is intentional",
			Run: func(root string) (string, string) {
				// On k8s nodes ip_forward MUST be 1 — flagging it as
				// fail would be a false positive on every cluster.
				// We just record the setting and emit warn so the UI
				// can show what it is.
				v, err := readSysctl(root, "net/ipv4/ip_forward")
				if err != nil {
					return "skip", err.Error()
				}
				return "warn", "net.ipv4.ip_forward=" + v
			},
		},
		{
			ID:    "3.3.1",
			Title: "TCP SYN cookies are enabled (net.ipv4.tcp_syncookies=1)",
			Run: func(root string) (string, string) {
				return checkSysctl(root, "net/ipv4/tcp_syncookies", "1")
			},
		},

		// 5.x — access, authentication, audit.
		{
			ID:    "5.1.2",
			Title: "Permissions on /etc/passwd are 0644 or stricter",
			Run: func(root string) (string, string) {
				return checkFileModeMax(root, "/etc/passwd", 0o644)
			},
		},
		{
			ID:    "5.1.3",
			Title: "Permissions on /etc/shadow are 0640 or stricter",
			Run: func(root string) (string, string) {
				return checkFileModeMax(root, "/etc/shadow", 0o640)
			},
		},
		{
			ID:    "5.2.5",
			Title: "SSH PermitRootLogin is disabled (or 'prohibit-password')",
			Run: func(root string) (string, string) {
				return checkSSHDOption(root, "PermitRootLogin", "no", "prohibit-password")
			},
		},
		{
			ID:    "5.2.10",
			Title: "SSH PasswordAuthentication is disabled",
			Run: func(root string) (string, string) {
				return checkSSHDOption(root, "PasswordAuthentication", "no")
			},
		},

		// 6.x — system maintenance.
		{
			ID:    "6.1.2",
			Title: "Permissions on /etc/ssh/sshd_config are 0600 or stricter",
			Run: func(root string) (string, string) {
				return checkFileModeMax(root, "/etc/ssh/sshd_config", 0o600)
			},
		},
	}
}

// ---------------------------------------------------------------------------
// Check helpers
// ---------------------------------------------------------------------------

// checkSysctl compares /proc/sys/<path> against want.
func checkSysctl(hostRoot, path, want string) (string, string) {
	v, err := readSysctl(hostRoot, path)
	if err != nil {
		return "skip", err.Error()
	}
	if v == want {
		return "pass", path + "=" + v
	}
	return "fail", path + "=" + v + " (want " + want + ")"
}

func readSysctl(hostRoot, path string) (string, error) {
	// /proc is at natural path in the agent container (hostPID); no
	// HostRoot prefix needed. See hostscan/facts.go docs.
	_ = hostRoot
	b, err := os.ReadFile(filepath.Join("/proc/sys", path))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// checkModuleDisabled reports bounded observed module state. Configuration text
// alone cannot prove that a module is disabled or cannot be explicitly loaded.
func checkModuleDisabled(hostRoot, name string) (string, string) {
	proc, err := os.OpenRoot("/proc")
	if err != nil {
		return "skip", "kernel module evidence unavailable"
	}
	if hostRoot == "" {
		hostRoot = "/"
	}
	host, hostErr := os.OpenRoot(hostRoot)
	var hostFS fs.FS
	if hostErr == nil {
		hostFS = host.FS()
	}
	result, detail := checkModuleEvidence(proc.FS(), hostFS, name)
	closeErr := proc.Close()
	if host != nil {
		closeErr = errors.Join(closeErr, host.Close())
	}
	if closeErr != nil && result != "fail" {
		return "skip", "kernel module evidence could not be completed"
	}
	return result, detail
}

// checkFileModeMax returns pass if the file's permission bits are a
// subset of maxMode — i.e. the file grants no permission bit outside
// the allowed mask. fail otherwise. skip if not present.
//
// This is a subset test, NOT a numeric magnitude test. A magnitude
// comparison (mode <= maxMode) is wrong for permissions: e.g. /etc/shadow
// at 0604 (world-READABLE) is numerically 388 <= 416 (0640) and would
// "pass" while world-readable. `mode &^ maxMode.Perm()` isolates any bit
// set in mode but not permitted by maxMode; if that is non-zero the file
// is more permissive than allowed and must fail.
func checkFileModeMax(hostRoot, path string, maxMode os.FileMode) (string, string) {
	p := filepath.Join(hostRoot, path)
	st, err := os.Stat(p)
	if err != nil {
		return "skip", err.Error()
	}
	mode := st.Mode().Perm()
	if mode&^maxMode.Perm() == 0 {
		return "pass", fmt.Sprintf("mode=%#o", mode)
	}
	return "fail", fmt.Sprintf("mode=%#o (want subset of %#o)", mode, maxMode)
}

// checkSSHDOption supports plain configuration only. Conditional/include syntax
// requires review, and incomplete reads never establish a passing result.
func checkSSHDOption(hostRoot, option string, acceptable ...string) (string, string) {
	if hostRoot == "" {
		hostRoot = "/"
	}
	root, err := os.OpenRoot(hostRoot)
	if err != nil {
		return "skip", "SSH configuration unavailable"
	}
	input, openErr := root.Open("etc/ssh/sshd_config")
	if openErr != nil {
		if err := root.Close(); err != nil {
			return "skip", "SSH configuration could not be completed"
		}
		return "skip", "SSH configuration unavailable"
	}
	result, detail := checkSSHDReader(input, option, acceptable...)
	if err := root.Close(); err != nil {
		return "skip", "SSH configuration could not be completed"
	}
	return result, detail
}
