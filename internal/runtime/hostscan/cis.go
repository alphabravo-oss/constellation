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
	"bufio"
	"errors"
	"fmt"
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

// checkModuleDisabled returns pass if modprobe.d says "install <mod>
// /bin/true" or the module isn't on disk. fail if the .ko file is on
// disk and there's no modprobe block.
func checkModuleDisabled(hostRoot, name string) (string, string) {
	// Look under /lib/modules/$release/ for the module file.
	rel, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "skip", "no /proc/sys/kernel/osrelease"
	}
	release := strings.TrimSpace(string(rel))
	modDir := filepath.Join(hostRoot, "/lib/modules", release)
	found := false
	_ = filepath.Walk(modDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		base := info.Name()
		if strings.HasPrefix(base, name+".") &&
			(strings.Contains(base, ".ko")) {
			found = true
			return errors.New("stop")
		}
		return nil
	})
	if !found {
		return "pass", "module " + name + " not present on disk"
	}
	// Module present — check modprobe.d for a disable directive.
	for _, dir := range []string{
		filepath.Join(hostRoot, "/etc/modprobe.d"),
		filepath.Join(hostRoot, "/lib/modprobe.d"),
		filepath.Join(hostRoot, "/usr/lib/modprobe.d"),
	} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			content := string(b)
			needle1 := "install " + name + " /bin/true"
			needle2 := "blacklist " + name
			if strings.Contains(content, needle1) || strings.Contains(content, needle2) {
				return "pass", "disabled via " + dir + "/" + e.Name()
			}
		}
	}
	return "warn", "module " + name + " on disk and not blacklisted"
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

// checkSSHDOption parses /etc/ssh/sshd_config and matches the named
// option's value against any of the acceptable values. If the option
// is absent, returns warn (defaults vary). If the file is missing,
// returns skip.
func checkSSHDOption(hostRoot, option string, acceptable ...string) (string, string) {
	p := filepath.Join(hostRoot, "/etc/ssh/sshd_config")
	f, err := os.Open(p)
	if err != nil {
		return "skip", err.Error()
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if !strings.EqualFold(fields[0], option) {
			continue
		}
		value := fields[1]
		for _, a := range acceptable {
			if strings.EqualFold(value, a) {
				return "pass", option + "=" + value
			}
		}
		return "fail", fmt.Sprintf("%s=%s (want one of %v)", option, value, acceptable)
	}
	return "warn", option + " not set in sshd_config (default applies)"
}
