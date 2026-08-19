package hostscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCheckFileModeMax_SubsetNotMagnitude guards the H3 fix: file-permission
// checks must be a SUBSET test, not a numeric magnitude (mode <= max) test.
// The old code did `mode <= maxMode`, so e.g. /etc/shadow at 0604 (world
// READABLE, 0604=388) passed against 0640 (416) because 388 <= 416 — leaving
// password hashes world-readable while reporting CIS-compliant.
func TestCheckFileModeMax_SubsetNotMagnitude(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		maxMode os.FileMode
		mode    os.FileMode
		want    string
	}{
		// /etc/shadow must be 0640 or stricter.
		{"shadow 0640 exact", "/etc/shadow", 0o640, 0o640, "pass"},
		{"shadow 0600 stricter", "/etc/shadow", 0o640, 0o600, "pass"},
		{"shadow 0000 stricter", "/etc/shadow", 0o640, 0o000, "pass"},
		{"shadow 0604 world-readable", "/etc/shadow", 0o640, 0o604, "fail"}, // the regression case
		{"shadow 0606 world-writable", "/etc/shadow", 0o640, 0o606, "fail"},
		{"shadow 0644 world-readable", "/etc/shadow", 0o640, 0o644, "fail"},
		// /etc/passwd must be 0644 or stricter.
		{"passwd 0644 exact", "/etc/passwd", 0o644, 0o644, "pass"},
		{"passwd 0622 world-writable", "/etc/passwd", 0o644, 0o622, "fail"},
		{"passwd 0755 group/other write", "/etc/passwd", 0o644, 0o755, "fail"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			full := filepath.Join(dir, tc.path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			// Chmod sets the exact bits regardless of umask.
			if err := os.Chmod(full, tc.mode); err != nil {
				t.Fatal(err)
			}
			res, det := checkFileModeMax(dir, tc.path, tc.maxMode)
			if res != tc.want {
				t.Errorf("checkFileModeMax(mode=%#o, max=%#o) = %q (%s), want %q",
					tc.mode, tc.maxMode, res, det, tc.want)
			}
		})
	}
}

func TestCheckFileModeMax_MissingFileSkips(t *testing.T) {
	res, _ := checkFileModeMax(t.TempDir(), "/etc/shadow", 0o640)
	if res != "skip" {
		t.Errorf("missing file: result %q, want skip", res)
	}
}

func TestRunCIS_DefaultChecks_NoCrashes(t *testing.T) {
	r := RunCIS(CISOptions{NodeName: "test", HostRoot: ""})
	if len(r.Checks) == 0 {
		t.Fatal("no checks ran")
	}
	if r.Node != "test" {
		t.Errorf("Node = %q", r.Node)
	}
	total := r.Passed + r.Failed + r.Warned + r.Skipped
	if total != len(r.Checks) {
		t.Errorf("counter sum %d != check count %d", total, len(r.Checks))
	}
	// Each result must be one of the known states.
	for _, c := range r.Checks {
		if c.Result != "pass" && c.Result != "fail" &&
			c.Result != "warn" && c.Result != "skip" {
			t.Errorf("check %s has unknown result %q", c.ID, c.Result)
		}
	}
}

func TestRunCIS_CustomCheckList(t *testing.T) {
	r := RunCIS(CISOptions{
		NodeName: "test",
		Checks: []CISCheck{
			{ID: "T.1", Title: "always pass",
				Run: func(string) (string, string) { return "pass", "ok" }},
			{ID: "T.2", Title: "always fail",
				Run: func(string) (string, string) { return "fail", "bad" }},
		},
	})
	if r.Passed != 1 || r.Failed != 1 {
		t.Errorf("counts = pass:%d fail:%d, want 1/1", r.Passed, r.Failed)
	}
}

func TestCheckSSHDOption(t *testing.T) {
	// Use a fake sshd_config in a tempdir.
	dir := t.TempDir()
	body := `# config
Port 22
PermitRootLogin prohibit-password
PasswordAuthentication yes
`
	if err := writeTree(dir, map[string]string{"/etc/ssh/sshd_config": body}); err != nil {
		t.Fatal(err)
	}
	res, det := checkSSHDOption(dir, "PermitRootLogin", "no", "prohibit-password")
	if res != "pass" {
		t.Errorf("PermitRootLogin: result %q, detail %q", res, det)
	}
	res, det = checkSSHDOption(dir, "PasswordAuthentication", "no")
	if res != "fail" {
		t.Errorf("PasswordAuthentication: result %q, detail %q", res, det)
	}
	if !strings.Contains(det, "yes") {
		t.Errorf("expected detail to mention 'yes', got %q", det)
	}
	res, _ = checkSSHDOption(dir, "MissingOption", "no")
	if res != "warn" {
		t.Errorf("missing option: result %q", res)
	}
}

// writeTree creates files under root for testing.
func writeTree(root string, files map[string]string) error {
	for p, body := range files {
		full := root + p
		if err := mkdirAll(full); err != nil {
			return err
		}
		if err := writeFile(full, body); err != nil {
			return err
		}
	}
	return nil
}

func mkdirAll(path string) error {
	// Path is .../<base>; strip the basename.
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return mkdirAllRaw(path[:i])
		}
	}
	return nil
}

func mkdirAllRaw(dir string) error {
	return mkdirAllStdlib(dir)
}

// Tiny wrapper so the test file doesn't import os twice.
func mkdirAllStdlib(dir string) error {
	return osMkdirAll(dir)
}
