package hostscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestCollect_BestEffort exercises the public entrypoint against the
// real host. It can't assert specific values (different CI envs have
// different kernels), but it asserts the collector NEVER panics, fills
// in the structural fields, and stamps observed_at + node.
func TestCollect_BestEffort(t *testing.T) {
	f := Collect(context.Background(), Options{NodeName: "test-node", AgentVersion: "0.0.0-test"})
	if f.Node != "test-node" {
		t.Errorf("Node = %q, want test-node", f.Node)
	}
	if f.ObservedAt.IsZero() {
		t.Error("ObservedAt is zero")
	}
	if f.AgentVersion != "0.0.0-test" {
		t.Errorf("AgentVersion = %q", f.AgentVersion)
	}
	// On any Linux CI runner Uname succeeds, so Release is populated.
	if f.Kernel.Release == "" {
		t.Error("Kernel.Release empty — Uname failed?")
	}
	if f.Kernel.Arch == "" {
		t.Error("Kernel.Arch empty — Uname failed?")
	}
}

func TestReadKeyValueFile_OSRelease(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	body := `NAME="Ubuntu"
ID=ubuntu
VERSION_ID="24.04"
# a comment

PRETTY_NAME='Ubuntu 24.04.4 LTS'
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	kv, ok := readKeyValueFile(path)
	if !ok {
		t.Fatal("readKeyValueFile failed")
	}
	if kv["NAME"] != "Ubuntu" {
		t.Errorf("NAME = %q", kv["NAME"])
	}
	if kv["ID"] != "ubuntu" {
		t.Errorf("ID = %q", kv["ID"])
	}
	if kv["VERSION_ID"] != "24.04" {
		t.Errorf("VERSION_ID = %q", kv["VERSION_ID"])
	}
	if kv["PRETTY_NAME"] != "Ubuntu 24.04.4 LTS" {
		t.Errorf("PRETTY_NAME = %q", kv["PRETTY_NAME"])
	}
}

func TestOptionsHostPath(t *testing.T) {
	t.Run("empty root", func(t *testing.T) {
		o := Options{}
		if got := o.hostPath("/etc/os-release"); got != "/etc/os-release" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("with root", func(t *testing.T) {
		o := Options{HostRoot: "/host"}
		if got := o.hostPath("/etc/os-release"); got != "/host/etc/os-release" {
			t.Errorf("got %q", got)
		}
	})
}

func TestCollectOS_UsesHostRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `ID=fakeos
VERSION_ID="42"
PRETTY_NAME="Fake OS 42"
`
	if err := os.WriteFile(filepath.Join(dir, "etc/os-release"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	o := collectOS(Options{HostRoot: dir})
	if o.ID != "fakeos" {
		t.Errorf("ID = %q", o.ID)
	}
	if o.VersionID != "42" {
		t.Errorf("VersionID = %q", o.VersionID)
	}
	if o.PrettyName != "Fake OS 42" {
		t.Errorf("PrettyName = %q", o.PrettyName)
	}
}

func TestCollectOS_DistroFixtures(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantID    string
		wantLike  string
		wantVerID string
	}{
		{
			name:      "ubuntu",
			body:      "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\n",
			wantID:    "ubuntu",
			wantLike:  "debian",
			wantVerID: "24.04",
		},
		{
			name:      "debian",
			body:      "ID=debian\nVERSION_ID=\"12\"\n",
			wantID:    "debian",
			wantVerID: "12",
		},
		{
			name:      "alpine",
			body:      "ID=alpine\nVERSION_ID=3.20.3\n",
			wantID:    "alpine",
			wantVerID: "3.20.3",
		},
		{
			name:      "rhel compatible",
			body:      "ID=rocky\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n",
			wantID:    "rocky",
			wantLike:  "rhel centos fedora",
			wantVerID: "9.4",
		},
		{
			name:      "suse",
			body:      "ID=sles\nID_LIKE=\"suse\"\nVERSION_ID=\"15.5\"\n",
			wantID:    "sles",
			wantLike:  "suse",
			wantVerID: "15.5",
		},
		{
			name:      "amazon linux",
			body:      "ID=amzn\nID_LIKE=\"fedora\"\nVERSION_ID=\"2023\"\n",
			wantID:    "amzn",
			wantLike:  "fedora",
			wantVerID: "2023",
		},
		{
			name:      "wolfi",
			body:      "ID=wolfi\nNAME=\"Wolfi\"\nVERSION_ID=\"20240612\"\n",
			wantID:    "wolfi",
			wantVerID: "20240612",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "etc/os-release")
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			got := collectOS(Options{HostRoot: dir})
			if got.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", got.ID, tc.wantID)
			}
			if got.IDLike != tc.wantLike {
				t.Errorf("IDLike = %q, want %q", got.IDLike, tc.wantLike)
			}
			if got.VersionID != tc.wantVerID {
				t.Errorf("VersionID = %q, want %q", got.VersionID, tc.wantVerID)
			}
		})
	}
}

func TestCollectOS_EmptyWhenHostRootHasNoOSRelease(t *testing.T) {
	got := collectOS(Options{HostRoot: t.TempDir()})
	if got.ID != "" || got.VersionID != "" {
		t.Fatalf("collectOS with empty HostRoot = ID %q version %q, want empty", got.ID, got.VersionID)
	}
}

func TestDecodeCaps(t *testing.T) {
	// All-zero -> empty.
	if got := decodeCaps(0); len(got) != 0 {
		t.Errorf("decodeCaps(0) = %v", got)
	}
	// NET_ADMIN (bit 12).
	got := decodeCaps(1 << 12)
	if len(got) != 1 || got[0] != "NET_ADMIN" {
		t.Errorf("decodeCaps(1<<12) = %v", got)
	}
	// NET_ADMIN | BPF (bits 12, 39).
	got = decodeCaps((1 << 12) | (1 << 39))
	if len(got) != 2 {
		t.Errorf("decodeCaps two caps = %v", got)
	}
	// Order is map iteration, so just check membership.
	have := map[string]bool{}
	for _, c := range got {
		have[c] = true
	}
	if !have["NET_ADMIN"] || !have["BPF"] {
		t.Errorf("missing caps in %v", got)
	}
}
