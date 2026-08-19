package hostscan

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestReadDpkg(t *testing.T) {
	dir := t.TempDir()
	body := `Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.21-2ubuntu4

Package: zlib1g
Status: install ok installed
Architecture: amd64
Version: 1:1.3+dfsg-3.1ubuntu2.1
Description: compression library - runtime
 long
 description
 ignored

Package: removed-thing
Status: deinstall ok config-files
Architecture: amd64
Version: 0.0.0
`
	path := filepath.Join(dir, "status")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := readDpkg(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (bash + zlib1g; removed-thing should be filtered)", len(pkgs))
	}
	// Should be sorted alphabetically.
	if pkgs[0].Name != "bash" {
		t.Errorf("first = %q, want bash", pkgs[0].Name)
	}
	if pkgs[0].Version != "5.2.21-2ubuntu4" {
		t.Errorf("bash version = %q", pkgs[0].Version)
	}
	if pkgs[1].Source != "dpkg" {
		t.Errorf("source = %q", pkgs[1].Source)
	}
}

// TestReadDpkg_StatusDir covers distroless images, which ship no monolithic
// /var/lib/dpkg/status and instead drop one control fragment per package in
// status.d/. readDpkg must walk status.d/ and union the parsed packages.
func TestReadDpkg_StatusDir(t *testing.T) {
	dir := t.TempDir()
	dpkgDir := filepath.Join(dir, "var", "lib", "dpkg")
	statusD := filepath.Join(dpkgDir, "status.d")
	if err := os.MkdirAll(statusD, 0o755); err != nil {
		t.Fatal(err)
	}
	// No monolithic status file at all (distroless).
	if err := os.WriteFile(filepath.Join(statusD, "libc6"), []byte(
		`Package: libc6
Status: install ok installed
Architecture: amd64
Version: 2.36-9+deb12u4
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statusD, "base-files"), []byte(
		`Package: base-files
Status: install ok installed
Architecture: amd64
Version: 12.4+deb12u4
`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A .md5sums sidecar must be ignored, not parsed as a package.
	if err := os.WriteFile(filepath.Join(statusD, "libc6.md5sums"), []byte("deadbeef  usr/lib/x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, err := readDpkg(filepath.Join(dpkgDir, "status"))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2 (base-files + libc6 from status.d/)", len(pkgs))
	}
	// Sorted alphabetically; base-files before libc6.
	if pkgs[0].Name != "base-files" || pkgs[1].Name != "libc6" {
		t.Fatalf("got %q, %q; want base-files, libc6", pkgs[0].Name, pkgs[1].Name)
	}
	if pkgs[1].Version != "2.36-9+deb12u4" {
		t.Errorf("libc6 version = %q", pkgs[1].Version)
	}
	if pkgs[1].Source != "dpkg" {
		t.Errorf("source = %q, want dpkg", pkgs[1].Source)
	}
}

func TestReadApk(t *testing.T) {
	dir := t.TempDir()
	body := `C:Q1abcdef
P:musl
V:1.2.5-r0
A:x86_64
S:614
I:602112

C:Q1xyz
P:alpine-keys
V:2.5-r0
A:noarch
`
	path := filepath.Join(dir, "installed")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, err := readApk(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "alpine-keys" {
		t.Errorf("first = %q (sorted) want alpine-keys", pkgs[0].Name)
	}
	if pkgs[1].Version != "1.2.5-r0" {
		t.Errorf("musl version = %q", pkgs[1].Version)
	}
}

func TestCollectPackages_LiveDpkg(t *testing.T) {
	// Skip if dpkg DB isn't present (e.g. running on RHEL/Alpine CI).
	if _, err := os.Stat("/var/lib/dpkg/status"); err != nil {
		t.Skip("dpkg status not present on this host")
	}
	p, err := CollectPackages(PackagesOptions{NodeName: "test", Distro: "ubuntu"})
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
	}
	if p.Source != "dpkg" {
		t.Errorf("Source = %q, want dpkg", p.Source)
	}
	if p.Count == 0 {
		t.Errorf("Count = 0 on a host with dpkg")
	}
}

func TestReadRpmSQLite(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "usr/lib/sysimage/rpm/rpmdb.sqlite")
	writeRpmSQLite(t, dbPath,
		rpmHeaderBlob(t, rpmHeaderPackage{
			name:    "zlib",
			version: "1.2.13",
			release: "2.el9",
			arch:    "x86_64",
		}),
		rpmHeaderBlob(t, rpmHeaderPackage{
			epoch:   intPtr(1),
			name:    "bash",
			version: "5.2",
			release: "6.fc40",
			arch:    "x86_64",
		}),
	)

	pkgs, err := readRpm(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	if pkgs[0].Name != "bash" {
		t.Fatalf("first package = %q, want sorted bash", pkgs[0].Name)
	}
	if pkgs[0].Version != "1:5.2-6.fc40" {
		t.Errorf("bash version = %q, want epoch:version-release", pkgs[0].Version)
	}
	if pkgs[0].Arch != "x86_64" {
		t.Errorf("bash arch = %q, want x86_64", pkgs[0].Arch)
	}
	if pkgs[0].Source != "rpm" {
		t.Errorf("bash source = %q, want rpm", pkgs[0].Source)
	}
	if pkgs[1].Version != "1.2.13-2.el9" {
		t.Errorf("zlib version = %q, want version-release", pkgs[1].Version)
	}
}

func TestCollectPackages_RpmDistro(t *testing.T) {
	root := t.TempDir()
	writeRpmSQLite(t, filepath.Join(root, "var/lib/rpm/rpmdb.sqlite"),
		rpmHeaderBlob(t, rpmHeaderPackage{
			name:    "kernel",
			version: "6.8.0",
			release: "100.fc40",
			arch:    "x86_64",
		}),
	)

	p, err := CollectPackages(PackagesOptions{HostRoot: root, NodeName: "node-a", Distro: "fedora", DistroVersion: "40"})
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
	}
	if p.DistroVersion != "40" {
		t.Errorf("DistroVersion = %q, want 40", p.DistroVersion)
	}
	if p.Source != "rpm" {
		t.Errorf("Source = %q, want rpm", p.Source)
	}
	if p.Count != 1 {
		t.Errorf("Count = %d, want 1", p.Count)
	}
	if p.Items[0].Name != "kernel" {
		t.Errorf("package = %q, want kernel", p.Items[0].Name)
	}
}

func TestCollectPackages_RpmUnknownDistro(t *testing.T) {
	root := t.TempDir()
	writeRpmSQLite(t, filepath.Join(root, "usr/lib/sysimage/rpm/rpmdb.sqlite"),
		rpmHeaderBlob(t, rpmHeaderPackage{
			name:    "custom-release",
			version: "1",
			release: "1",
			arch:    "noarch",
		}),
	)

	p, err := CollectPackages(PackagesOptions{HostRoot: root, NodeName: "node-a", Distro: "customrpm"})
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
	}
	if p.Source != "rpm" {
		t.Errorf("Source = %q, want rpm", p.Source)
	}
}

func TestCollectPackages_WolfiUsesApk(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "lib/apk/db/installed")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("P:wolfi-baselayout\nV:20230201-r15\nA:x86_64\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	p, err := CollectPackages(PackagesOptions{HostRoot: root, NodeName: "node-a", Distro: "wolfi"})
	if err != nil {
		t.Fatalf("CollectPackages: %v", err)
	}
	if p.Source != "apk" {
		t.Errorf("Source = %q, want apk", p.Source)
	}
	if p.Items[0].Name != "wolfi-baselayout" {
		t.Errorf("package = %q, want wolfi-baselayout", p.Items[0].Name)
	}
}

type rpmHeaderPackage struct {
	epoch   *int
	name    string
	version string
	release string
	arch    string
}

type rpmHeaderEntry struct {
	tag    int32
	typ    uint32
	offset int32
	count  uint32
}

const (
	rpmTagName    = 1000
	rpmTagVersion = 1001
	rpmTagRelease = 1002
	rpmTagEpoch   = 1003
	rpmTagArch    = 1022

	rpmInt32Type  = 4
	rpmStringType = 6
)

func writeRpmSQLite(t *testing.T, path string, blobs ...[]byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := db.Exec(`CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, blob := range blobs {
		if _, err := db.Exec(`INSERT INTO Packages(blob) VALUES (?)`, blob); err != nil {
			t.Fatal(err)
		}
	}
}

func rpmHeaderBlob(t *testing.T, pkg rpmHeaderPackage) []byte {
	t.Helper()
	var (
		entries []rpmHeaderEntry
		data    []byte
	)
	addString := func(tag int32, value string) {
		entries = append(entries, rpmHeaderEntry{
			tag:    tag,
			typ:    rpmStringType,
			offset: int32(len(data)),
			count:  1,
		})
		data = append(data, value...)
		data = append(data, 0)
	}
	addInt32 := func(tag int32, value int32) {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		entries = append(entries, rpmHeaderEntry{
			tag:    tag,
			typ:    rpmInt32Type,
			offset: int32(len(data)),
			count:  1,
		})
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], uint32(value))
		data = append(data, buf[:]...)
	}

	addString(rpmTagName, pkg.name)
	addString(rpmTagVersion, pkg.version)
	addString(rpmTagRelease, pkg.release)
	if pkg.epoch != nil {
		addInt32(rpmTagEpoch, int32(*pkg.epoch))
	}
	addString(rpmTagArch, pkg.arch)

	var out bytes.Buffer
	if err := binary.Write(&out, binary.BigEndian, int32(len(entries))); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&out, binary.BigEndian, int32(len(data))); err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if err := binary.Write(&out, binary.BigEndian, entry.tag); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&out, binary.BigEndian, entry.typ); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&out, binary.BigEndian, entry.offset); err != nil {
			t.Fatal(err)
		}
		if err := binary.Write(&out, binary.BigEndian, entry.count); err != nil {
			t.Fatal(err)
		}
	}
	out.Write(data)
	return out.Bytes()
}

func intPtr(v int) *int {
	return &v
}
