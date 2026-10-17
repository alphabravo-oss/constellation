package hostscan

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

var errCISTestRead = errors.New("injected CIS read failure")
var errCISTestClose = errors.New("injected CIS close failure")

const cisTestRelease = "6.8-fixture"
const cisTestLoaded = "cramfs 4096 0 - Live 0x0\n"

func cisProcFixture() fstest.MapFS {
	return fstest.MapFS{
		"modules":              &fstest.MapFile{Data: []byte("overlay 4096 0 - Live 0x0\n")},
		"sys/kernel/osrelease": &fstest.MapFile{Data: []byte(cisTestRelease + "\n")},
	}
}

func cisHostFixture() fstest.MapFS {
	return fstest.MapFS{
		"lib/modules/" + cisTestRelease + "/modules.builtin": &fstest.MapFile{Data: []byte("kernel/fs/ext4/ext4.ko\n")},
		"lib/modules/" + cisTestRelease + "/kernel/ext4.ko":  &fstest.MapFile{Data: []byte("fixture module")},
	}
}

func cisModuleFile(host fstest.MapFS, name string) {
	host["lib/modules/"+cisTestRelease+"/kernel/"+name] = &fstest.MapFile{Data: []byte("fixture module")}
}

type cisOpenFS struct {
	base fs.FS
	open func(string) (fs.File, error)
}

func (f cisOpenFS) Open(name string) (fs.File, error) {
	if f.open != nil {
		return f.open(name)
	}
	return f.base.Open(name)
}

type cisReadFile struct {
	fs.File
	readErr  error
	closeErr error
	closed   int
}

func (f *cisReadFile) Read(data []byte) (int, error) {
	n, err := f.File.Read(data)
	if errors.Is(err, io.EOF) && f.readErr != nil {
		return n, f.readErr
	}
	return n, err
}

func (f *cisReadFile) Close() error {
	f.closed++
	return errors.Join(f.File.Close(), f.closeErr)
}

func cisFaultFile(t *testing.T, base fs.FS, name string, readErr, closeErr error) *cisReadFile {
	t.Helper()
	file, err := base.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	return &cisReadFile{File: file, readErr: readErr, closeErr: closeErr}
}

func requireCISResult(t *testing.T, result, detail, want string) {
	t.Helper()
	if result != want {
		t.Fatalf("result=%q detail=%q want=%q", result, detail, want)
	}
}

func TestCISModuleLoadedAndBuiltinOverrideMissingSources(t *testing.T) {
	for _, state := range []string{"Live", "Loading", "Unloading"} {
		t.Run(state, func(t *testing.T) {
			proc := cisProcFixture()
			proc["modules"].Data = []byte(strings.ReplaceAll(cisTestLoaded, "Live", state))
			delete(proc, "sys/kernel/osrelease")
			result, detail := checkModuleEvidence(proc, nil, "cramfs")
			requireCISResult(t, result, detail, "fail")
		})
	}
	t.Run("builtin without loadable file or proc module list", func(t *testing.T) {
		proc, host := cisProcFixture(), cisHostFixture()
		delete(proc, "modules")
		host["lib/modules/"+cisTestRelease+"/modules.builtin"].Data = []byte("kernel/fs/cramfs/cramfs.ko\n")
		result, detail := checkModuleEvidence(proc, host, "cramfs")
		requireCISResult(t, result, detail, "fail")
	})
}

func TestCISModuleCompleteAbsenceAndExactInstalledIdentity(t *testing.T) {
	for _, filename := range []string{"cramfs_extra.ko", "cramfs.ko.backup", "cramfs-extra.ko", "other.ko"} {
		t.Run(filename, func(t *testing.T) {
			host := cisHostFixture()
			cisModuleFile(host, filename)
			result, detail := checkModuleEvidence(cisProcFixture(), host, "cramfs")
			requireCISResult(t, result, detail, "pass")
		})
	}
	for _, suffix := range []string{".ko", ".ko.gz", ".ko.xz", ".ko.zst"} {
		t.Run(suffix, func(t *testing.T) {
			host := cisHostFixture()
			cisModuleFile(host, "test_module"+suffix)
			result, detail := checkModuleEvidence(cisProcFixture(), host, "test-module")
			requireCISResult(t, result, detail, "warn")
			if !strings.Contains(detail, "effective disabling unverified") {
				t.Fatal("available evidence implies verified disabling")
			}
		})
	}
}

func TestCISModuleConfigurationTextNeverProvesDisabled(t *testing.T) {
	for _, config := range []string{"blacklist cramfs\n", "# blacklist cramfs\n", "blacklist cramfs_extra\n", "install cramfs /bin/true\n", "install cramfs /bin/true-extra\n", "install cramfs /bin/false\nsoftdep cramfs pre: other\n"} {
		t.Run(config, func(t *testing.T) {
			host := cisHostFixture()
			cisModuleFile(host, "cramfs.ko")
			host["etc/modprobe.d/fixture.conf"] = &fstest.MapFile{Data: []byte(config)}
			result, detail := checkModuleEvidence(cisProcFixture(), host, "cramfs")
			requireCISResult(t, result, detail, "warn")
		})
	}
}

func TestCISModuleIncompleteEvidenceNeverProvesAbsence(t *testing.T) {
	cases := []struct {
		name   string
		change func(fstest.MapFS, fstest.MapFS)
	}{
		{"missing proc modules", func(p, h fstest.MapFS) { delete(p, "modules") }},
		{"malformed proc modules", func(p, h fstest.MapFS) { p["modules"].Data = []byte("cramfs_extra malformed\n") }},
		{"missing release", func(p, h fstest.MapFS) { delete(p, "sys/kernel/osrelease") }},
		{"release path escape", func(p, h fstest.MapFS) { p["sys/kernel/osrelease"].Data = []byte("../../elsewhere") }},
		{"missing builtin", func(p, h fstest.MapFS) { delete(h, "lib/modules/"+cisTestRelease+"/modules.builtin") }},
		{"malformed builtin", func(p, h fstest.MapFS) {
			h["lib/modules/"+cisTestRelease+"/modules.builtin"].Data = []byte("../../cramfs.ko\n")
		}},
		{"unresolved installed link", func(p, h fstest.MapFS) {
			h["lib/modules/"+cisTestRelease+"/linked"] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("external")}
		}},
		{"missing matching release tree", func(p, h fstest.MapFS) { p["sys/kernel/osrelease"].Data = []byte("different-release\n") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proc, host := cisProcFixture(), cisHostFixture()
			tc.change(proc, host)
			result, detail := checkModuleEvidence(proc, host, "cramfs")
			requireCISResult(t, result, detail, "skip")
		})
	}
}

func TestCISModuleLateSourceFailuresAndPositiveRecords(t *testing.T) {
	for _, positive := range []bool{false, true} {
		t.Run(strings.ToUpper(strconv.FormatBool(positive)), func(t *testing.T) {
			proc := cisProcFixture()
			if positive {
				proc["modules"].Data = []byte(cisTestLoaded)
			}
			var opened *cisReadFile
			fault := cisOpenFS{open: func(name string) (fs.File, error) {
				if name == "modules" {
					opened = cisFaultFile(t, proc, name, errCISTestRead, errCISTestClose)
					return opened, nil
				}
				return proc.Open(name)
			}}
			result, detail := checkModuleEvidence(fault, cisHostFixture(), "cramfs")
			want := "skip"
			if positive {
				want = "fail"
			}
			requireCISResult(t, result, detail, want)
			if opened == nil || opened.closed != 1 {
				t.Fatal("source not closed exactly once")
			}
		})
	}
}

func TestCISModuleChangingEvidenceNeverPasses(t *testing.T) {
	for _, change := range []string{"release", "loaded"} {
		t.Run(change, func(t *testing.T) {
			proc := cisProcFixture()
			counts := map[string]int{}
			changing := cisOpenFS{open: func(name string) (fs.File, error) {
				counts[name]++
				if counts[name] == 2 && change == "release" && name == "sys/kernel/osrelease" {
					return (fstest.MapFS{name: &fstest.MapFile{Data: []byte("new-release\n")}}).Open(name)
				}
				if counts[name] == 2 && change == "loaded" && name == "modules" {
					return (fstest.MapFS{name: &fstest.MapFile{Data: []byte(cisTestLoaded)}}).Open(name)
				}
				return proc.Open(name)
			}}
			result, detail := checkModuleEvidence(changing, cisHostFixture(), "cramfs")
			want := "skip"
			if change == "loaded" {
				want = "fail"
			}
			requireCISResult(t, result, detail, want)
		})
	}
}

func TestCISModuleTraversalAndReadBounds(t *testing.T) {
	host := cisHostFixture()
	for _, limits := range [][2]int{{0, 64}, {100, 0}} {
		if _, err := scanModuleTree(host, "lib/modules/"+cisTestRelease, "cramfs", limits[0], limits[1]); err == nil {
			t.Fatal("bounded traversal was treated as complete")
		}
	}
	file := io.NopCloser(strings.NewReader("four"))
	if _, err := readCISClosed(file, 3); err == nil {
		t.Fatal("overflow read accepted")
	}
}

func TestCISSSHPlainFirstValueAndComments(t *testing.T) {
	cases := []struct {
		body, want string
	}{
		{"# PasswordAuthentication yes\nPasswordAuthentication no\n", "pass"},
		{"PasswordAuthentication no\nPasswordAuthentication yes\n", "pass"},
		{"PasswordAuthentication yes\nPasswordAuthentication no\n", "fail"},
		{"PasswordAuthenticationExtra no\n", "warn"},
		{"PasswordAuthentication no # operator comment\n", "pass"},
		{"PasswordAuthentication no # don't enable passwords\n", "pass"},
		{"pAsSwOrDaUtHeNtIcAtIoN no\n", "pass"},
	}
	for _, tc := range cases {
		t.Run(tc.body, func(t *testing.T) {
			result, detail := checkSSHDReader(io.NopCloser(strings.NewReader(tc.body)), "PasswordAuthentication", "no")
			requireCISResult(t, result, detail, tc.want)
		})
	}
}

func TestCISSSHConditionalOrUnsupportedScopeNeverPasses(t *testing.T) {
	for _, body := range []string{
		"Match User root\nPasswordAuthentication no\n",
		"PasswordAuthentication no\nInclude /etc/ssh/sshd_config.d/*.conf\n",
		"PasswordAuthentication no\nMatch all\nPasswordAuthentication yes\n",
		"PasswordAuthentication no\nPasswordAuthentication yes extra\n",
		"PasswordAuthentication no\nInclude=/private/fixture\n",
		"PasswordAuthentication \"no\"\n",
		"PasswordAuthentication no\\\n",
		"PasswordAuthentication no\n\x00hidden\n",
		"PasswordAuthentication no\nPasswordAuthentication nonsense\n",
		"PasswordAuthentication NO\n",
	} {
		t.Run(body, func(t *testing.T) {
			result, detail := checkSSHDReader(io.NopCloser(strings.NewReader(body)), "PasswordAuthentication", "no")
			requireCISResult(t, result, detail, "warn")
			if strings.Contains(detail, "/private/fixture") {
				t.Fatal("arbitrary configuration echoed in evidence detail")
			}
		})
	}
}

func TestCISSSHUnreadTailAndCloseFailureCannotPass(t *testing.T) {
	for _, fault := range []string{"read", "close", "both"} {
		t.Run(fault, func(t *testing.T) {
			base := fstest.MapFS{"config": &fstest.MapFile{Data: []byte("PasswordAuthentication no\n")}}
			var readErr, closeErr error
			if fault != "close" {
				readErr = errCISTestRead
			}
			if fault != "read" {
				closeErr = errCISTestClose
			}
			file := cisFaultFile(t, base, "config", readErr, closeErr)
			result, detail := checkSSHDReader(file, "PasswordAuthentication", "no")
			requireCISResult(t, result, detail, "skip")
			if file.closed != 1 {
				t.Fatal("SSH input not closed exactly once")
			}
		})
	}
	for _, size := range []int{65537, (1 << 20) + 1} {
		result, detail := checkSSHDReader(io.NopCloser(strings.NewReader("PasswordAuthentication no\n"+strings.Repeat("x", size))), "PasswordAuthentication", "no")
		requireCISResult(t, result, detail, "skip")
	}
}

func TestCISSSHPublicWrapperAndReportCounts(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.MkdirAll("etc/ssh", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("etc/ssh/sshd_config", []byte("PasswordAuthentication no\nMatch User legacy\nPasswordAuthentication yes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	result, detail := checkSSHDOption(directory, "PasswordAuthentication", "no")
	requireCISResult(t, result, detail, "warn")
	checks := []CISCheck{
		{ID: "absent", Run: func(string) (string, string) {
			return checkModuleEvidence(cisProcFixture(), cisHostFixture(), "cramfs")
		}},
		{ID: "unavailable", Run: func(string) (string, string) { return checkModuleEvidence(nil, nil, "cramfs") }},
		{ID: "conditional", Run: func(string) (string, string) { return checkSSHDOption(directory, "PasswordAuthentication", "no") }},
	}
	report := RunCIS(CISOptions{NodeName: "fixture-node", Checks: checks})
	if report.Passed != 1 || report.Warned != 1 || report.Skipped != 1 || report.Failed != 0 || len(report.Checks) != 3 {
		t.Fatalf("incorrect evidence counts: %+v", report)
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var wire CISReport
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Node != "fixture-node" || wire.Profile != "cis-distro-linux-min" || wire.ObservedAt.IsZero() || wire.Passed != 1 {
		t.Fatal("existing caller report contract changed")
	}
}

func TestCISModuleProcShapeSupportsKernelVariants(t *testing.T) {
	for _, record := range []string{
		"other 4096 - - Live 0x0\n",
		"other 4096 -1 - Unloading 0x0000000000000000\n",
		"other 4096 1 first,second,[permanent], Live 0xffffffffffffffff (OE)\n",
	} {
		proc := cisProcFixture()
		proc["modules"].Data = []byte(record)
		result, detail := checkModuleEvidence(proc, cisHostFixture(), "cramfs")
		requireCISResult(t, result, detail, "pass")
	}
	for _, record := range []string{
		"other 4096 not-a-count - Live 0x0\n",
		"other 4096 0 not-a-dependency Live 0x0\n",
		"other 4096 0 - Live not-an-address\n",
		"other 4096 0 - Live 0x0 invalid-annotation\n",
		"other 4096 0 - Live 0x0 (OE) extra\n",
	} {
		proc := cisProcFixture()
		proc["modules"].Data = []byte(record)
		result, detail := checkModuleEvidence(proc, cisHostFixture(), "cramfs")
		requireCISResult(t, result, detail, "skip")
	}
}

type cisFaultDirectory struct {
	fs.ReadDirFile
	readErr  error
	closeErr error
	closed   int
}

func (f *cisFaultDirectory) ReadDir(count int) ([]fs.DirEntry, error) {
	entries, err := f.ReadDirFile.ReadDir(count)
	if f.readErr == nil {
		return entries, err
	}
	return entries, errors.Join(err, f.readErr)
}

func (f *cisFaultDirectory) Close() error {
	f.closed++
	return errors.Join(f.ReadDirFile.Close(), f.closeErr)
}

func cisDirectoryFaultSource(host fstest.MapFS, fault string) (fs.FS, **cisFaultDirectory) {
	var directory *cisFaultDirectory
	wrapper := cisOpenFS{open: func(name string) (fs.File, error) {
		if name != "lib/modules/"+cisTestRelease {
			return host.Open(name)
		}
		if fault == "open" {
			return nil, errCISTestRead
		}
		file, err := host.Open(name)
		if err != nil {
			return nil, err
		}
		directory = &cisFaultDirectory{ReadDirFile: file.(fs.ReadDirFile)}
		if fault == "read" {
			directory.readErr = errCISTestRead
		}
		if fault == "close" {
			directory.closeErr = errCISTestClose
		}
		return directory, nil
	}}
	return wrapper, &directory
}

func TestCISModuleDirectoryReadAndCloseFailuresCannotPass(t *testing.T) {
	for _, fault := range []string{"none", "open", "read", "close"} {
		t.Run(fault, func(t *testing.T) {
			wrapper, directory := cisDirectoryFaultSource(cisHostFixture(), fault)
			result, detail := checkModuleEvidence(cisProcFixture(), wrapper, "cramfs")
			want := "skip"
			if fault == "none" {
				want = "pass"
			}
			requireCISResult(t, result, detail, want)
			if *directory != nil && (*directory).closed != 1 {
				t.Fatal("module directory not closed exactly once")
			}
		})
	}
}

type cisEOFWrapper struct{ cause error }

func (e *cisEOFWrapper) Error() string { return "wrapped CIS directory result" }
func (e *cisEOFWrapper) Unwrap() error { return e.cause }

type cisClaimedEOF struct{ cause error }

func (e *cisClaimedEOF) Error() string        { return "claimed EOF with another cause" }
func (e *cisClaimedEOF) Unwrap() error        { return e.cause }
func (e *cisClaimedEOF) Is(target error) bool { return errors.Is(target, io.EOF) }

type cisCyclicError struct{}

func (e *cisCyclicError) Error() string { return "cyclic CIS directory result" }
func (e *cisCyclicError) Unwrap() error { return e }

type cisTerminalDirectory struct {
	fs.ReadDirFile
	terminal error
}

func (f *cisTerminalDirectory) ReadDir(count int) ([]fs.DirEntry, error) {
	entries, err := f.ReadDirFile.ReadDir(count)
	if errors.Is(err, io.EOF) {
		return entries, f.terminal
	}
	return entries, err
}

func cisTerminalDirectorySource(host fstest.MapFS, terminal error) fs.FS {
	return cisOpenFS{open: func(name string) (fs.File, error) {
		file, err := host.Open(name)
		if err != nil || name != "lib/modules/"+cisTestRelease {
			return file, err
		}
		return &cisTerminalDirectory{ReadDirFile: file.(fs.ReadDirFile), terminal: terminal}, nil
	}}
}

func requireCISTerminalEOF(t *testing.T, terminal error, complete bool) {
	t.Helper()
	if got := cleanModuleDirectoryEOF(terminal); got != complete {
		t.Fatalf("clean terminal EOF = %t, want %t", got, complete)
	}
	wrapped := cisTerminalDirectorySource(cisHostFixture(), terminal)
	result, detail := checkModuleEvidence(cisProcFixture(), wrapped, "cramfs")
	want := "skip"
	if complete {
		want = "pass"
	}
	requireCISResult(t, result, detail, want)
}

func TestCISModuleDirectoryTerminalEOF(t *testing.T) {
	deep := io.EOF
	for range 33 {
		deep = &cisEOFWrapper{cause: deep}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"plain EOF", io.EOF, true},
		{"clean wrapped EOF", &cisEOFWrapper{cause: &cisEOFWrapper{cause: io.EOF}}, true},
		{"joined EOF only", errors.Join(io.EOF), false},
		{"joined EOF and failure", errors.Join(io.EOF, errCISTestRead), false},
		{"whole wrapped join", &cisEOFWrapper{cause: errors.Join(io.EOF, errCISTestRead)}, false},
		{"outer Is hides inner failure", &cisClaimedEOF{cause: errCISTestRead}, false},
		{"cyclic wrapper", &cisCyclicError{}, false},
		{"excessive depth", deep, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			requireCISTerminalEOF(t, item.err, item.want)
		})
	}
}

func TestCISBuiltinPositiveSurvivesUnrelatedSourceFailure(t *testing.T) {
	proc, host := cisProcFixture(), cisHostFixture()
	delete(proc, "modules")
	builtinPath := "lib/modules/" + cisTestRelease + "/modules.builtin"
	host[builtinPath].Data = []byte("kernel/fs/cramfs/cramfs.ko\n")
	var file *cisReadFile
	fault := cisOpenFS{open: func(name string) (fs.File, error) {
		if name != builtinPath {
			return host.Open(name)
		}
		file = cisFaultFile(t, host, name, errCISTestRead, errCISTestClose)
		return file, nil
	}}
	result, detail := checkModuleEvidence(proc, fault, "cramfs")
	requireCISResult(t, result, detail, "fail")
	if file == nil || file.closed != 1 {
		t.Fatal("builtin source not closed exactly once")
	}
}

func TestCISModuleMetadataBoundsCannotPass(t *testing.T) {
	for _, record := range []string{strings.Repeat("\n", cisModuleEntries+1), strings.Repeat("x", 65537)} {
		proc := cisProcFixture()
		proc["modules"].Data = []byte(record)
		result, detail := checkModuleEvidence(proc, cisHostFixture(), "cramfs")
		requireCISResult(t, result, detail, "skip")
	}
}
