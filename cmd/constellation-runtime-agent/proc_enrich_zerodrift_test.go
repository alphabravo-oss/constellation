package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fakeProcPid writes a minimal /proc/<pid> tree (stat, status, cgroup, exe) under root.
func fakeProcPid(t *testing.T, root string, pid, ppid uint32, nspid string, containerID, exeTarget string) {
	t.Helper()
	dir := filepath.Join(root, strconv.FormatUint(uint64(pid), 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// stat: "pid (comm) state ppid ..."
	if err := os.WriteFile(filepath.Join(dir, "stat"),
		[]byte(strconv.FormatUint(uint64(pid), 10)+" (proc) S "+strconv.FormatUint(uint64(ppid), 10)+" 1 1 0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "status"),
		[]byte("Name:\tproc\nNSpid:\t"+strconv.FormatUint(uint64(pid), 10)+"\t"+nspid+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cg := "0::/kubepods/pod/" + containerID + "\n"
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(cg), 0o644); err != nil {
		t.Fatal(err)
	}
	if exeTarget != "" {
		_ = os.Symlink(exeTarget, filepath.Join(dir, "exe"))
	}
}

func TestZeroDriftContextFromProc_AnchoredImage(t *testing.T) {
	root := t.TempDir()
	cid := "abcdef012345abcdef01" // >=12 hex, passes looksLikeContainerID

	// image binary: created in the past relative to container start.
	exe := filepath.Join(t.TempDir(), "nginx")
	if err := os.WriteFile(exe, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(time.Hour).UnixNano() // start AFTER the file ctime -> from image

	// init(100, NSpid 1) <- 300(exec, NSpid 5)
	fakeProcPid(t, root, 100, 1, "1", cid, "")
	fakeProcPid(t, root, 300, 100, "5", cid, exe)

	z := zeroDriftContextFromProc(root, 300, cid, start)
	if !z.Anchored {
		t.Fatalf("expected anchored (lineage 300->100(init))")
	}
	if !z.FromImage {
		t.Fatalf("expected FromImage (exe ctime precedes start)")
	}
	if execIsDrift(z) {
		t.Fatalf("anchored image exec must not be drift")
	}
}

func TestZeroDriftContextFromProc_ImageDrift(t *testing.T) {
	root := t.TempDir()
	cid := "abcdef012345abcdef01"

	exe := filepath.Join(t.TempDir(), "evil")
	if err := os.WriteFile(exe, []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Hour).UnixNano() // start BEFORE the file ctime -> drifted

	fakeProcPid(t, root, 100, 1, "1", cid, "")
	fakeProcPid(t, root, 300, 100, "5", cid, exe)

	z := zeroDriftContextFromProc(root, 300, cid, start)
	if z.FromImage {
		t.Fatalf("expected NOT FromImage (exe written after start)")
	}
	if !execIsDrift(z) {
		t.Fatalf("post-start binary (mv evil in) must be flagged as drift")
	}
}

func TestNspidIsOneAt(t *testing.T) {
	root := t.TempDir()
	cid := "abcdef012345abcdef01"
	fakeProcPid(t, root, 100, 1, "1", cid, "")
	fakeProcPid(t, root, 300, 100, "7", cid, "")
	if !nspidIsOneAt(root, 100) {
		t.Fatalf("pid 100 should be container init (NSpid 1)")
	}
	if nspidIsOneAt(root, 300) {
		t.Fatalf("pid 300 (NSpid 7) is not init")
	}
}
