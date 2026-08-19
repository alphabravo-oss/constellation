//go:build linux

package ebpf

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestContainerIDFromCgroupPath(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cases := []string{
		"/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/pod123/cri-containerd-" + id + ".scope",
		"/sys/fs/cgroup/system.slice/docker-" + id + ".scope",
		"/sys/fs/cgroup/kubepods/burstable/pod123/" + id,
	}
	for _, path := range cases {
		if got := containerIDFromCgroupPath(path); got != id {
			t.Fatalf("containerIDFromCgroupPath(%q) = %q", path, got)
		}
	}
}

func TestContainerIDFromCgroupRootMatchesInode(t *testing.T) {
	root := t.TempDir()
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dir := filepath.Join(root, "kubepods.slice", "pod123", "cri-containerd-"+id+".scope")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("stat did not expose syscall.Stat_t")
	}
	if got := containerIDFromCgroupRoot(root, st.Ino); got != id {
		t.Fatalf("containerIDFromCgroupRoot = %q", got)
	}
}
