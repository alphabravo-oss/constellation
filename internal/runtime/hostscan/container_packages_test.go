package hostscan

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectContainerPackagesReadsDpkgViaProcRoot(t *testing.T) {
	root := t.TempDir()
	listener := createTestCRISocket(t, root)
	defer listener.Close()

	procRoot := filepath.Join(root, "proc")
	containerRoot := filepath.Join(procRoot, "1234", "root")
	writeContainerOSRelease(t, containerRoot, "ubuntu", "24.04")
	writeContainerDpkgStatus(t, containerRoot)
	crictl := writeFakeCrictl(t, root, `{
  "status": {
    "id": "abcdef123456",
    "metadata": {"name": "api"},
    "image": {"image": "example.test/api:dev"},
    "imageRef": "example.test/api@sha256:aaaaaaaa",
    "state": "CONTAINER_RUNNING",
    "labels": {
      "io.kubernetes.pod.namespace": "payments",
      "io.kubernetes.pod.name": "api-7d9c",
      "io.kubernetes.pod.uid": "pod-uid"
    }
  },
  "info": {"pid": "1234"}
}`)

	got, err := CollectContainerPackages(context.Background(), ContainerPackagesOptions{
		HostRoot:  root,
		ProcRoot:  procRoot,
		NodeName:  "node-a",
		CrictlBin: crictl,
		Container: Container{
			ID:      "abcdef123456",
			Name:    "api",
			State:   "CONTAINER_RUNNING",
			PodNS:   "payments",
			PodName: "api-7d9c",
		},
		WorkloadID: "payments/pod/api-7d9c",
		Timeout:    time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.ContainerPID != 1234 {
		t.Fatalf("pid = %d, want 1234", got.ContainerPID)
	}
	if got.WorkloadID != "payments/pod/api-7d9c" || got.Namespace != "payments" || got.PodName != "api-7d9c" {
		t.Fatalf("identity = %+v", got)
	}
	if got.Distro != "ubuntu" || got.DistroVersion != "24.04" || got.Source != "dpkg" {
		t.Fatalf("distro/source = %s/%s/%s", got.Distro, got.DistroVersion, got.Source)
	}
	if got.Count != 1 || len(got.Items) != 1 || got.Items[0].Name != "openssl" {
		t.Fatalf("packages = %+v", got.Items)
	}
}

func TestContainerPIDParsesNumberAndNestedString(t *testing.T) {
	if got := containerPID(map[string]any{"pid": float64(4321)}); got != 4321 {
		t.Fatalf("numeric pid = %d, want 4321", got)
	}
	if got := containerPID(map[string]any{"info": map[string]any{"pid": "9876"}}); got != 9876 {
		t.Fatalf("nested string pid = %d, want 9876", got)
	}
}

func TestCollectPackagesAtRootDoesNotFallbackToHost(t *testing.T) {
	root := t.TempDir()
	pkgs, err := collectPackagesAtRoot(root, "node-a", "ubuntu", "24.04")
	if err == nil {
		t.Fatalf("expected error for empty root, got packages: %+v", pkgs)
	}
	if pkgs.Count != 0 || len(pkgs.Items) != 0 {
		t.Fatalf("unexpected packages from fallback: %+v", pkgs)
	}
}

func createTestCRISocket(t *testing.T, root string) net.Listener {
	t.Helper()
	path := filepath.Join(root, "run", "k3s", "containerd", "containerd.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func writeFakeCrictl(t *testing.T, root, response string) string {
	t.Helper()
	path := filepath.Join(root, "crictl")
	body := "#!/bin/sh\ncat <<'JSON'\n" + response + "\nJSON\n"
	if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeContainerOSRelease(t *testing.T, root, distro, version string) {
	t.Helper()
	path := filepath.Join(root, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "ID=" + distro + "\nVERSION_ID=\"" + version + "\"\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeContainerDpkgStatus(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, "var", "lib", "dpkg", "status")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	body := `Package: openssl
Status: install ok installed
Architecture: amd64
Version: 3.0.13-0ubuntu3.5
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
