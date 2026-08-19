package quarantine

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestExecuteSnapshot(t *testing.T) {
	dir := t.TempDir()
	q, err := New(Options{OutputDir: dir, DryRun: false}, CollectorSet{
		Cordon: LocalCordonCollector(),
		Proc: func(ctx context.Context, pid int) (map[string][]byte, error) {
			return map[string][]byte{
				"cmdline": []byte("nginx -g daemon off;"),
				"status":  []byte("Name:\tnginx\nState:\tS (sleeping)\n"),
			}, nil
		},
		Logs: func(ctx context.Context, ns, pod string, lines int) (map[string][]string, error) {
			return map[string][]string{
				"nginx": {"2026-05-12 access GET /", "2026-05-12 error: SQLi"},
			}, nil
		},
		PCAP: func(ctx context.Context, veth string, _ time.Duration, _ int64) ([]byte, error) {
			return []byte("PCAP-bytes"), nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tgt := Target{
		Namespace: "default", Pod: "web-1", WorkloadID: "default/Deployment/web",
		PID: 1234, Veth: "veth1234",
	}
	trig := Trigger{Source: "waf", Reason: "SQLi: CRS 942100", Severity: "critical", Match: "942100"}

	res, err := q.Execute(context.Background(), tgt, trig)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.HasSuffix(res.TarballPath, ".tar.gz") {
		t.Fatalf("bad tarball name: %s", res.TarballPath)
	}
	if !strings.Contains(res.NetPolicy, "constellation-quarantine") {
		t.Fatalf("missing netpolicy yaml")
	}

	parts, m, err := Restore(res.TarballPath)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, ok := parts["manifest.json"]; !ok {
		t.Fatalf("manifest missing from tarball")
	}
	if _, ok := parts["proc/cmdline"]; !ok {
		t.Fatalf("proc snapshot missing")
	}
	if _, ok := parts["logs/nginx.log"]; !ok {
		t.Fatalf("logs missing")
	}
	if _, ok := parts["capture.pcap"]; !ok {
		t.Fatalf("pcap missing")
	}
	if m.SHA256 == "" {
		t.Fatalf("manifest sha256 empty")
	}
	if m.Target.PID != 1234 || m.Trigger.Source != "waf" {
		t.Fatalf("manifest target/trigger wrong: %+v", m)
	}
}

func TestDryRunSkipsCordon(t *testing.T) {
	dir := t.TempDir()
	q, err := New(Options{OutputDir: dir, DryRun: true}, CollectorSet{
		Cordon: LocalCordonCollector(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := q.Execute(context.Background(), Target{Namespace: "ns", Pod: "p"}, Trigger{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.NetPolicy != "" {
		t.Fatalf("dry run should NOT apply netpolicy, got %s", res.NetPolicy)
	}
}

func TestRenderCordonYAML(t *testing.T) {
	y := RenderCordonYAML(Target{Namespace: "ns", Pod: "web-1", WorkloadID: "ns/Deployment/web"})
	if !strings.Contains(y, "podSelector") || !strings.Contains(y, "kube-dns") {
		t.Fatalf("bad yaml: %s", y)
	}
}
