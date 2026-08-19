package runtime

import (
	"context"
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/runtime/ebpf"
	"github.com/alphabravocompany/constellation/pkg/reachability"
)

func TestConfirmsViaProcessExec(t *testing.T) {
	var marks []Mark
	c := New(nil, func(m Mark) { marks = append(marks, m) })

	c.AddSubject(Subject{
		VulnerabilityID: "CVE-2024-9999",
		Symbol:          "main.BadFunc",
		ExePath:         "/usr/local/bin/payments",
	})

	c.OnEvent(ebpf.Event{
		Kind: ebpf.EventKindProcess,
		Process: &ebpf.ProcessEvent{
			PID: 1234, Comm: "payments", Filename: "/usr/local/bin/payments",
			ContainerID: "abc",
		},
	})

	if len(marks) != 1 {
		t.Fatalf("expected 1 mark, got %d", len(marks))
	}
	if marks[0].Source != SourceProcess || marks[0].VulnerabilityID != "CVE-2024-9999" {
		t.Fatalf("bad mark: %+v", marks[0])
	}
}

func TestConfirmsViaLibraryLoad(t *testing.T) {
	var marks []Mark
	c := New(nil, func(m Mark) { marks = append(marks, m) })

	c.AddSubject(Subject{
		VulnerabilityID: "CVE-2024-1234",
		Symbol:          "SSL_read",
		LibraryName:     "libssl.so.3",
	})

	c.OnEvent(ebpf.Event{
		Kind: ebpf.EventKindFile,
		File: &ebpf.FileEvent{
			PID: 4444, Path: "/usr/lib/x86_64-linux-gnu/libssl.so.3",
			ContainerID: "xyz",
		},
	})

	if len(marks) != 1 {
		t.Fatalf("expected 1 mark, got %d", len(marks))
	}
	if marks[0].Source != SourceLibLoad {
		t.Fatalf("bad source: %s", marks[0].Source)
	}
}

func TestDedup(t *testing.T) {
	var marks []Mark
	c := New(nil, func(m Mark) { marks = append(marks, m) })
	c.AddSubject(Subject{VulnerabilityID: "CVE-1", ExePath: "/x"})
	for range 5 {
		c.OnEvent(ebpf.Event{Kind: ebpf.EventKindProcess, Process: &ebpf.ProcessEvent{Filename: "/x"}})
	}
	if len(marks) != 1 {
		t.Fatalf("dedup failed; got %d marks", len(marks))
	}
}

func TestLoadFromVerdicts(t *testing.T) {
	c := New(nil, nil)
	c.LoadFromVerdicts([]reachability.Verdict{
		{VulnerabilityID: "CVE-1", Symbol: "pkg.Foo", Module: "m1"},
		{VulnerabilityID: "CVE-empty"}, // skipped (no symbol/module)
	})
	subs := c.Subjects()
	if len(subs) != 1 || subs[0].VulnerabilityID != "CVE-1" {
		t.Fatalf("bad load: %+v", subs)
	}
}

func TestRunDrainsChannel(t *testing.T) {
	c := New(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	ch := make(chan ebpf.Event, 4)
	ch <- ebpf.Event{Kind: ebpf.EventKindProcess, Process: &ebpf.ProcessEvent{}}
	close(ch)
	if err := c.Run(ctx, ch); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestAttachUprobeStub(t *testing.T) {
	_, err := AttachUprobe("/bin/true", "main.main", nil)
	if err == nil {
		t.Fatal("expected error from closed event source")
	}
}
