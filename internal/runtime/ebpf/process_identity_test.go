package ebpf

import (
	"context"
	"testing"
)

type identityTestLoader struct {
	value uint64
	known bool
}

func (l *identityTestLoader) Start(context.Context, func(Event)) error   { return nil }
func (l *identityTestLoader) Close() error                               { return nil }
func (l *identityTestLoader) ProcessStartIdentity(uint32) (uint64, bool) { return l.value, l.known }

type legacyIdentityTestLoader struct{}

func (l *legacyIdentityTestLoader) Start(context.Context, func(Event)) error { return nil }
func (l *legacyIdentityTestLoader) Close() error                             { return nil }
func TestAgentExactProcessIdentityIsOptionalForCapture(t *testing.T) {
	for _, provider := range []loader{nil, &legacyIdentityTestLoader{}, &identityTestLoader{}} {
		agent := &Agent{events: make(chan Event, 1), loader: provider}
		if value, known := agent.ProcessStartIdentity(4242); known || value != 0 {
			t.Fatal("unsupported identity invented a process start")
		}
		event := Event{Kind: EventKindProcess, Process: &ProcessEvent{PID: 4242}}
		if err := agent.Inject(event); err != nil {
			t.Fatal(err)
		}
		if captured := <-agent.Events(); captured.Process.PID != 4242 {
			t.Fatal("missing response identity stopped ordinary capture")
		}
	}
	agent := &Agent{loader: &identityTestLoader{value: 12349999999, known: true}}
	if value, known := agent.ProcessStartIdentity(4242); !known || value != 12349999999 {
		t.Fatal("exact source identity was lost")
	}
	agent.closed = true
	if _, known := agent.ProcessStartIdentity(4242); known {
		t.Fatal("closed agent retained actionable identity")
	}
}
