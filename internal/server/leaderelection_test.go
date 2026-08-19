package server

import (
	"testing"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler"
)

// TestRegistryWalkerInterval covers the P1-11 wiring: the api server now runs the
// scheduled-registry-rescan loop leader-gated, reading its cadence from
// WALKER_INTERVAL and falling back to the handler default. Without the wiring these
// helpers do not exist and the loop never ticks in a shipped deploy.
func TestRegistryWalkerInterval(t *testing.T) {
	t.Setenv("WALKER_INTERVAL", "")
	if got := registryWalkerInterval(); got != handler.DefaultRegistryWalkerInterval {
		t.Fatalf("empty WALKER_INTERVAL = %v, want default %v", got, handler.DefaultRegistryWalkerInterval)
	}
	t.Setenv("WALKER_INTERVAL", "90s")
	if got := registryWalkerInterval(); got != 90*time.Second {
		t.Fatalf("WALKER_INTERVAL=90s = %v, want 90s", got)
	}
	// Unparseable / non-positive falls back to the default (fail safe, never 0).
	for _, v := range []string{"garbage", "0s", "-5s"} {
		t.Setenv("WALKER_INTERVAL", v)
		if got := registryWalkerInterval(); got != handler.DefaultRegistryWalkerInterval {
			t.Fatalf("WALKER_INTERVAL=%q = %v, want default", v, got)
		}
	}
}

func TestRegistryWalkerConcurrency(t *testing.T) {
	t.Setenv("WALKER_CONCURRENCY", "")
	if got := registryWalkerConcurrency(); got != handler.DefaultRegistryWalkerConcurrency {
		t.Fatalf("empty WALKER_CONCURRENCY = %d, want default %d", got, handler.DefaultRegistryWalkerConcurrency)
	}
	t.Setenv("WALKER_CONCURRENCY", "8")
	if got := registryWalkerConcurrency(); got != 8 {
		t.Fatalf("WALKER_CONCURRENCY=8 = %d, want 8", got)
	}
	// Invalid / <1 falls back to the default so the loop never runs with a 0-size
	// semaphore (which would deadlock the tick).
	for _, v := range []string{"garbage", "0", "-3"} {
		t.Setenv("WALKER_CONCURRENCY", v)
		if got := registryWalkerConcurrency(); got != handler.DefaultRegistryWalkerConcurrency {
			t.Fatalf("WALKER_CONCURRENCY=%q = %d, want default", v, got)
		}
	}
}

// TestEnvBoolDefaultOff locks in the D5 safety contract: with
// LEADER_ELECTION_ENABLED unset, leader election is off, so the singleton loops
// run inline exactly as in the historical single-replica deploy.
func TestEnvBoolDefaultOff(t *testing.T) {
	t.Setenv("LEADER_ELECTION_ENABLED", "")
	if envBool("LEADER_ELECTION_ENABLED", false) {
		t.Fatal("leader election must default to off when unset")
	}
	for _, v := range []string{"1", "true", "on", "yes", "enabled"} {
		t.Setenv("LEADER_ELECTION_ENABLED", v)
		if !envBool("LEADER_ELECTION_ENABLED", false) {
			t.Fatalf("envBool(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"0", "false", "off", "garbage"} {
		t.Setenv("LEADER_ELECTION_ENABLED", v)
		if envBool("LEADER_ELECTION_ENABLED", false) {
			t.Fatalf("envBool(%q) = true, want false", v)
		}
	}
}

func TestEnvDefault(t *testing.T) {
	t.Setenv("X_LE_TEST", "")
	if got := env("X_LE_TEST", "fallback"); got != "fallback" {
		t.Fatalf("env empty = %q, want fallback", got)
	}
	t.Setenv("X_LE_TEST", "  set  ")
	if got := env("X_LE_TEST", "fallback"); got != "set" {
		t.Fatalf("env trimmed = %q, want set", got)
	}
}
