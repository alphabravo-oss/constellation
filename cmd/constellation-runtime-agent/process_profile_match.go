package main

// P0-2 (process match granularity) + P0-4 (zero-drift) pure decision core.
//
// Today's enforcer (process_enforcer.go / processBaselineAllows) keys only on the
// bare basename (server-side allowedBasenames() collapses name+path.Base() to a
// flat string set). That means `mv evil /bin/nginx` executes as basename "nginx"
// and slips through an nginx-allowed baseline. This file adds a richer matcher
// that mirrors NeuVector's share.CLUSProcessProfileEntry
// (/root/constellation-all/neuvector/share/clus_apis.go:1820): each entry can key
// on full path + optional sha256 hash + parent name + uid, with a per-entry
// allow/deny action. The eBPF exec record already carries filename/exe/ppid/uid;
// process_enforcer.go enriches the rest from /proc.
//
// ponytail: full path/hash/parent/uid enforcement only bites when the server
// process-baseline bundle emits rich entries. The current bundle
// (internal/handler/runtime/process_baselines_bundle.go, a different subsystem)
// still sends a flat []string of basenames, so bridgeBasenameEntries() maps that
// to allow-by-basename entries for backward compatibility. Emitting the rich rows
// (path/sha256/action columns + a migration) is the server-side seam that lets the
// path/hash keys actually reject `mv evil /bin/nginx` via the profile alone; until
// then the zero-drift path below (which needs no server change) is what catches it.

import (
	"path"
	"strings"
)

// processProfileEntry is the agent-side mirror of NeuVector's
// CLUSProcessProfileEntry. Every non-empty field is an AND constraint the exec must
// satisfy for the entry to match; empty fields are wildcards. Action is "allow" or
// "deny" (deny wins over allow when both match).
type processProfileEntry struct {
	Basename   string // matches path.Base(exe) OR comm; "" = any
	Path       string // full executable path; "" = any
	Sha256     string // lowercase hex of the executable; "" = any
	ParentName string // parent process comm/basename; "" = any
	Uid        int64  // effective uid; matched only when UidSet
	UidSet     bool
	Action     string // "allow" | "deny"
}

// processExecContext is the enriched view of a single exec the matcher decides on.
type processExecContext struct {
	Comm       string
	ExePath    string
	Sha256     string
	ParentName string
	Uid        uint32
	UidKnown   bool
}

const (
	processActionAllow = "allow"
	processActionDeny  = "deny"
)

// entryMatches reports whether ex satisfies every constraint the entry specifies.
func entryMatches(e processProfileEntry, ex processExecContext) bool {
	if b := strings.TrimSpace(e.Basename); b != "" {
		if b != path.Base(strings.TrimSpace(ex.ExePath)) && b != strings.TrimSpace(ex.Comm) {
			return false
		}
	}
	if p := strings.TrimSpace(e.Path); p != "" {
		if p != strings.TrimSpace(ex.ExePath) {
			return false
		}
	}
	if h := strings.ToLower(strings.TrimSpace(e.Sha256)); h != "" {
		if h != strings.ToLower(strings.TrimSpace(ex.Sha256)) {
			return false
		}
	}
	if pn := strings.TrimSpace(e.ParentName); pn != "" {
		if pn != strings.TrimSpace(ex.ParentName) {
			return false
		}
	}
	if e.UidSet {
		if !ex.UidKnown || int64(ex.Uid) != e.Uid {
			return false
		}
	}
	return true
}

// processProfileDecision evaluates ex against a profile. It returns the resolved
// action and whether any entry matched. Deny entries take precedence over allow
// entries (fail-closed on an explicit deny). When nothing matches, matched=false
// and the caller applies its allowlist default (unmatched exec == out-of-profile).
func processProfileDecision(entries []processProfileEntry, ex processExecContext) (action string, matched bool) {
	sawAllow := false
	for _, e := range entries {
		if !entryMatches(e, ex) {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(e.Action), processActionDeny) {
			return processActionDeny, true // explicit deny wins immediately
		}
		sawAllow = true
	}
	if sawAllow {
		return processActionAllow, true
	}
	return "", false
}

// processProfileAllows is the allowlist wrapper used by the enforcer: an exec is
// allowed iff the profile has an explicit allow match and no deny match. An empty
// profile allows everything (nothing learned yet -> never block), matching the
// existing "len(Processes)==0 -> never kill" guard.
func processProfileAllows(entries []processProfileEntry, ex processExecContext) bool {
	if len(entries) == 0 {
		return true
	}
	action, matched := processProfileDecision(entries, ex)
	if !matched {
		return false // out-of-profile under an allowlist
	}
	return action == processActionAllow
}

// bridgeBasenameEntries converts the legacy flat basename set (what the current
// server bundle sends) into allow-by-basename entries so the rich matcher stays
// bug-for-bug compatible with processBaselineAllows until the bundle emits rich
// rows. ponytail: server bundle (process_baselines_bundle.go) is the seam that
// would supply Path/Sha256/Action here.
func bridgeBasenameEntries(basenames []string) []processProfileEntry {
	out := make([]processProfileEntry, 0, len(basenames))
	for _, b := range basenames {
		if b = strings.TrimSpace(b); b == "" {
			continue
		}
		out = append(out, processProfileEntry{Basename: b, Action: processActionAllow})
	}
	return out
}

// ----- P0-4 zero-drift (anchor + shield) pure decision -----------------------
//
// Models NeuVector's ProfileZeroDrift (agent/probe/faccess_linux.go
// checkAllowedShieldProcess + process.go IsAllowedShieldProcess). An exec is
// allowed — regardless of name — only when BOTH hold:
//
//   (a) anchored: it descends from the container's root process (lineage intact,
//       not injected via `kubectl exec`/`docker exec`/nsenter), and
//   (b) fromImage: its executable came from the original image and was NOT written
//       after container start (IsNotExistingImageFile in fsn.go).
//
// Anything else is "drift". The root process itself is always anchored+fromImage.

// zeroDriftContext carries the two provenance bits plus a flag for the container
// root process (always allowed, like proc.pid == c.rootPid in IsAllowedShieldProcess).
type zeroDriftContext struct {
	IsRootProcess bool
	Anchored      bool
	FromImage     bool
}

// execIsDrift reports whether an exec violates the zero-drift invariant. The
// container root process is never drift. Otherwise drift == not (anchored AND
// fromImage).
func execIsDrift(z zeroDriftContext) bool {
	if z.IsRootProcess {
		return false
	}
	return !(z.Anchored && z.FromImage)
}
