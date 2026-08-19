package main

import (
	"os"
	"strings"
)

// protectedSet is the NON-OVERRIDABLE guard that stops runtime enforcement from
// ever acting on the platform's own components, Kubernetes system infrastructure,
// or the host/node itself. It is modeled on NeuVector's capBlock / GetPlatformRole
// exemption (agent/engine.go:1209, share/orchestration/kubernetes.go:472): those
// containers structurally cannot enter block mode, regardless of any rule an
// operator writes.
//
// The CORE set — this agent's own namespace (self-protection) plus the kube-system
// family plus the host/node — is baked in and cannot be removed by configuration.
// An operator may only ADD extra protected namespaces, never subtract. That one-way
// door is the whole point: a mis-scoped or malicious enforcement rule must not be
// able to kill Constellation itself or brick the node.
type protectedSet struct {
	namespaces map[string]struct{}
}

// coreProtectedNamespaces are always protected and can never be removed by config.
// These are Kubernetes' own control-plane/system namespaces; the agent's own
// namespace is added on top from the downward API (see newProtectedSet).
var coreProtectedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
}

// newProtectedSet builds the guard from the agent's own namespace (self-protection),
// the hardcoded system namespaces, and any operator-supplied additions. ownNamespace
// comes from the downward API (CONSTELLATION_POD_NAMESPACE); extra is additive-only.
func newProtectedSet(ownNamespace string, extra []string) *protectedSet {
	ns := make(map[string]struct{}, len(coreProtectedNamespaces)+len(extra)+1)
	for _, n := range coreProtectedNamespaces {
		ns[n] = struct{}{}
	}
	// Self-protection: the agent's own namespace (constellation-system by default,
	// but taken from the live pod so a non-default install is still protected).
	if own := strings.TrimSpace(ownNamespace); own != "" {
		ns[own] = struct{}{}
	}
	for _, e := range extra {
		if e = strings.TrimSpace(e); e != "" {
			ns[e] = struct{}{}
		}
	}
	return &protectedSet{namespaces: ns}
}

// newProtectedSetFromEnv wires the guard from the runtime environment: the agent's
// own namespace plus the additive CONSTELLATION_ENFORCEMENT_PROTECTED_NAMESPACES
// (comma-separated). The env list can only extend the set, never shrink the core.
func newProtectedSetFromEnv(ownNamespace string) *protectedSet {
	return newProtectedSet(ownNamespace, parseProtectedNamespaceList(os.Getenv("CONSTELLATION_ENFORCEMENT_PROTECTED_NAMESPACES")))
}

// protectsNamespace reports whether a namespace is in the protected set.
func (p *protectedSet) protectsNamespace(namespace string) bool {
	if p == nil {
		return false
	}
	_, ok := p.namespaces[strings.TrimSpace(namespace)]
	return ok
}

// protects reports whether enforcement must NEVER act on this target.
//
//   - A host/node process (no container ID) is ALWAYS protected — the node is
//     sacrosanct, mirroring NeuVector's `if id == "" { return true }`
//     (agent/probe/process.go:3223). Enforcement never touches host binaries.
//   - A container is protected when its namespace is in the set (own/system/extra).
//
// Callers use this at BOTH mark-time (do not arm fanotify on a protected container)
// and decision-time (allow immediately) so the guard holds even if one path is
// missed — defense in depth.
func (p *protectedSet) protects(containerID, namespace string) bool {
	if strings.TrimSpace(containerID) == "" {
		return true // host/node process — never enforce
	}
	return p.protectsNamespace(namespace)
}

// parseProtectedNamespaceList splits a comma-separated namespace list, trimming
// blanks. Nil for an empty/whitespace input.
func parseProtectedNamespaceList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
