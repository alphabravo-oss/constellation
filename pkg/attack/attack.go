// Package attack maps syscall / network / file events to MITRE ATT&CK techniques.
//
// The mapping is hand-curated and version-pinned with each agent release (per spec's
// "MITRE ATT&CK mapping table is versioned alongside the agent" rule). Updates require
// a new agent build, never a config-only change, so the technique set the agent claims
// to map is exactly the set in the table.
//
// Source canonical IDs at https://attack.mitre.org/techniques/enterprise/. We carry
// the technique + sub-technique IDs + name + tactic so the UI can pivot
// technique → events → workloads.
package attack

import (
	"sort"
	"strings"
)

// Technique is one ATT&CK technique entry.
type Technique struct {
	ID     string `json:"id"`     // e.g. "T1059.004"
	Name   string `json:"name"`   // e.g. "Unix Shell"
	Tactic string `json:"tactic"` // e.g. "Execution"
}

// Tactic ordering — used by the UI to render technique columns in the canonical kill-chain
// order rather than alphabetically.
var Tactics = []string{
	"Reconnaissance", "Resource Development", "Initial Access", "Execution",
	"Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
	"Discovery", "Lateral Movement", "Collection", "Command and Control",
	"Exfiltration", "Impact",
}

// Catalog is the v1 ATT&CK technique catalog we recognize. ~30 entries — the high-value
// container-runtime techniques. Grows with each agent release.
var Catalog = []Technique{
	{ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"},
	{ID: "T1059.004", Name: "Unix Shell", Tactic: "Execution"},
	{ID: "T1059.006", Name: "Python", Tactic: "Execution"},
	{ID: "T1068", Name: "Exploitation for Privilege Escalation", Tactic: "Privilege Escalation"},
	{ID: "T1611", Name: "Escape to Host", Tactic: "Privilege Escalation"},
	{ID: "T1610", Name: "Deploy Container", Tactic: "Defense Evasion"},
	{ID: "T1613", Name: "Container and Resource Discovery", Tactic: "Discovery"},
	{ID: "T1552", Name: "Unsecured Credentials", Tactic: "Credential Access"},
	{ID: "T1552.001", Name: "Credentials In Files", Tactic: "Credential Access"},
	{ID: "T1552.007", Name: "Container API", Tactic: "Credential Access"},
	{ID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion"},
	{ID: "T1078.004", Name: "Cloud Accounts", Tactic: "Defense Evasion"},
	{ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control"},
	{ID: "T1071.001", Name: "Web Protocols", Tactic: "Command and Control"},
	{ID: "T1071.004", Name: "DNS", Tactic: "Command and Control"},
	{ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactic: "Exfiltration"},
	{ID: "T1567", Name: "Exfiltration Over Web Service", Tactic: "Exfiltration"},
	{ID: "T1486", Name: "Data Encrypted for Impact", Tactic: "Impact"},
	{ID: "T1499", Name: "Endpoint Denial of Service", Tactic: "Impact"},
	{ID: "T1496", Name: "Resource Hijacking", Tactic: "Impact"},
	{ID: "T1574", Name: "Hijack Execution Flow", Tactic: "Persistence"},
	{ID: "T1136", Name: "Create Account", Tactic: "Persistence"},
	{ID: "T1505.003", Name: "Web Shell", Tactic: "Persistence"},
	{ID: "T1027", Name: "Obfuscated Files or Information", Tactic: "Defense Evasion"},
	{ID: "T1140", Name: "Deobfuscate/Decode Files or Information", Tactic: "Defense Evasion"},
	{ID: "T1083", Name: "File and Directory Discovery", Tactic: "Discovery"},
	{ID: "T1057", Name: "Process Discovery", Tactic: "Discovery"},
	{ID: "T1135", Name: "Network Share Discovery", Tactic: "Discovery"},
	{ID: "T1110", Name: "Brute Force", Tactic: "Credential Access"},
	{ID: "T1557", Name: "Adversary-in-the-Middle", Tactic: "Credential Access"},
}

// byID is the lookup map built at init.
var byID = map[string]Technique{}

func init() {
	for _, t := range Catalog {
		byID[t.ID] = t
	}
}

// Get returns the technique entry for an id (with sub-technique fallback to parent).
func Get(id string) (Technique, bool) {
	if t, ok := byID[id]; ok {
		return t, true
	}
	// Try parent technique: "T1059.004" → "T1059".
	if dot := strings.Index(id, "."); dot > 0 {
		if t, ok := byID[id[:dot]]; ok {
			return t, true
		}
	}
	return Technique{}, false
}

// All returns the catalog in stable order (by ID).
func All() []Technique {
	out := append([]Technique(nil), Catalog...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ByTactic groups techniques by their tactic, preserving the canonical Tactics order.
func ByTactic() map[string][]Technique {
	out := map[string][]Technique{}
	for _, t := range Catalog {
		out[t.Tactic] = append(out[t.Tactic], t)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool { return out[k][i].ID < out[k][j].ID })
	}
	return out
}

// EventKind is a coarse classification of a runtime event the agent emits.
type EventKind string

const (
	EventShellSpawn          EventKind = "shell-spawn"
	EventPrivilegeEscalation EventKind = "privesc"
	EventReverseShell        EventKind = "reverse-shell"
	EventCredAccess          EventKind = "cred-access"
	EventCryptoMiner         EventKind = "crypto-miner"
	EventEgress              EventKind = "egress"
	EventDNSTunnel           EventKind = "dns-tunnel"
	EventWriteSensitiveFile  EventKind = "write-sensitive-file"
	EventReadSensitiveFile   EventKind = "read-sensitive-file"
	EventContainerBreakout   EventKind = "container-breakout"
)

// Map returns the ATT&CK technique IDs this event maps to.
func Map(kind EventKind) []string {
	switch kind {
	case EventShellSpawn:
		return []string{"T1059.004"}
	case EventPrivilegeEscalation:
		return []string{"T1068"}
	case EventReverseShell:
		return []string{"T1059.004", "T1071.001"}
	case EventCredAccess:
		return []string{"T1552", "T1552.001"}
	case EventCryptoMiner:
		return []string{"T1496"}
	case EventEgress:
		return []string{"T1071", "T1041"}
	case EventDNSTunnel:
		return []string{"T1071.004", "T1041"}
	case EventWriteSensitiveFile:
		return []string{"T1574"}
	case EventReadSensitiveFile:
		return []string{"T1552.001"}
	case EventContainerBreakout:
		return []string{"T1611"}
	}
	return nil
}
