// Package vulnprofile implements the NeuVector-style vulnerability profile rule engine.
//
// A Profile is a named set of Entries. On scan completion the engine evaluates every
// CVE in the result against the active profile and produces a Decision:
//
//	SuppressAccept — the CVE is acknowledged and should not raise a finding
//	SuppressDefer  — fix is required but the rule grants a grace window
//	Escalate       — the rule explicitly escalates this CVE (e.g. recent + critical)
//	None           — default; no profile decision applies
//
// Reserved entry names (mirrors NeuVector): "_recent" matches CVEs published within
// RecentDays of the current time. Per-domain (cluster / namespace) and per-image
// overrides are encoded as profile DomainScope + entry Images globs.
package vulnprofile

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Decision is the verdict a profile evaluation emits for a CVE.
type Decision string

const (
	DecisionNone           Decision = "none"
	DecisionSuppressAccept Decision = "suppress_accept"
	DecisionSuppressDefer  Decision = "suppress_defer"
	DecisionEscalate       Decision = "escalate"
)

// ActionKind is the entry's effect when its match conditions are met.
type ActionKind string

const (
	ActionSuppress ActionKind = "suppress" // dropped, with optional days_to_fix grace
	ActionEscalate ActionKind = "escalate" // bump severity / raise notification
)

// Entry is one rule inside a profile.
type Entry struct {
	Name          string     `json:"name"`            // identifier
	NameRegex     string     `json:"name_regex,omitempty"` // CVE id regex, e.g. CVE-2024-.*
	Images        []string   `json:"images,omitempty"`     // image-name globs
	Action        ActionKind `json:"action"`
	DaysToFix     int        `json:"days_to_fix,omitempty"` // 0 = no deadline
	SeverityFloor string     `json:"severity_floor,omitempty"` // low|medium|high|critical
	ScoreFloor    float64    `json:"score_floor,omitempty"`    // CVSS base score floor
	Reserved      string     `json:"reserved,omitempty"`       // "" | "_recent"
	RecentDays    int        `json:"recent_days,omitempty"`    // for Reserved=_recent
	Comment       string     `json:"comment,omitempty"`
}

// DomainScope narrows a profile to specific clusters/namespaces.
type DomainScope struct {
	Clusters   []string `json:"clusters,omitempty"`
	Namespaces []string `json:"namespaces,omitempty"`
}

// Profile is a named vulnerability profile.
type Profile struct {
	ID          string      `json:"id,omitempty"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Active      bool        `json:"active"`
	Entries     []Entry     `json:"entries"`
	DomainScope DomainScope `json:"domain_scope,omitempty"`
}

// CVE is the minimal CVE shape the engine inspects.
type CVE struct {
	ID          string
	Severity    string
	BaseScore   float64
	PublishedAt time.Time
	Image       string
	Cluster     string
	Namespace   string
}

// Outcome is the tagged finding decision.
type Outcome struct {
	CVE       string   `json:"cve"`
	Decision  Decision `json:"decision"`
	Reason    string   `json:"reason"`
	EntryName string   `json:"entry_name,omitempty"`
}

// Now is overridable in tests.
var Now = time.Now

// Evaluate runs the active profile against the list of CVEs and returns one
// Outcome per CVE (in input order).
func (p *Profile) Evaluate(cves []CVE) []Outcome {
	out := make([]Outcome, len(cves))
	for i, cv := range cves {
		out[i] = p.evaluateOne(cv)
	}
	return out
}

func (p *Profile) evaluateOne(cv CVE) Outcome {
	if !p.inScope(cv) {
		return Outcome{CVE: cv.ID, Decision: DecisionNone}
	}
	for _, e := range p.Entries {
		matched, reason := entryMatches(e, cv)
		if !matched {
			continue
		}
		switch e.Action {
		case ActionEscalate:
			return Outcome{CVE: cv.ID, Decision: DecisionEscalate, EntryName: e.Name, Reason: reason}
		case ActionSuppress:
			if e.DaysToFix > 0 {
				return Outcome{CVE: cv.ID, Decision: DecisionSuppressDefer, EntryName: e.Name, Reason: reason}
			}
			return Outcome{CVE: cv.ID, Decision: DecisionSuppressAccept, EntryName: e.Name, Reason: reason}
		}
	}
	return Outcome{CVE: cv.ID, Decision: DecisionNone}
}

func (p *Profile) inScope(cv CVE) bool {
	if len(p.DomainScope.Clusters) > 0 && !contains(p.DomainScope.Clusters, cv.Cluster) {
		return false
	}
	if len(p.DomainScope.Namespaces) > 0 && !contains(p.DomainScope.Namespaces, cv.Namespace) {
		return false
	}
	return true
}

// entryMatches returns (matched, reason).
func entryMatches(e Entry, cv CVE) (bool, string) {
	// Reserved: _recent — CVEs published within RecentDays.
	if e.Reserved == "_recent" {
		days := e.RecentDays
		if days <= 0 {
			days = 14
		}
		if cv.PublishedAt.IsZero() {
			return false, ""
		}
		if Now().Sub(cv.PublishedAt) > time.Duration(days)*24*time.Hour {
			return false, ""
		}
	}
	if e.NameRegex != "" {
		re, err := regexp.Compile(e.NameRegex)
		if err != nil || !re.MatchString(cv.ID) {
			return false, ""
		}
	}
	if len(e.Images) > 0 {
		matched := false
		for _, glob := range e.Images {
			if ok, _ := filepath.Match(glob, cv.Image); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false, ""
		}
	}
	if e.SeverityFloor != "" {
		rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
		if rank[strings.ToLower(cv.Severity)] < rank[strings.ToLower(e.SeverityFloor)] {
			return false, ""
		}
	}
	if e.ScoreFloor > 0 && cv.BaseScore < e.ScoreFloor {
		return false, ""
	}
	return true, e.Name
}

// Validate returns an error if the profile is malformed.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("vulnprofile: name required")
	}
	for i, e := range p.Entries {
		if strings.TrimSpace(e.Name) == "" {
			return fmt.Errorf("vulnprofile: entry %d: name required", i)
		}
		if e.Action != ActionSuppress && e.Action != ActionEscalate {
			return fmt.Errorf("vulnprofile: entry %d: invalid action %q", i, e.Action)
		}
		if e.NameRegex != "" {
			if _, err := regexp.Compile(e.NameRegex); err != nil {
				return fmt.Errorf("vulnprofile: entry %d: bad regex: %w", i, err)
			}
		}
		if e.Reserved != "" && e.Reserved != "_recent" {
			return fmt.Errorf("vulnprofile: entry %d: unknown reserved %q", i, e.Reserved)
		}
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
