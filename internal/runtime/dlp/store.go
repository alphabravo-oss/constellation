// Package dlp is the userspace DLP sensor store + API surface.
//
// SCOPE: Wave D owns the sensor catalog + REST CRUD. The data plane (in-line traffic
// inspection) is owned by Wave A.
//
// A DlpSensor is a named bundle of pattern rules with an operating context
// (header / body / url) and an action (alert / block). Predefined sensors mirror
// the NeuVector "Federal" pack (CC / SSN / national IDs) and add modern secret
// patterns (AWS access keys, GitHub PATs, Slack tokens, Stripe keys, generic
// high-entropy strings).
package dlp

import (
	"fmt"
	"strings"
)

// CfgType classifies a sensor as Federal / Predefined / User.
type CfgType string

const (
	CfgFederal    CfgType = "federal"
	CfgPredefined CfgType = "predefined"
	CfgUser       CfgType = "user"
)

// Action is the verdict when a rule fires.
type Action string

const (
	ActionAlert Action = "alert"
	ActionBlock Action = "block"
)

// Context is the request part the rule inspects.
type Context string

const (
	ContextHeader Context = "header"
	ContextBody   Context = "body"
	ContextURL    Context = "url"
)

// DlpRule is one pattern rule.
type DlpRule struct {
	Name    string  `json:"name"`
	Pattern string  `json:"pattern"` // PCRE
	Context Context `json:"context"`
	Action  Action  `json:"action"`
	Comment string  `json:"comment,omitempty"`
}

// DlpSensor is a named set of rules.
type DlpSensor struct {
	ID      string    `json:"id,omitempty"`
	Name    string    `json:"name"`
	CfgType CfgType   `json:"cfg_type"`
	Rules   []DlpRule `json:"rules"`
	Comment string    `json:"comment,omitempty"`
}

// Validate returns an error if s is malformed.
func (s *DlpSensor) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("dlp: name required")
	}
	switch s.CfgType {
	case CfgFederal, CfgPredefined, CfgUser:
	default:
		return fmt.Errorf("dlp: invalid cfg_type %q", s.CfgType)
	}
	for i, r := range s.Rules {
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("dlp: rule %d: name required", i)
		}
		if err := CompilePattern(r.Pattern); err != nil {
			return fmt.Errorf("dlp: rule %d: bad pattern: %w", i, err)
		}
		switch r.Context {
		case ContextHeader, ContextBody, ContextURL:
		default:
			return fmt.Errorf("dlp: rule %d: invalid context %q", i, r.Context)
		}
		switch r.Action {
		case ActionAlert, ActionBlock:
		default:
			return fmt.Errorf("dlp: rule %d: invalid action %q", i, r.Action)
		}
	}
	return nil
}

// DefaultCatalog returns the predefined sensor catalog (Federal + modern secrets).
// This is loaded at server boot as seed entries when an org has no sensors yet.
func DefaultCatalog() []DlpSensor {
	return []DlpSensor{
		{
			Name: "federal-pii", CfgType: CfgFederal,
			Comment: "Credit cards (Luhn-style), US SSN, common EU national IDs",
			Rules: []DlpRule{
				{Name: "credit-card", Pattern: `\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011|65\d{2})[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`, Context: ContextBody, Action: ActionAlert},
				{Name: "us-ssn", Pattern: `\b\d{3}-\d{2}-\d{4}\b`, Context: ContextBody, Action: ActionAlert},
				{Name: "uk-nino", Pattern: `\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b`, Context: ContextBody, Action: ActionAlert},
				{Name: "de-tax-id", Pattern: `\b\d{11}\b`, Context: ContextBody, Action: ActionAlert},
			},
		},
		{
			Name: "modern-secrets", CfgType: CfgPredefined,
			Comment: "AWS keys, GitHub PATs, Slack tokens, Stripe keys, high-entropy strings",
			Rules: []DlpRule{
				{Name: "aws-access-key", Pattern: `AKIA[0-9A-Z]{16}`, Context: ContextBody, Action: ActionBlock},
				{Name: "github-pat", Pattern: `gh[pousr]_[A-Za-z0-9]{36,}`, Context: ContextHeader, Action: ActionBlock},
				{Name: "slack-token", Pattern: `xox[abprs]-[A-Za-z0-9-]{10,}`, Context: ContextBody, Action: ActionBlock},
				{Name: "stripe-secret", Pattern: `sk_(test|live)_[A-Za-z0-9]{24,}`, Context: ContextBody, Action: ActionBlock},
				{Name: "generic-high-entropy", Pattern: `\b[A-Za-z0-9+/]{40,}={0,2}\b`, Context: ContextBody, Action: ActionAlert},
			},
		},
	}
}
