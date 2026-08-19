// Templates render the per-receiver-kind message body for an outbound delivery.
//
// Each receiver row carries a template_id (default = "default"). The Dispatcher passes
// (receiverKind, templateID, Event) to renderBody which picks the right template and
// produces the request body + Content-Type.
//
// The templates here are intentionally simple Go text/template strings; operators can
// later override via a UI-managed template store, but v1 ships these inline so a fresh
// install delivers nicely-formatted messages without configuration.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"
)

// templateBundle holds parsed templates for one receiver kind.
type templateBundle struct {
	body        *template.Template
	contentType string
}

var (
	tmplMu      sync.RWMutex
	tmplCache   = map[string]*templateBundle{}
)

func renderBody(rec receiverRow, ev Event) ([]byte, string, error) {
	kindKey := strings.ToLower(rec.Kind)
	templateKey := rec.TemplateID
	if templateKey == "" {
		templateKey = "default"
	}
	cacheKey := kindKey + "/" + templateKey

	tmplMu.RLock()
	b, ok := tmplCache[cacheKey]
	tmplMu.RUnlock()
	if !ok {
		raw, ct, err := pickTemplate(kindKey, templateKey)
		if err != nil {
			return nil, "", err
		}
		parsed, err := template.New(cacheKey).Funcs(templateFuncs).Parse(raw)
		if err != nil {
			return nil, "", fmt.Errorf("parse template %s: %w", cacheKey, err)
		}
		b = &templateBundle{body: parsed, contentType: ct}
		tmplMu.Lock()
		tmplCache[cacheKey] = b
		tmplMu.Unlock()
	}

	data := templateData(ev)
	var buf bytes.Buffer
	if err := b.body.Execute(&buf, data); err != nil {
		return nil, "", fmt.Errorf("execute template %s: %w", cacheKey, err)
	}
	return buf.Bytes(), b.contentType, nil
}

func templateData(ev Event) map[string]any {
	payloadJSON := ""
	if ev.Payload != nil {
		if b, err := json.Marshal(ev.Payload); err == nil {
			payloadJSON = string(b)
		}
	}
	return map[string]any{
		"Kind":           ev.Kind,
		"Severity":       nonempty(ev.Severity, "info"),
		"SeverityPD":     mapToPagerDutySeverity(ev.Severity),
		"SNOWUrgency":    mapToSNOWUrgency(ev.Severity),
		"Title":          jsonString(ev.Title),
		"TitleRaw":       ev.Title,
		"Body":           jsonString(ev.Body),
		"BodyRaw":        ev.Body,
		"Cluster":        ev.Cluster,
		"Workload":       ev.Workload,
		"URL":            ev.URL,
		"FiredAt":        ev.FiredAt.UTC().Format(time.RFC3339),
		"IdempotencyKey": ev.IdempotencyKey.String(),
		"OrgID":          ev.OrgID.String(),
		"Labels":         ev.Labels,
		"LabelsJSON":     jsonOr(ev.Labels, "{}"),
		"PayloadJSON":    payloadJSON,
	}
}

func jsonOr(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fallback
	}
	return string(b)
}

// jsonString returns a JSON-string-safe rendering (no surrounding quotes) of a Go
// string. Used inside template bodies so titles with quotes don't break the JSON
// envelope.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	// Strip the leading/trailing quote so callers can embed in their own quoted slot.
	return strings.Trim(string(b), `"`)
}

var templateFuncs = template.FuncMap{
	"upper":      strings.ToUpper,
	"lower":      strings.ToLower,
	"teamsColor": teamsThemeColor,
}

// pickTemplate returns (raw template, content-type) for (receiverKind, templateID).
// Falls back to "default" templateID if the requested one is unknown. Unknown
// receiver kinds fall through to the generic JSON template.
func pickTemplate(kind, id string) (string, string, error) {
	switch kind {
	case "slack":
		return slackTemplate, "application/json", nil
	case "pagerduty":
		return pagerdutyTemplate, "application/json", nil
	case "jira":
		return jiraTemplate, "application/json", nil
	case "servicenow":
		return servicenowTemplate, "application/json", nil
	case "teams":
		return teamsTemplate, "application/json", nil
	case "webhook", "":
		return webhookTemplate, "application/json", nil
	}
	return webhookTemplate, "application/json", nil
}

// Slack: blocks-formatted (header + section). Severity prefix surfaces the priority.
const slackTemplate = `{
  "blocks": [
    {"type":"header","text":{"type":"plain_text","text":"[{{ upper .Severity }}] {{ .Title }}"}},
    {"type":"section","text":{"type":"mrkdwn","text":"*{{ .Kind }}* on _{{ .Cluster }}/{{ .Workload }}_\n<{{ .URL }}|Open in Constellation>"}},
    {"type":"context","elements":[{"type":"mrkdwn","text":"fired {{ .FiredAt }} · idempotency {{ .IdempotencyKey }}"}]}
  ]
}`

// PagerDuty Events API v2: trigger event with severity mapped to PD vocabulary.
const pagerdutyTemplate = `{
  "event_action": "trigger",
  "dedup_key": "{{ .IdempotencyKey }}",
  "payload": {
    "summary": "{{ .Title }}",
    "severity": "{{ .SeverityPD }}",
    "source": "{{ .Cluster }}",
    "component": "{{ .Workload }}",
    "class": "{{ .Kind }}",
    "custom_details": {"url":"{{ .URL }}","org":"{{ .OrgID }}","fired_at":"{{ .FiredAt }}"}
  },
  "links": [{"href":"{{ .URL }}","text":"Open in Constellation"}]
}`

// Jira: REST v3 issue-create with ADF description.
const jiraTemplate = `{
  "fields": {
    "summary": "[Constellation] {{ .Title }}",
    "description": {
      "type": "doc",
      "version": 1,
      "content": [{
        "type":"paragraph",
        "content":[{"type":"text","text":"{{ .Kind }} · severity={{ .Severity }} · cluster={{ .Cluster }} · workload={{ .Workload }} · link={{ .URL }} · fired_at={{ .FiredAt }}"}]
      }]
    },
    "issuetype": {"name":"Task"},
    "labels": ["constellation","{{ lower .Severity }}"]
  }
}`

// ServiceNow: incident table create.
const servicenowTemplate = `{
  "short_description": "[Constellation] {{ .Title }}",
  "description": "{{ .Kind }} on {{ .Cluster }}/{{ .Workload }}. Severity={{ .Severity }}. Link={{ .URL }}. Fired at {{ .FiredAt }}.",
  "urgency": "{{ .SNOWUrgency }}",
  "category": "Security"
}`

// MS Teams: legacy MessageCard (still accepted by Teams Incoming Webhooks). One section
// with the alert facts + an OpenUri action deep-linking back into Constellation.
const teamsTemplate = `{
  "@type": "MessageCard",
  "@context": "http://schema.org/extensions",
  "themeColor": "{{ .Severity | teamsColor }}",
  "summary": "[{{ .Severity }}] {{ .Title }}",
  "title": "[{{ upper .Severity }}] {{ .Title }}",
  "sections": [{
    "activityTitle": "{{ .Title }}",
    "markdown": true,
    "facts": [
      {"name":"Kind","value":"{{ .Kind }}"},
      {"name":"Severity","value":"{{ .Severity }}"},
      {"name":"Cluster","value":"{{ .Cluster }}"},
      {"name":"Workload","value":"{{ .Workload }}"},
      {"name":"Fired","value":"{{ .FiredAt }}"}
    ]
  }],
  "potentialAction": [{
    "@type": "OpenUri",
    "name": "Open in Constellation",
    "targets": [{"os":"default","uri":"{{ .URL }}"}]
  }]
}`

// Generic webhook: envelope with the full event shape so receivers can do their own
// rendering. `signature_header` is documented at the receiver side — the dispatcher
// also sends `X-Constellation-Signature` + `X-Constellation-Idempotency` headers.
const webhookTemplate = `{
  "source": "constellation",
  "kind": "{{ .Kind }}",
  "severity": "{{ .Severity }}",
  "title": "{{ .Title }}",
  "body": "{{ .Body }}",
  "cluster": "{{ .Cluster }}",
  "workload": "{{ .Workload }}",
  "url": "{{ .URL }}",
  "fired_at": "{{ .FiredAt }}",
  "org_id": "{{ .OrgID }}",
  "idempotency_key": "{{ .IdempotencyKey }}",
  "labels": {{ if .LabelsJSON }}{{ .LabelsJSON }}{{ else }}{}{{ end }}
}`
