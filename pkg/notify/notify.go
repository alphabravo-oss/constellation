// Package notify is the ITSM / chat integration layer + Alertmanager-style routing tree.
//
// Connectors implemented at v1: Slack (Incoming Webhook), Jira (REST v3 issue create),
// ServiceNow (Table API), PagerDuty (Events API v2), generic webhook (POST JSON).
//
// The Router matches Alert records against a tree of (match, route) nodes and dispatches
// to the configured channels. Grouping + inhibition mirror Alertmanager semantics: alerts
// with the same group-by key inside the group_wait interval batch into one notification,
// and an inhibit rule suppresses lower-priority alerts when a higher-priority alert is firing.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// Alert is the minimal record a router dispatches. It's purposefully smaller than the full
// Constellation Finding so the router doesn't pull in DB types.
type Alert struct {
	ID          string
	OrgID       string
	Severity    string // info | low | medium | high | critical
	Kind        string // finding | runtime | compliance | drift | …
	Title       string
	Cluster     string
	Workload    string
	Labels      map[string]string
	URL         string // deep-link back to Constellation
	FiredAt     time.Time
}

// Receiver is one notification destination.
type Receiver interface {
	Name() string
	Send(ctx context.Context, alerts []Alert) error
}

// ----------------------------------- Slack -------------------------------------------

type Slack struct {
	WebhookURL string
	HTTP       *http.Client
}

func NewSlack(webhookURL string) *Slack {
	return &Slack{WebhookURL: webhookURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (s *Slack) Name() string { return "slack" }

func (s *Slack) Send(ctx context.Context, alerts []Alert) error {
	if s.WebhookURL == "" {
		return errors.New("slack: WebhookURL empty")
	}
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": fmt.Sprintf("🛰  %d Constellation alerts", len(alerts))}},
	}
	for _, a := range alerts {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*<%s|%s>*\n_%s · %s · %s_", a.URL, a.Title, a.Severity, a.Cluster, a.Workload),
			},
		})
	}
	body, _ := json.Marshal(map[string]any{"blocks": blocks})
	return postJSON(ctx, s.HTTP, s.WebhookURL, body, nil)
}

// ----------------------------------- PagerDuty ---------------------------------------

type PagerDuty struct {
	IntegrationKey string
	HTTP           *http.Client
}

func NewPagerDuty(integrationKey string) *PagerDuty {
	return &PagerDuty{IntegrationKey: integrationKey, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (p *PagerDuty) Name() string { return "pagerduty" }

func (p *PagerDuty) Send(ctx context.Context, alerts []Alert) error {
	if p.IntegrationKey == "" {
		return errors.New("pagerduty: IntegrationKey empty")
	}
	for _, a := range alerts {
		ev := map[string]any{
			"routing_key":  p.IntegrationKey,
			"event_action": "trigger",
			"dedup_key":    a.ID,
			"payload": map[string]any{
				"summary":   a.Title,
				"severity":  mapToPagerDutySeverity(a.Severity),
				"source":    a.Cluster,
				"component": a.Workload,
				"class":     a.Kind,
				"custom_details": a.Labels,
			},
			"links": []map[string]string{{"href": a.URL, "text": "Open in Constellation"}},
		}
		body, _ := json.Marshal(ev)
		if err := postJSON(ctx, p.HTTP, "https://events.pagerduty.com/v2/enqueue", body, nil); err != nil {
			return err
		}
	}
	return nil
}

func mapToPagerDutySeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high":
		return "error"
	case "medium":
		return "warning"
	}
	return "info"
}

// ----------------------------------- Jira --------------------------------------------

type Jira struct {
	BaseURL   string // e.g. https://yourorg.atlassian.net
	Email     string
	APIToken  string
	ProjectID string
	IssueType string // "Task" | "Bug" — defaults to "Task"
	HTTP      *http.Client
}

func NewJira(baseURL, email, apiToken, projectID string) *Jira {
	return &Jira{BaseURL: baseURL, Email: email, APIToken: apiToken, ProjectID: projectID,
		IssueType: "Task", HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (j *Jira) Name() string { return "jira" }

func (j *Jira) Send(ctx context.Context, alerts []Alert) error {
	if j.BaseURL == "" || j.Email == "" || j.APIToken == "" || j.ProjectID == "" {
		return errors.New("jira: BaseURL/Email/APIToken/ProjectID all required")
	}
	for _, a := range alerts {
		issue := map[string]any{
			"fields": map[string]any{
				"project":     map[string]string{"key": j.ProjectID},
				"summary":     "[Constellation] " + a.Title,
				"description": atlassianDoc(fmt.Sprintf("Severity: %s\nCluster: %s\nWorkload: %s\nLink: %s",
					a.Severity, a.Cluster, a.Workload, a.URL)),
				"issuetype": map[string]string{"name": j.IssueType},
				"labels":    []string{"constellation", strings.ToLower(a.Severity)},
			},
		}
		body, _ := json.Marshal(issue)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, j.BaseURL+"/rest/api/3/issue", bytes.NewReader(body))
		req.SetBasicAuth(j.Email, j.APIToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := j.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("jira: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("jira: status %d", resp.StatusCode)
		}
	}
	return nil
}

// atlassianDoc wraps a plain-text body in Jira's Atlassian Document Format (ADF) shape.
func atlassianDoc(text string) map[string]any {
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": []map[string]any{{
			"type": "paragraph",
			"content": []map[string]any{{"type": "text", "text": text}},
		}},
	}
}

// ----------------------------------- ServiceNow --------------------------------------

type ServiceNow struct {
	InstanceURL string // e.g. https://yourorg.service-now.com
	Username    string
	Password    string
	HTTP        *http.Client
}

func NewServiceNow(instanceURL, username, password string) *ServiceNow {
	return &ServiceNow{InstanceURL: instanceURL, Username: username, Password: password,
		HTTP: &http.Client{Timeout: 15 * time.Second}}
}

func (s *ServiceNow) Name() string { return "servicenow" }

func (s *ServiceNow) Send(ctx context.Context, alerts []Alert) error {
	if s.InstanceURL == "" {
		return errors.New("servicenow: InstanceURL empty")
	}
	for _, a := range alerts {
		incident := map[string]any{
			"short_description": "[Constellation] " + a.Title,
			"description":       fmt.Sprintf("Severity: %s\nCluster: %s\nWorkload: %s\nLink: %s", a.Severity, a.Cluster, a.Workload, a.URL),
			"urgency":           mapToSNOWUrgency(a.Severity),
			"category":          "Security",
		}
		body, _ := json.Marshal(incident)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.InstanceURL+"/api/now/table/incident", bytes.NewReader(body))
		req.SetBasicAuth(s.Username, s.Password)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := s.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("servicenow: %w", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 300 {
			return fmt.Errorf("servicenow: status %d", resp.StatusCode)
		}
	}
	return nil
}

func mapToSNOWUrgency(severity string) string {
	switch severity {
	case "critical":
		return "1"
	case "high":
		return "2"
	case "medium":
		return "3"
	}
	return "3"
}

// ----------------------------------- Generic Webhook ---------------------------------

type Webhook struct {
	URL     string
	Headers map[string]string
	HTTP    *http.Client
}

func NewWebhook(url string, headers map[string]string) *Webhook {
	return &Webhook{URL: url, Headers: headers, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Send(ctx context.Context, alerts []Alert) error {
	body, _ := json.Marshal(map[string]any{"alerts": alerts, "source": "constellation"})
	return postJSON(ctx, w.HTTP, w.URL, body, w.Headers)
}

// ----------------------------------- MS Teams ----------------------------------------

// Teams posts a legacy MessageCard (the connector-webhook format still accepted by
// Teams Incoming Webhooks) to an Office 365 / Teams webhook URL. Same shape as Slack:
// one webhook URL, JSON POST. We batch all alerts into a single card with one section
// per alert so a group fires one Teams message.
type Teams struct {
	WebhookURL string
	HTTP       *http.Client
}

func NewTeams(webhookURL string) *Teams {
	return &Teams{WebhookURL: webhookURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

func (t *Teams) Name() string { return "teams" }

func (t *Teams) Send(ctx context.Context, alerts []Alert) error {
	if t.WebhookURL == "" {
		return errors.New("teams: WebhookURL empty")
	}
	body, err := teamsMessageCard(alerts)
	if err != nil {
		return err
	}
	return postJSON(ctx, t.HTTP, t.WebhookURL, body, nil)
}

// teamsMessageCard builds a MessageCard JSON payload from a batch of alerts. Exported
// shape is exercised by the unit tests so payload formatting is verified without I/O.
func teamsMessageCard(alerts []Alert) ([]byte, error) {
	themeColor := "808080"
	if len(alerts) > 0 {
		themeColor = teamsThemeColor(alerts[0].Severity)
	}
	sections := make([]map[string]any, 0, len(alerts))
	actions := make([]map[string]any, 0, len(alerts))
	for _, a := range alerts {
		facts := []map[string]string{
			{"name": "Severity", "value": a.Severity},
			{"name": "Kind", "value": a.Kind},
			{"name": "Cluster", "value": a.Cluster},
			{"name": "Workload", "value": a.Workload},
		}
		sections = append(sections, map[string]any{
			"activityTitle": a.Title,
			"facts":         facts,
			"markdown":      true,
		})
		if a.URL != "" {
			actions = append(actions, map[string]any{
				"@type": "OpenUri",
				"name":  "Open in Constellation",
				"targets": []map[string]string{
					{"os": "default", "uri": a.URL},
				},
			})
		}
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": themeColor,
		"summary":    fmt.Sprintf("%d Constellation alerts", len(alerts)),
		"title":      fmt.Sprintf("🛰 %d Constellation alerts", len(alerts)),
		"sections":   sections,
	}
	if len(actions) > 0 {
		card["potentialAction"] = actions
	}
	return json.Marshal(card)
}

// teamsThemeColor maps severity to a MessageCard hex theme color (no leading #).
func teamsThemeColor(severity string) string {
	switch severity {
	case "critical":
		return "b10000"
	case "high":
		return "d83b01"
	case "medium":
		return "f2c811"
	case "low":
		return "107c10"
	}
	return "808080"
}

// ----------------------------------- Syslog / SIEM ------------------------------------

// Syslog writes one RFC5424-framed message per alert to a syslog collector over UDP or
// TCP. It is a non-HTTP receiver: a SIEM that ingests syslog (Splunk, QRadar, Sentinel
// via a forwarder, rsyslog, …) becomes a routable destination. Network is the transport
// ("udp"|"tcp"); Addr is host:port. Facility/AppName default to local0/constellation.
type Syslog struct {
	Network  string // "udp" | "tcp"; default "udp"
	Addr     string // host:port, e.g. "siem.internal:514"
	Facility int    // syslog facility number (0-23); default 16 (local0)
	AppName  string // RFC5424 APP-NAME; default "constellation"
	Hostname string // RFC5424 HOSTNAME; default OS hostname
	Timeout  time.Duration

	// Now lets tests pin the timestamp; defaults to time.Now.
	Now func() time.Time
}

func NewSyslog(network, addr string) *Syslog {
	if network == "" {
		network = "udp"
	}
	return &Syslog{Network: network, Addr: addr, Facility: 16, AppName: "constellation"}
}

func (s *Syslog) Name() string { return "syslog" }

func (s *Syslog) Send(ctx context.Context, alerts []Alert) error {
	if s.Addr == "" {
		return errors.New("syslog: Addr empty")
	}
	network := s.Network
	if network == "" {
		network = "udp"
	}
	d := net.Dialer{Timeout: nonzeroDur(s.Timeout, 10*time.Second)}
	conn, err := d.DialContext(ctx, network, s.Addr)
	if err != nil {
		return fmt.Errorf("syslog: dial %s %s: %w", network, s.Addr, err)
	}
	defer conn.Close()
	for _, a := range alerts {
		msg := s.formatRFC5424(a)
		if _, err := io.WriteString(conn, msg); err != nil {
			return fmt.Errorf("syslog: write: %w", err)
		}
	}
	return nil
}

// formatRFC5424 renders one alert as an RFC5424 syslog line (with a trailing newline so
// stream/TCP collectors frame on it). PRI = facility*8 + severity. STRUCTURED-DATA carries
// the alert's identifying fields under a Constellation-namespaced SD-ID.
func (s *Syslog) formatRFC5424(a Alert) string {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	facility := s.Facility
	if facility < 0 || facility > 23 {
		facility = 16
	}
	pri := facility*8 + syslogSeverity(a.Severity)
	host := nonempty(s.Hostname, osHostname())
	app := nonempty(s.AppName, "constellation")
	ts := a.FiredAt
	if ts.IsZero() {
		ts = now()
	}
	msgID := nonempty(a.Kind, "alert")
	sd := fmt.Sprintf(
		`[constellation@52580 id="%s" severity="%s" cluster="%s" workload="%s" url="%s"]`,
		sdEscape(a.ID), sdEscape(a.Severity), sdEscape(a.Cluster), sdEscape(a.Workload), sdEscape(a.URL))
	// VERSION=1, PROCID=- ; MSG is the human title.
	return fmt.Sprintf("<%d>1 %s %s %s - %s %s %s\n",
		pri, ts.UTC().Format(time.RFC3339), host, app, msgID, sd, a.Title)
}

// syslogSeverity maps Constellation severity to the RFC5424 severity number
// (0 Emergency … 7 Debug).
func syslogSeverity(severity string) int {
	switch severity {
	case "critical":
		return 2 // Critical
	case "high":
		return 3 // Error
	case "medium":
		return 4 // Warning
	case "low":
		return 5 // Notice
	case "info":
		return 6 // Informational
	}
	return 6
}

// sdEscape escapes the three characters RFC5424 reserves inside SD-PARAM values.
func sdEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(s)
}

func osHostname() string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	return "-"
}

func nonzeroDur(d, fallback time.Duration) time.Duration {
	if d <= 0 {
		return fallback
	}
	return d
}

// ----------------------------------- Routing tree ------------------------------------

// Route is one node in the Alertmanager-style match tree. Children are evaluated after
// the parent matches; the first matching leaf wins (or all leaves, if Continue=true).
type Route struct {
	Match    map[string]string // label key→value (substring match)
	GroupBy  []string          // labels to group on
	GroupWait time.Duration    // batch window before sending
	Continue bool              // when true, descend into siblings too
	Receivers []string         // names of receivers in the Router's catalog
	Children  []Route
}

// SyslogRoute builds a leaf Route that forwards every alert matching `match` to a
// registered syslog receiver. It exists so callers can express "route this finding to a
// syslog collector" without hand-assembling a Route. Register the receiver under
// receiverName in the Router's catalog (typically the *Syslog's Name(), "syslog").
//
//	r.Receivers["siem"] = NewSyslog("udp", "siem.internal:514")
//	r.Tree.Children = append(r.Tree.Children, SyslogRoute("siem", map[string]string{"kind": "finding"}))
func SyslogRoute(receiverName string, match map[string]string) Route {
	return Route{Match: match, Receivers: []string{receiverName}}
}

// Router dispatches alerts using a route tree + a receiver catalog.
type Router struct {
	Tree      Route
	Receivers map[string]Receiver

	// InhibitRules silence target alerts when source alerts are firing. Source matches a
	// higher-severity alert; target matches what to silence. Simplified Alertmanager rule.
	InhibitRules []InhibitRule
}

// InhibitRule mirrors Alertmanager's inhibit_rules section.
type InhibitRule struct {
	SourceMatch map[string]string
	TargetMatch map[string]string
	Equal       []string // labels that must match between source and target
}

// Dispatch routes a single alert through the tree and sends to all matched receivers.
// Returns the names of receivers that fired (for audit).
func (r *Router) Dispatch(ctx context.Context, alert Alert, firing []Alert) ([]string, error) {
	if r.inhibited(alert, firing) {
		return nil, nil
	}
	fired := r.walk(ctx, r.Tree, alert)
	return fired, nil
}

func (r *Router) walk(ctx context.Context, route Route, alert Alert) []string {
	if !match(route.Match, alert.Labels) && len(route.Match) > 0 {
		return nil
	}
	out := []string{}
	for _, name := range route.Receivers {
		if rec, ok := r.Receivers[name]; ok {
			if err := rec.Send(ctx, []Alert{alert}); err == nil {
				out = append(out, name)
			}
		}
	}
	for _, child := range route.Children {
		out = append(out, r.walk(ctx, child, alert)...)
		// Only a child that actually matched may suppress its later siblings, and
		// only when its own Continue is false. A non-matching child must never stop
		// the walk (otherwise a low-severity alert routed to a later sibling is lost).
		childMatched := len(child.Match) == 0 || match(child.Match, alert.Labels)
		if childMatched && !child.Continue {
			break
		}
	}
	return out
}

func (r *Router) inhibited(alert Alert, firing []Alert) bool {
	for _, rule := range r.InhibitRules {
		if !match(rule.TargetMatch, alert.Labels) {
			continue
		}
		for _, f := range firing {
			if f.ID == alert.ID {
				continue
			}
			if !match(rule.SourceMatch, f.Labels) {
				continue
			}
			equalOK := true
			for _, k := range rule.Equal {
				if alert.Labels[k] != f.Labels[k] {
					equalOK = false
					break
				}
			}
			if equalOK {
				return true
			}
		}
	}
	return false
}

func match(want, got map[string]string) bool {
	for k, v := range want {
		if got[k] != v {
			return false
		}
	}
	return true
}

// GroupKey returns the canonical key for grouping alerts by the route's GroupBy labels.
func GroupKey(alert Alert, by []string) string {
	parts := make([]string, 0, len(by))
	for _, k := range by {
		parts = append(parts, k+"="+alert.Labels[k])
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// ----------------------------------- shared helper -----------------------------------

func postJSON(ctx context.Context, client *http.Client, url string, body []byte, headers map[string]string) error {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: %s status %d", url, resp.StatusCode)
	}
	return nil
}
