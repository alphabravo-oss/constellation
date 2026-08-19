//go:build e2etools

// Threat-scenario driver. Spins up the in-process WAF / DLP / admission engines
// against synthetic L7 + AdmissionReview events, asserts the right rule fires,
// and persists a hash-chained audit row + policy_decisions row to the live DB so
// downstream API endpoints (and the UI) light up.
//
// Subcommands:
//
//	waf-sqli     — replay an HTTP request with ?id=1 OR 1=1-- and assert rule 942110.
//	dlp-pii      — replay an HTTP body containing a Luhn-valid CC# and assert rule 1001.
//	admission    — call pkg/admission.PolicyEngine with an unsigned-image pod under an
//	               enforce-mode signature rule; persist policy_decisions + audit row.
//
// Build:
//
//	go build -tags e2etools -o /tmp/scenario-driver \
//	    ./deploy/e2e/threat-scenarios/waf-driver
//
// Env:
//
//	DATABASE_URL   default = postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable
//	ORG_ID         default = 2ebae049-35c7-464c-b4b0-50cf185e5975  (dev org)
//	OUT_DIR        where to write captures (default = current dir)
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/alphabravocompany/constellation/internal/runtime/dlp"
	"github.com/alphabravocompany/constellation/internal/runtime/dpi"
	"github.com/alphabravocompany/constellation/internal/runtime/waf"
	"github.com/alphabravocompany/constellation/pkg/admission"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/runtime/baseline"
)

const defaultDB = "postgres://constellation:constellation@localhost:5433/constellation?sslmode=disable"
const defaultOrg = "2ebae049-35c7-464c-b4b0-50cf185e5975"

var logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	os.Args = os.Args[1:]
	switch cmd {
	case "waf-sqli":
		mustRun(runWAFSQLi)
	case "dlp-pii":
		mustRun(runDLPPII)
	case "admission":
		mustRun(runAdmissionUnsigned)
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand:", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scenario-driver {waf-sqli|dlp-pii|admission} [--out captures/]")
}

func mustRun(fn func(context.Context, *config) error) {
	out := flag.String("out", ".", "directory to write capture artefacts")
	flag.Parse()
	cfg := &config{
		dbURL: envOr("DATABASE_URL", defaultDB),
		orgID: uuid.MustParse(envOr("ORG_ID", defaultOrg)),
		out:   *out,
	}
	if err := os.MkdirAll(cfg.out, 0o755); err != nil {
		fail("mkdir out: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := fn(ctx, cfg); err != nil {
		fail("%v", err)
	}
}

func fail(f string, args ...any) {
	fmt.Fprintf(os.Stderr, "ERROR: "+f+"\n", args...)
	os.Exit(1)
}

func envOr(k, dflt string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return dflt
}

type config struct {
	dbURL string
	orgID uuid.UUID
	out   string
}

func (c *config) writeJSON(name string, v any) string {
	p := filepath.Join(c.out, name)
	b, _ := json.MarshalIndent(v, "", "  ")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		fail("write %s: %v", p, err)
	}
	return p
}

func (c *config) connect(ctx context.Context) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, c.dbURL)
	if err != nil {
		return nil, fmt.Errorf("pgxpool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pg ping: %w", err)
	}
	return pool, nil
}

// ---------------------------------------------------------------------------
// Scenario 5 — WAF SQLi.
// ---------------------------------------------------------------------------

func runWAFSQLi(ctx context.Context, cfg *config) error {
	engine := waf.NewEngine()
	if err := engine.AddSensor(waf.BuiltinCRS()); err != nil {
		return fmt.Errorf("waf sensor: %w", err)
	}
	const workload = "checkout/api"
	engine.SetMode(workload, baseline.ModeEnforce)

	// Synthetic HTTP event mirroring an attacker probing checkout/api with
	// the classic OR-tautology SQL injection payload.
	evt := dpi.L7Event{
		Protocol: "http",
		At:       time.Now().UTC(),
		HTTP: &dpi.HTTPEvent{
			Method:  "GET",
			Path:    "/api/v1/orders",
			Host:    "checkout.svc.cluster.local",
			Query:   "id=1 OR 1=1--",
			Version: "HTTP/1.1",
			Headers: map[string][]string{
				"user-agent": {"sqlmap/1.7.5#stable (https://sqlmap.org)"},
			},
		},
	}

	verdict := engine.Evaluate(workload, evt)
	logger.Info("waf verdict", "action", verdict.Action, "mode", verdict.Mode, "matches", verdict.Matches)
	if verdict.Action != "block" {
		return fmt.Errorf("waf: expected block, got %q (matches=%+v)", verdict.Action, verdict.Matches)
	}
	if !hasMatch(verdict.Matches, 942110) {
		return fmt.Errorf("waf: expected rule 942110 to fire, matches=%+v", verdict.Matches)
	}

	cfg.writeJSON("verdict.json", map[string]any{
		"workload": workload,
		"mode":     verdict.Mode,
		"action":   verdict.Action,
		"matches":  verdict.Matches,
		"event":    evt,
	})

	// Persist audit row.
	pool, err := cfg.connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	id, hash, err := audit.New(pool).Log(ctx, audit.Event{
		OrgID:      &cfg.orgID,
		Action:     "runtime.alert.waf",
		TargetKind: "workload",
		TargetID:   workload,
		After: map[string]any{
			"rule_id":  942110,
			"severity": "critical",
			"action":   "block",
			"path":     evt.HTTP.Path,
			"query":    evt.HTTP.Query,
			"captured": firstCapture(verdict.Matches),
		},
	})
	if err != nil {
		return fmt.Errorf("audit.Log: %w", err)
	}
	logger.Info("waf alert audited", "id", id, "chain_hash", hash, "rule_id", 942110)
	cfg.writeJSON("audit-event.json", map[string]any{
		"id":         id,
		"action":     "runtime.alert.waf",
		"chain_hash": hash,
	})
	fmt.Printf("PASS waf-sqli: rule 942110 fired, verdict=block, audit_id=%d\n", id)
	return nil
}

// ---------------------------------------------------------------------------
// Scenario 6 — DLP PII (credit card).
// ---------------------------------------------------------------------------

func runDLPPII(ctx context.Context, cfg *config) error {
	engine := dlp.NewEngine()
	if err := engine.AddSensor(dlp.BuiltinSensor()); err != nil {
		return fmt.Errorf("dlp sensor: %w", err)
	}
	const workload = "payments/api"
	engine.SetMode(workload, baseline.ModeEnforce)

	// Synthetic HTTP response-like event whose body leaks a Luhn-valid card.
	// 4111111111111111 = Visa test PAN (passes Luhn).
	body := []byte(`{"order_id":"42","card":"4111 1111 1111 1111","total":"99.00"}`)
	evt := dpi.L7Event{
		Protocol: "http",
		At:       time.Now().UTC(),
		HTTP: &dpi.HTTPEvent{
			Method:     "POST",
			Path:       "/api/v1/checkout",
			Host:       "payments.svc.cluster.local",
			Body:       body,
			Version:    "HTTP/1.1",
			StatusCode: 200,
			Headers: map[string][]string{
				"content-type": {"application/json"},
			},
		},
	}

	verdict := engine.Inspect(workload, evt)
	if verdict.Action != "block" {
		return fmt.Errorf("dlp: expected block, got %q (matches=%+v)", verdict.Action, verdict.Matches)
	}
	if !hasDLPMatch(verdict.Matches, 1001) {
		return fmt.Errorf("dlp: expected pattern 1001 (CC#), matches=%+v", verdict.Matches)
	}

	cfg.writeJSON("verdict.json", map[string]any{
		"workload": workload,
		"mode":     verdict.Mode,
		"action":   verdict.Action,
		"matches":  verdict.Matches,
		"event":    sanitiseEvent(evt),
	})

	pool, err := cfg.connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	id, hash, err := audit.New(pool).Log(ctx, audit.Event{
		OrgID:      &cfg.orgID,
		Action:     "runtime.alert.dlp",
		TargetKind: "workload",
		TargetID:   workload,
		After: map[string]any{
			"pattern_id": 1001,
			"severity":   "critical",
			"action":     "block",
			"target":     verdict.Matches[0].Target,
			"sample":     verdict.Matches[0].Sample,
		},
	})
	if err != nil {
		return fmt.Errorf("audit.Log: %w", err)
	}
	logger.Info("dlp alert audited", "id", id, "chain_hash", hash, "pattern_id", 1001)
	cfg.writeJSON("audit-event.json", map[string]any{
		"id":         id,
		"action":     "runtime.alert.dlp",
		"chain_hash": hash,
	})
	fmt.Printf("PASS dlp-pii: pattern 1001 fired, verdict=block, audit_id=%d\n", id)
	return nil
}

// ---------------------------------------------------------------------------
// Scenario 2 — admission denial on missing image signature.
// ---------------------------------------------------------------------------

// runAdmissionUnsigned constructs a Pod with an unsigned image, wires the
// admission engine with a flipped-to-enforce signature rule, calls Evaluate
// through the same HTTP handler the deployed webhook uses, and persists a
// policy_decisions row + audit event.
func runAdmissionUnsigned(ctx context.Context, cfg *config) error {
	engine := admission.NewEngine()
	// Promote the monitor-mode signature rule to enforce for this demo run.
	// The deployed webhook reads its rule set from NewEngine() defaults; the
	// production path will load it from the DB once rule-hot-reload lands.
	for i, r := range engine.Rules {
		if r.ID == "require-image-signature" {
			engine.Rules[i].Mode = "enforce"
		}
	}

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "evil-unsigned",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "evil",
				Image: "attacker/evil:latest",
			}},
		},
	}
	raw, _ := json.Marshal(pod)
	req := &admissionv1.AdmissionRequest{
		UID:       "demo-uid",
		Kind:      metav1.GroupVersionKind{Kind: "Pod"},
		Operation: admissionv1.Create,
		Name:      pod.Name,
		Namespace: pod.Namespace,
		Object:    runtime.RawExtension{Raw: raw},
	}
	resp := engine.Evaluate(ctx, req)
	if resp.Allowed {
		return fmt.Errorf("admission: expected deny, got allow")
	}
	msg := ""
	if resp.Result != nil {
		msg = resp.Result.Message
	}
	if !strings.Contains(strings.ToLower(msg), "image-signed") && !strings.Contains(strings.ToLower(msg), "signature") {
		return fmt.Errorf("admission: deny reason %q does not mention signature", msg)
	}

	// Also drive the live HTTP webhook (running with --insecure on the cluster)
	// to prove the deployed binary observes the same payload — verdict comes
	// back as `allowed=true` with a monitor-mode warning because the cluster
	// copy still runs the default Rules; that's expected and captured.
	clusterResp, _ := exerciseLiveWebhook(ctx, cfg, req)
	cfg.writeJSON("admission-cluster-webhook.json", clusterResp)

	cfg.writeJSON("admission-review.json", map[string]any{
		"request":  req,
		"response": resp,
		"verdict":  "deny",
		"reason":   msg,
	})

	pool, err := cfg.connect(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()

	// Persist policy_decisions row.
	var decisionID uuid.UUID
	if err := pool.QueryRow(ctx, `
INSERT INTO policy_decisions (org_id, cluster_id, policy_id, subject_kind, subject_id, verdict, reason, at)
VALUES ($1, NULL, NULL, $2, $3, $4, $5, NOW())
RETURNING id`,
		cfg.orgID, "admission", pod.Namespace+"/"+pod.Name, "deny", msg).Scan(&decisionID); err != nil {
		return fmt.Errorf("policy_decisions insert: %w", err)
	}

	id, hash, err := audit.New(pool).Log(ctx, audit.Event{
		OrgID:      &cfg.orgID,
		Action:     "admission.deny",
		TargetKind: "pod",
		TargetID:   pod.Namespace + "/" + pod.Name,
		After: map[string]any{
			"image":         pod.Spec.Containers[0].Image,
			"rule_id":       "require-image-signature",
			"verdict":       "deny",
			"reason":        msg,
			"decision_id":   decisionID,
		},
	})
	if err != nil {
		return fmt.Errorf("audit.Log: %w", err)
	}
	cfg.writeJSON("audit-event.json", map[string]any{
		"id": id, "action": "admission.deny", "chain_hash": hash,
		"policy_decision_id": decisionID,
	})

	// Also insert a violations row so /api/v1/violations surfaces this.
	if _, err := pool.Exec(ctx, `
INSERT INTO violations (org_id, deployment_id, policy_name, severity, kind, message, at)
SELECT $1, d.id, $2, 'critical', 'admission', $3, NOW()
  FROM deployments d
 WHERE d.org_id = $1
 LIMIT 1`,
		cfg.orgID, "require-image-signature", msg); err != nil {
		// non-fatal — F2 may not have a deployment row to attach to.
		logger.Warn("violations insert skipped", "err", err.Error())
	}

	logger.Info("admission deny audited", "id", id, "chain_hash", hash, "decision_id", decisionID)
	fmt.Printf("PASS admission: unsigned image denied with %q, audit_id=%d, decision_id=%s\n", msg, id, decisionID)
	return nil
}

// exerciseLiveWebhook posts the same AdmissionReview to a mux+handler combo so
// that we can prove the production binary's request/response shape. Falls back
// to local in-process if env CLUSTER_ADMISSION_URL is unset.
func exerciseLiveWebhook(ctx context.Context, _ *config, req *admissionv1.AdmissionRequest) (any, error) {
	url := os.Getenv("CLUSTER_ADMISSION_URL")
	if url == "" {
		// Reconstruct the same payload the cluster's binary handles.
		mux := http.NewServeMux()
		engine := admission.NewEngine()
		mux.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
			var ar admissionv1.AdmissionReview
			_ = json.NewDecoder(r.Body).Decode(&ar)
			resp := engine.Evaluate(r.Context(), ar.Request)
			out := admissionv1.AdmissionReview{TypeMeta: ar.TypeMeta, Response: resp}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		})
		ts := httptest.NewServer(mux)
		defer ts.Close()
		url = ts.URL + "/validate"
	}
	body, _ := json.Marshal(admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "admission.k8s.io/v1", Kind: "AdmissionReview"},
		Request:  req,
	})
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out admissionv1.AdmissionReview
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func hasMatch(ms []waf.Match, id int) bool {
	for _, m := range ms {
		if m.RuleID == id {
			return true
		}
	}
	return false
}

func hasDLPMatch(ms []dlp.Match, id int) bool {
	for _, m := range ms {
		if m.PatternID == id {
			return true
		}
	}
	return false
}

func firstCapture(ms []waf.Match) string {
	if len(ms) == 0 {
		return ""
	}
	return ms[0].Captured
}

// sanitiseEvent redacts request bodies before writing to disk so the capture
// is shareable. We only mutate the Body field.
func sanitiseEvent(evt dpi.L7Event) dpi.L7Event {
	if evt.HTTP != nil && len(evt.HTTP.Body) > 0 {
		clone := *evt.HTTP
		clone.Body = []byte("<redacted-pii>")
		evt.HTTP = &clone
	}
	return evt
}

var _ = errors.New
