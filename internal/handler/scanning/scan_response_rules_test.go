package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

func TestScanResponseRuleLegacyTagIsUnsupported(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	ctx := context.Background()
	pool := database.Pool()
	orgID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Tag Action Test')`, orgID, "tag-action-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
	})
	image := "tag-unsupported-" + uuid.NewString()
	jobs := NewScanJobs(database, audit.New(pool))
	event := &responserule.Event{Type: responserule.EventScan, Fields: map[string]string{"image": image}}
	jobs.applyScanResponseRuleActions(ctx, orgID, handler.ScanTarget{Type: "image", Ref: image}, scanImageIdentity{}, event,
		[]responserule.Action{{Type: responserule.ActionTag, Params: map[string]string{"key": "team", "value": "sec"}}})
	var enforced, reason string
	if err := pool.QueryRow(ctx, `SELECT after->>'enforced', after->>'enforce_error' FROM audit_events WHERE org_id=$1 AND target_id=$2 AND action='response_rule.action.tag'`, orgID, image).Scan(&enforced, &reason); err != nil {
		t.Fatal(err)
	}
	if enforced != "unsupported" || reason == "" {
		t.Fatalf("legacy tag outcome=%q reason=%q", enforced, reason)
	}
}

func TestScanResponseRuleSuppressLogCompletion(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		evaluateErr error
		wantAction  bool
	}{
		{name: "matching action", wantAction: true},
		{name: "evaluator failure", evaluateErr: errors.New("rule lookup failed")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := openTestDB(t)
			t.Cleanup(database.Close)
			ctx := context.Background()
			pool := database.Pool()
			orgID := uuid.New()
			targetID := uuid.New()
			jobID := uuid.New()
			imageRef := "registry.example.test/suppress-" + jobID.String() + ":latest"
			imageDigest := "sha256:" + jobID.String()
			if _, err := pool.Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Scan Suppress Test')`, orgID, "scan-suppress-"+orgID.String()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, orgID)
			})
			rawToken, tokenID, err := handler.IssueScannerToken(ctx, pool, orgID, "suppress-test", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO scan_targets (id, org_id, type, ref, source_type, image_ref, image_digest)
VALUES ($1, $2, 'image', $3, 'manual', $3, $4)`, targetID, orgID, imageRef, imageDigest); err != nil {
				t.Fatal(err)
			}
			workerID := "scanner:suppress-test:" + tokenID.String()
			if _, err := pool.Exec(ctx, `INSERT INTO scan_jobs (id, org_id, target_id, status, worker_id, claimed_at, attempt_count)
VALUES ($1, $2, $3, 'running', $4, NOW(), 1)`, jobID, orgID, targetID, workerID); err != nil {
				t.Fatal(err)
			}

			evaluated := false
			jobs := NewScanJobs(database, audit.New(pool)).WithResponseRuleEngine(func(ctx context.Context, evaluatedOrg uuid.UUID, event *responserule.Event) ([]responserule.Action, error) {
				evaluated = true
				if evaluatedOrg != orgID || event.Type != responserule.EventScan || event.Fields["image"] != imageRef {
					t.Errorf("unexpected scan event: org=%s event=%+v", evaluatedOrg, event)
				}
				var completionAudits int
				if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='scan-job.complete' AND target_id=$2`, orgID, jobID.String()).Scan(&completionAudits); err != nil {
					t.Error(err)
				} else if completionAudits != 0 {
					t.Errorf("completion audited before rule evaluation: %d", completionAudits)
				}
				if testCase.evaluateErr != nil {
					return nil, testCase.evaluateErr
				}
				return []responserule.Action{{Type: responserule.ActionSuppressLog}}, nil
			})
			requestBody, err := json.Marshal(map[string]any{"image_ref": imageRef, "image_digest": imageDigest, "findings": []any{}})
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/scan-jobs/"+jobID.String()+"/complete", bytes.NewReader(requestBody))
			request.Header.Set("Authorization", "Bearer "+rawToken)
			route := chi.NewRouteContext()
			route.URLParams.Add("id", jobID.String())
			request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
			response := httptest.NewRecorder()
			handler.ScannerTokenMiddleware(pool)(http.HandlerFunc(jobs.Complete)).ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("complete status=%d body=%s", response.Code, response.Body.String())
			}
			if !evaluated {
				t.Fatal("scan rule evaluator was not called")
			}
			var jobStatus, attemptStatus string
			if err := pool.QueryRow(ctx, `SELECT sj.status, sja.status FROM scan_jobs sj JOIN scan_job_attempts sja ON sja.job_id=sj.id WHERE sj.id=$1`, jobID).Scan(&jobStatus, &attemptStatus); err != nil {
				t.Fatal(err)
			}
			if jobStatus != "completed" || attemptStatus != "completed" {
				t.Fatalf("job/attempt statuses = %q/%q", jobStatus, attemptStatus)
			}
			var resultCount, completionAudits, actionAudits int
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM image_scan_results WHERE org_id=$1 AND last_scan_job_id=$2`, orgID, jobID).Scan(&resultCount); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE org_id=$1 AND action='scan-job.complete' AND target_id=$2`, orgID, jobID.String()).Scan(&completionAudits); err != nil {
				t.Fatal(err)
			}
			var enforced, reason string
			if err := pool.QueryRow(ctx, `SELECT COUNT(*), COALESCE(MAX(after->>'enforced'), ''), COALESCE(MAX(after->>'enforce_skip_reason'), '')
FROM audit_events WHERE org_id=$1 AND action='response_rule.action.suppress_log' AND target_id=$2`, orgID, imageRef).Scan(&actionAudits, &enforced, &reason); err != nil {
				t.Fatal(err)
			}
			expectedActionAudits := 0
			if testCase.wantAction {
				expectedActionAudits = 1
			}
			if resultCount != 1 || completionAudits != 1 || actionAudits != expectedActionAudits {
				t.Fatalf("result/completion/action counts = %d/%d/%d", resultCount, completionAudits, actionAudits)
			}
			if testCase.wantAction && (enforced != "skipped_no_security_event" || reason == "") {
				t.Fatalf("suppression outcome=%q reason=%q", enforced, reason)
			}
		})
	}
}

// TestScanResponseRuleEventFiresOnMatch proves the E1 EventScan ingest seam: a "scan" rule
// fires its action when the folded scan event matches its conditions, and does NOT fire when
// the conditions do not match — the exact gap E1b closes (admission/scan rules that previously
// never fired). It exercises the real folding (scanResponseRuleEvent) feeding the real matcher
// (responserule.MatchRules), so a regression in field names or rank derivation is caught.
func TestScanResponseRuleEventFiresOnMatch(t *testing.T) {
	target := handler.ScanTarget{
		Type:       "image",
		Ref:        "ghcr.io/acme/api:1.2.3",
		SourceType: "registry",
	}
	identity := scanImageIdentity{
		Ref:        "ghcr.io/acme/api:1.2.3",
		Repository: "ghcr.io/acme/api",
		Digest:     "sha256:abc",
	}

	// A scan whose worst finding is HIGH (not critical), one of which is fixable.
	highFindings := []scanner.Finding{
		{VulnerabilityID: "CVE-2024-1", Severity: "medium"},
		{VulnerabilityID: "CVE-2024-2", Severity: "high", FixedVersion: "1.2.4"},
	}
	// A scan that includes a CRITICAL finding.
	critFindings := []scanner.Finding{
		{VulnerabilityID: "CVE-2024-9", Severity: "critical"},
		{VulnerabilityID: "CVE-2024-2", Severity: "high"},
	}

	// Folding sanity: max severity + counts are what conditions reference.
	highEv := scanResponseRuleEvent(target, identity, highFindings)
	if got := highEv.Fields["severity"]; got != "high" {
		t.Fatalf("max severity = %q, want high", got)
	}
	if got := highEv.Fields["cve_count"]; got != "2" {
		t.Fatalf("cve_count = %q, want 2", got)
	}
	if got := highEv.Fields["fixable_count"]; got != "1" {
		t.Fatalf("fixable_count = %q, want 1", got)
	}
	if got := highEv.Fields["image_repository"]; got != "ghcr.io/acme/api" {
		t.Fatalf("image_repository = %q", got)
	}

	// Rule: quarantine any image whose scan has a CRITICAL finding.
	rule := responserule.ResponseRule{
		Name:      "block-critical-images",
		Enabled:   true,
		EventType: responserule.EventScan,
		Conditions: []responserule.Condition{
			{Field: "severity", Op: responserule.OpEq, Value: "critical"},
		},
		Actions: []responserule.Action{{Type: responserule.ActionQuarantine}},
	}
	rules := []responserule.ResponseRule{rule}

	// Non-match: worst severity is "high", rule wants "critical" -> must NOT fire.
	if acts := responserule.Match(rules, scanResponseRuleEvent(target, identity, highFindings)); len(acts) != 0 {
		t.Fatalf("rule fired on non-matching scan (max=high): got %d actions, want 0", len(acts))
	}

	// Match: scan contains a "critical" finding -> rule fires its quarantine action.
	critEv := scanResponseRuleEvent(target, identity, critFindings)
	if got := critEv.Fields["severity"]; got != "critical" {
		t.Fatalf("max severity = %q, want critical", got)
	}
	acts := responserule.Match(rules, critEv)
	if len(acts) != 1 || acts[0].Type != responserule.ActionQuarantine {
		t.Fatalf("rule did not fire on matching scan: got %#v, want one quarantine action", acts)
	}

	// Org-scope sanity: a disabled rule never fires even on a match.
	disabled := rule
	disabled.Enabled = false
	if acts := responserule.Match([]responserule.ResponseRule{disabled}, critEv); len(acts) != 0 {
		t.Fatalf("disabled rule fired: got %d actions, want 0", len(acts))
	}
}
