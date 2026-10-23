//go:build integration

package scanning

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler"
	"github.com/alphabravocompany/constellation/internal/scanner"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/responserule"
)

func TestScanCompletionProfilesReachResponseRules(t *testing.T) {
	for _, targetType := range []string{"image", "platform"} {
		t.Run(targetType, func(t *testing.T) {
			d := openTestDB(t)
			defer d.Close()
			pool, ctx := d.Pool(), t.Context()
			org, cluster, target, profile := uuid.New(), uuid.New(), uuid.New(), uuid.New()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "profile-completion-"+org.String())
			exec(`INSERT INTO clusters(id,org_id,name,state) VALUES($1,$2,'profile-cluster','connected')`, cluster, org)
			digest := "sha256:" + strings.Repeat("a", 64)
			imageRef := "registry.example.test/profile/app@" + digest
			ref := "cluster:" + cluster.String()
			if targetType == "image" {
				ref = imageRef
			}
			exec(`INSERT INTO scan_targets(id,org_id,cluster_id,type,ref,source_type,image_ref)
    VALUES($1,$2,$3,$4,$5,'manual',$6)`, target, org, cluster, targetType, ref, imageRef)
			if targetType == "image" {
				deployment := uuid.New()
				exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind,image_refs)
     VALUES($1,$2,$3,'prod','app','Deployment',$4)`, deployment, org, cluster, []string{imageRef})
				exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_digest)
     VALUES($1,$2,$3,'prod/app','prod','app','Deployment',$4,$4,'registry.example.test/profile/app',$5)`, org, cluster, deployment, imageRef, digest)
			}
			entries := `[{"name":"accept","name_regex":"ACCEPT$","action":"suppress"},{"name":"defer","name_regex":"DEFER$","action":"suppress","days_to_fix":30},{"name":"escalate","name_regex":"ESCALATE$","action":"escalate"}]`
			exec(`INSERT INTO vuln_profiles(id,org_id,name,active,entries) VALUES($1,$2,'profile',true,$3)`, profile, org, entries)
			token, _, err := handler.IssueScannerToken(ctx, pool, org, "profile-proof", time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			findings := []scanner.Finding{
				{VulnerabilityID: "CVE-2099-ACCEPT", Severity: "critical", FixedVersion: "2", KEVListed: true},
				{VulnerabilityID: "CVE-2099-DEFER", Severity: "high", FixedVersion: "2", KEVListed: true},
				{VulnerabilityID: "CVE-2099-ESCALATE", Severity: "medium", FixedVersion: "2", KEVListed: true},
				{VulnerabilityID: "CVE-2099-PLAIN", Severity: "low"},
			}
			for i := range findings {
				findings[i].Package = scanner.Package{Name: "package-" + findings[i].VulnerabilityID, Version: "1", Ecosystem: "generic"}
			}
			payload, err := json.Marshal(map[string]any{"image_ref": imageRef, "image_digest": digest, "findings": findings})
			if err != nil {
				t.Fatal(err)
			}
			h := NewScanJobs(d, audit.New(pool))
			var events []*responserule.Event
			rule := responserule.ResponseRule{Enabled: true, EventType: responserule.EventScan, Conditions: []responserule.Condition{{Field: "severity", Op: responserule.OpEq, Value: "critical"}}, Actions: []responserule.Action{{Type: responserule.ActionQuarantine}}}
			h.evalResponseRules = func(_ context.Context, gotOrg uuid.UUID, event *responserule.Event) ([]responserule.Action, error) {
				if gotOrg != org {
					t.Fatalf("response dispatched to foreign org %s", gotOrg)
				}
				events = append(events, event)
				if rule.Match(event) {
					return rule.Actions, nil
				}
				return nil, nil
			}
			for _, stage := range []struct {
				name        string
				entries     string
				active      bool
				lifecycles  []string
				severities  []string
				event       map[string]string
				quarantined int
			}{
				{"mixed", entries, true, []string{"accepted", "suppressed", "open", "open"}, []string{"critical", "high", "critical", "low"}, map[string]string{"severity": "critical", "highest_cve": "CVE-2099-ESCALATE", "cve_count": "2", "fixable_count": "1", "kev_count": "1"}, 1},
				{"all suppressed", `[{"name":"accept-all","action":"suppress"}]`, true, []string{"accepted", "accepted", "accepted", "accepted"}, []string{"critical", "high", "medium", "low"}, map[string]string{"severity": "info", "highest_cve": "", "cve_count": "0", "fixable_count": "0", "kev_count": "0"}, 0},
				{"disabled", entries, false, []string{"open", "open", "open", "open"}, []string{"critical", "high", "medium", "low"}, map[string]string{"severity": "critical", "highest_cve": "CVE-2099-ACCEPT", "cve_count": "4", "fixable_count": "3", "kev_count": "3"}, 1},
			} {
				exec(`UPDATE vuln_profiles SET entries=$2,active=$3 WHERE id=$1`, profile, stage.entries, stage.active)
				exec(`DELETE FROM quarantine_entries WHERE org_id=$1`, org)
				job := uuid.New()
				exec(`INSERT INTO scan_jobs(id,org_id,target_id,status) VALUES($1,$2,$3,'pending')`, job, org, target)
				request := func(fn http.HandlerFunc, body []byte) *httptest.ResponseRecorder {
					t.Helper()
					req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/scan", bytes.NewReader(body))
					req.Header.Set("Authorization", "Bearer "+token)
					req = withRouteParam(req, "id", job.String())
					rec := httptest.NewRecorder()
					handler.ScannerTokenMiddleware(pool)(fn).ServeHTTP(rec, currentScanLeaseRequest(t, pool, req))
					if rec.Code != http.StatusOK {
						t.Fatalf("%s request: %d %s", stage.name, rec.Code, rec.Body.String())
					}
					return rec
				}
				request(h.Claim, nil)
				before := len(events)
				request(h.Complete, payload)
				if len(events) != before+1 {
					t.Fatalf("%s: response dispatches=%d want 1", stage.name, len(events)-before)
				}
				event := events[len(events)-1]
				for key, want := range stage.event {
					if got := event.Fields[key]; got != want {
						t.Errorf("%s response %s=%q want %q", stage.name, key, got, want)
					}
				}
				for i, finding := range findings {
					var lifecycle, severity string
					var risk int
					if err := pool.QueryRow(ctx, `SELECT lifecycle,severity,risk_score FROM findings WHERE org_id=$1 AND external_id=$2`, org, finding.VulnerabilityID).Scan(&lifecycle, &severity, &risk); err != nil {
						t.Fatal(err)
					}
					if lifecycle != stage.lifecycles[i] || severity != stage.severities[i] {
						t.Errorf("%s %s stored %s/%s want %s/%s", stage.name, finding.VulnerabilityID, lifecycle, severity, stage.lifecycles[i], stage.severities[i])
					}
					if stage.name == "mixed" && i == 2 && risk < handler.SeverityToScore("critical", 0, false) {
						t.Errorf("escalated risk=%d below critical floor", risk)
					}
				}
				var count, quarantined, rawCount int
				if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM findings WHERE org_id=$1),(SELECT count(*) FROM quarantine_entries WHERE org_id=$1),(SELECT finding_count FROM scan_jobs WHERE id=$2)`, org, job).Scan(&count, &quarantined, &rawCount); err != nil {
					t.Fatal(err)
				}
				wantQuarantined := stage.quarantined
				if targetType != "image" {
					wantQuarantined = 0
				}
				if count != 4 || rawCount != 4 || quarantined != wantQuarantined {
					t.Errorf("%s counts findings=%d raw=%d quarantine=%d want 4/4/%d", stage.name, count, rawCount, quarantined, wantQuarantined)
				}
				request(h.Complete, payload)
				if len(events) != before+1 {
					t.Fatal("completion replay repeated response rules")
				}
			}
		})
	}
}
