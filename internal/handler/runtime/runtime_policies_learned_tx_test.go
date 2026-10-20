//go:build integration

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/internal/runtime/dp"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/alphabravocompany/constellation/pkg/netpolicy"
)

func generatedPolicyRequest(t *testing.T, f reviewedPolicyFixture, cluster uuid.UUID, apply bool) *httptest.ResponseRecorder {
	t.Helper()
	body := GenerateRequest{ClusterID: cluster, Workload: "app/api", Namespace: "app", Name: "reviewed", Hours: 24}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := "/runtime-policies:generate"
	if apply {
		path = "/runtime-policies:apply-generated"
	}
	req := httptest.NewRequestWithContext(authctx.WithSubject(t.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}), http.MethodPost, path, bytes.NewReader(raw))
	req.Header.Set("X-Request-Id", "generated-fixture-request")
	w := httptest.NewRecorder()
	if apply {
		f.h.ApplyGenerated(w, req)
	} else {
		f.h.Generate(w, req)
	}
	return w
}

func learnedCandidate(f reviewedPolicyFixture, name string) RuntimePolicy {
	return RuntimePolicy{OrgID: f.org, ClusterID: f.cluster, Workload: "app/api", Namespace: "app", Name: name, Mode: PolicyModeEnforce, DefAction: dp.PolicyActionDeny, ApplyDir: dp.ApplyDirBoth}
}

func learnedTestRules(port uint16) []*dp.PolicyRule {
	return []*dp.PolicyRule{{Port: port, IPProto: dp.IPProtoTCP, Action: dp.PolicyActionAllow}}
}

func TestGeneratedPoliciesRejectForeignClusterBeforePreviewOrMutation(t *testing.T) {
	f := reviewedFixture(t)
	for _, cluster := range []uuid.UUID{f.foreignCluster, uuid.New()} {
		for _, apply := range []bool{false, true} {
			w := generatedPolicyRequest(t, f, cluster, apply)
			if w.Code != 404 {
				t.Fatalf("foreign generation%d %s", w.Code, w.Body.String())
			}
		}
		p := learnedCandidate(f, "foreign learned")
		p.ClusterID = cluster
		if id, err := f.h.store.UpsertLearnedPolicy(t.Context(), &p, learnedTestRules(8443), &f.actor); err == nil || id != uuid.Nil || p.ID != uuid.Nil {
			t.Fatal("public learned upsert accepted foreign cluster")
		}
	}
	// Historic policy scope columns have no ownership FK. An old malformed row
	// must not re-open the regeneration update path after Create was secured.
	if _, err := f.h.store.db.Pool().Exec(t.Context(), `INSERT INTO runtime_policies(org_id,cluster_id,workload,namespace,name,rules)VALUES($1,$2,'app/api','app','reviewed','[]')`, f.org, f.foreignCluster); err != nil {
		t.Fatal(err)
	}
	if w := generatedPolicyRequest(t, f, f.foreignCluster, true); w.Code != 404 {
		t.Fatalf("retained foreign regeneration%d", w.Code)
	}
	if f.countAudit(t) != 0 {
		t.Fatal("scope rejection wrote audit")
	}
}

func TestGeneratedAndPublicLearnedAuditFailureRollsBackInsertAndMerge(t *testing.T) {
	f := reviewedFixture(t)
	before, err := f.h.store.Get(t.Context(), f.org, f.id)
	if err != nil {
		t.Fatal(err)
	}
	rejectLegacyPolicyAudit(t, f)
	if w := generatedPolicyRequest(t, f, f.cluster, true); w.Code != 500 || strings.Contains(w.Body.String(), "fixture") {
		t.Fatalf("generated audit failure%d %s", w.Code, w.Body.String())
	}
	for _, name := range []string{"reviewed", "new learned"} {
		p := learnedCandidate(f, name)
		if id, err := f.h.store.UpsertLearnedPolicy(t.Context(), &p, learnedTestRules(8443), &f.actor); err == nil || id != uuid.Nil || p.ID != uuid.Nil {
			t.Fatalf("uncommitted learned receipt escaped %+v %v", p, err)
		}
	}
	assertLegacyPolicyUnchanged(t, f, before)
}

func TestGeneratedInsertIsMonitorAndReturnsCommittedAuditReceipt(t *testing.T) {
	f := reviewedFixture(t)
	if _, err := f.h.store.db.Pool().Exec(t.Context(), `DELETE FROM runtime_policies WHERE id=$1`, f.id); err != nil {
		t.Fatal(err)
	}
	w := generatedPolicyRequest(t, f, f.cluster, true)
	p := assertLegacyPolicyReceipt(t, w, 201)
	if p.Mode != PolicyModeMonitor || p.OrgID != f.org || p.ClusterID != f.cluster || p.CreatedBy == nil || *p.CreatedBy != f.actor {
		t.Fatalf("wrong generated creation %+v", p)
	}
	event := lastLegacyPolicyAudit(t, f, p.ID)
	if event.action != audit.ActionPolicyCreate || event.before != nil || event.after["revision"] != p.Revision || event.request != "generated-fixture-request" || event.actor == nil || *event.actor != f.actor {
		t.Fatalf("wrong generated audit %+v", event)
	}
	w = generatedPolicyRequest(t, f, f.cluster, true)
	updated := assertLegacyPolicyReceipt(t, w, 200)
	if updated.ID != p.ID || updated.Mode != PolicyModeMonitor {
		t.Fatal("regeneration created duplicate or promoted")
	}
}

func setLearnedFixtureRules(t *testing.T, f reviewedPolicyFixture) {
	t.Helper()
	if _, err := f.h.store.db.Pool().Exec(t.Context(), `UPDATE runtime_policies SET mode='enforce',def_action=7,apply_dir=1,rules='[{"cfg":"user","port":443,"proto":6,"action":7},{"cfg":"fed","port":9443,"proto":6,"action":3},{"cfg":"learned","port":8080,"proto":6,"action":3}]' WHERE id=$1`, f.id); err != nil {
		t.Fatal(err)
	}
}

func TestLearnedMergePreservesAuthoredRulesModePostureAndActor(t *testing.T) {
	f := reviewedFixture(t)
	setLearnedFixtureRules(t, f)
	before, err := f.h.store.Get(t.Context(), f.org, f.id)
	if err != nil {
		t.Fatal(err)
	}
	candidate := learnedCandidate(f, "reviewed")
	candidate.Mode = PolicyModeDisabled
	candidate.DefAction = dp.PolicyActionAllow
	if id, err := f.h.store.UpsertLearnedPolicy(t.Context(), &candidate, learnedTestRules(8443), nil); err != nil || id != f.id {
		t.Fatalf("merge %s %v", id, err)
	}
	assertLearnedPorts(t, &candidate, map[uint16]netpolicy.CfgType{443: netpolicy.CfgTypeUser, 9443: netpolicy.CfgTypeFed, 8443: netpolicy.CfgTypeLearned})
	if candidate.Mode != before.Mode || candidate.DefAction != before.DefAction || candidate.ApplyDir != before.ApplyDir || candidate.Namespace != before.Namespace || candidate.Version != before.Version+1 {
		t.Fatalf("regeneration changed authored posture %+v", candidate)
	}
	event := lastLegacyPolicyAudit(t, f, f.id)
	if event.actor != nil || event.action != audit.ActionPolicyUpdate || event.before["revision"] != before.Revision || event.after["revision"] != candidate.Revision {
		t.Fatalf("wrong machine audit %+v", event)
	}
	p := learnedCandidate(f, "new-machine-policy")
	if _, err := f.h.store.UpsertLearnedPolicy(t.Context(), &p, learnedTestRules(8443), &f.actor); err != nil {
		t.Fatal(err)
	}
	if p.Mode != PolicyModeMonitor {
		t.Fatal("public learned insertion promoted a policy")
	}
}

func assertLearnedPorts(t *testing.T, p *RuntimePolicy, want map[uint16]netpolicy.CfgType) {
	t.Helper()
	rules, err := netpolicy.DecodeSourced(p.Rules)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint16]netpolicy.CfgType{}
	for _, rule := range rules {
		got[rule.Port] = rule.CfgType
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lost authored or retained stale learned rule got%+v want%+v", got, want)
	}
}

func TestLearnedFirstInsertRaceCommitsOneIdentityAndBothAudits(t *testing.T) {
	f := reviewedFixture(t)
	start := make(chan struct{})
	results := make(chan struct {
		p   RuntimePolicy
		err error
	}, 2)
	var writers sync.WaitGroup
	for _, port := range []uint16{8443, 9443} {
		writers.Go(func() {
			<-start
			p := learnedCandidate(f, "concurrent-new")
			_, err := f.h.store.UpsertLearnedPolicy(t.Context(), &p, learnedTestRules(port), &f.actor)
			results <- struct {
				p   RuntimePolicy
				err error
			}{p, err}
		})
	}
	close(start)
	writers.Wait()
	close(results)
	var id uuid.UUID
	for result := range results {
		if result.err != nil || result.p.Mode != PolicyModeMonitor {
			t.Fatalf("concurrent insert %+v %v", result.p, result.err)
		}
		if id != uuid.Nil && id != result.p.ID {
			t.Fatal("first-insert race created different identities")
		}
		id = result.p.ID
	}
	var created, updated int
	if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT count(*) FILTER(WHERE action=$3),count(*) FILTER(WHERE action=$4) FROM audit_events WHERE org_id=$1 AND target_id=$2`, f.org, id.String(), audit.ActionPolicyCreate, audit.ActionPolicyUpdate).Scan(&created, &updated); err != nil || created != 1 || updated != 1 {
		t.Fatalf("race audits create%d update%d %v", created, updated, err)
	}
}

func TestLearnedRegenerationLocksLatestAuthoredState(t *testing.T) {
	f := reviewedFixture(t)
	tx, err := f.h.store.db.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	if _, err := tx.Exec(t.Context(), `UPDATE runtime_policies SET rules='[{"cfg":"user","port":1234,"proto":6,"action":7}]',mode='enforce',def_action=7 WHERE id=$1`, f.id); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	candidate := learnedCandidate(f, "reviewed")
	go func() {
		_, err := f.h.store.UpsertLearnedPolicy(t.Context(), &candidate, learnedTestRules(8443), &f.actor)
		result <- err
	}()
	awaitLearnedRowLock(t, f, result)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	assertLearnedPorts(t, &candidate, map[uint16]netpolicy.CfgType{1234: netpolicy.CfgTypeUser, 8443: netpolicy.CfgTypeLearned})
	if candidate.Mode != PolicyModeEnforce || candidate.DefAction != dp.PolicyActionDeny {
		t.Fatal("regeneration used stale authored state")
	}
}

func awaitLearnedRowLock(t *testing.T, f reviewedPolicyFixture, result <-chan error) {
	t.Helper()
	awaitLearnedDatabaseLock(t, f, result, "%workload=$3 AND name=$4 FOR UPDATE%")
}

func awaitLearnedDatabaseLock(t *testing.T, f reviewedPolicyFixture, result <-chan error, pattern string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := f.h.store.db.Pool().QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)`, pattern).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		select {
		case err := <-result:
			t.Fatalf("regeneration did not lock before reading: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("regeneration did not wait for authored row lock")
}

func TestLearnedPrivateTransactionRejectsUnownedScope(t *testing.T) {
	f := reviewedFixture(t)
	tx, err := f.h.store.db.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	p := learnedCandidate(f, "foreign")
	p.ClusterID = f.foreignCluster
	if _, _, err := f.h.store.upsertLearnedPolicyTx(t.Context(), tx, &p, learnedTestRules(8443), &f.actor); !errors.Is(err, errLegacyPolicyClusterNotFound) {
		t.Fatalf("private upsert accepted foreign cluster %v", err)
	}
}
