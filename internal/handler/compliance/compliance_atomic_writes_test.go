//go:build integration

package compliance

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestComplianceConfiguredAuditFailureRollsBackWrites(t *testing.T) {
	for _, action := range []string{"ingest", "bench/run"} {
		t.Run(action, func(t *testing.T) {
			f := newComplianceAgentFixture(t)
			installComplianceAuditFailure(t, f)
			w := f.call(t, action, "?cluster_id="+f.cluster.String(), "", false)
			if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "private fixture failure") {
				t.Fatalf("false/leaking success %d %s", w.Code, w.Body.String())
			}
			var checks, requests, audits int
			if err := f.database.Pool().QueryRow(t.Context(), `SELECT(SELECT count(*)FROM compliance_checks WHERE org_id=$1),(SELECT count(*)FROM compliance_bench_run_requests WHERE org_id=$1),(SELECT count(*)FROM audit_events WHERE org_id=$1)`, f.org).Scan(&checks, &requests, &audits); err != nil || checks != 0 || requests != 0 || audits != 0 {
				t.Fatalf("partial mutation checks%d requests%d audits%d err%v", checks, requests, audits, err)
			}
		})
	}
}
func installComplianceAuditFailure(t *testing.T, f *complianceAgentFixture) {
	t.Helper()
	name := "atomic_bench_" + strings.ReplaceAll(f.org.String(), "-", "")
	sql := `CREATE FUNCTION ` + name + `()RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.org_id='` + f.org.String() + `'::uuid AND NEW.action IN('compliance.ingest','compliance.bench.run_requested')THEN RAISE EXCEPTION 'private fixture failure';END IF;RETURN NEW;END$$`
	if _, err := f.database.Pool().Exec(t.Context(), sql); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.Pool().Exec(t.Context(), `CREATE TRIGGER `+name+` BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION `+name+`()`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = f.database.Pool().Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER IF EXISTS `+name+` ON audit_events;DROP FUNCTION IF EXISTS `+name+`()`)
	})
}

func TestComplianceWriteClusterLockFencesOwnershipChange(t *testing.T) {
	f := newComplianceAgentFixture(t)
	tx, err := f.database.Pool().Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(t.Context()) }()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/fixture", nil)
	w := httptest.NewRecorder()
	scope := complianceWriteScope{orgID: f.org, clusterID: &f.cluster}
	if !scope.lockCluster(w, r, tx) {
		t.Fatalf("owned cluster lock refused %s", w.Body.String())
	}
	ctx, cancel := context.WithTimeout(t.Context(), 150*time.Millisecond)
	defer cancel()
	_, err = f.database.Pool().Exec(ctx, `UPDATE clusters SET org_id=$1 WHERE id=$2`, f.foreignOrg, f.cluster)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("owner change bypassed FOR SHARE: %v", err)
	}
	if err := tx.Rollback(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.database.Pool().Exec(t.Context(), `UPDATE clusters SET org_id=$1 WHERE id=$2`, f.foreignOrg, f.cluster); err != nil {
		t.Fatal(err)
	}
}

func TestCompliancePreparedScopeRechecksOwnershipInsideWrite(t *testing.T) {
	f := newComplianceAgentFixture(t)
	task := f.queue(t, f.org, &f.cluster)
	scope := complianceWriteScope{orgID: f.org, clusterID: &f.cluster, actorID: &f.user}
	if _, err := f.database.Pool().Exec(t.Context(), `UPDATE clusters SET org_id=$1 WHERE id=$2`, f.foreignOrg, f.cluster); err != nil {
		t.Fatal(err)
	}
	for _, write := range []func(http.ResponseWriter, *http.Request, complianceWriteScope){f.service.ingest, f.service.claimBenchRun} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/fixture", bytes.NewBufferString(kbClusterSampleJSON))
		w := httptest.NewRecorder()
		write(w, r, scope)
		if w.Code != http.StatusNotFound {
			t.Fatalf("stale owner write accepted %d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT count(*)FROM compliance_checks WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("changedscope evidence count%d err%v", count, err)
	}
	assertBenchTasksPending(t, f, []uuid.UUID{task})
}

func TestComplianceBenchmarkIdentifierCompatibility(t *testing.T) {
	f := newComplianceAgentFixture(t)
	for _, action := range []string{"ingest", "bench/run"} {
		if w := f.call(t, action, "?benchmark=..%2Foutside", "", false); w.Code != http.StatusBadRequest {
			t.Fatalf("unsafe benchmark %s %d %s", action, w.Code, w.Body.String())
		}
		w := f.call(t, action, "?benchmark=%20eks-1.4.0%20&cluster_id="+f.cluster.String(), "", false)
		if w.Code != http.StatusOK && w.Code != http.StatusAccepted {
			t.Fatalf("trimmed known pin refused %s %d %s", action, w.Code, w.Body.String())
		}
	}
	var framework, pin string
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT framework FROM compliance_checks WHERE org_id=$1 ORDER BY framework LIMIT 1`, f.org).Scan(&framework); err != nil || framework != "cis-eks-1.4.0" {
		t.Fatalf("pin not attributed in evidence %s %v", framework, err)
	}
	if err := f.database.Pool().QueryRow(t.Context(), `SELECT benchmark FROM compliance_bench_run_requests WHERE org_id=$1`, f.org).Scan(&pin); err != nil || pin != "eks-1.4.0" {
		t.Fatalf("pin not retained exactly %s %v", pin, err)
	}
}
