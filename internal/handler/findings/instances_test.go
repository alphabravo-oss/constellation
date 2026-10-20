//go:build integration

package findings

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

func instanceRequest(t *testing.T, f *exceptionEvidenceFixture, id uuid.UUID, path, query string, body any, fn http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&b).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	method := "GET"
	if body != nil {
		method = "POST"
	}
	r := httptest.NewRequestWithContext(t.Context(), method, path+"?"+query, &b)
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id.String())
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
	r = r.WithContext(authctx.WithSubject(ctx, authctx.Subject{OrgID: f.org, UserID: f.actor}))
	w := httptest.NewRecorder()
	fn(w, r)
	return w
}
func insertInstance(t *testing.T, f *exceptionEvidenceFixture, id uuid.UUID, at time.Time) {
	t.Helper()
	f.exec(t, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,title,severity,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'vulnerability','instance fixture','high',$5,$5)`, id, f.org, f.cluster, f.asset, at)
	t.Cleanup(func() { _, _ = f.d.Pool().Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, f.org) })
}
func exactQuery(at time.Time) string {
	return "first_seen_at=" + url.QueryEscape(at.Format(time.RFC3339Nano))
}
func TestFindingInstancesExactReadsMutationsAndComments(t *testing.T) {
	t.Parallel()
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	first := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	second := first.Add(time.Microsecond)
	insertInstance(t, f, id, first)
	insertInstance(t, f, id, second)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	comments := NewComments(f.d, audit.New(f.d.Pool()))
	var identities []instanceIdentity
	for _, at := range []time.Time{first, second} {
		w := instanceRequest(t, f, id, "/finding-instances/"+id.String(), exactQuery(at), nil, h.Get)
		if w.Code != 200 {
			t.Fatalf("GET%d %s", w.Code, w.Body)
		}
		var got instanceIdentity
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if !got.FirstSeen.Equal(at) || got.Revision != "1" || got.SourceClusterID == nil || *got.SourceClusterID != f.cluster || got.TargetClusterID != nil {
			t.Fatalf("identity%+v", got)
		}
		identities = append(identities, got)
	}
	if identities[0].RowID == identities[1].RowID {
		t.Fatal("recurrence row IDs collided")
	}
	for _, fn := range []http.HandlerFunc{h.Get, comments.List} {
		w := instanceRequest(t, f, id, "/findings/"+id.String(), "", nil, fn)
		if w.Code != 409 || !strings.Contains(w.Body.String(), "ambiguous_finding_id") {
			t.Fatalf("legacy ambiguity%d %s", w.Code, w.Body)
		}
	}
	for _, q := range []string{"", "first_seen_at=", exactQuery(first) + "&first_seen_at=" + url.QueryEscape(second.Format(time.RFC3339Nano)), "first_seen_at=2026-10-12T00:00:00.1234567Z"} {
		w := instanceRequest(t, f, id, "/finding-instances/"+id.String(), q, nil, h.Get)
		if w.Code != 400 {
			t.Fatalf("selector%d %s", w.Code, w.Body)
		}
	}
	for _, body := range []map[string]any{{"reason": "reviewed"}, {"reason": "reviewed", "reviewed_revision": "01"}, {"reason": "reviewed", "reviewed_revision": "2"}} {
		w := instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/suppress", exactQuery(first), body, h.Suppress)
		want := 409
		switch body["reviewed_revision"] {
		case nil:
			want = 428
		case "01":
			want = 400
		}
		if w.Code != want {
			t.Fatalf("precondition%d want%d %s", w.Code, want, w.Body)
		}
	}
	w := instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/suppress", exactQuery(first), map[string]any{"reason": "first occurrence only", "reviewed_revision": "1"}, h.Suppress)
	if w.Code != 200 {
		t.Fatalf("suppress%d %s", w.Code, w.Body)
	}
	var receipt instanceIdentity
	_ = json.Unmarshal(w.Body.Bytes(), &receipt)
	if receipt.Revision != "2" || receipt.RowID != identities[0].RowID {
		t.Fatalf("receipt%+v", receipt)
	}
	var lifecycle, revision string
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT lifecycle,revision::text FROM findings WHERE id=$1 AND first_seen_at=$2`, id, second).Scan(&lifecycle, &revision); err != nil || lifecycle != "open" || revision != "1" {
		t.Fatalf("sibling changed%s %s %v", lifecycle, revision, err)
	}
	var logged time.Time
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT (after->>'finding_first_seen_at')::timestamptz FROM audit_events WHERE org_id=$1 AND action='finding.suppress'`, f.org).Scan(&logged); err != nil || !logged.Equal(first) {
		t.Fatalf("audit identity%v %v", logged, err)
	}
	// A UUID-only legacy comment is retained as UUID history, not assigned to either recurrence.
	f.exec(t, `INSERT INTO finding_comments(finding_id,org_id,author_id,body) VALUES($1,$2,$3,'old UUID history')`, id, f.org, f.actor)
	w = instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/comments", exactQuery(first), map[string]any{"body": "exact comment", "reviewed_revision": "2"}, comments.Create)
	if w.Code != 201 {
		t.Fatalf("comment%d %s", w.Code, w.Body)
	}
	var comment commentDTO
	_ = json.Unmarshal(w.Body.Bytes(), &comment)
	if comment.FindingID != id || comment.ID == id || comment.RowID != identities[0].RowID || comment.FirstSeen == nil || !comment.FirstSeen.Equal(first) {
		t.Fatalf("commentidentity%+v", comment)
	}
	for i, at := range []time.Time{first, second} {
		w = instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/comments", exactQuery(at), nil, comments.List)
		var got struct{ Comments, LegacyComments []commentDTO }
		var raw struct {
			Comments []commentDTO `json:"comments"`
			Legacy   []commentDTO `json:"legacy_comments"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &raw)
		got.Comments, got.LegacyComments = raw.Comments, raw.Legacy
		if w.Code != 200 || len(got.Comments) != (1-i) || len(got.LegacyComments) != 1 {
			t.Fatalf("threads%d %s", w.Code, w.Body)
		}
	}
	var count int
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 2 {
		t.Fatalf("failed precondition audited%d %v", count, err)
	}
}
func TestFindingInstancesConcurrentRevisionAndScope(t *testing.T) {
	t.Parallel()
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	at := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	insertInstance(t, f, id, at)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	target := uuid.New()
	f.exec(t, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'target')`, target, f.org)
	f.exec(t, `UPDATE findings SET target_cluster_id=$1 WHERE id=$2 AND first_seen_at=$3`, target, id, at)
	for _, cluster := range []uuid.UUID{f.cluster, target} {
		w := instanceRequest(t, f, id, "/finding-instances/"+id.String(), exactQuery(at)+"&cluster_id="+cluster.String(), nil, h.Get)
		if w.Code != 200 {
			t.Fatalf("actual scope%d %s", w.Code, w.Body)
		}
	}
	w := instanceRequest(t, f, id, "/finding-instances/"+id.String(), exactQuery(at)+"&cluster_id="+uuid.NewString(), nil, h.Get)
	if w.Code != 404 {
		t.Fatal("unknown cluster accepted")
	}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, fn := range []http.HandlerFunc{h.Triage, h.Suppress} {
		wg.Add(1)
		go func(fn http.HandlerFunc) {
			defer wg.Done()
			codes <- instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/action", exactQuery(at), map[string]any{"reviewed_revision": "2", "reason": "one winner"}, fn).Code
		}(fn)
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[409] != 1 {
		t.Fatalf("CAS%v", counts)
	}
	var n int
	_ = f.d.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1`, f.org).Scan(&n)
	if n != 1 {
		t.Fatalf("CASaudit%d", n)
	}
}
func TestFindingInstancesLegacyUniqueAndRevisionPartitionRetention(t *testing.T) {
	t.Parallel()
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	insertInstance(t, f, id, at)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	w := instanceRequest(t, f, id, "/findings/"+id.String()+"/triage", "", map[string]any{"priority": "high"}, h.Triage)
	if w.Code != 200 {
		t.Fatalf("legacy%d %s", w.Code, w.Body)
	}
	// Existing default and newly-created partitions must both inherit revision behavior.
	table := "findings_revision_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.exec(t, fmt.Sprintf(`CREATE TABLE %s PARTITION OF findings FOR VALUES FROM ('2100-01-01') TO ('2101-01-01')`, table))
	t.Cleanup(func() { _, _ = f.d.Pool().Exec(context.Background(), "DROP TABLE IF EXISTS "+table) })
	future := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	newID := uuid.New()
	insertInstance(t, f, newID, future)
	f.exec(t, `UPDATE findings SET title='new partition update' WHERE id=$1 AND first_seen_at=$2`, newID, future)
	var rev string
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT revision::text FROM findings WHERE id=$1 AND first_seen_at=$2`, newID, future).Scan(&rev); err != nil || rev != "2" {
		t.Fatalf("partitiontrigger%s %v", rev, err)
	}
	// An exact comment does not add an FK that prevents normal finding partition removal.
	c := NewComments(f.d, audit.New(f.d.Pool()))
	w = instanceRequest(t, f, newID, "/finding-instances/"+newID.String()+"/comments", exactQuery(future), map[string]any{"body": "retained history", "reviewed_revision": "2"}, c.Create)
	if w.Code != 201 {
		t.Fatalf("futurecomment%d %s", w.Code, w.Body)
	}
	f.exec(t, "DROP TABLE "+table)
	w = instanceRequest(t, f, newID, "/finding-instances/"+newID.String(), exactQuery(future), nil, h.Get)
	if w.Code != 404 {
		t.Fatalf("removedinstance%d", w.Code)
	}
}

func TestFindingInstancesAcceptanceReachabilityAndExport(t *testing.T) {
	t.Parallel()
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	a := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	b := a.Add(time.Microsecond)
	insertInstance(t, f, id, a)
	insertInstance(t, f, id, b)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	w := instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/accept-risk", exactQuery(a), map[string]any{"reason": "only the reviewed recurrence", "accepted_until": time.Now().UTC().Add(time.Hour), "reviewed_revision": "1"}, h.AcceptRisk)
	if w.Code != 200 {
		t.Fatalf("accept%d %s", w.Code, w.Body)
	}
	w = instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/reachability", exactQuery(b), map[string]any{"runtime_confirmed": true, "source": "uprobe", "reviewed_revision": "1"}, h.Reachability)
	if w.Code != 200 {
		t.Fatalf("reachability%d %s", w.Code, w.Body)
	}
	var receipt struct {
		RiskInputs map[string]any `json:"risk_inputs"`
		Revision   string         `json:"revision"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &receipt)
	if receipt.RiskInputs["reachable_runtime"] != true || receipt.Revision != "2" {
		t.Fatalf("reachabilityreceipt%+v", receipt)
	}
	var untouched bool
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT risk_inputs ? 'reachable_runtime' FROM findings WHERE id=$1 AND first_seen_at=$2`, id, a).Scan(&untouched); err != nil || untouched {
		t.Fatalf("acceptedsiblingreachability%v %v", untouched, err)
	}
	// List and matching CSV preserve both UUID recurrences and deterministic ties.
	w = instanceRequest(t, f, id, "/findings", "q=id:"+id.String()+"&sort=title&order=asc", nil, h.List)
	var list struct {
		Findings []findingDTO `json:"findings"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if w.Code != 200 || len(list.Findings) != 2 || !list.Findings[0].FirstSeen.Equal(a) || list.Findings[0].RowID == list.Findings[1].RowID {
		t.Fatalf("list%d %s", w.Code, w.Body)
	}
	csvH := NewFindingsCSV(f.d)
	w = instanceRequest(t, f, id, "/findings.csv", "q=id:"+id.String()+"&sort=title&order=asc", nil, csvH.Stream)
	rows, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(rows) != 3 {
		t.Fatalf("csv%d %v %s", w.Code, err, w.Body)
	}
	headers := map[string]int{}
	for i, key := range rows[0] {
		headers[key] = i
	}
	if rows[1][headers["first_seen_at"]] != a.Format(time.RFC3339Nano) || rows[2][headers["first_seen_at"]] != b.Format(time.RFC3339Nano) || rows[1][headers["row_id"]] != list.Findings[0].RowID {
		t.Fatal("CSV lost exact identity/precision")
	}
	// One UUID-wide historical audit event cannot supply a reason to both records.
	f.log(t, f.actor, "finding.accept_risk", "finding", id.String(), map[string]any{"reason": "unidentified UUID reason"})
	exceptions := f.list(t, "")
	if len(exceptions) != 1 || exceptions[0].Reason != "only the reviewed recurrence" || len(exceptions[0].FindingInstances) != 1 || !exceptions[0].FindingInstances[0].FirstSeen.Equal(a) {
		t.Fatalf("exception attribution%+v", exceptions)
	}
}

func TestFindingInstanceSelectorAndRevisionParsing(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	for _, tc := range []struct {
		value string
		valid bool
	}{{"", false}, {"0", false}, {"01", false}, {"+1", false}, {"1.0", false}, {"1", true}, {"9223372036854775807", true}, {"9223372036854775808", false}} {
		err := checkReviewedRevision(true, tc.value, tc.value)
		if (err == nil) != tc.valid {
			t.Fatalf("revision%q %v", tc.value, err)
		}
	}
	for _, at := range []time.Time{time.Unix(0, -500000000), time.Unix(0, 0), time.Unix(1791763200, 123456000)} {
		key := findingRowID(id, at)
		if !strings.HasPrefix(key, id.String()+":") {
			t.Fatal("identityprefix")
		}
		if at.UnixMicro() == -500000 && !strings.HasSuffix(key, "-0.500000") {
			t.Fatal(key)
		}
	}
}

func TestFindingInstancesTenantIsolationAndMissingRows(t *testing.T) {
	t.Parallel()
	f, foreign := newExceptionEvidenceFixture(t), newExceptionEvidenceFixture(t)
	id := uuid.New()
	at := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	insertInstance(t, f, id, at)
	insertInstance(t, foreign, id, at.Add(time.Microsecond))
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	w := instanceRequest(t, f, id, "/findings/"+id.String(), "", nil, h.Get)
	if w.Code != 200 {
		t.Fatalf("foreign recurrence must not cause ambiguity%d %s", w.Code, w.Body)
	}
	for _, selector := range []string{exactQuery(at.Add(time.Microsecond)), exactQuery(at) + "&cluster_id=" + foreign.cluster.String()} {
		w = instanceRequest(t, f, id, "/finding-instances/"+id.String(), selector, nil, h.Get)
		if w.Code != 404 {
			t.Fatalf("foreign scope%d %s", w.Code, w.Body)
		}
	}
	for _, fn := range []http.HandlerFunc{h.Triage, h.Suppress, h.AcceptRisk, h.Reachability} {
		body := map[string]any{"reviewed_revision": "1", "reason": "no missing finding mutation", "accepted_until": time.Now().Add(time.Hour), "runtime_confirmed": true}
		w = instanceRequest(t, f, uuid.New(), "/finding-instances/missing/action", exactQuery(at), body, fn)
		if w.Code != 404 {
			t.Fatalf("missing mutation%d %s", w.Code, w.Body)
		}
	}
	var count int
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1`, f.org).Scan(&count); err != nil || count != 0 {
		t.Fatalf("missing audit%d %v", count, err)
	}
}

func TestFindingInstancesAuditFailureRollsBackMutation(t *testing.T) {
	t.Parallel()
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	at := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	insertInstance(t, f, id, at)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	name := "reject_finding_audit_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	f.exec(t, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.org_id='%s'::uuid THEN RAISE EXCEPTION 'fixture audit unavailable'; END IF; RETURN NEW; END$$`, name, f.org.String()))
	f.exec(t, fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION %s()`, name, name))
	t.Cleanup(func() {
		_, _ = f.d.Pool().Exec(context.Background(), fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON audit_events", name))
		_, _ = f.d.Pool().Exec(context.Background(), "DROP FUNCTION IF EXISTS "+name+"()")
	})
	w := instanceRequest(t, f, id, "/finding-instances/"+id.String()+"/suppress", exactQuery(at), map[string]any{"reason": "must roll back", "reviewed_revision": "1"}, h.Suppress)
	if w.Code != 500 {
		t.Fatalf("audit failure%d %s", w.Code, w.Body)
	}
	var lifecycle, revision string
	if err := f.d.Pool().QueryRow(t.Context(), `SELECT lifecycle,revision::text FROM findings WHERE id=$1 AND first_seen_at=$2`, id, at).Scan(&lifecycle, &revision); err != nil || lifecycle != "open" || revision != "1" {
		t.Fatalf("nonatomic mutation%s %s %v", lifecycle, revision, err)
	}
}

func TestFindingInstanceChooserEnumeratesOwnedWorkloadOccurrences(t *testing.T) {
	t.Parallel()
	f, foreign := newExceptionEvidenceFixture(t), newExceptionEvidenceFixture(t)
	id, otherID := uuid.New(), uuid.New()
	first := time.Date(2026, 10, 12, 0, 0, 0, 123456000, time.UTC)
	second := first.Add(time.Microsecond)
	insertInstance(t, f, id, first)
	insertInstance(t, f, id, second)
	insertInstance(t, foreign, id, second.Add(time.Microsecond))
	insertInstance(t, f, otherID, second.Add(2*time.Microsecond))
	target := uuid.New()
	f.exec(t, `INSERT INTO clusters(id,org_id,name)VALUES($1,$2,'chooser target')`, target, f.org)
	f.exec(t, `UPDATE findings SET target_type='workload',target_ref='apps/api',target_cluster_id=$1 WHERE org_id=$2 AND id=$3`, target, f.org, id)
	f.exec(t, `UPDATE findings SET lifecycle='accepted' WHERE org_id=$1 AND id=$2 AND first_seen_at=$3`, f.org, id, second)
	h := NewFindings(f.d, audit.New(f.d.Pool()), nil)
	read := func(query string) []findingDTO {
		t.Helper()
		w := instanceRequest(t, f, id, "/findings", query, nil, h.List)
		if w.Code != 200 {
			t.Fatalf("chooser%d %s", w.Code, w.Body)
		}
		var got struct {
			Findings []findingDTO `json:"findings"`
			Total    int          `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Total != len(got.Findings) {
			t.Fatal("chooser total mismatch")
		}
		return got.Findings
	}
	ordinary := read("sort=title&order=asc")
	if len(ordinary) != 1 || ordinary[0].ID != otherID {
		t.Fatalf("ordinary canonical exclusion changed%+v", ordinary)
	}
	chooser := "q=" + url.QueryEscape("id:"+id.String()) + "&sort=title&order=asc"
	rows := read(chooser)
	if len(rows) != 2 || rows[0].RowID == rows[1].RowID || !rows[0].FirstSeen.Equal(first) || !rows[1].FirstSeen.Equal(second) {
		t.Fatalf("chooser lost owned recurrence%+v", rows)
	}
	for _, cluster := range []uuid.UUID{f.cluster, target} {
		if got := read(chooser + "&cluster_id=" + cluster.String()); len(got) != 2 {
			t.Fatal("chooser lost exact source/target context")
		}
	}
	if got := read(chooser + "&cluster_id=" + foreign.cluster.String()); len(got) != 0 {
		t.Fatal("chooser borrowed foreign cluster")
	}
	if got := read("q=" + url.QueryEscape("id:"+id.String()+" severity:high")); len(got) != 0 {
		t.Fatal("compound query bypassed canonical exclusion")
	}
	if got := read("q=" + url.QueryEscape("id:"+id.String()[:8])); len(got) != 0 {
		t.Fatal("partial ID bypassed canonical exclusion")
	}
	for _, row := range rows {
		w := instanceRequest(t, f, id, "/finding-instances/"+id.String(), exactQuery(row.FirstSeen)+"&cluster_id="+target.String(), nil, h.Get)
		if w.Code != 200 {
			t.Fatalf("chooser exact destination%d %s", w.Code, w.Body)
		}
	}
	csvH := NewFindingsCSV(f.d)
	w := instanceRequest(t, f, id, "/findings.csv", chooser, nil, csvH.Stream)
	exported, err := csv.NewReader(strings.NewReader(w.Body.String())).ReadAll()
	if w.Code != 200 || err != nil || len(exported) != 3 {
		t.Fatalf("chooser export%d %v rows%d", w.Code, err, len(exported))
	}
}
func TestFindingExactIDChooserGrammar(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	for _, raw := range []string{"id:" + id.String(), "  ID:" + strings.ToUpper(id.String()) + "  "} {
		got, ok := findingExactIDQuery(raw)
		if !ok || got != id {
			t.Fatalf("valid chooser%q", raw)
		}
	}
	for _, raw := range []string{"id:" + id.String()[:8], "id:bad", "id:" + id.String() + " severity:high", "id:g/" + id.String(), "id:\"" + id.String() + "\"", "id:{" + id.String() + "}", "id:urn:uuid:" + id.String()} {
		if _, ok := findingExactIDQuery(raw); ok {
			t.Fatalf("unsafe chooser%q", raw)
		}
	}
}
