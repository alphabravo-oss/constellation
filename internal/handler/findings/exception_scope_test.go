package findings

import (
	"context"
	"encoding/json"
	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler/authctx"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFindingGetReturnsClusterScope(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, cluster, asset, id := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	defer func() { _, _ = d.Pool().Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, org) }()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,external_id,title,severity) VALUES($1,$2,$3,$4,'vulnerability','CVE-2099-1234','scope','high')`, id, org, cluster, asset); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		org    uuid.UUID
		status int
	}{{org, 200}, {uuid.New(), 404}} {
		req := httptest.NewRequest("GET", "/", nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id.String())
		req = req.WithContext(context.WithValue(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: tc.org}), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		NewFindings(d, nil, nil).Get(w, req)
		if w.Code != tc.status {
			t.Fatalf("status %d %s", w.Code, w.Body.String())
		}
		if tc.status == 200 {
			var got struct {
				ClusterID string `json:"cluster_id"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.ClusterID != cluster.String() {
				t.Fatalf("scope %+v %v", got, err)
			}
		}
	}
}

func TestVulnerabilityExceptionsClusterScope(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := t.Context()
	org, foreign, c1, c2, foreignCluster, a1, a2, f1, f2, accept := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	defer func() {
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM findings WHERE org_id=$1`, org)
		_, _ = d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=ANY($1)`, []uuid.UUID{org, foreign})
	}()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, id.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, org uuid.UUID }{{c1, org}, {c2, org}, {foreignCluster, foreign}} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,$3)`, item.id, item.org, item.id.String()); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct{ id, cluster, finding uuid.UUID }{{a1, c1, f1}, {a2, c2, f2}} {
		if _, err := d.Pool().Exec(ctx, `INSERT INTO assets(id,org_id,cluster_id,kind,name,digest) VALUES($1,$2,$3,'image',$4,$4)`, item.id, org, item.cluster, item.id.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Pool().Exec(ctx, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,external_id,title,severity,lifecycle,accepted_until) VALUES($1,$2,$3,$4,'vulnerability','CVE-2099-9999','accepted','high','accepted',NOW()+interval '1 day')`, item.finding, org, item.cluster, item.id); err != nil {
			t.Fatal(err)
		}
	}
	actor := uuid.New()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'Scope actor')`, actor, org, actor.String()+"@example.test"); err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + accept.String()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO images(asset_id,registry,repository,digest) VALUES($1,'example.test','fixture',$2)`, a1, digest); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO image_acceptances(id,org_id,image_digest,rationale,accepted_until,approver_id) VALUES($1,$2,$3,'cluster scoped test acceptance',NOW()+interval '1 day',$4)`, accept, org, digest, actor); err != nil {
		t.Fatal(err)
	}
	globalAsset, globalAcceptance, dep := uuid.New(), uuid.New(), uuid.New()
	globalDigest := "sha256:" + globalAcceptance.String()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO assets(id,org_id,kind,name) VALUES($1,$2,'image','global image')`, globalAsset, org); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO images(asset_id,registry,repository,digest) VALUES($1,'example.test','global',$2)`, globalAsset, globalDigest); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO image_acceptances(id,org_id,image_digest,rationale,accepted_until,approver_id) VALUES($1,$2,$3,'linked acceptance',NOW()+interval '1 day',$4)`, globalAcceptance, org, globalDigest, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind) VALUES($1,$2,$3,'apps','api','Deployment')`, dep, org, c2); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool().Exec(ctx, `INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest) VALUES($1,$2,$3,'apps/api','apps','api','Deployment','example.test/global:tag','example.test/global:tag',$4)`, org, c2, dep, globalDigest); err != nil {
		t.Fatal(err)
	}
	request := func(cluster string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/?cluster_id="+cluster, nil)
		req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: org}))
		w := httptest.NewRecorder()
		NewVulnerabilityExceptions(d).List(w, req)
		return w
	}
	for _, tc := range []struct {
		cluster       string
		status, total int
	}{{c1.String(), 200, 2}, {c2.String(), 200, 2}, {"", 200, 4}, {foreignCluster.String(), 404, 0}, {"bad", 400, 0}} {
		w := request(tc.cluster)
		if w.Code != tc.status {
			t.Fatalf("cluster %s status %d: %s", tc.cluster, w.Code, w.Body.String())
		}
		if w.Code != 200 {
			continue
		}
		var got struct {
			Exceptions []vulnerabilityExceptionDTO `json:"exceptions"`
			Summary    map[string]int              `json:"summary"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if len(got.Exceptions) != tc.total || got.Summary["total"] != tc.total {
			t.Fatalf("unexpected scope results %+v", got)
		}
		if tc.cluster != "" {
			for _, item := range got.Exceptions {
				if len(item.Scope.Clusters) != 1 || item.Scope.Clusters[0] != tc.cluster {
					t.Fatalf("scope evidence %+v", item.Scope)
				}
			}
		}
	}
}

type exceptionEvidenceFixture struct {
	d                                             *db.DB
	org, cluster, asset, actor, approver, revoker uuid.UUID
}

func newExceptionEvidenceFixture(t *testing.T) *exceptionEvidenceFixture {
	t.Helper()
	f := &exceptionEvidenceFixture{d: openTestDB(t), org: uuid.New(), cluster: uuid.New(), asset: uuid.New(), actor: uuid.New(), approver: uuid.New(), revoker: uuid.New()}
	t.Cleanup(f.d.Close)
	t.Cleanup(func() { _, _ = f.d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, f.org) })
	f.exec(t, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, f.org, f.org.String())
	f.exec(t, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'truth fixture')`, f.cluster, f.org)
	f.exec(t, `INSERT INTO assets(id,org_id,cluster_id,kind,name,digest,labels) VALUES($1,$2,$3,'image','truth image','sha256:fixture','{"namespace":"apps","workload":"api"}')`, f.asset, f.org, f.cluster)
	for _, id := range []uuid.UUID{f.actor, f.approver, f.revoker} {
		f.exec(t, `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,$3)`, id, f.org, id.String()+"@example.test")
	}
	return f
}
func (f *exceptionEvidenceFixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.d.Pool().Exec(t.Context(), query, args...); err != nil {
		t.Fatal(err)
	}
}
func (f *exceptionEvidenceFixture) log(t *testing.T, actor uuid.UUID, action, kind, target string, after any) {
	t.Helper()
	if _, _, err := audit.New(f.d.Pool()).Log(t.Context(), audit.Event{OrgID: &f.org, ActorID: &actor, Action: action, TargetKind: kind, TargetID: target, After: after}); err != nil {
		t.Fatal(err)
	}
}
func (f *exceptionEvidenceFixture) list(t *testing.T, cluster string) []vulnerabilityExceptionDTO {
	t.Helper()
	req := httptest.NewRequest("GET", "/?cluster_id="+cluster, nil)
	req = req.WithContext(authctx.WithSubject(req.Context(), authctx.Subject{OrgID: f.org, UserID: f.actor}))
	w := httptest.NewRecorder()
	NewVulnerabilityExceptions(f.d).List(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		Exceptions       []vulnerabilityExceptionDTO          `json:"exceptions"`
		Summary          map[string]int                       `json:"summary"`
		PolicyGuardrails []vulnerabilityExceptionGuardrailDTO `json:"policy_guardrails"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Summary["total"] != len(got.Exceptions) {
		t.Fatalf("summary mismatch %+v", got)
	}
	for _, guard := range got.PolicyGuardrails {
		if guard.Enforcement != "advisory" {
			t.Fatalf("unverified enforced guard %+v", guard)
		}
	}
	for _, item := range got.Exceptions {
		if item.Scope.AdmissionScope != "not_evaluated" || len(item.PolicyGuardIDs) != 0 || len(item.RiskAcceptance.CompensatingControls) != 0 || item.RiskAcceptance.ReviewCadence != "" {
			t.Fatalf("fabricated enforcement evidence %+v", item)
		}
	}
	return got.Exceptions
}
func exceptionByID(t *testing.T, items []vulnerabilityExceptionDTO, id string) vulnerabilityExceptionDTO {
	t.Helper()
	var matches []vulnerabilityExceptionDTO
	for _, item := range items {
		if item.ID == id {
			return item
		}
		if strings.HasPrefix(id, "finding-") && len(item.FindingRefs) == 1 && item.FindingRefs[0] == strings.TrimPrefix(id, "finding-") {
			matches = append(matches, item)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	t.Fatalf("missing or ambiguous %s in %+v", id, items)
	return vulnerabilityExceptionDTO{}
}

func TestVulnerabilityExceptionsMissingAuditDoesNotInventFindingEvidence(t *testing.T) {
	f := newExceptionEvidenceFixture(t)
	for _, lifecycle := range []string{"accepted", "suppressed"} {
		id := uuid.New()
		f.exec(t, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,title,description,severity,lifecycle,accepted_until) VALUES($1,$2,$3,$4,'vulnerability','finding','not a recorded reason','critical',$5,NOW()+interval '1 day')`, id, f.org, f.cluster, f.asset, lifecycle)
		item := exceptionByID(t, f.list(t, f.cluster.String()), "finding-"+id.String())
		if item.Reason != "" || item.Requester.ID != "" || item.Requester.Name != "" || item.Requester.Email != "" || item.Requester.Team != "" || item.Approver != nil || item.RequestedAt != "" || item.ApprovedAt != "" || len(item.AuditEvents) != 0 {
			t.Fatalf("fabricated audit evidence %+v", item)
		}
		if lifecycle == "suppressed" && item.ExpiresAt != "" {
			t.Fatalf("invented suppression expiry %+v", item)
		}
	}
}
func TestVulnerabilityExceptionsUsesMatchingFindingAuditAndExplicitApprover(t *testing.T) {
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	f.exec(t, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,title,severity,lifecycle,accepted_until) VALUES($1,$2,$3,$4,'vulnerability','finding','high','accepted',NOW()+interval '1 day')`, id, f.org, f.cluster, f.asset)
	f.log(t, f.actor, "finding.accept_risk", "finding", id.String(), map[string]any{"reason": "Actually recorded justification", "approver_id": f.approver.String()})
	// A newer unrelated lifecycle event cannot replace the current acceptance's reason/approver.
	f.log(t, f.revoker, "finding.suppress", "finding", id.String(), map[string]any{"reason": "Different lifecycle operation"})
	item := exceptionByID(t, f.list(t, f.cluster.String()), "finding-"+id.String())
	if item.Reason != "Actually recorded justification" || item.Requester.ID != f.actor.String() || item.Approver == nil || item.Approver.ID != f.approver.String() || item.RequestedAt == "" || item.ApprovedAt == "" || len(item.AuditEvents) != 2 {
		t.Fatalf("lost actual audit evidence %+v", item)
	}
	if item.AuditEvents[1].Actor != f.revoker.String()+"@example.test" {
		t.Fatalf("wrong historical actor %+v", item.AuditEvents)
	}
	idNoApprover := uuid.New()
	f.exec(t, `INSERT INTO findings(id,org_id,cluster_id,asset_id,kind,title,severity,lifecycle,accepted_until) VALUES($1,$2,$3,$4,'vulnerability','finding','high','accepted',NOW()+interval '1 day')`, idNoApprover, f.org, f.cluster, f.asset)
	f.log(t, f.actor, "finding.accept_risk", "finding", idNoApprover.String(), map[string]any{"reason": "No independent approver assigned"})
	without := exceptionByID(t, f.list(t, f.cluster.String()), "finding-"+idNoApprover.String())
	if without.Approver != nil {
		t.Fatalf("requester became approver %+v", without)
	}
}
func TestVulnerabilityExceptionsFindingNullScopeDoesNotInheritAssetCluster(t *testing.T) {
	f := newExceptionEvidenceFixture(t)
	id := uuid.New()
	f.exec(t, `INSERT INTO findings(id,org_id,asset_id,kind,title,severity,lifecycle,accepted_until) VALUES($1,$2,$3,'vulnerability','global finding','high','accepted',NOW()+interval '1 day')`, id, f.org, f.asset)
	if got := f.list(t, f.cluster.String()); len(got) != 0 {
		t.Fatalf("null finding scope inherited asset cluster %+v", got)
	}
	global := exceptionByID(t, f.list(t, ""), "finding-"+id.String())
	if len(global.Scope.Clusters) != 0 {
		t.Fatalf("fabricated cluster evidence %+v", global.Scope)
	}
}
func TestVulnerabilityExceptionsSharedDigestHasBothClusterAssociations(t *testing.T) {
	f := newExceptionEvidenceFixture(t)
	otherCluster, otherAsset, acceptance := uuid.New(), uuid.New(), uuid.New()
	digest := "sha256:" + acceptance.String()
	f.exec(t, `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'other')`, otherCluster, f.org)
	f.exec(t, `INSERT INTO assets(id,org_id,cluster_id,kind,name,labels) VALUES($1,$2,$3,'image','other image','{"namespace":"other-apps","workload":"worker"}')`, otherAsset, f.org, otherCluster)
	for _, asset := range []uuid.UUID{f.asset, otherAsset} {
		f.exec(t, `INSERT INTO images(asset_id,registry,repository,digest) VALUES($1,'example.test','shared',$2)`, asset, digest)
	}
	f.exec(t, `INSERT INTO image_acceptances(id,org_id,image_digest,rationale,approver_id,accepted_until) VALUES($1,$2,$3,'shared digest rationale',$4,NOW()+interval '1 day')`, acceptance, f.org, digest, f.approver)
	for _, cluster := range []string{f.cluster.String(), otherCluster.String(), ""} {
		items := f.list(t, cluster)
		if len(items) != 1 {
			t.Fatalf("duplicate digest exception %+v", items)
		}
		item := items[0]
		if len(item.Scope.Clusters) != 2 || !containsAll(item.Scope.Clusters, f.cluster.String(), otherCluster.String()) || !containsAll(item.Scope.Namespaces, "apps", "other-apps") || !containsAll(item.Scope.Workloads, "api", "worker") {
			t.Fatalf("lost shared digest scope %+v", item.Scope)
		}
		if len(item.AuditEvents) != 0 || item.RiskAcceptance.Severity != "" {
			t.Fatalf("fabricated image audit/risk evidence %+v", item)
		}
	}
}
func TestVulnerabilityExceptionsImageRevokeActorIsExactRecordedRevoker(t *testing.T) {
	f := newExceptionEvidenceFixture(t)
	digest := "sha256:" + uuid.NewString()
	f.exec(t, `INSERT INTO images(asset_id,registry,repository,digest) VALUES($1,'example.test','revoked',$2)`, f.asset, digest)
	// Historical acceptances sharing a digest need their own audit associations.
	for index := 0; index < 2; index++ {
		id := uuid.New()
		f.exec(t, `INSERT INTO image_acceptances(id,org_id,image_digest,rationale,approver_id,accepted_until,revoked_at) VALUES($1,$2,$3,'revoked acceptance',$4,$5,NOW())`, id, f.org, digest, f.approver, time.Now().Add(time.Duration(index+1)*24*time.Hour))
		if index == 0 {
			f.log(t, f.approver, "image.accept-risk", "image", digest, map[string]any{"acceptance_id": id.String(), "rationale": "Actual create reason"})
			f.log(t, f.revoker, "image.accept-risk.revoke", "image", digest, map[string]any{"acceptance_id": id.String()})
		}
		item := exceptionByID(t, f.list(t, f.cluster.String()), "image-"+id.String())
		if index == 0 {
			if len(item.AuditEvents) != 2 || item.AuditEvents[1].Action != "image.accept-risk.revoke" || item.AuditEvents[1].Actor != f.revoker.String()+"@example.test" {
				t.Fatalf("wrong revoke evidence %+v", item.AuditEvents)
			}
		} else if len(item.AuditEvents) != 0 {
			t.Fatalf("borrowed another acceptance's audit actor %+v", item.AuditEvents)
		}
		if item.Approver == nil || item.Approver.ID != f.approver.String() {
			t.Fatalf("lost actual recorded approver %+v", item)
		}
	}
}
