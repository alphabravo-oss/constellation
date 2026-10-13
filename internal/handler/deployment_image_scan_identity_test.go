package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestDeploymentImageScanIdentity(t *testing.T) {
	d := openTestDB(t)
	t.Cleanup(d.Close)
	ctx := context.Background()
	pool := d.Pool()
	org, foreignOrg, cluster, foreignCluster, deployment, foreignDeployment := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(ctx, `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreignOrg); err != nil {
			t.Errorf("cleanup: %v", err)
		}
	})
	for _, id := range []uuid.UUID{org, foreignOrg} {
		exec(`INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Image identity test')`, id, "image-identity-"+id.String())
	}
	exec(`INSERT INTO clusters(id,org_id,name,distro,state) VALUES($1,$2,'owned','k3s','connected'),($3,$4,'foreign','k3s','connected')`, cluster, org, foreignCluster, foreignOrg)
	exec(`INSERT INTO deployments(id,org_id,cluster_id,namespace,name,kind) VALUES($1,$2,$3,'apps','api','Deployment'),($4,$5,$6,'apps','api','Deployment')`, deployment, org, cluster, foreignDeployment, foreignOrg, foreignCluster)
	ref, normalized, repository, tag := "registry.test/apps/api:current", "registry.test/apps/api:current", "registry.test/apps/api", "current"
	now := time.Now().UTC().Truncate(time.Second)
	old, tiedA, tiedB, reused, foreign := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	if tiedA.String() > tiedB.String() {
		tiedA, tiedB = tiedB, tiedA
	}
	insertScan := func(id, owner uuid.UUID, digest, profile string, scanned time.Time) {
		t.Helper()
		exec(`INSERT INTO image_scan_results(id,org_id,image_ref,image_ref_normalized,image_repository,image_tag,image_digest,scanner_profile,package_count,finding_count,last_scanned_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,12,2,$9)`, id, owner, ref, normalized, repository, tag, digest, profile, scanned)
	}
	insertScan(old, org, "sha256:abcdef", "old", now.Add(-time.Hour))
	insertScan(tiedA, org, "sha256:abcdef", "tie-a", now)
	insertScan(tiedB, org, "sha256:abcdef", "tie-b", now)
	insertScan(reused, org, "sha256:123456", "new-tag", now.Add(time.Hour))
	insertScan(foreign, foreignOrg, "sha256:abcdef", "foreign", now.Add(2*time.Hour))
	exec(`INSERT INTO image_scan_findings(org_id,image_scan_result_id,finding_key,title,severity,risk_score) VALUES($1,$2,'critical','Owned critical','critical',77),($1,$2,'high','Owned high','high',60),($3,$2,'foreign-child','Foreign child','critical',100)`, org, tiedB, foreignOrg)
	for _, scan := range []struct{ id, owner uuid.UUID }{{tiedB, org}, {reused, org}, {foreign, foreignOrg}} {
		exec(`INSERT INTO image_scan_artifacts(org_id,image_scan_result_id,artifact_type,format,payload,sha256,package_count) VALUES($1,$2,'file-risk','constellation-image-file-risk-v1','{"status":"observed","file_risk_count":1,"findings":[{"path":"/usr/bin/helper"}]}'::jsonb,'sha256:fixture',1)`, scan.owner, scan.id)
	}
	// Independent org columns must not let a foreign artifact borrow the owned scan.
	exec(`INSERT INTO image_scan_artifacts(org_id,image_scan_result_id,artifact_type,format,payload,sha256,package_count) VALUES($1,$2,'file-risk','constellation-image-file-risk-v1','{"status":"observed","file_risk_count":99}'::jsonb,'sha256:foreign-child',99)`, foreignOrg, tiedB)
	h := NewDeployments(d, nil)
	for _, tc := range []struct {
		name       string
		digest     any
		imageRef   string
		normalized string
		repository string
		tag        string
		want       uuid.UUID
	}{
		{"known digest defeats newer reused tag and foreign scan", "sha256:abcdef", ref, normalized, repository, tag, tiedB},
		{"uppercase algorithm fails closed", "SHA256:abcdef", ref, normalized, repository, tag, uuid.Nil},
		{"uppercase suffix does not case fold", "sha256:ABCDEF", ref, normalized, repository, tag, uuid.Nil},
		{"malformed nonempty digest fails closed", "not-a-digest", ref, normalized, repository, tag, uuid.Nil},
		{"unmatched opaque digest fails closed", "sha256:unmatched", ref, normalized, repository, tag, uuid.Nil},
		{"padded known digest remains exact", " sha256:abcdef ", ref, normalized, repository, tag, uuid.Nil},
		{"null digest reference fallback", nil, ref, "unrelated-normalized", "unrelated", "unrelated", reused},
		{"empty digest normalized reference fallback", "", "unrelated-ref", normalized, "unrelated", "unrelated", reused},
		{"blank digest repository tag fallback", "   ", "unrelated-ref", "unrelated-normalized", repository, tag, reused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// One retained link at a time keeps each fallback branch independently exercised.
			exec(`DELETE FROM image_workload_links WHERE org_id=$1`, org)
			exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_repository,image_tag,image_digest) VALUES($1,$2,$3,'apps/api','apps','api','Deployment',$4,$5,$6,$7,$8)`, org, cluster, deployment, tc.imageRef, tc.normalized, tc.repository, tc.tag, tc.digest)
			for attempt := 0; attempt < 2; attempt++ {
				images, err := h.deploymentImages(httptest.NewRequest("GET", "/", nil), org, deployment)
				if err != nil || len(images) != 1 {
					t.Fatalf("images=%+v err=%v", images, err)
				}
				wantID := ""
				if tc.want != uuid.Nil {
					wantID = tc.want.String()
				}
				if images[0].ImageScanResultID != wantID {
					t.Fatalf("selected scan=%q want=%q", images[0].ImageScanResultID, wantID)
				}
				if tc.want == tiedB && (images[0].CriticalCount != 1 || images[0].HighCount != 1 || images[0].MaxRiskScore != 77 || images[0].ScannerProfile != "tie-b") {
					t.Fatalf("owned rollups/latest profile: %+v", images[0])
				}
				if tc.want == uuid.Nil && (images[0].LastScannedAt != nil || images[0].FindingCount != 0 || images[0].CriticalCount != 0 || images[0].MaxRiskScore != 0) {
					t.Fatalf("unmatched digest borrowed scan evidence: %+v", images[0])
				}
				risks, err := h.deploymentFileRisks(httptest.NewRequest("GET", "/", nil), org, deployment)
				if err != nil {
					t.Fatal(err)
				}
				if tc.want == uuid.Nil {
					if len(risks) != 0 {
						t.Fatalf("unmatched digest borrowed file-risk artifact: %+v", risks)
					}
				} else if len(risks) != 1 || risks[0].ImageScanResultID != wantID || risks[0].FileRiskCount != 1 || len(risks[0].Findings) != 1 {
					t.Fatalf("file-risk identity/owned artifact: %+v want scan=%s", risks, wantID)
				}
			}
		})
	}
	t.Run("malformed cross organization and cluster links do not borrow deployments", func(t *testing.T) {
		exec(`DELETE FROM image_workload_links WHERE org_id=$1`, org)
		exec(`INSERT INTO image_workload_links(org_id,cluster_id,deployment_id,workload_id,namespace,name,kind,image_ref,image_ref_normalized,image_digest) VALUES($1,$2,$3,'apps/api','apps','api','Deployment','wrong-org','wrong-org','sha256:abcdef'),($1,$2,$4,'apps/api','apps','api','Deployment','wrong-cluster','wrong-cluster','sha256:abcdef')`, org, foreignCluster, foreignDeployment, deployment)
		for _, target := range []uuid.UUID{deployment, foreignDeployment} {
			images, err := h.deploymentImages(httptest.NewRequest("GET", "/", nil), org, target)
			if err != nil || len(images) != 0 {
				t.Fatalf("target=%s images=%+v err=%v", target, images, err)
			}
			risks, err := h.deploymentFileRisks(httptest.NewRequest("GET", "/", nil), org, target)
			if err != nil || len(risks) != 0 {
				t.Fatalf("target=%s file risks=%+v err=%v", target, risks, err)
			}
		}
	})
}
