package handler

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

func TestDeploymentListFiltersAndExportParity(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	ctx := t.Context()
	pool := database.Pool()
	org, foreign, cluster, sibling := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, id := range []uuid.UUID{org, foreign} {
		if _, err := pool.Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, id, "deployment-list-"+id.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM orgs WHERE id IN ($1,$2)`, org, foreign) })
	if _, err := pool.Exec(ctx, `INSERT INTO clusters(id,org_id,name) VALUES($1,$3,'main'),($2,$3,'sibling')`, cluster, sibling, org); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,labels,risk_score,finding_count,critical_count,last_seen_at)
 SELECT $1,$2,'custom-install','agent-'||n,'Deployment','{"helm.sh/chart":" Constellation-1.2.3 "}'::jsonb,99,99,99,'2026-10-12T00:00:00Z' FROM generate_series(1,650)n`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_score,finding_count,high_count,last_seen_at)
 SELECT $1,$2,'payments','customer-'||lpad(n::text,4,'0'),'Deployment',60,1,1,'2026-10-12T00:00:00Z' FROM generate_series(1,605)n`, org, cluster); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO deployments(org_id,cluster_id,namespace,name,kind,risk_score,last_seen_at) VALUES
 ($1,$2,'astronomer-screenshot-demo','prefix-app','Deployment',40,'2026-10-12T00:00:00Z'),
 ($1,$2,'payments','percent%under_score','Deployment',20,'2026-10-12T00:00:00Z'),
 ($1,$3,'payments','customer-sibling','Deployment',90,'2026-10-12T00:00:00Z'),
 ($4,$2,'payments','customer-foreign','Deployment',100,'2026-10-12T00:00:00Z')`, org, cluster, sibling, foreign); err != nil {
		t.Fatal(err)
	}
	handler := NewDeployments(database, nil)
	request := func(params url.Values, export bool, allowed *[]string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/deployments?"+params.Encode(), nil)
		req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: org}))
		if allowed != nil {
			req = req.WithContext(authctx.WithNamespaceFilter(req.Context(), *allowed))
		}
		w := httptest.NewRecorder()
		if export {
			handler.ExportCSV(w, req)
		} else {
			handler.List(w, req)
		}
		return w
	}
	type listResponse struct {
		Deployments          []deploymentListRow `json:"deployments"`
		Total, PlatformCount int64
		HasMore              bool                  `json:"has_more"`
		Summary              deploymentListSummary `json:"summary"`
	}
	// Read snake-case source metadata without changing the DTO's public contract.
	get := func(params url.Values, allowed *[]string) listResponse {
		t.Helper()
		w := request(params, false, allowed)
		if w.Code != 200 {
			t.Fatalf("list status=%d: %s", w.Code, w.Body.String())
		}
		var result listResponse
		var envelope struct {
			PlatformCount int64 `json:"platform_count"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(w.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		result.PlatformCount = envelope.PlatformCount
		return result
	}
	params := url.Values{"cluster_id": {cluster.String()}, "hide_platform": {"true"}, "limit": {"100"}}
	first := get(params, nil)
	if len(first.Deployments) != 100 || first.Total != 607 || first.PlatformCount != 650 || !first.HasMore || first.Summary.AtRisk != 605 || first.Summary.HighCount != 605 || first.Summary.CriticalCount != 0 {
		t.Fatalf("first page count=%d total=%d platform=%d summary=%+v", len(first.Deployments), first.Total, first.PlatformCount, first.Summary)
	}
	for _, row := range first.Deployments {
		if row.PlatformRole != "" {
			t.Fatal("platform row escaped hidden filter")
		}
	}
	repeated := get(params, nil)
	for i, row := range first.Deployments {
		if repeated.Deployments[i].ID != row.ID {
			t.Fatal("unstable tie order")
		}
	}
	params.Set("offset", "600")
	last := get(params, nil)
	if len(last.Deployments) != 7 || last.Total != 607 || last.HasMore {
		t.Fatal("last page/count disagree")
	}
	exported := request(params, true, nil)
	records, err := csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 608 {
		t.Fatalf("full filtered export rows=%d", len(records))
	}
	for i, row := range first.Deployments {
		if records[i+1][2] != row.Name {
			t.Fatal("CSV/page ordering differs")
		}
	}
	if strings.Contains(exported.Body.String(), "agent-") || !strings.Contains(exported.Body.String(), "customer-0605") {
		t.Fatal("export does not match visibility/source filters")
	}
	params.Del("offset")
	params.Set("q", "payments/customer-0605")
	deep := get(params, nil)
	if deep.Total != 1 || len(deep.Deployments) != 1 || deep.Deployments[0].Name != "customer-0605" {
		t.Fatal("qualified deep search failed")
	}
	params.Del("q")
	params.Set("name", "CUSTOMER-0605")
	if got := get(params, nil); got.Total != 1 {
		t.Fatal("case-insensitive name alias failed")
	}
	params.Del("name")
	for _, literal := range []string{"%", "_"} {
		params.Set("q", literal)
		if got := get(params, nil); got.Total != 1 || got.Deployments[0].Name != "percent%under_score" {
			t.Fatal("search treated literal punctuation as wildcards")
		}
	}
	params.Del("q")
	params.Set("hide_platform", "false")
	params.Set("platform_role", "core")
	core := get(params, nil)
	if core.Total != 650 || core.PlatformCount != 650 || core.Deployments[0].PlatformRole != "core" {
		t.Fatal("explicit core filter failed")
	}
	params.Set("hide_platform", "true")
	if got := get(params, nil); got.Total != 0 || got.PlatformCount != 650 {
		t.Fatal("contradictory visibility must not broaden rows")
	}
	params.Set("platform_role", "none")
	if got := get(params, nil); got.Total != 607 || got.PlatformCount != 0 {
		t.Fatal("customer role filter failed")
	}
	params.Del("platform_role")
	allowed := []string{"payments"}
	restricted := get(params, &allowed)
	if restricted.Total != 606 || restricted.PlatformCount != 0 {
		t.Fatal("namespace restriction leaked counts")
	}
	exported = request(params, true, &allowed)
	records, err = csv.NewReader(strings.NewReader(exported.Body.String())).ReadAll()
	if err != nil || len(records) != 607 {
		t.Fatal("namespace restriction/export differs")
	}
	params.Set("namespace", "custom-install")
	if got := get(params, &allowed); got.Total != 0 || got.PlatformCount != 0 {
		t.Fatal("explicit namespace bypassed grant")
	}
	params.Del("namespace")
	denied := []string{"ungranted-namespace"}
	if got := get(params, &denied); got.Total != 0 || len(got.Deployments) != 0 {
		t.Fatal("nonmatching namespace grant must not broaden inventory")
	}
	// The shared namespace context contract treats nil/empty filters as absent.
	// requireVerbNS rejects a caller with no grants before invoking this handler.
	for _, unrestricted := range [][]string{nil, {}} {
		if got := get(params, &unrestricted); got.Total != 607 {
			t.Fatal("changed empty namespace-filter contract")
		}
	}
	for key, value := range map[string]string{"platform_role": "other", "hide_platform": "other", "cluster_id": "bad"} {
		bad := url.Values{}
		for k, v := range params {
			bad[k] = append([]string{}, v...)
		}
		bad.Set(key, value)
		for _, export := range []bool{false, true} {
			if w := request(bad, export, nil); w.Code != 400 {
				t.Fatalf("invalid %s export=%t status=%d", key, export, w.Code)
			}
		}
	}
	var unchanged int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM deployments WHERE org_id=$1 AND cluster_id=$2`, org, cluster).Scan(&unchanged); err != nil || unchanged != 1257 {
		t.Fatal("visibility changed collection")
	}
}

func TestDeploymentPlatformSQLParity(t *testing.T) {
	database := openTestDB(t)
	defer database.Close()
	type fixture struct{ namespace, labels string }
	cases := []fixture{
		{"custom-install", `{"app.kubernetes.io/part-of":"  ASTRONOMER-DELIVERY\t"}`},
		{"custom-install", `{"helm.sh/chart":"constellation"}`}, {"custom-install", `{"helm.sh/chart":"constellation-9.0"}`},
		{"custom-install", `{"app.kubernetes.io/instance":"astronomer","app.kubernetes.io/managed-by":"\u0085HELM\u3000"}`},
		{"custom-install", `{"app.kubernetes.io/instance":"constellation"}`},
		{"custom-install", `{"app.kubernetes.io/part-of":"constellation","unrelated":42}`},
		{"custom-install", `{"app.kubernetes.io/part-of":"constellation","unrelated":null}`},
		{"custom-install", `{"app.kubernetes.io/part-of":"customer","helm.sh/chart":"constellation-app"}`},
		{"custom-install", `[]`}, {"custom-install", `null`}, {"custom-install", `{"nested":{}}`},
		{"astronomer-screenshot-demo", `{}`}, {"\t KUBE-SYSTEM\u00a0", `[]`},
	}
	for ns := range platformNamespaces {
		cases = append(cases, fixture{" \t" + strings.ToUpper(ns) + "\u00a0", `{}`})
	}
	for _, item := range cases {
		var got string
		if err := database.Pool().QueryRow(t.Context(), "SELECT "+platformRoleSQL("$1::text", "$2::jsonb"), item.namespace, item.labels).Scan(&got); err != nil {
			t.Fatal(err)
		}
		want := PlatformRoleJSON(item.namespace, json.RawMessage(item.labels))
		if got != want {
			t.Fatalf("namespace=%q SQL=%q Go=%q", item.namespace, got, want)
		}
	}
}
