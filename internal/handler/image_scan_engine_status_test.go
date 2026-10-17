package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestImageScanResultsExposeEngineOutcomes(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	orgID, resultID := uuid.New(), uuid.New()
	ctx := t.Context()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,'Scan evidence')`, orgID, "scan-engines-"+orgID.String()); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = d.Pool().Exec(context.WithoutCancel(ctx), `DELETE FROM orgs WHERE id=$1`, orgID) }()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO image_scan_results(id,org_id,image_ref,image_ref_normalized,image_repository,image_digest,platform,scanner_profile) VALUES($1,$2,'example.com/test:latest','example.com/test:latest','example.com/test','sha256:test','linux/amd64','default')`, resultID, orgID); err != nil {
		t.Fatal(err)
	}
	h := NewImageScanResults(d)
	request := func(org uuid.UUID, list bool) *httptest.ResponseRecorder {
		route := chi.NewRouteContext()
		route.URLParams.Add("id", resultID.String())
		requestCtx := WithSubject(ctx, Subject{OrgID: org})
		requestCtx = context.WithValue(requestCtx, chi.RouteCtxKey, route)
		r := httptest.NewRequestWithContext(requestCtx, http.MethodGet, "/api/v1/image-scan-results", nil)
		w := httptest.NewRecorder()
		if list {
			h.List(w, r)
		} else {
			h.Get(w, r)
		}
		return w
	}
	for _, status := range []string{`{}`, `{"syft":"succeeded","trivy":"succeeded","grype":"failed"}`, `{"syft":"succeeded","trivy":"succeeded","grype":"succeeded"}`} {
		if _, err := d.Pool().Exec(ctx, `UPDATE image_scan_results SET engine_status=$2 WHERE id=$1`, resultID, status); err != nil {
			t.Fatal(err)
		}
		var want map[string]string
		if err := json.Unmarshal([]byte(status), &want); err != nil {
			t.Fatal(err)
		}
		for _, list := range []bool{false, true} {
			w := request(orgID, list)
			if w.Code != 200 {
				t.Fatalf("list=%v status=%d", list, w.Code)
			}
			assertImageEngineResponse(t, w.Body.Bytes(), want, list)
		}
	}
	if w := request(uuid.New(), false); w.Code != 404 {
		t.Fatalf("foreign result status=%d", w.Code)
	}
}

func assertImageEngineResponse(t *testing.T, response []byte, want map[string]string, list bool) {
	t.Helper()
	var body struct {
		Result  imageScanResultDTO   `json:"image_scan_result"`
		Results []imageScanResultDTO `json:"image_scan_results"`
	}
	if err := json.Unmarshal(response, &body); err != nil {
		t.Fatal(err)
	}
	got := body.Result.EngineStatus
	if list {
		if len(body.Results) != 1 {
			t.Fatal("unexpected result count")
		}
		got = body.Results[0].EngineStatus
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("engine outcomes got %v want %v", got, want)
	}
}
