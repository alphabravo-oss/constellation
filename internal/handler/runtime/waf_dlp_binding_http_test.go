package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/handler/authctx"
)

// TestGroupSensorBindings_HTTP_RoundTrip exercises Bind → List → Unbind against a
// live DB and asserts the binding is org-scoped (a second org never sees it).
func TestGroupSensorBindings_HTTP_RoundTrip(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}

	// A real group to bind to (FK on group_dpi_sensor_bindings.group_id).
	groupID := uuid.New()
	groupName := "net43-http-" + groupID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO groups (id, org_id, name, kind, criteria) VALUES ($1,$2,$3,'ground','[]'::jsonb)`,
		groupID, orgID, groupName); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	sensorID := uuid.New()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM group_dpi_sensor_bindings WHERE group_id=$1`, groupID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, groupID)
	})

	h := NewGroupSensorBindingsHTTP(d, nil)
	// created_by is a real FK to users(id); use a seeded user so Bind doesn't trip it.
	var userID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM users LIMIT 1`).Scan(&userID); err != nil {
		t.Skipf("no seed user: %v", err)
	}
	withUser := func(r *http.Request, org uuid.UUID) *http.Request {
		return r.WithContext(authctx.WithSubject(r.Context(),
			authctx.Subject{UserID: userID, OrgID: org}))
	}

	// --- Bind (happy path) ---
	body, _ := json.Marshal(BindRequest{GroupID: groupID, SensorKind: SensorKindWAF, SensorID: sensorID})
	rec := httptest.NewRecorder()
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/runtime/dpi-sensor-bindings", bytes.NewReader(body)), orgID)
	h.Bind(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Bind status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created GroupSensorBinding
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode Bind: %v", err)
	}
	if created.ID == uuid.Nil || created.GroupID != groupID || created.Kind != SensorKindWAF || created.SensorID != sensorID {
		t.Fatalf("Bind returned %+v", created)
	}

	// --- Bind (new UI path): sensor_id is optional and defaults to the
	// stable per-kind "all current DLP rules" sentinel. ---
	implicitGroupID := uuid.New()
	implicitName := "net43-http-implicit-" + implicitGroupID.String()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO groups (id, org_id, name, kind, criteria) VALUES ($1,$2,$3,'ground','[]'::jsonb)`,
		implicitGroupID, orgID, implicitName); err != nil {
		t.Fatalf("seed implicit group: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM group_dpi_sensor_bindings WHERE group_id=$1`, implicitGroupID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=$1`, implicitGroupID)
	})
	body, _ = json.Marshal(map[string]any{"group_id": implicitGroupID, "sensor_kind": SensorKindDLP})
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodPost, "/api/v1/runtime/dpi-sensor-bindings", bytes.NewReader(body)), orgID)
	h.Bind(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Bind implicit status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var implicitCreated GroupSensorBinding
	if err := json.Unmarshal(rec.Body.Bytes(), &implicitCreated); err != nil {
		t.Fatalf("decode implicit Bind: %v", err)
	}
	if implicitCreated.GroupID != implicitGroupID || implicitCreated.Kind != SensorKindDLP || implicitCreated.SensorID != defaultDPISensorID(SensorKindDLP) {
		t.Fatalf("implicit Bind returned %+v", implicitCreated)
	}

	// --- List (owning org sees it) ---
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodGet, "/api/v1/runtime/dpi-sensor-bindings", nil), orgID)
	h.List(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("List status = %d", rec.Code)
	}
	var listResp struct {
		Bindings []GroupSensorBinding `json:"bindings"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &listResp)
	found := false
	for _, b := range listResp.Bindings {
		if b.ID == created.ID {
			found = true
		}
	}
	if !found {
		t.Fatalf("owning org List missing binding %s: %+v", created.ID, listResp.Bindings)
	}

	// --- Org scoping: a different org never sees it ---
	otherOrg := uuid.New()
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodGet, "/api/v1/runtime/dpi-sensor-bindings", nil), otherOrg)
	h.List(rec, req)
	var otherResp struct {
		Bindings []GroupSensorBinding `json:"bindings"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &otherResp)
	for _, b := range otherResp.Bindings {
		if b.ID == created.ID {
			t.Fatalf("org scoping broken: other org saw binding %s", created.ID)
		}
	}

	// --- Unbind is org-scoped: the other org cannot delete it ---
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/runtime/dpi-sensor-bindings/"+created.ID.String(), nil), otherOrg)
	h.Unbind(rec, req)
	// still present under the owning org
	got, err := h.store.ListForOrg(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("cross-org Unbind deleted the binding (org scoping broken)")
	}

	// --- Unbind (owning org) removes it ---
	rec = httptest.NewRecorder()
	req = withUser(httptest.NewRequest(http.MethodDelete, "/api/v1/runtime/dpi-sensor-bindings/"+created.ID.String(), nil), orgID)
	h.Unbind(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("Unbind status = %d", rec.Code)
	}
	got, _ = h.store.ListForOrg(ctx, orgID)
	for _, b := range got {
		if b.ID == created.ID {
			t.Fatal("binding still present after owning-org Unbind")
		}
	}
}

// TestGroupSensorBindings_BoundGroupDefs asserts the bundle helper returns the
// selector of a bound group and omits an unbound one.
func TestGroupSensorBindings_BoundGroupDefs(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	pool := d.Pool()

	var orgID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM orgs ORDER BY created_at LIMIT 1`).Scan(&orgID); err != nil {
		t.Skipf("no seed org: %v", err)
	}
	boundID, unboundID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx,
		`INSERT INTO groups (id, org_id, name, kind, criteria) VALUES
		 ($1,$3,$4,'ground','[{"key":"namespace","value":"payments","op":"eq"}]'::jsonb),
		 ($2,$3,$5,'ground','[]'::jsonb)`,
		boundID, unboundID, orgID, "net43-bound-"+boundID.String()[:8], "net43-unbound-"+unboundID.String()[:8]); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM group_dpi_sensor_bindings WHERE group_id=ANY($1)`, []uuid.UUID{boundID, unboundID})
		_, _ = pool.Exec(context.Background(), `DELETE FROM groups WHERE id=ANY($1)`, []uuid.UUID{boundID, unboundID})
	})

	store := NewGroupSensorBindingStore(d)
	if _, err := store.Bind(ctx, orgID, boundID, SensorKindDLP, uuid.New(), nil); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	defs, err := store.BoundGroupDefs(ctx, orgID)
	if err != nil {
		t.Fatal(err)
	}
	var sawBound, sawUnbound bool
	for _, dfn := range defs {
		if dfn.ID == boundID {
			sawBound = true
			if len(dfn.Criteria) != 1 || dfn.Criteria[0].Key != "namespace" || dfn.Criteria[0].Value != "payments" {
				t.Fatalf("bound group selector = %+v", dfn.Criteria)
			}
		}
		if dfn.ID == unboundID {
			sawUnbound = true
		}
	}
	if !sawBound {
		t.Fatal("BoundGroupDefs omitted the bound group")
	}
	if sawUnbound {
		t.Fatal("BoundGroupDefs included an unbound group")
	}
}
