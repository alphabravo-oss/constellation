package handler

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

const registrySinkCanary = "938475621938475621938475621"

type registryErrorSinkFixture struct {
	cache   *registryCacheCallerFixture
	handler *Registries
	user    uuid.UUID
	armed   atomic.Bool
	stage   string
	fault   string
}

func newRegistryErrorSinkFixture(t *testing.T, database *db.DB, stage, fault string) *registryErrorSinkFixture {
	t.Helper()
	f := &registryErrorSinkFixture{user: uuid.New(), stage: stage, fault: fault}
	f.cache = newRegistryCacheCallerFixture(t, database, f.response)
	f.handler = NewRegistries(database, audit.New(database.Pool()))
	if _, err := database.Pool().Exec(t.Context(), `INSERT INTO users(id,org_id,email,display_name) VALUES($1,$2,$3,'Owned registry error fixture')`, f.user, f.cache.orgs[0], f.user.String()+"@example.invalid"); err != nil {
		t.Fatal("owned audit actor fixture creation failed")
	}
	return f
}

func (f *registryErrorSinkFixture) response(stage string, status int, body string) (int, string) {
	if !f.armed.Load() || stage != f.stage {
		return status, body
	}
	if f.fault == "status" {
		return http.StatusUnauthorized, registrySinkCanary
	}
	if stage == "token" {
		return http.StatusOK, `{"access_token":"owned-invalid-expiry","expires_in":` + registrySinkCanary + `}`
	}
	return http.StatusOK, `{"dockerImages":[{"updateTime":"` + registrySinkCanary + `"}]}`
}

func (f *registryErrorSinkFixture) call(t *testing.T, operation string, org, id uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	method := http.MethodPost
	path := "/registries/" + id.String() + "/" + operation
	var serve http.HandlerFunc
	switch operation {
	case "test":
		serve = f.handler.Test
	case "sync-now":
		serve = f.handler.SyncNow
	case "get":
		method, path, serve = http.MethodGet, "/registries/"+id.String(), f.handler.Get
	case "list":
		method, path, serve = http.MethodGet, "/registries", f.handler.List
	default:
		t.Fatal("invalid owned handler operation")
	}
	req := httptest.NewRequestWithContext(t.Context(), method, path, nil)
	route := chi.NewRouteContext()
	route.URLParams.Add("id", id.String())
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, route)
	req = req.WithContext(WithSubject(ctx, Subject{OrgID: org, UserID: f.user}))
	out := httptest.NewRecorder()
	serve(out, req)
	return out
}

func readRegistrySinkJSON(t *testing.T, rr *httptest.ResponseRecorder, value any) {
	t.Helper()
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), value) != nil {
		t.Fatal("actual registry handler did not return expected JSON response")
	}
}

func (f *registryErrorSinkFixture) auditCount(t *testing.T, id uuid.UUID, action string) int {
	t.Helper()
	var count int
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM audit_events WHERE org_id=$1 AND actor_id=$2 AND target_kind='registry' AND target_id=$3 AND action=$4`, f.cache.orgs[0], f.user, id.String(), action).Scan(&count); err != nil {
		t.Fatal("owned actor audit count failed")
	}
	return count
}

func (f *registryErrorSinkFixture) requireSuccessfulControl(t *testing.T) {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[0]
	var tested struct {
		OK bool `json:"ok"`
	}
	readRegistrySinkJSON(t, f.call(t, "test", org, id), &tested)
	var synced SyncResult
	readRegistrySinkJSON(t, f.call(t, "sync-now", org, id), &synced)
	if !tested.OK || synced.Status != "ok" || synced.ImagesSeen != 0 || synced.JobsEnqueued != 0 {
		t.Fatal("owned successful control did not complete Test and SyncNow")
	}
	if f.auditCount(t, id, "registry.test") != 1 || f.auditCount(t, id, "registry.sync-now") != 1 {
		t.Fatal("successful control did not prove both real actor audit writers")
	}
}

func requireRegistrySinkRedacted(t *testing.T, text, stage, fault string) {
	t.Helper()
	label := "gcp token"
	if stage == "catalog" {
		label = "artifact-registry list"
	}
	status := "HTTP 200"
	if fault == "status" {
		status = "HTTP 401"
	}
	if text == "" || strings.Contains(text, registrySinkCanary) || !strings.Contains(text, label) || !strings.Contains(text, status) {
		t.Fatal("actual registry sink did not retain categorical stage/status without secret")
	}
}

func (f *registryErrorSinkFixture) requireFailedHandlers(t *testing.T) string {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[1]
	f.armed.Store(true)
	var tested struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	readRegistrySinkJSON(t, f.call(t, "test", org, id), &tested)
	if tested.OK {
		t.Fatal("failed registry Test reported success")
	}
	requireRegistrySinkRedacted(t, tested.Error, f.stage, f.fault)
	var synced SyncResult
	readRegistrySinkJSON(t, f.call(t, "sync-now", org, id), &synced)
	if synced.Status != "failed" || synced.ImagesSeen != 0 || synced.JobsEnqueued != 0 || synced.Error != tested.Error {
		t.Fatal("failed SyncNow lost safe failure or enqueued inventory")
	}
	if f.auditCount(t, id, "registry.test") != 0 || f.auditCount(t, id, "registry.sync-now") != 1 {
		t.Fatal("failed Test emitted success receipt or SyncNow lost existing audit behavior")
	}
	var status, persisted string
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT last_sync_status,last_sync_error FROM registries WHERE id=$1 AND org_id=$2`, id, org).Scan(&status, &persisted); err != nil {
		t.Fatal("owned saved registry status read failed")
	}
	if status != "failed" || persisted != synced.Error {
		t.Fatal("persisted registry error differed from safe API error")
	}
	return persisted
}

func (f *registryErrorSinkFixture) requireReaderSinks(t *testing.T, expected string) {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[1]
	var got registryDTO
	readRegistrySinkJSON(t, f.call(t, "get", org, id), &got)
	if got.ID != id || got.OrgID != org || got.LastSyncError != expected {
		t.Fatal("owned Get lost safe retained error")
	}
	var list struct {
		Registries []registryDTO `json:"registries"`
	}
	readRegistrySinkJSON(t, f.call(t, "list", org, id), &list)
	found := false
	for _, row := range list.Registries {
		if row.ID == id {
			found = row.OrgID == org && row.LastSyncError == expected
		}
	}
	if !found {
		t.Fatal("owning List omitted current safe failure")
	}
	if f.call(t, "get", f.cache.orgs[1], id).Code != http.StatusNotFound {
		t.Fatal("foreign Get disclosed owned registry")
	}
	readRegistrySinkJSON(t, f.call(t, "list", f.cache.orgs[1], id), &list)
	for _, row := range list.Registries {
		if row.ID == id {
			t.Fatal("foreign List disclosed owned registry")
		}
	}
}

func (f *registryErrorSinkFixture) requireWalkerSink(t *testing.T, expected string) {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[1]
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	walkerSyncOne(t.Context(), f.cache.database.Pool(), logger, audit.New(f.cache.database.Pool()), walkerDueRow{id: id, orgID: org, name: "owned-error-registry"})
	var count int
	var after []byte
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT count(*),COALESCE(jsonb_agg(after),'[]'::jsonb) FROM audit_events WHERE org_id=$1 AND target_kind='registry' AND target_id=$2 AND action='registry.sync.walker'`, org, id.String()).Scan(&count, &after); err != nil {
		t.Fatal("owned walker audit receipt read failed")
	}
	var records []struct {
		Error  string `json:"error"`
		Status string `json:"status"`
	}
	if json.Unmarshal(after, &records) != nil || count != 1 || len(records) != 1 || records[0].Error != expected || records[0].Status != "failed" {
		t.Fatal("exact walker audit did not retain categorical current failure")
	}
	requireRegistrySinkRedacted(t, string(after), f.stage, f.fault)
	var jobs int
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM scan_jobs WHERE org_id=$1`, org).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("failed registry response enqueued a job")
	}
}

func exerciseRegistryErrorSinks(t *testing.T, database *db.DB, stage, fault string) {
	t.Helper()
	f := newRegistryErrorSinkFixture(t, database, stage, fault)
	f.requireSuccessfulControl(t)
	safe := f.requireFailedHandlers(t)
	f.requireReaderSinks(t, safe)
	f.requireWalkerSink(t, safe)
}

func TestRegistryCloudResponseErrorsRemainRedactedAtActualSinks(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	for _, stage := range []string{"token", "catalog"} {
		for _, fault := range []string{"status", "json"} {
			t.Run(stage+"/"+fault, func(t *testing.T) { exerciseRegistryErrorSinks(t, database, stage, fault) })
		}
	}
}
