//go:build integration

package handler

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
)

type primaryCatalogSinkCase struct {
	kind  string
	path  string
	empty string
	label string
}

func primaryCatalogSinkCases() []primaryCatalogSinkCase {
	return []primaryCatalogSinkCase{
		{"generic-v2", "/v2/_catalog", `{"repositories":[]}`, "generic-v2 catalog"},
		{"nexus", "/v2/_catalog", `{"repositories":[]}`, "nexus catalog"},
		{"openshift", "/v2/_catalog", `{"repositories":[]}`, "openshift catalog"},
		{"quay", "/api/v1/repository", `{"repositories":[]}`, "quay list"},
		{"harbor", "/api/v2.0/projects", `[]`, "harbor list"},
		{"gitlab", "/api/v4/projects", `[]`, "gitlab list"},
		{"jfrog", "/api/repositories", `[]`, "jfrog list"},
	}
}

func newPrimaryCatalogSinkFixture(t *testing.T, database *db.DB, test primaryCatalogSinkCase, fault string) *registryErrorSinkFixture {
	t.Helper()
	f := newRegistryErrorSinkFixture(t, database, "unused", "unused")
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != test.path || (r.Header.Get("Authorization") == "" && r.Header.Get("PRIVATE-TOKEN") == "") {
			t.Error("owned primary catalog refused unexpected path/method or missing credential")
			http.Error(w, "unexpected owned fixture request", http.StatusBadRequest)
			return
		}
		status, body := http.StatusOK, test.empty
		if f.armed.Load() {
			body = registrySinkCanary
			if fault == "status" {
				status = http.StatusUnauthorized
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if _, err := io.WriteString(w, body); err != nil {
			t.Error("owned primary catalog response write failed")
		}
	}))
	t.Cleanup(server.Close)
	sealed, err := sealCredentials(t.Context(), database.Pool(), "static", map[string]string{"username": "owned-user", "password": "owned-password", "token": "owned-token"})
	if err != nil {
		t.Fatal("owned catalog credentials could not be sealed")
	}
	// Existing fixture trusts TLS only in its freshly owned orgs. IgnoreProxy is
	// row-local, so all network access here goes directly to this loopback server;
	// fixed public-authority DockerHub/GHCR are covered by injected transports.
	if _, err := database.Pool().Exec(t.Context(), `UPDATE registries SET kind=$1,endpoint=$2,auth_kind='static',auth_secret=$3,scan_policy='{"ignore_proxy":true}'::jsonb WHERE org_id=$4 AND id=ANY($5)`, test.kind, server.URL, sealed, f.cache.orgs[0], f.cache.ids[:2]); err != nil {
		t.Fatal("owned catalog registry fixture update failed")
	}
	return f
}

func requirePrimaryCatalogSafe(t *testing.T, text string, test primaryCatalogSinkCase, fault string) {
	t.Helper()
	status := "HTTP 200"
	if fault == "status" {
		status = "HTTP 401"
	}
	if text == "" || strings.Contains(text, registrySinkCanary) || !strings.Contains(text, test.label) || !strings.Contains(text, status) {
		t.Fatal("primary catalog error exposed remote value or lost stage/status")
	}
}

func requirePrimaryCatalogFailedHandlers(t *testing.T, f *registryErrorSinkFixture, test primaryCatalogSinkCase, fault string) string {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[1]
	f.armed.Store(true)
	var tested struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	readRegistrySinkJSON(t, f.call(t, "test", org, id), &tested)
	if tested.OK {
		t.Fatal("failed primary catalog Test reported success")
	}
	requirePrimaryCatalogSafe(t, tested.Error, test, fault)
	var synced SyncResult
	readRegistrySinkJSON(t, f.call(t, "sync-now", org, id), &synced)
	if synced.Status != "failed" || synced.Error != tested.Error || synced.ImagesSeen != 0 || synced.JobsEnqueued != 0 {
		t.Fatal("failed primary catalog SyncNow lost safe failure or enqueued inventory")
	}
	if f.auditCount(t, id, "registry.test") != 0 || f.auditCount(t, id, "registry.sync-now") != 1 {
		t.Fatal("failed primary catalog altered audit outcome semantics")
	}
	var status, saved string
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT last_sync_status,last_sync_error FROM registries WHERE id=$1 AND org_id=$2`, id, org).Scan(&status, &saved); err != nil || status != "failed" || saved != synced.Error {
		t.Fatal("stored primary catalog error differs from categorical response")
	}
	return saved
}

func requirePrimaryCatalogWalker(t *testing.T, f *registryErrorSinkFixture, expected string) {
	t.Helper()
	org, id := f.cache.orgs[0], f.cache.ids[1]
	walkerSyncOne(t.Context(), f.cache.database.Pool(), slog.New(slog.NewTextHandler(io.Discard, nil)), audit.New(f.cache.database.Pool()), walkerDueRow{id: id, orgID: org, name: "owned-primary-catalog"})
	var records []byte
	var count int
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT count(*),COALESCE(jsonb_agg(after),'[]'::jsonb) FROM audit_events WHERE org_id=$1 AND target_kind='registry' AND target_id=$2 AND action='registry.sync.walker'`, org, id.String()).Scan(&count, &records); err != nil {
		t.Fatal("owned primary catalog walker audit read failed")
	}
	var after []struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if json.Unmarshal(records, &after) != nil || count != 1 || len(after) != 1 || after[0].Status != "failed" || after[0].Error != expected || strings.Contains(string(records), registrySinkCanary) {
		t.Fatal("primary catalog walker audit exposed remote value or lost exact receipt")
	}
	var jobs int
	if err := f.cache.database.Pool().QueryRow(t.Context(), `SELECT count(*) FROM scan_jobs WHERE org_id=$1`, org).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatal("failed primary catalog enqueued scan jobs")
	}
}

func TestPrimaryCatalogErrorsRemainRedactedAtActualSinks(t *testing.T) {
	database := openTestDB(t)
	t.Cleanup(database.Close)
	for _, test := range primaryCatalogSinkCases() {
		for _, fault := range []string{"status", "json"} {
			t.Run(test.kind+"/"+fault, func(t *testing.T) {
				f := newPrimaryCatalogSinkFixture(t, database, test, fault)
				f.requireSuccessfulControl(t)
				safe := requirePrimaryCatalogFailedHandlers(t, f, test, fault)
				f.requireReaderSinks(t, safe)
				requirePrimaryCatalogWalker(t, f, safe)
			})
		}
	}
}
