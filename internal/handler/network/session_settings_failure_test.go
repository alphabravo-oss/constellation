package network

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/internal/handler"
)

type sessionSettingsFixture struct {
	database                                 *db.DB
	org, cluster, foreignOrg, foreignCluster uuid.UUID
	token                                    *handler.RuntimeAgentToken
}

func newSessionSettingsFixture(t *testing.T) sessionSettingsFixture {
	t.Helper()
	database := openTestDB(t)
	t.Cleanup(database.Close)
	f := sessionSettingsFixture{database: database, org: uuid.New(), cluster: uuid.New(), foreignOrg: uuid.New(), foreignCluster: uuid.New()}
	pool := database.Pool()
	for _, org := range []uuid.UUID{f.org, f.foreignOrg} {
		if _, err := pool.Exec(t.Context(), `INSERT INTO orgs(id,name,display_name) VALUES($1,$2,$2)`, org, "session-settings-"+org.String()); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, table := range []string{"network_session_kills", "network_sessions", "dpi_threat_settings"} {
			if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM `+table+` WHERE org_id IN ($1,$2)`, f.org, f.foreignOrg); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DELETE FROM orgs WHERE id IN ($1,$2)`, f.org, f.foreignOrg); err != nil {
			t.Error(err)
		}
	})
	if _, err := pool.Exec(t.Context(), `INSERT INTO clusters(id,org_id,name) VALUES($1,$2,'settings'),($3,$4,'foreign')`, f.cluster, f.org, f.foreignCluster, f.foreignOrg); err != nil {
		t.Fatal(err)
	}
	// A token with no init bundle uses the existing single-owned-cluster resolver.
	f.token = &handler.RuntimeAgentToken{ID: uuid.New(), OrgID: f.org}
	if _, err := pool.Exec(t.Context(), `INSERT INTO network_session_kills(org_id,cluster_id,node,session_id) VALUES($1,$2,'node-settings',101),($3,$4,'node-settings',202)`, f.org, f.cluster, f.foreignOrg, f.foreignCluster); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f sessionSettingsFixture) post(t *testing.T, database *db.DB) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/network-sessions:bulk", bytes.NewBufferString(`[{"id":77,"node":"node-settings","client_bytes":123}]`))
	request = request.WithContext(handler.WithRuntimeAgentToken(request.Context(), f.token))
	response := httptest.NewRecorder()
	NewNetwork(database).IngestSessions(response, request)
	return response
}

func (f sessionSettingsFixture) assertStored(t *testing.T, wantKills int) {
	t.Helper()
	pool := f.database.Pool()
	var count, bytesWritten int
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*),COALESCE(SUM(client_bytes),0) FROM network_sessions WHERE org_id=$1 AND cluster_id=$2 AND node='node-settings'`, f.org, f.cluster).Scan(&count, &bytesWritten); err != nil {
		t.Fatal(err)
	}
	if count != 1 || bytesWritten != 123 {
		t.Fatalf("snapshot count=%d bytes=%d", count, bytesWritten)
	}
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM network_session_kills WHERE org_id=$1 AND cluster_id=$2`, f.org, f.cluster).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != wantKills {
		t.Fatalf("owned pending kills=%d want=%d", count, wantKills)
	}
	if err := pool.QueryRow(t.Context(), `SELECT COUNT(*) FROM network_session_kills WHERE org_id=$1 AND cluster_id=$2 AND session_id=202`, f.foreignOrg, f.foreignCluster).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("foreign pending kills=%d", count)
	}
}

func sessionSettingsRestrictedDB(t *testing.T, database *db.DB) (*db.DB, string) {
	t.Helper()
	pool := database.Pool()
	roleName := "session_settings_" + uuid.NewString()
	role := pgx.Identifier{roleName}.Sanitize()
	if _, err := pool.Exec(t.Context(), `CREATE ROLE `+role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DROP OWNED BY `+role); err != nil {
			t.Error(err)
		}
		if _, err := pool.Exec(context.WithoutCancel(t.Context()), `DROP ROLE `+role); err != nil {
			t.Error(err)
		}
	})
	for _, statement := range []string{
		`GRANT USAGE ON SCHEMA public TO ` + role,
		`GRANT SELECT ON cluster_init_bundles,clusters TO ` + role,
		`GRANT SELECT,INSERT,DELETE,UPDATE ON network_sessions TO ` + role,
		`GRANT SELECT,DELETE ON network_session_kills TO ` + role,
	} {
		if _, err := pool.Exec(t.Context(), statement); err != nil {
			t.Fatal(err)
		}
	}
	cfg := pool.Config().Copy()
	cfg.MinConns, cfg.MaxConns = 0, 1
	cfg.ConnConfig.RuntimeParams["role"] = roleName
	restricted, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restricted.Close)
	return db.NewFromPool(restricted), role
}

func assertSessionSettingsResponse(t *testing.T, response *httptest.ResponseRecorder, wantToggle bool, wantKills int) {
	t.Helper()
	var result struct {
		Accepted int     `json:"accepted"`
		Kill     []int64 `json:"kill"`
		WeakTLS  *bool   `json:"weak_tls"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || result.Accepted != 1 || result.WeakTLS == nil || *result.WeakTLS != wantToggle || len(result.Kill) != wantKills {
		t.Fatalf("response status=%d body=%s", response.Code, response.Body.String())
	}
	if wantKills == 1 && result.Kill[0] != 101 {
		t.Fatalf("wrong kill IDs: %v", result.Kill)
	}
}

func TestIngestSessionsSettingsReadFailurePreservesCommittedSnapshotAndKills(t *testing.T) {
	f := newSessionSettingsFixture(t)
	pool := f.database.Pool()
	if _, err := pool.Exec(t.Context(), `INSERT INTO dpi_threat_settings(org_id,cluster_id,weak_tls_enabled) VALUES($1,$2,true)`, f.org, f.cluster); err != nil {
		t.Fatal(err)
	}
	restricted, role := sessionSettingsRestrictedDB(t, f.database)
	response := f.post(t, restricted)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("settings failure status=%d body=%s", response.Code, response.Body.String())
	}
	var failure map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatal(err)
	}
	if len(failure) != 1 || failure["error"] != "read threat settings failed" {
		t.Fatalf("failure response exposes false success or database internals: %s", response.Body.String())
	}
	f.assertStored(t, 1)
	if _, err := pool.Exec(t.Context(), `GRANT SELECT ON dpi_threat_settings TO `+role); err != nil {
		t.Fatal(err)
	}
	assertSessionSettingsResponse(t, f.post(t, restricted), true, 1)
	f.assertStored(t, 0)
	assertSessionSettingsResponse(t, f.post(t, restricted), true, 0)
	f.assertStored(t, 0)
}

func TestIngestSessionsSettingsDeliberateFalseDefaults(t *testing.T) {
	for _, configured := range []bool{false, true} {
		name := "missing row"
		if configured {
			name = "configured false"
		}
		t.Run(name, func(t *testing.T) {
			f := newSessionSettingsFixture(t)
			if configured {
				if _, err := f.database.Pool().Exec(t.Context(), `INSERT INTO dpi_threat_settings(org_id,cluster_id,weak_tls_enabled) VALUES($1,$2,false)`, f.org, f.cluster); err != nil {
					t.Fatal(err)
				}
			}
			assertSessionSettingsResponse(t, f.post(t, f.database), false, 1)
			f.assertStored(t, 0)
		})
	}
}
