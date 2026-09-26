package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alphabravocompany/constellation/internal/db"
	"github.com/alphabravocompany/constellation/pkg/audit"
	"github.com/google/uuid"
)

const migrationRemainingSecret = "MIG1-credential-sentinel-do-not-persist"

// Decode the public JSON contract so these tests do not depend on converter DTOs.
type migrationRemainingPreview struct {
	ImportID              string                       `json:"import_id"`
	Summary               map[string]json.RawMessage   `json:"summary"`
	VulnerabilityProfiles []map[string]json.RawMessage `json:"vulnerability_profiles"`
	Registries            []map[string]json.RawMessage `json:"registries"`
	Unsupported           []migrationUnsupportedDTO    `json:"unsupported"`
}

type migrationRemainingFixture struct {
	t    *testing.T
	d    *db.DB
	h    *Enterprise
	org  uuid.UUID
	user uuid.UUID
}

func newMigrationRemainingFixture(t *testing.T) *migrationRemainingFixture {
	t.Helper()
	d := openTestDB(t)
	t.Cleanup(d.Close)
	f := &migrationRemainingFixture{t: t, d: d, h: NewEnterprise(d).WithAudit(audit.New(d.Pool())), org: uuid.New(), user: uuid.New()}
	ctx := context.Background()
	if _, err := d.Pool().Exec(ctx, `INSERT INTO orgs (id, name, display_name) VALUES ($1, $2, 'Migration remaining tests')`, f.org, "migration-remaining-"+f.org.String()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	t.Cleanup(func() {
		if _, err := d.Pool().Exec(context.Background(), `DELETE FROM orgs WHERE id=$1`, f.org); err != nil {
			t.Errorf("clean migration org: %v", err)
		}
	})
	if _, err := d.Pool().Exec(ctx, `INSERT INTO users (id, org_id, email, display_name) VALUES ($1, $2, $3, 'Migration admin')`, f.user, f.org, f.user.String()+"@migration.example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return f
}

func migrationRemainingExport(t *testing.T, extra map[string]any) string {
	t.Helper()
	source := map[string]any{
		"vulnerability_profiles": []any{
			map[string]any{"name": "remaining-existing", "entries": []any{map[string]any{"name": "CVE-2026-1000"}}},
			map[string]any{"name": "remaining-new", "entries": []any{map[string]any{"name": "CVE-2026-1001"}}},
		},
		"registries": []any{map[string]any{
			"name": "remaining-registry", "registry": "https://registry.example.com", "registry_type": "harbor",
			"username": migrationRemainingSecret, "password": migrationRemainingSecret,
		}},
	}
	for k, v := range extra {
		source[k] = v
	}
	b, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func migrationRemainingPreviewCall(t *testing.T, h *Enterprise, subj Subject, export string) (migrationRemainingPreview, string) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"source": "neuvector", "export": export})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(body)))
	if subj.OrgID != uuid.Nil {
		req = req.WithContext(WithSubject(req.Context(), subj))
	}
	w := httptest.NewRecorder()
	h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var out migrationRemainingPreview
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.VulnerabilityProfiles) != 2 || len(out.Registries) != 1 {
		t.Fatalf("remaining family preview: profiles=%d registries=%d body=%s", len(out.VulnerabilityProfiles), len(out.Registries), w.Body.String())
	}
	for key, want := range map[string]int{"vulnerability_profiles": 2, "registries": 1, "total": 3} {
		var got int
		if err := json.Unmarshal(out.Summary[key], &got); err != nil || got != want {
			t.Fatalf("summary %s=%s want %d (decode=%v)", key, out.Summary[key], want, err)
		}
	}
	assertMigrationRemainingRedacted(t, w.Body.String())
	return out, w.Body.String()
}

func (f *migrationRemainingFixture) preview(export string) migrationRemainingPreview {
	f.t.Helper()
	out, _ := migrationRemainingPreviewCall(f.t, f.h, Subject{OrgID: f.org, UserID: f.user}, export)
	if _, err := uuid.Parse(out.ImportID); err != nil {
		f.t.Fatalf("missing persisted import ID: %q", out.ImportID)
	}
	return out
}

func (f *migrationRemainingFixture) call(fn http.HandlerFunc, method, id string, want int) map[string]json.RawMessage {
	f.t.Helper()
	req := migrationActionRequest(method, "/api/v1/migration/imports/"+id, id, f.org, f.user)
	w := httptest.NewRecorder()
	fn(w, req)
	if w.Code != want {
		f.t.Fatalf("migration action status=%d want=%d body=%s", w.Code, want, w.Body.String())
	}
	assertMigrationRemainingRedacted(f.t, w.Body.String())
	var out map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func migrationRemainingString(t *testing.T, obj map[string]json.RawMessage, key string) string {
	t.Helper()
	var value string
	if err := json.Unmarshal(obj[key], &value); err != nil {
		t.Fatalf("decode %s from %v: %v", key, obj, err)
	}
	return value
}

func assertMigrationRemainingRedacted(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, migrationRemainingSecret) {
		t.Fatal("migration response or persisted data contains raw credential sentinel")
	}
}

func (f *migrationRemainingFixture) snapshot(query string, args ...any) map[string]any {
	f.t.Helper()
	var raw []byte
	if err := f.d.Pool().QueryRow(context.Background(), query, args...).Scan(&raw); err != nil {
		f.t.Fatalf("snapshot: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *migrationRemainingFixture) counts(profiles, registries int) {
	f.t.Helper()
	var gotProfiles, gotRegistries int
	if err := f.d.Pool().QueryRow(context.Background(), `SELECT (SELECT count(*) FROM vuln_profiles WHERE org_id=$1), (SELECT count(*) FROM registries WHERE org_id=$1)`, f.org).Scan(&gotProfiles, &gotRegistries); err != nil {
		f.t.Fatal(err)
	}
	if gotProfiles != profiles || gotRegistries != registries {
		f.t.Fatalf("DB profiles/registries=%d/%d want %d/%d", gotProfiles, gotRegistries, profiles, registries)
	}
}

func TestMigrationRemainingPreviewRedactsAndAccountsUnsupported(t *testing.T) {
	export := migrationRemainingExport(t, map[string]any{
		"users":           []any{map[string]any{"fullname": "legacy-user", "password": migrationRemainingSecret, "apikey": migrationRemainingSecret}},
		"roles":           []any{map[string]any{"name": "legacy-role", "permissions": []string{"admin"}}},
		"future_settings": map[string]any{"token": migrationRemainingSecret, "nested": map[string]any{"password": migrationRemainingSecret}},
	})
	preview, _ := migrationRemainingPreviewCall(t, NewEnterprise(), Subject{}, export)
	if len(preview.Unsupported) < 3 {
		t.Fatalf("users, roles, and unknown settings must be explicit unsupported objects: %+v", preview.Unsupported)
	}
	unsupportedKinds := map[string]int{}
	for _, unsupported := range preview.Unsupported {
		unsupportedKinds[unsupported.Kind]++
	}
	if unsupportedKinds["user"] != 1 || unsupportedKinds["role"] != 1 || unsupportedKinds["unknown"] != 1 {
		t.Fatalf("users/roles/unknown accounting=%v", unsupportedKinds)
	}
	var unaccounted int
	if raw := preview.Summary["unaccounted_source"]; len(raw) > 0 {
		if err := json.Unmarshal(raw, &unaccounted); err != nil {
			t.Fatal(err)
		}
	}
	if unaccounted != 0 {
		t.Fatalf("unaccounted source objects=%d", unaccounted)
	}
	for _, object := range append(preview.VulnerabilityProfiles, preview.Registries...) {
		var provenance map[string]string
		if err := json.Unmarshal(object["imported_from"], &provenance); err != nil || len(provenance) == 0 {
			t.Fatalf("missing preview provenance: %v (%v)", object, err)
		}
	}
	seen := map[string]bool{}
	for _, profile := range preview.VulnerabilityProfiles {
		var entries []struct {
			Name   string `json:"name"`
			Action string `json:"action"`
		}
		if err := json.Unmarshal(profile["entries"], &entries); err != nil || len(entries) != 1 {
			t.Fatalf("invalid exact-CVE conversion: %s (%v)", profile["entries"], err)
		}
		if entries[0].Action != "suppress" {
			t.Fatalf("unexpected CVE action: %+v", entries[0])
		}
		seen[entries[0].Name] = true
	}
	if !seen["CVE-2026-1000"] || !seen["CVE-2026-1001"] || len(seen) != 2 {
		t.Fatalf("converted CVE names=%v", seen)
	}
	registry := preview.Registries[0]
	if migrationRemainingString(t, registry, "auth_kind") != "none" || migrationRemainingString(t, registry, "scan_cadence") != "manual" {
		t.Fatalf("registry must require manual credential setup: %v", registry)
	}
}

func TestMigrationRemainingLifecycleIdempotencyAndRollback(t *testing.T) {
	f := newMigrationRemainingFixture(t)
	export := migrationRemainingExport(t, nil)
	first := f.preview(export)
	f.counts(0, 0)
	if string(first.Summary["create"]) != "3" {
		t.Fatalf("first preview create count=%s want 3", first.Summary["create"])
	}
	profileName := migrationRemainingString(t, first.VulnerabilityProfiles[0], "name")
	registryName := migrationRemainingString(t, first.Registries[0], "name")
	if _, err := f.d.Pool().Exec(context.Background(), `INSERT INTO vuln_profiles (org_id, name, description, active, entries, domain_scope, created_by) VALUES ($1, $2, 'original description', true, '[{"name":"CVE-2025-4321","action":"suppress"}]', '{"namespaces":["original"]}', $3)`, f.org, profileName, f.user); err != nil {
		t.Fatal(err)
	}
	const profileSnapshot = `SELECT to_jsonb(p)-'updated_at' FROM vuln_profiles p WHERE org_id=$1 AND name=$2`
	before := f.snapshot(profileSnapshot, f.org, profileName)
	apply := f.call(f.h.MigrationApply, http.MethodPost, first.ImportID, http.StatusOK)
	if status := migrationRemainingString(t, apply, "status"); status != "applied" && status != "partial_applied" {
		t.Fatalf("apply status=%q", status)
	}
	f.counts(2, 1)
	after := f.snapshot(profileSnapshot, f.org, profileName)
	if reflect.DeepEqual(before["entries"], after["entries"]) {
		t.Fatal("apply did not replace existing vulnerability entries")
	}
	var expectedEntries any
	if err := json.Unmarshal(first.VulnerabilityProfiles[0]["entries"], &expectedEntries); err != nil || !reflect.DeepEqual(after["entries"], expectedEntries) {
		t.Fatalf("stored CVE entries differ from preview: got=%v expected=%v (%v)", after["entries"], expectedEntries, err)
	}
	const registrySnapshot = `SELECT to_jsonb(r) FROM registries r WHERE org_id=$1 AND name=$2`
	registry := f.snapshot(registrySnapshot, f.org, registryName)
	if registry["auth_kind"] != "none" || registry["auth_secret"] != nil || registry["scan_cadence"] != "manual" || registry["kind"] != "harbor" {
		t.Fatalf("unsafe persisted registry configuration: %v", registry)
	}
	repeat := f.call(f.h.MigrationApply, http.MethodPost, first.ImportID, http.StatusOK)
	if string(repeat["already_applied"]) != "true" {
		t.Fatalf("same import apply was not idempotent: %v", repeat)
	}
	f.counts(2, 1)
	bundle := f.call(f.h.MigrationRollbackBundle, http.MethodGet, first.ImportID, http.StatusOK)
	for family, want := range map[string]int{"vulnerability_profiles": 2, "registries": 1} {
		var entries []map[string]json.RawMessage
		if err := json.Unmarshal(bundle[family], &entries); err != nil || len(entries) != want {
			t.Fatalf("rollback bundle %s=%s want %d entries (%v)", family, bundle[family], want, err)
		}
	}
	f.assertPersistedRedacted()
	// A new preview of the same source must not claim ownership of the existing
	// registry: rolling it back must leave the first import's registry untouched.
	second := f.preview(export)
	if string(second.Summary["unchanged"]) != "3" || migrationRemainingString(t, second.Registries[0], "diff_action") != "unchanged" {
		t.Fatalf("repeat preview must mark all objects unchanged: %+v", second.Summary)
	}
	f.call(f.h.MigrationApply, http.MethodPost, second.ImportID, http.StatusOK)
	f.counts(2, 1)
	if got := f.snapshot(registrySnapshot, f.org, registryName); !reflect.DeepEqual(registry, got) {
		t.Fatalf("safe repeat modified registry: before=%v after=%v", registry, got)
	}
	f.call(f.h.MigrationRollback, http.MethodPost, second.ImportID, http.StatusOK)
	f.counts(2, 1)
	if got := f.snapshot(profileSnapshot, f.org, profileName); !reflect.DeepEqual(after, got) {
		t.Fatalf("second rollback did not restore first import's profile: before=%v after=%v", after, got)
	}
	rolledBack := f.call(f.h.MigrationRollback, http.MethodPost, first.ImportID, http.StatusOK)
	if string(rolledBack["restored"]) != "1" || string(rolledBack["deleted"]) != "2" {
		t.Fatalf("rollback counts=%v want restored=1 deleted=2", rolledBack)
	}
	f.counts(1, 0)
	if got := f.snapshot(profileSnapshot, f.org, profileName); !reflect.DeepEqual(before, got) {
		t.Fatalf("rollback did not restore original profile: before=%v after=%v", before, got)
	}
	imports := f.call(f.h.MigrationImports, http.MethodGet, "", http.StatusOK)
	var items []migrationImportListItemDTO
	if err := json.Unmarshal(imports["imports"], &items); err != nil || len(items) != 2 {
		t.Fatalf("history=%s (%v)", imports["imports"], err)
	}
	for _, item := range items {
		if item.Status != "rolled_back" || item.RolledBackAt == "" || item.AppliedAt == "" {
			t.Fatalf("incorrect lifecycle history: %+v", item)
		}
	}
	f.assertPersistedRedacted()
}

func (f *migrationRemainingFixture) assertPersistedRedacted() {
	f.t.Helper()
	for _, query := range []string{
		`SELECT COALESCE(jsonb_agg(to_jsonb(m))::text,'[]') FROM migration_imports m WHERE org_id=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(a))::text,'[]') FROM audit_events a WHERE org_id=$1`,
		`SELECT COALESCE(jsonb_agg(to_jsonb(r))::text,'[]') FROM registries r WHERE org_id=$1`,
	} {
		var raw string
		if err := f.d.Pool().QueryRow(context.Background(), query, f.org).Scan(&raw); err != nil {
			f.t.Fatal(err)
		}
		assertMigrationRemainingRedacted(f.t, raw)
	}
}

func TestMigrationRemainingRegistryCollisionIsAtomic(t *testing.T) {
	f := newMigrationRemainingFixture(t)
	preview := f.preview(migrationRemainingExport(t, nil))
	name := migrationRemainingString(t, preview.Registries[0], "name")
	// Insert after preview to ensure apply rechecks collisions within its transaction.
	if _, err := f.d.Pool().Exec(context.Background(), `INSERT INTO registries (org_id, name, kind, endpoint, auth_kind, auth_secret, scan_cadence) VALUES ($1, $2, 'harbor', 'https://production.example.com', 'static', decode('01020304','hex'), 'daily')`, f.org, name); err != nil {
		t.Fatal(err)
	}
	const query = `SELECT to_jsonb(r) FROM registries r WHERE org_id=$1 AND name=$2`
	before := f.snapshot(query, f.org, name)
	w := httptest.NewRecorder()
	f.h.MigrationApply(w, migrationActionRequest(http.MethodPost, "/migration/apply", preview.ImportID, f.org, f.user))
	if w.Code != http.StatusConflict {
		t.Fatalf("registry collision status=%d want 409: %s", w.Code, w.Body.String())
	}
	assertMigrationRemainingRedacted(t, w.Body.String())
	f.counts(0, 1)
	if got := f.snapshot(query, f.org, name); !reflect.DeepEqual(before, got) {
		t.Fatalf("collision modified existing registry: before=%v after=%v", before, got)
	}
	f.assertPersistedRedacted()
}

func TestMigrationRemainingUnsupportedPersistsRedacted(t *testing.T) {
	f := newMigrationRemainingFixture(t)
	preview := f.preview(migrationRemainingExport(t, map[string]any{
		"users":           []any{map[string]any{"fullname": "legacy-user", "password": migrationRemainingSecret}},
		"roles":           []any{map[string]any{"name": "legacy-role", "permissions": []string{"admin"}}},
		"future_settings": map[string]any{"api_key": migrationRemainingSecret},
	}))
	if len(preview.Unsupported) < 3 {
		t.Fatalf("missing unsupported remaining objects: %+v", preview.Unsupported)
	}
	applied := f.call(f.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
	if migrationRemainingString(t, applied, "status") != "partial_applied" {
		t.Fatalf("unsupported objects must remain visible as partial apply: %v", applied)
	}
	listed := f.call(f.h.MigrationImports, http.MethodGet, "", http.StatusOK)
	var imports []migrationImportListItemDTO
	if err := json.Unmarshal(listed["imports"], &imports); err != nil || len(imports) != 1 || len(imports[0].Unsupported) != len(preview.Unsupported) {
		t.Fatalf("unsupported history differs from preview: %s (%v)", listed["imports"], err)
	}
	var userCount int
	if err := f.d.Pool().QueryRow(context.Background(), `SELECT count(*) FROM users WHERE org_id=$1`, f.org).Scan(&userCount); err != nil || userCount != 1 {
		t.Fatalf("unsupported users changed tenant identities: count=%d (%v)", userCount, err)
	}
	f.call(f.h.MigrationRollbackBundle, http.MethodGet, preview.ImportID, http.StatusOK)
	f.assertPersistedRedacted()
	f.call(f.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusOK)
	f.counts(0, 0)
	f.assertPersistedRedacted()
}

func TestMigrationRemainingTenantIsolation(t *testing.T) {
	owner := newMigrationRemainingFixture(t)
	other := newMigrationRemainingFixture(t)
	export := migrationRemainingExport(t, nil)
	owned := owner.preview(export)
	foreign := other.preview(export)
	other.call(other.h.MigrationApply, http.MethodPost, foreign.ImportID, http.StatusOK)
	registryName := migrationRemainingString(t, foreign.Registries[0], "name")
	profileName := migrationRemainingString(t, foreign.VulnerabilityProfiles[0], "name")
	const registryQuery = `SELECT to_jsonb(r) FROM registries r WHERE org_id=$1 AND name=$2`
	const profileQuery = `SELECT to_jsonb(p) FROM vuln_profiles p WHERE org_id=$1 AND name=$2`
	registryBefore := other.snapshot(registryQuery, other.org, registryName)
	profileBefore := other.snapshot(profileQuery, other.org, profileName)
	owner.call(owner.h.MigrationApply, http.MethodPost, owned.ImportID, http.StatusOK)
	for _, action := range []struct {
		fn     http.HandlerFunc
		method string
	}{
		{other.h.MigrationApply, http.MethodPost},
		{other.h.MigrationRollbackBundle, http.MethodGet},
		{other.h.MigrationRollback, http.MethodPost},
	} {
		other.call(action.fn, action.method, owned.ImportID, http.StatusNotFound)
	}
	listed := other.call(other.h.MigrationImports, http.MethodGet, "", http.StatusOK)
	if strings.Contains(string(listed["imports"]), owned.ImportID) {
		t.Fatal("history leaked another tenant's import")
	}
	if got := other.snapshot(registryQuery, other.org, registryName); !reflect.DeepEqual(registryBefore, got) {
		t.Fatal("owner apply changed another tenant's registry")
	}
	if got := other.snapshot(profileQuery, other.org, profileName); !reflect.DeepEqual(profileBefore, got) {
		t.Fatal("owner apply changed another tenant's vulnerability profile")
	}
	owner.call(owner.h.MigrationRollback, http.MethodPost, owned.ImportID, http.StatusOK)
	owner.counts(0, 0)
	other.counts(2, 1)
	if got := other.snapshot(registryQuery, other.org, registryName); !reflect.DeepEqual(registryBefore, got) {
		t.Fatal("owner lifecycle changed another tenant's registry")
	}
	if got := other.snapshot(profileQuery, other.org, profileName); !reflect.DeepEqual(profileBefore, got) {
		t.Fatal("owner lifecycle changed another tenant's vulnerability profile")
	}
}

func TestMigrationRemainingVulnerabilityRollbackRestoresOriginal(t *testing.T) {
	f := newMigrationRemainingFixture(t)
	if _, err := f.d.Pool().Exec(context.Background(), `INSERT INTO vuln_profiles (org_id, name, description, active, entries, domain_scope, created_by) VALUES ($1, 'remaining-existing', 'original description', false, '[{"name":"CVE-2025-4321","action":"suppress"}]', '{"namespaces":["original"]}', $2)`, f.org, f.user); err != nil {
		t.Fatal(err)
	}
	const query = `SELECT to_jsonb(p)-'updated_at' FROM vuln_profiles p WHERE org_id=$1 AND name='remaining-existing'`
	before := f.snapshot(query, f.org)
	body, err := json.Marshal(map[string]string{"source": "neuvector", "export": migrationRemainingExport(t, map[string]any{"registries": []any{}})})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/migration/preview", strings.NewReader(string(body)))
	req = req.WithContext(WithSubject(req.Context(), Subject{OrgID: f.org, UserID: f.user}))
	w := httptest.NewRecorder()
	f.h.MigrationPreview(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", w.Code, w.Body.String())
	}
	var preview migrationRemainingPreview
	if err := json.Unmarshal(w.Body.Bytes(), &preview); err != nil || len(preview.VulnerabilityProfiles) != 2 || len(preview.Registries) != 0 {
		t.Fatalf("profile-only preview=%s (%v)", w.Body.String(), err)
	}
	f.counts(1, 0)
	if migrationRemainingString(t, preview.VulnerabilityProfiles[0], "diff_action") != "update" {
		t.Fatal("existing profile must have update diff")
	}
	applied := f.call(f.h.MigrationApply, http.MethodPost, preview.ImportID, http.StatusOK)
	if migrationRemainingString(t, applied, "status") != "applied" {
		t.Fatalf("safe profile-only import status=%s", applied["status"])
	}
	f.counts(2, 0)
	f.call(f.h.MigrationRollbackBundle, http.MethodGet, preview.ImportID, http.StatusOK)
	rollback := f.call(f.h.MigrationRollback, http.MethodPost, preview.ImportID, http.StatusOK)
	if string(rollback["restored"]) != "1" || string(rollback["deleted"]) != "1" {
		t.Fatalf("profile rollback counts=%v", rollback)
	}
	f.counts(1, 0)
	if got := f.snapshot(query, f.org); !reflect.DeepEqual(before, got) {
		t.Fatalf("profile rollback did not restore original row: before=%v after=%v", before, got)
	}
}
