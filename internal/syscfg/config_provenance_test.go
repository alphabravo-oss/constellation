package syscfg

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func clearBootstrapEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "CONSTELLATION_TLS_VERIFY", "CONSTELLATION_CA_BUNDLE_PEM", "CONSTELLATION_SYSLOG_HOST", "CONSTELLATION_SYSLOG_PORT", "CONSTELLATION_SYSLOG_PROTOCOL"} {
		t.Setenv(key, "")
	}
}

func TestConfigProvenanceBootstrapPersistenceAndPatch(t *testing.T) {
	clearBootstrapEnv(t)
	t.Setenv("CONSTELLATION_TLS_VERIFY", "true")
	t.Setenv("HTTPS_PROXY", "https://bootstrap:private-secret@proxy.test:3128")
	defaults := DefaultsFromEnv()
	if got := defaults.Provenance()["tls_verify"].Source; got != SourceEnvironmentBootstrap {
		t.Fatalf("explicit default-valued env source = %s", got)
	}
	ctx := context.Background()
	store := newFakeStore()
	orgID := uuid.New()
	cfg, revision, err := Seed(ctx, store, orgID, defaults)
	if err != nil || revision != 1 {
		t.Fatalf("seed revision=%d: %v", revision, err)
	}
	for field, expected := range map[string]Source{
		"tls_verify":               SourceEnvironmentBootstrap,
		"egress_proxy.https_proxy": SourceEnvironmentBootstrap,
		"events_retention_days":    SourceDefault,
		"smtp.password":            SourceDefault,
	} {
		if got := cfg.Provenance()[field].Source; got != expected {
			t.Errorf("%s source=%s, want %s", field, got, expected)
		}
	}
	if !cfg.Provenance()["egress_proxy.https_proxy"].Redacted {
		t.Fatal("proxy secret not marked redacted")
	}
	encoded, err := json.Marshal(cfg.Provenance())
	if err != nil || strings.Contains(string(encoded), "private-secret") {
		t.Fatalf("provenance contains secret or failed encoding: %v", err)
	}
	patch, _ := json.Marshal(map[string]any{
		"tls_verify":            true,
		"events_retention_days": 0,
		"egress_proxy":          map[string]any{"https_proxy": cfg.Redacted().EgressProxy.HTTPSProxy},
	})
	patched, err := cfg.ApplyPatch(patch)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tls_verify", "events_retention_days"} {
		if patched.Provenance()[field].Source != SourceDatabase {
			t.Errorf("explicit default-valued PATCH %s not database sourced", field)
		}
	}
	if patched.Provenance()["egress_proxy.https_proxy"].Source != SourceEnvironmentBootstrap {
		t.Fatal("redacted echo changed source")
	}
	blob, err := marshalStoredConfig(patched)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := unmarshalStoredConfig(blob)
	if err != nil || reloaded.Provenance()["events_retention_days"].Source != SourceDatabase {
		t.Fatalf("zero-valued provenance lost through persistence: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "http://changed.test")
	again, _, err := Seed(ctx, store, orgID, DefaultsFromEnv())
	if err != nil || again.EgressProxy.HTTPSProxy != defaults.EgressProxy.HTTPSProxy {
		t.Fatalf("reseed changed bootstrap config: %v", err)
	}
	if again.Provenance()["egress_proxy.https_proxy"].Source != SourceEnvironmentBootstrap {
		t.Fatal("reseed changed historical origin")
	}
}

func TestConfigProvenanceLegacyAndInvalidBootstrap(t *testing.T) {
	cfg, err := unmarshalStoredConfig(json.RawMessage(`{"tls_verify":true,"egress_proxy":{"https_proxy":""}}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"tls_verify", "egress_proxy.https_proxy"} {
		if cfg.Provenance()[field].Source != SourceDatabase {
			t.Errorf("legacy persisted field %s falsely attributed", field)
		}
	}
	if cfg.Provenance()["egress_proxy.no_proxy"].Source != SourceDefault {
		t.Fatal("missing legacy key must be default")
	}
	clearBootstrapEnv(t)
	t.Setenv("HTTPS_PROXY", "://bad")
	t.Setenv("CONSTELLATION_TLS_VERIFY", "true")
	for field, origin := range DefaultsFromEnv().Provenance() {
		if origin.Source != SourceDefault {
			t.Errorf("rejected bootstrap attributed %s to %s", field, origin.Source)
		}
	}
}

func TestConfigProvenanceDirectMutationDoesNotRetainOrigin(t *testing.T) {
	cfg := Default()
	cfg.EventsRetentionDays = 30
	if cfg.Provenance()["events_retention_days"].Source != SourceDatabase {
		t.Fatal("programmatic mutation incorrectly retained default origin")
	}
}

func TestConfigProvenanceRedactedAbsentSecretAndDuplicatePatch(t *testing.T) {
	patched, err := Default().ApplyPatch(json.RawMessage(`{"nvd_api_key":"***REDACTED***"}`))
	if err != nil || patched.Provenance()["nvd_api_key"].Source != SourceDefault {
		t.Fatalf("redacted no-op changed absent secret origin: %v", err)
	}
	_, err = Default().ApplyPatch(json.RawMessage(`{"smtp":{"port":25},"smtp":{"host":"relay.test","from":"a@example.test"}}`))
	var validation *ValidationError
	if !errors.As(err, &validation) || len(validation.Fields) != 1 || validation.Fields[0].Code != "duplicate_field" {
		t.Fatalf("duplicate object keys must not corrupt provenance: %v", err)
	}
}

func TestProviderAppliedRevisionAndLiveHTTPReload(t *testing.T) {
	ctx := context.Background()
	store := newFakeStore()
	orgID := uuid.New()
	provider := NewProvider(store)
	if got := provider.Applied(orgID, 1); got.Status != "unavailable" || got.Revision != nil {
		t.Fatalf("unloaded provider claimed revision: %+v", got)
	}
	if _, _, err := Seed(ctx, store, orgID, Default()); err != nil {
		t.Fatal(err)
	}
	_ = provider.Get(ctx, orgID)
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	cfg := Default()
	cfg.EgressProxy.HTTPSProxy = proxy.URL
	revision := store.save(orgID, cfg)
	if got := provider.Applied(orgID, revision); got.Status != "behind" || *got.Revision != 1 {
		t.Fatalf("provider did not expose actual lag: %+v", got)
	}
	if changed := provider.Refresh(ctx); changed != 1 {
		t.Fatalf("refresh changed=%d", changed)
	}
	client := provider.HTTPClient(ctx, orgID, time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Get("http://config-reload.invalid/test")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if proxyHits.Load() != 1 || response.StatusCode != http.StatusNoContent {
		t.Fatal("live provider did not route request through new proxy")
	}
	if got := provider.Applied(orgID, revision); got.Status != "current" || *got.Revision != revision || got.Scope != "serving_replica" {
		t.Fatalf("wrong applied revision: %+v", got)
	}
	provider.UpdateAfterPatch(orgID, Default(), 1)
	if provider.Get(ctx, orgID).EgressProxy.HTTPSProxy != proxy.URL {
		t.Fatal("stale writer rolled provider back")
	}
	if provider.Applied(orgID, 1).Status != "ahead" {
		t.Fatal("ahead provider status not reported")
	}
}

type unavailableConfigStore struct{ *fakeStore }

func (store unavailableConfigStore) QueryRow(context.Context, string, ...any) pgx.Row {
	return fakeRow{err: errors.New("database unavailable")}
}

func TestProviderAppliedDoesNotClaimFallbackAndProtectsSnapshot(t *testing.T) {
	ctx := context.Background()
	orgID := uuid.New()
	provider := NewProvider(unavailableConfigStore{newFakeStore()})
	_ = provider.Get(ctx, orgID)
	if provider.Applied(orgID, 1).Revision != nil {
		t.Fatal("fallback defaults claimed applied revision")
	}
	cfg := Default()
	cfg.SyslogSIEM.Categories = []string{"runtime"}
	provider.UpdateAfterPatch(orgID, cfg, 2)
	cfg.SyslogSIEM.Categories[0] = "mutated"
	read := provider.Get(ctx, orgID)
	read.SyslogSIEM.Categories[0] = "also-mutated"
	if provider.Get(ctx, orgID).SyslogSIEM.Categories[0] != "runtime" {
		t.Fatal("consumer mutated cached config without a revision")
	}
}
