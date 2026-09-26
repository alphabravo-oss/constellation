// Package syscfg implements task B1: runtime-mutable, RBAC-gated system configuration.
//
// One row per org in the system_config table holds the operational knobs that
// historically required a Deployment edit + restart (egress proxy, TLS verify + CA
// bundle, syslog/SIEM target, scanner autoscale bounds). The DB row is the source of
// truth; env vars become BOOTSTRAP DEFAULTS the server seeds on first boot.
//
// The Config struct is the single validating gatekeeper: GET redacts secrets via
// Redacted(), PATCH applies a partial update through ApplyPatch() which re-validates
// the whole struct. A Provider caches the parsed Config per org and a background
// reloader (mirroring server.runSessionKeyReloader) polls the row's revision so a PATCH
// propagates to every replica WITHOUT a restart. Other packages read the live config
// through the Provider's accessor (Get).
//
// Wired consumers (read the LIVE config via the Provider):
//   - (a) shared outbound HTTP client — Provider.HTTPClient honors egress_proxy +
//     tls_verify/ca_bundle_pem (see httpclient.go). REAL CALLER: the registry walker /
//     Test path builds every connector's outbound client from Provider.HTTPClient
//     (internal/handler.BuildConnector), so a PATCH to the proxy/TLS/CA knobs takes
//     effect on the next registry walk or Test without a restart.
//   - (b) syslog/SIEM sender — the audit/notifier Dispatcher mirrors every event to
//     Provider.SyslogSender's live target (see syslog.go, wired in internal/server).
//
// Two knobs are deliberately NOT in this Provider:
//   - Scanner autoscaling is owned by the operator: ConstellationCluster.Spec.ScannerAutoscale
//     drives a real HorizontalPodAutoscaler (deploy/operator reconcileScannerHPA) — the
//     K8s-native, runtime-adjustable mechanism — so there is no scanner-pool knob here.
//   - Server TLS / OIDC discovery / federation-peer TLS verification are read once at startup
//     by design: they are security-sensitive bootstrap config and are intentionally not
//     runtime-mutable through this Provider.
package syscfg

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Config is the typed view of a system_config row's JSONB blob. Every field is
// validated by Validate(); secret-bearing fields are stripped by Redacted().
type Config struct {
	origins map[string]configOrigin
	// EgressProxy controls outbound HTTP(S) routing for shared clients.
	EgressProxy EgressProxy `json:"egress_proxy"`
	// TLSVerify toggles verification of upstream TLS certs for shared outbound clients.
	// Default true (verification on). CABundlePEM, when set, is added to the trust pool.
	TLSVerify   bool   `json:"tls_verify"`
	CABundlePEM string `json:"ca_bundle_pem,omitempty"` // SECRET-ish: redacted on GET
	// SyslogSIEM is the audit/notifier syslog target.
	SyslogSIEM SyslogTarget `json:"syslog_siem_target"`

	// ScannerDBRefreshMinutes is how often connected scanners refresh their
	// Trivy/Grype vulnerability DBs from upstream. UI-settable; 0 means use the
	// scanner's env default. Scanners poll GET /api/v1/scanner/config and honor
	// this without a redeploy.
	ScannerDBRefreshMinutes int `json:"scanner_db_refresh_minutes,omitempty"`
	// ScannerOfflineDB puts scanners in air-gapped mode: Trivy/Grype do NOT pull
	// DBs from the internet (operators pre-load them — see docs). When true, the
	// auto-refresh loop is a no-op.
	ScannerOfflineDB bool `json:"scanner_offline_db,omitempty"`
	// ScannerDBRefreshNow is a unix-seconds "force refresh" signal. When an admin
	// clicks "Refresh now", POST /scanner/refresh bumps this to the current time;
	// scanners polling /scanner/config refresh their DBs when they see a value
	// newer than their last-applied one. Works even outside air-gapped mode.
	ScannerDBRefreshNow int64 `json:"scanner_db_refresh_now,omitempty"`

	// NVDEnabled turns on the NVD full-catalog CVE importer (descriptions + CVSS),
	// complementing the always-on KEV+EPSS exploitation-intel importer.
	NVDEnabled bool `json:"nvd_enabled,omitempty"`
	// NVDAPIKey is the api.nvd.nist.gov key (raises the rate limit from 5 to 50
	// requests / 30s). SECRET-ish: redacted on GET.
	NVDAPIKey string `json:"nvd_api_key,omitempty"`
	// NVDMirrorURL overrides the NVD API base (air-gapped mirror of the 2.0 feed).
	NVDMirrorURL string `json:"nvd_mirror_url,omitempty"`

	// SMTP is the global email server for the "email" notification receiver kind.
	// Empty Host means email delivery is unconfigured.
	SMTP SMTPServer `json:"smtp"`

	// Retention windows in days. 0 = disabled (never prune). Read live by the
	// retention loops, so a PATCH takes effect without a restart. These bound the
	// two biggest sources of unbounded storage growth: raw network flows + events.
	NetworkFlowRetentionDays int `json:"network_flow_retention_days,omitempty"`
	EventsRetentionDays      int `json:"events_retention_days,omitempty"`
	// ScanJobRetentionDays bounds the scan_jobs queue history: terminal jobs
	// (completed/failed/canceled) older than this are pruned. 0 = keep forever.
	ScanJobRetentionDays int `json:"scan_job_retention_days,omitempty"`

	// AutoScanDisabled turns OFF the automatic scanning of running-workload images
	// (NeuVector `enable_auto_scan_workload`). Default false = auto-scan ON, so a
	// discovered running image is scanned by the live pipeline without a manual trigger.
	AutoScanDisabled bool `json:"auto_scan_disabled,omitempty"`
	// AutoScanRescanHours is how often an already-scanned running image is re-scanned by
	// the auto-scan loop. 0 = default (24h).
	AutoScanRescanHours int `json:"auto_scan_rescan_hours,omitempty"`
}

// SMTPServer is the global outbound email server. Password is redacted on GET.
type SMTPServer struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"` // SECRET: redacted on GET
	From     string `json:"from,omitempty"`
	STARTTLS bool   `json:"starttls,omitempty"`
}

// EgressProxy holds the proxy routing knobs (mirrors HTTPS_PROXY / NO_PROXY env).
type EgressProxy struct {
	HTTPSProxy string `json:"https_proxy,omitempty"`
	NoProxy    string `json:"no_proxy,omitempty"`
}

// SyslogTarget is the syslog/SIEM destination: host:port over udp|tcp|tls. Empty Host
// means "no syslog target configured" (the audit/notifier sender skips syslog).
//
// SIEM-TLS-14 adds TLS transport, structured formats, and level/category filtering
// (parity with NeuVector's SyslogServerCert / SyslogInJSON / syslog_level+categories).
// All new fields are optional and default to the legacy behavior: plaintext + rfc5424 +
// no filtering, so existing configs are unaffected.
type SyslogTarget struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // "udp" | "tcp" | "tls"

	// TLS forces the TLS transport even when Protocol is left blank/tcp (Protocol "tls"
	// is equivalent). Over untrusted networks a SIEM export must be TLS.
	TLS bool `json:"tls,omitempty"`
	// CACert is an optional PEM CA bundle used to verify the collector's server cert.
	// Empty => the system root pool is used.
	CACert string `json:"ca_cert,omitempty"`
	// ClientCert / ClientKey are an optional PEM client keypair for mutual TLS.
	// ClientKey is a SECRET: redacted on GET.
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`

	// Format is the wire encoding: "" or "rfc5424" (default) | "json" | "cef".
	Format string `json:"format,omitempty"`
	// MinLevel drops events below this severity (critical|high|medium|low|info).
	// Empty = no floor (ship all levels).
	MinLevel string `json:"min_level,omitempty"`
	// Categories, when non-empty, restricts shipping to events whose kind is in the set.
	// Empty = all categories.
	Categories []string `json:"categories,omitempty"`
}

// Addr returns "host:port" or "" when no host is configured.
func (t SyslogTarget) Addr() string {
	if strings.TrimSpace(t.Host) == "" {
		return ""
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Default returns the zero-value-safe baseline config: TLS verification on, no
// proxy/syslog. Used when an org has no row yet.
func Default() Config {
	return trackConfig(Config{
		TLSVerify: true,
	}, nil, SourceDefault)
}

// Validate enforces the field invariants. Called on every PATCH (after merge) and on
// every load from the DB so a malformed row can never become the live config.
func (c Config) Validate() error {
	var validation ValidationError
	if p := strings.TrimSpace(c.EgressProxy.HTTPSProxy); p != "" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			validation.add("egress_proxy.https_proxy", "invalid_url", "Value must be an HTTP or HTTPS URL.")
		}
	}
	if pem := strings.TrimSpace(c.CABundlePEM); pem != "" {
		if !validCABundle(pem) {
			validation.add("ca_bundle_pem", "invalid_pem", "Value must be a valid PEM certificate bundle.")
		}
	}
	if c.SyslogSIEM.Host != "" {
		if c.SyslogSIEM.Port <= 0 || c.SyslogSIEM.Port > 65535 {
			validation.add("syslog_siem_target.port", "out_of_range", "Port must be between 1 and 65535.")
		}
		switch c.SyslogSIEM.Protocol {
		case "tls":
		case "", "udp", "tcp":
			if !c.SyslogSIEM.TLS && (strings.TrimSpace(c.SyslogSIEM.CACert) != "" || strings.TrimSpace(c.SyslogSIEM.ClientCert) != "" || strings.TrimSpace(c.SyslogSIEM.ClientKey) != "") {
				validation.add("syslog_siem_target.tls", "required", "TLS must be enabled when a CA or client certificate is configured.")
			}
		default:
			validation.add("syslog_siem_target.protocol", "invalid_value", "Protocol must be udp, tcp, or tls.")
		}
		switch strings.ToLower(c.SyslogSIEM.Format) {
		case "", "rfc5424", "json", "cef":
		default:
			validation.add("syslog_siem_target.format", "invalid_value", "Format must be rfc5424, json, or cef.")
		}
		if ml := strings.ToLower(strings.TrimSpace(c.SyslogSIEM.MinLevel)); ml != "" {
			switch ml {
			case "critical", "high", "medium", "low", "info":
			default:
				validation.add("syslog_siem_target.min_level", "invalid_value", "Minimum level must be critical, high, medium, low, or info.")
			}
		}
		if ca := strings.TrimSpace(c.SyslogSIEM.CACert); ca != "" && !validCABundle(ca) {
			validation.add("syslog_siem_target.ca_cert", "invalid_pem", "Value must be a valid PEM certificate bundle.")
		}
		hasCert := strings.TrimSpace(c.SyslogSIEM.ClientCert) != ""
		hasKey := strings.TrimSpace(c.SyslogSIEM.ClientKey) != ""
		if hasCert != hasKey {
			if !hasCert {
				validation.add("syslog_siem_target.client_cert", "required", "Client certificate is required when a client key is set.")
			} else {
				validation.add("syslog_siem_target.client_key", "required", "Client key is required when a client certificate is set.")
			}
		}
	}
	if c.ScannerDBRefreshMinutes != 0 && (c.ScannerDBRefreshMinutes < 15 || c.ScannerDBRefreshMinutes > 30*24*60) {
		validation.add("scanner_db_refresh_minutes", "out_of_range", "Value must be 0 or between 15 and 43200.")
	}
	if strings.TrimSpace(c.SMTP.Host) != "" {
		if c.SMTP.Port <= 0 || c.SMTP.Port > 65535 {
			validation.add("smtp.port", "out_of_range", "Port must be between 1 and 65535.")
		}
		if strings.TrimSpace(c.SMTP.From) == "" {
			validation.add("smtp.from", "required", "From address is required when an SMTP host is set.")
		}
	}
	for _, retention := range []struct {
		field string
		days  int
	}{
		{"network_flow_retention_days", c.NetworkFlowRetentionDays},
		{"events_retention_days", c.EventsRetentionDays},
		{"scan_job_retention_days", c.ScanJobRetentionDays},
	} {
		if retention.days < 0 || retention.days > 3650 {
			validation.add(retention.field, "out_of_range", "Value must be between 0 and 3650.")
		}
	}
	if c.AutoScanRescanHours < 0 || c.AutoScanRescanHours > 24*365 {
		validation.add("auto_scan_rescan_hours", "out_of_range", "Value must be between 0 and 8760.")
	}
	return validation.err()
}

func validCABundle(b string) bool {
	rest := []byte(b)
	found := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		found = true
	}
	return found
}

// redactedMarker is what GET returns in place of a configured secret so a caller can
// tell "a CA bundle is set" without leaking its bytes.
const redactedMarker = "***REDACTED***"

// Redacted returns a copy with secret-bearing fields masked, for GET responses (and the
// audit trail). A configured CA bundle is replaced with a marker; absence is preserved as
// empty so the UI can distinguish "set" from "unset". An egress proxy URL that embeds
// userinfo (https://user:pass@proxy:3128) has its credentials stripped to the marker so
// neither GET nor the audit Before/After leaks the proxy password.
func (c Config) Redacted() Config {
	out := c
	if strings.TrimSpace(c.CABundlePEM) != "" {
		out.CABundlePEM = redactedMarker
	}
	if strings.TrimSpace(c.NVDAPIKey) != "" {
		out.NVDAPIKey = redactedMarker
	}
	if strings.TrimSpace(c.SMTP.Password) != "" {
		out.SMTP.Password = redactedMarker
	}
	if strings.TrimSpace(c.SyslogSIEM.ClientKey) != "" {
		out.SyslogSIEM.ClientKey = redactedMarker
	}
	out.EgressProxy.HTTPSProxy = redactProxyUserinfo(c.EgressProxy.HTTPSProxy)
	out.NVDMirrorURL = redactProxyUserinfo(c.NVDMirrorURL)
	return out
}

// redactProxyUserinfo masks URL credentials, query strings, and fragments. Malformed
// URLs are masked in full so redaction never depends on successful validation.
func redactProxyUserinfo(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return redactedMarker
	}
	if _, err := url.ParseQuery(u.RawQuery); err != nil {
		return redactedMarker
	}
	if u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		return raw
	}
	if u.User != nil {
		u.User = url.User(redactedMarker)
	}
	if u.RawQuery != "" {
		u.RawQuery = url.QueryEscape(redactedMarker)
	}
	if u.Fragment != "" {
		u.Fragment = redactedMarker
		u.RawFragment = ""
	}
	return u.String()
}

// proxyUserinfoIsRedacted reports whether a URL contains a redaction marker.
func proxyUserinfoIsRedacted(raw string) bool {
	if raw == redactedMarker {
		return true
	}
	if strings.TrimSpace(raw) == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return (u.User != nil && u.User.Username() == redactedMarker) ||
		u.RawQuery == url.QueryEscape(redactedMarker) || u.Fragment == redactedMarker
}

// ApplyPatch merges a partial JSON patch (only the keys present in `patch` are changed)
// into c and returns the validated result. A patch field equal to the redaction marker
// for a secret is treated as "leave unchanged" so a GET→edit→PATCH round-trip of the
// redacted body does not wipe the stored secret.
func (c Config) ApplyPatch(patch json.RawMessage) (Config, error) {
	if err := validateConfigPatch(patch); err != nil {
		return Config{}, err
	}
	merged := c
	merged.SyslogSIEM.Categories = append([]string(nil), c.SyslogSIEM.Categories...)
	if err := json.Unmarshal(patch, &merged); err != nil {
		return Config{}, &ValidationError{Fields: []FieldError{{Field: "$", Code: "invalid_json", Message: "Patch must contain one valid JSON object."}}}
	}
	if merged.CABundlePEM == redactedMarker {
		merged.CABundlePEM = c.CABundlePEM
	}
	if merged.NVDAPIKey == redactedMarker {
		merged.NVDAPIKey = c.NVDAPIKey
	}
	if merged.SMTP.Password == redactedMarker {
		merged.SMTP.Password = c.SMTP.Password
	}
	if merged.SyslogSIEM.ClientKey == redactedMarker {
		merged.SyslogSIEM.ClientKey = c.SyslogSIEM.ClientKey
	}
	if proxyUserinfoIsRedacted(merged.EgressProxy.HTTPSProxy) {
		merged.EgressProxy.HTTPSProxy = c.EgressProxy.HTTPSProxy
	}
	if proxyUserinfoIsRedacted(merged.NVDMirrorURL) {
		merged.NVDMirrorURL = c.NVDMirrorURL
	}
	if err := merged.Validate(); err != nil {
		return Config{}, err
	}
	return c.withPatchProvenance(merged, patch), nil
}

// --------------------------------- store ------------------------------------

// store is the minimal pgx surface syscfg needs; *pgxpool.Pool satisfies it.
type store interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Load returns the org's config + its revision. When no row exists it returns
// Default() at revision 0 (the caller can seed it).
func Load(ctx context.Context, s store, orgID uuid.UUID) (Config, int64, error) {
	var raw json.RawMessage
	var rev int64
	err := s.QueryRow(ctx,
		`SELECT config, revision FROM system_config WHERE org_id = $1`, orgID).Scan(&raw, &rev)
	if errors.Is(err, pgx.ErrNoRows) {
		return Default(), 0, nil
	}
	if err != nil {
		return Config{}, 0, fmt.Errorf("syscfg: load: %w", err)
	}
	cfg, err := unmarshalStoredConfig(raw)
	if err != nil {
		return Config{}, 0, errors.New("syscfg: invalid stored config encoding")
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, 0, fmt.Errorf("syscfg: stored config invalid: %w", err)
	}
	return cfg, rev, nil
}

// Seed inserts the env-derived bootstrap config for org if (and only if) no row exists
// yet, making env vars first-boot defaults that the DB then owns. Idempotent: a second
// call is a no-op once a row is present. Returns the in-effect config + revision.
func Seed(ctx context.Context, s store, orgID uuid.UUID, defaults Config) (Config, int64, error) {
	if err := defaults.Validate(); err != nil {
		return Config{}, 0, fmt.Errorf("syscfg: seed defaults invalid: %w", err)
	}
	blob, err := marshalStoredConfig(defaults)
	if err != nil {
		return Config{}, 0, err
	}
	if _, err := s.Exec(ctx, `
INSERT INTO system_config (org_id, config, revision)
VALUES ($1, $2::jsonb, 1)
ON CONFLICT (org_id) DO NOTHING`, orgID, blob); err != nil {
		return Config{}, 0, fmt.Errorf("syscfg: seed: %w", err)
	}
	return Load(ctx, s, orgID)
}

// ErrRevisionConflict is returned by Save when the row's current revision no longer
// matches the expectedRev the caller read (a concurrent PATCH won the race). The caller
// should re-Load, re-apply its patch, and retry (HTTP 409). This makes the read-modify-
// write optimistically concurrent so a simultaneous PATCH cannot silently lose updates.
var ErrRevisionConflict = errors.New("syscfg: revision conflict (config changed concurrently)")

// Save persists cfg for org and bumps the revision so reloaders detect the change. The
// caller must have validated cfg (PATCH does this via ApplyPatch). updatedBy may be nil.
//
// expectedRev is the revision the caller based its merge on (0 means "no row existed
// yet"). Save enforces it as an optimistic-concurrency precondition: if a row exists and
// its revision != expectedRev, no write happens and ErrRevisionConflict is returned. When
// expectedRev is 0 the INSERT path creates the row; a concurrent insert that wins the
// race surfaces as a conflict on the DO UPDATE precondition (current revision != 0).
func Save(ctx context.Context, s store, orgID uuid.UUID, cfg Config, expectedRev int64, updatedBy *uuid.UUID) (int64, error) {
	if err := cfg.Validate(); err != nil {
		return 0, err
	}
	blob, err := marshalStoredConfig(cfg)
	if err != nil {
		return 0, err
	}
	var rev int64
	err = s.QueryRow(ctx, `
INSERT INTO system_config (org_id, config, revision, updated_by, updated_at)
VALUES ($1, $2::jsonb, 1, $3, now())
ON CONFLICT (org_id) DO UPDATE
   SET config = EXCLUDED.config,
       revision = system_config.revision + 1,
       updated_by = EXCLUDED.updated_by,
       updated_at = now()
   WHERE system_config.revision = $4
RETURNING revision`, orgID, blob, updatedBy, expectedRev).Scan(&rev)
	if errors.Is(err, pgx.ErrNoRows) {
		// The ON CONFLICT WHERE precondition filtered the update out: the row exists but
		// its revision moved since the caller read it, so RETURNING produced no row.
		return 0, ErrRevisionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("syscfg: save: %w", err)
	}
	return rev, nil
}

// --------------------------- in-process accessor ----------------------------

// Provider is the in-process, hot-reloadable accessor other packages read the live
// config from. It caches the parsed Config per org and a background reloader refreshes
// the cache by polling each org's revision, so a PATCH on any replica propagates here
// WITHOUT a restart. Get is safe for concurrent use.
type Provider struct {
	store store

	mu    sync.RWMutex
	cache map[uuid.UUID]cachedConfig
}

type cachedConfig struct {
	cfg Config
	rev int64
}

// NewProvider builds a Provider backed by store (a *pgxpool.Pool).
func NewProvider(s store) *Provider {
	return &Provider{store: s, cache: map[uuid.UUID]cachedConfig{}}
}

// Get returns the live config for org. On a cache miss it loads from the DB (and caches
// the result). On any DB error it falls back to Default() so a transient DB hiccup never
// hard-fails a consumer that just wants the current knobs.
func (p *Provider) Get(ctx context.Context, orgID uuid.UUID) Config {
	p.mu.RLock()
	c, ok := p.cache[orgID]
	p.mu.RUnlock()
	if ok {
		return cloneConfig(c.cfg)
	}
	cfg, rev, err := Load(ctx, p.store, orgID)
	if err != nil {
		return Default()
	}
	p.set(orgID, cfg, rev)
	p.mu.RLock()
	c = p.cache[orgID]
	p.mu.RUnlock()
	return cloneConfig(c.cfg)
}

// set replaces the cached config for org (used by the reloader and right after a PATCH
// so the writing replica sees its own change immediately, before the next poll tick).
func (p *Provider) set(orgID uuid.UUID, cfg Config, rev int64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if current, ok := p.cache[orgID]; ok && current.rev >= rev {
		return false
	}
	p.cache[orgID] = cachedConfig{cfg: cloneConfig(cfg), rev: rev}
	return true
}

// Refresh re-reads every cached org's row and swaps the cache entry when the revision
// advanced. Returns the number of orgs whose config changed. Best-effort: an org that
// errors is left at its previous cached value. Called by the reloader loop.
func (p *Provider) Refresh(ctx context.Context) int {
	p.mu.RLock()
	orgs := make([]uuid.UUID, 0, len(p.cache))
	revs := make(map[uuid.UUID]int64, len(p.cache))
	for id, c := range p.cache {
		orgs = append(orgs, id)
		revs[id] = c.rev
	}
	p.mu.RUnlock()

	changed := 0
	for _, id := range orgs {
		cfg, rev, err := Load(ctx, p.store, id)
		if err != nil || rev <= revs[id] {
			continue
		}
		if p.set(id, cfg, rev) {
			changed++
		}
	}
	return changed
}

// UpdateAfterPatch is called by the PATCH handler so the writing replica's cache
// reflects the new value immediately (other replicas pick it up on the next Refresh).
func (p *Provider) UpdateAfterPatch(orgID uuid.UUID, cfg Config, rev int64) {
	p.set(orgID, cfg, rev)
}

// Run starts the polling reloader until ctx is cancelled. interval defaults to 30s
// (mirroring runSessionKeyReloader) when non-positive.
func (p *Provider) Run(ctx context.Context, interval time.Duration, onChange func(int)) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := p.Refresh(ctx); n > 0 && onChange != nil {
				onChange(n)
			}
		}
	}
}
