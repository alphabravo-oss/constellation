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

// SyslogTarget is the syslog/SIEM destination: host:port over udp|tcp. Empty Host
// means "no syslog target configured" (the audit/notifier sender skips syslog).
type SyslogTarget struct {
	Host     string `json:"host,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // "udp" | "tcp"
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
	return Config{
		TLSVerify: true,
	}
}

// Validate enforces the field invariants. Called on every PATCH (after merge) and on
// every load from the DB so a malformed row can never become the live config.
func (c Config) Validate() error {
	if p := strings.TrimSpace(c.EgressProxy.HTTPSProxy); p != "" {
		u, err := url.Parse(p)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("egress_proxy.https_proxy must be an http(s) URL: %q", p)
		}
	}
	if pem := strings.TrimSpace(c.CABundlePEM); pem != "" {
		if !validCABundle(pem) {
			return errors.New("ca_bundle_pem is not a valid PEM certificate bundle")
		}
	}
	if c.SyslogSIEM.Host != "" {
		if c.SyslogSIEM.Port <= 0 || c.SyslogSIEM.Port > 65535 {
			return fmt.Errorf("syslog_siem_target.port out of range: %d", c.SyslogSIEM.Port)
		}
		switch c.SyslogSIEM.Protocol {
		case "", "udp", "tcp":
		default:
			return fmt.Errorf("syslog_siem_target.protocol must be udp or tcp: %q", c.SyslogSIEM.Protocol)
		}
	}
	// 0 = use scanner env default; otherwise clamp to a sane window (15 min .. 30 days).
	if c.ScannerDBRefreshMinutes != 0 && (c.ScannerDBRefreshMinutes < 15 || c.ScannerDBRefreshMinutes > 30*24*60) {
		return fmt.Errorf("scanner_db_refresh_minutes must be 0 or between 15 and 43200: %d", c.ScannerDBRefreshMinutes)
	}
	if strings.TrimSpace(c.SMTP.Host) != "" {
		if c.SMTP.Port <= 0 || c.SMTP.Port > 65535 {
			return fmt.Errorf("smtp.port out of range: %d", c.SMTP.Port)
		}
		if strings.TrimSpace(c.SMTP.From) == "" {
			return errors.New("smtp.from is required when an SMTP host is set")
		}
	}
	for name, d := range map[string]int{
		"network_flow_retention_days": c.NetworkFlowRetentionDays,
		"events_retention_days":       c.EventsRetentionDays,
		"scan_job_retention_days":     c.ScanJobRetentionDays,
	} {
		if d < 0 || d > 3650 {
			return fmt.Errorf("%s must be between 0 and 3650: %d", name, d)
		}
	}
	if c.AutoScanRescanHours < 0 || c.AutoScanRescanHours > 24*365 {
		return fmt.Errorf("auto_scan_rescan_hours out of range: %d", c.AutoScanRescanHours)
	}
	return nil
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
	out.EgressProxy.HTTPSProxy = redactProxyUserinfo(c.EgressProxy.HTTPSProxy)
	return out
}

// redactProxyUserinfo replaces any embedded userinfo in a proxy URL with the redaction
// marker, preserving the rest of the URL. A URL without credentials is returned unchanged;
// an unparseable value is returned as-is (Validate() rejects bad URLs before persist).
func redactProxyUserinfo(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User(redactedMarker)
	return u.String()
}

// proxyUserinfoIsRedacted reports whether raw is a proxy URL whose userinfo is the
// redaction marker (i.e. a redacted value echoed back unmodified).
func proxyUserinfoIsRedacted(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return false
	}
	return u.User.Username() == redactedMarker
}

// ApplyPatch merges a partial JSON patch (only the keys present in `patch` are changed)
// into c and returns the validated result. A patch field equal to the redaction marker
// for a secret is treated as "leave unchanged" so a GET→edit→PATCH round-trip of the
// redacted body does not wipe the stored secret.
func (c Config) ApplyPatch(patch json.RawMessage) (Config, error) {
	// Round-trip the current config through JSON, then overlay the patch object. Unknown
	// keys are rejected so typos surface as 400s rather than silent no-ops.
	merged := c
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&merged); err != nil {
		return Config{}, fmt.Errorf("invalid config patch: %w", err)
	}
	if merged.CABundlePEM == redactedMarker {
		merged.CABundlePEM = c.CABundlePEM // preserve the existing secret on redacted echo
	}
	if merged.NVDAPIKey == redactedMarker {
		merged.NVDAPIKey = c.NVDAPIKey // preserve the existing key on redacted echo
	}
	if merged.SMTP.Password == redactedMarker {
		merged.SMTP.Password = c.SMTP.Password // preserve the existing SMTP password on redacted echo
	}
	// If the proxy URL was echoed back with its userinfo still redacted (a GET→edit→PATCH
	// round-trip of the masked value), restore the original credentialed URL so the secret
	// is not wiped or persisted as the literal marker.
	if proxyUserinfoIsRedacted(merged.EgressProxy.HTTPSProxy) {
		merged.EgressProxy.HTTPSProxy = c.EgressProxy.HTTPSProxy
	}
	if err := merged.Validate(); err != nil {
		return Config{}, err
	}
	return merged, nil
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
	cfg := Default()
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, 0, fmt.Errorf("syscfg: unmarshal: %w", err)
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
	blob, err := json.Marshal(defaults)
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
	blob, err := json.Marshal(cfg)
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
		return c.cfg
	}
	cfg, rev, err := Load(ctx, p.store, orgID)
	if err != nil {
		return Default()
	}
	p.mu.Lock()
	p.cache[orgID] = cachedConfig{cfg: cfg, rev: rev}
	p.mu.Unlock()
	return cfg
}

// set replaces the cached config for org (used by the reloader and right after a PATCH
// so the writing replica sees its own change immediately, before the next poll tick).
func (p *Provider) set(orgID uuid.UUID, cfg Config, rev int64) {
	p.mu.Lock()
	p.cache[orgID] = cachedConfig{cfg: cfg, rev: rev}
	p.mu.Unlock()
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
		if err != nil || rev == revs[id] {
			continue
		}
		p.set(id, cfg, rev)
		changed++
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
