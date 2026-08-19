package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	neturl "net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/alphabravocompany/constellation/internal/auth"
	"github.com/alphabravocompany/constellation/pkg/federation"
)

// ── G3a: master-side revision write hook ────────────────────────────────────
//
// recordFedRevision appends one row to fed_rule_revisions for a master-org
// mutation, so joints polling GET /sync?since= observe and replicate it. It is a
// no-op unless the org is in the `master` federation state — standalone/joint
// orgs do not author federated rules. Best-effort: callers log-and-continue on
// error; failing to record a revision must never fail the underlying mutation.
//
// payload is the full rule body the joint upserts locally (read-only, fed-typed).
// revision is monotonic per org: max(existing)+1.
//
// Concurrency: two master mutations can compute the same max(revision)+1 at once.
// With UNIQUE(org_id, revision) (migration 092) the loser's INSERT fails with a
// unique-violation; we retry, recomputing the next revision, so no two revisions
// collide and none are silently skipped.
func recordFedRevision(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind, ruleID string, payload any) error {
	var state string
	if err := pool.QueryRow(ctx,
		`SELECT state FROM federation_state WHERE org_id=$1`, orgID).Scan(&state); err != nil {
		// No federation_state row => standalone; nothing to replicate.
		return nil
	}
	if state != string(federation.StateMaster) {
		return nil
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// Retry on unique(org_id,revision) conflict: a concurrent master mutation took
	// the revision number we computed. Recompute and try again.
	const maxAttempts = 8
	for attempt := 0; attempt < maxAttempts; attempt++ {
		_, err = pool.Exec(ctx, `
INSERT INTO fed_rule_revisions (org_id, rule_kind, rule_id, revision, payload)
VALUES ($1, $2, $3,
        (SELECT COALESCE(MAX(revision),0)+1 FROM fed_rule_revisions WHERE org_id=$1),
        $4)`, orgID, kind, ruleID, raw)
		if err == nil {
			return nil
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			continue // revision raced; recompute MAX and retry
		}
		return err
	}
	return err
}

// errFedReadOnly is returned when a caller tries to locally mutate a row that was
// replicated from a master (cfg_type='fed'). Such rows are owned by the poller and
// must only change via the next sync, otherwise the joint drifts from its master.
var errFedReadOnly = errors.New("rule is federated (read-only); change it on the master")

// ── P2-3: broadened federated rule kinds ─────────────────────────────────────
//
// Beyond policy/group/admission/response-override, master orgs federate the
// per-workload runtime profiles that previously stayed per-cluster (so runtime
// protection drifted across a fleet). Mirrors NeuVector's FedFileMonitorProfiles
// and FedProcessProfiles types.
//
// Only the two runtime domains that expose a runtime-agent pull bundle
// (file-profile-rules:bundle, process-baselines:bundle) are federated: the master
// authors a revision on each mutation (see internal/handler/runtime) and the
// joint merges the replicated row read-only into what its agents receive.
// NeuVector's third fed runtime type, FedNetworkRules, has no analogue here —
// Constellation network policies are rendered as k8s NetworkPolicy manifests
// applied out-of-band, not pulled by a runtime agent, so there is no serving path
// to federate them into.
//
// Unlike the other federated kinds — each of which replicates into its own
// org-scoped table (policies/groups/response_rule_overrides) — these land in the
// single generic fed_runtime_profiles table (migration 123). The live runtime
// tables (file_profile_rules, process_baseline_states) are per-cluster STATE
// keyed by a NOT NULL cluster_id FK, so a joint has no matching cluster to bind a
// master-authored row to. Following NeuVector, a fed profile is a fleet-wide
// template stored opaquely by (kind, key) and consulted read-only by the joint's
// agents across every cluster.
const (
	fedKindFileProfile        = "file_profile"
	fedKindHostProcessProfile = "host_process_profile"
)

// fedProfileKind reports whether kind is one of the P2-3 runtime-profile kinds
// that materialize into fed_runtime_profiles (including its `_delete` tombstone).
// Pure classification helper — unit tested without a DB.
func fedProfileKind(kind string) bool {
	switch kind {
	case fedKindFileProfile, fedKindFileProfile + "_delete",
		fedKindHostProcessProfile, fedKindHostProcessProfile + "_delete":
		return true
	default:
		return false
	}
}

// policyIsFed reports whether the policy with the given id/org is a fed
// (master-authored, read-only) row. Missing rows report false so the caller's own
// not-found handling stays in charge.
func policyIsFed(ctx context.Context, pool *pgxpool.Pool, id, orgID uuid.UUID) (bool, error) {
	var cfg string
	err := pool.QueryRow(ctx,
		`SELECT cfg_type FROM policies WHERE id=$1 AND org_id=$2`, id, orgID).Scan(&cfg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return cfg == "fed", nil
}

// groupIsFed reports whether the group with the given id/org is a fed row.
func groupIsFed(ctx context.Context, pool *pgxpool.Pool, id, orgID uuid.UUID) (bool, error) {
	var cfg string
	err := pool.QueryRow(ctx,
		`SELECT cfg_type FROM groups WHERE id=$1 AND org_id=$2`, id, orgID).Scan(&cfg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return cfg == "fed", nil
}

// responseRuleOverrideIsFed reports whether the v1 response-rule override for the
// given catalog ruleID/org is a fed (master-authored, read-only) row. Missing rows
// report false so the caller's own create/update path stays in charge.
func responseRuleOverrideIsFed(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, ruleID string) (bool, error) {
	var cfg string
	err := pool.QueryRow(ctx,
		`SELECT cfg_type FROM response_rule_overrides WHERE org_id=$1 AND rule_id=$2`, orgID, ruleID).Scan(&cfg)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return cfg == "fed", nil
}

// logFedRevision wraps recordFedRevision with best-effort warn-on-error logging
// so handler call sites stay one line.
func logFedRevision(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind, ruleID string, payload any) {
	if err := recordFedRevision(ctx, pool, orgID, kind, ruleID, payload); err != nil {
		slog.Default().Warn("fed revision record failed",
			slog.String("kind", kind), slog.String("rule_id", ruleID), slog.String("err", err.Error()))
	}
}

// ── G3b: joint-side background poller ────────────────────────────────────────
//
// A joint pulls its master's modified-rules log and replicates each revision
// locally as a read-only, fed-typed rule, advancing last_synced_revision. Shape
// mirrors ReconcileCVEEnrichmentLoop: a no-op-when-unconfigured loop that runs
// shortly after start and on interval.

// fedSyncPayload is the rule body a master ships and a joint upserts. Only the
// fields the joint needs to materialize a local fed rule are carried.
type fedSyncPayload struct {
	OrgID       uuid.UUID `json:"org_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Engine      string    `json:"engine"`
	Category    string    `json:"category"`
	SpecYAML    string    `json:"spec_yaml"`
	Mode        string    `json:"mode"`
	Enabled     bool      `json:"enabled"`
	// group fields
	Kind     string          `json:"kind"`
	Comment  string          `json:"comment"`
	Criteria json.RawMessage `json:"criteria"`
	// response-rule override fields (the master ships a responseRuleDTO whose json
	// tags overlap these: id/override_reason/event_type alongside mode/enabled).
	ID             string `json:"id"`
	OverrideReason string `json:"override_reason"`
	EventType      string `json:"event_type"`
}

// syncResponse mirrors the master's GET /sync envelope.
type syncResponse struct {
	Revisions []federation.RuleRevision `json:"revisions"`
	Since     int64                     `json:"since"`
}

// ReconcileFedSync runs one poll cycle for every joint org: GET master /sync?since=,
// upsert fetched rules under cfg_type=fed (read-only), advance last_synced_revision.
// masterURL is the base URL of this joint's master controller (no trailing /sync).
// token authenticates the joint to the master's API. No-op when either is empty.
func ReconcileFedSync(ctx context.Context, pool *pgxpool.Pool, sealer auth.Sealer, client *http.Client, masterURL, token string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	masterURL = strings.TrimRight(strings.TrimSpace(masterURL), "/")
	if masterURL == "" {
		return nil
	}
	// Every org currently in the joint state polls.
	rows, err := pool.Query(ctx, `SELECT org_id FROM federation_state WHERE state=$1`, string(federation.StateJoint))
	if err != nil {
		return err
	}
	var orgs []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		orgs = append(orgs, id)
	}
	rows.Close()

	for _, orgID := range orgs {
		if err := reconcileFedSyncOrg(ctx, pool, sealer, client, masterURL, token, orgID, logger); err != nil {
			logger.Warn("fed sync org failed", slog.String("org", orgID.String()), slog.String("err", err.Error()))
		}
	}
	return nil
}

func reconcileFedSyncOrg(ctx context.Context, pool *pgxpool.Pool, sealer auth.Sealer, client *http.Client, masterURL, token string, orgID uuid.UUID, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	var since int64
	_ = pool.QueryRow(ctx, `SELECT last_synced_revision FROM fed_sync_state WHERE org_id=$1`, orgID).Scan(&since)

	// Identify this joint to the master by the cluster name it recorded when it
	// Joined, so the master can stamp the matching fed_members heartbeat and reject
	// us once we are kicked.
	var clusterID string
	_ = pool.QueryRow(ctx, `SELECT cluster_name FROM federation_state WHERE org_id=$1`, orgID).Scan(&clusterID)

	// D1: prefer the per-cluster sync ticket this joint received at join time over the
	// static fallback token. The master authenticates the ticket on every poll and
	// derives the cluster id from it, so a credentialed joint need not pass ?cluster_id=.
	// D2: also load the per-joint client cert material so the poll presents the cert
	// (mutual auth) and pins the master CA. The private key is stored encrypted at rest;
	// it is decrypted here via the install-KEK cipher only to build the TLS client.
	var (
		storedClusterID string
		clientCertPEM   string
		clientKeyEnc    []byte
		masterCAPEM     string
	)
	if err := pool.QueryRow(ctx, `
SELECT secret, cluster_id, client_cert_pem, client_key_enc, master_ca_pem
  FROM fed_joint_secret WHERE org_id=$1`, orgID).
		Scan(&token, &storedClusterID, &clientCertPEM, &clientKeyEnc, &masterCAPEM); err == nil {
		if storedClusterID != "" {
			clusterID = storedClusterID
		}
		if clientCertPEM != "" && sealer != nil && len(clientKeyEnc) > 0 {
			keyPEM, derr := sealer.Open(clientKeyEnc)
			if derr != nil {
				return fmt.Errorf("decrypt joint client key: %w", derr)
			}
			mtls, cerr := fedJointPollClient([]byte(clientCertPEM), keyPEM, []byte(masterCAPEM), client)
			if cerr != nil {
				return fmt.Errorf("build joint mTLS client: %w", cerr)
			}
			client = mtls
		}
	}

	url := fmt.Sprintf("%s/api/v1/federation/sync?since=%d", masterURL, since)
	if clusterID != "" {
		url += "&cluster_id=" + neturl.QueryEscape(clusterID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("master /sync status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var sr syncResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return err
	}
	if len(sr.Revisions) == 0 {
		return nil
	}

	var maxRev int64 = since
	for _, rev := range sr.Revisions {
		if err := applyFedRevision(ctx, pool, orgID, rev); err != nil {
			return err
		}
		if rev.Revision > maxRev {
			maxRev = rev.Revision
		}
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO fed_sync_state (org_id, last_synced_revision, last_synced_at)
VALUES ($1, $2, NOW())
ON CONFLICT (org_id) DO UPDATE SET last_synced_revision=EXCLUDED.last_synced_revision, last_synced_at=NOW()`,
		orgID, maxRev); err != nil {
		return err
	}
	logger.Info("fed sync applied", slog.String("org", orgID.String()),
		slog.Int("revisions", len(sr.Revisions)), slog.Int64("since", since), slog.Int64("now", maxRev))
	return nil
}

// applyFedRevision upserts one master-authored revision into the joint's local
// tables under cfg_type=fed (policies) / kind=federated (groups). Idempotent:
// re-applying the same revision is a harmless upsert.
func applyFedRevision(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, rev federation.RuleRevision) error {
	var p fedSyncPayload
	if err := json.Unmarshal(rev.Payload, &p); err != nil {
		return fmt.Errorf("decode fed payload (rev %d): %w", rev.Revision, err)
	}
	switch rev.Kind {
	case "policy":
		// Carry the master's enabled value so master-enabled policies actually
		// take effect on joints; ON CONFLICT must set it too (re-applied fed rows
		// would otherwise keep a stale enabled).
		_, err := pool.Exec(ctx, `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode, version, cfg_type)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,'fed')
ON CONFLICT (org_id, name, version) DO UPDATE SET
    description=EXCLUDED.description, engine=EXCLUDED.engine, category=EXCLUDED.category,
    spec_yaml=EXCLUDED.spec_yaml, enabled=EXCLUDED.enabled, mode=EXCLUDED.mode,
    cfg_type='fed', updated_at=NOW()`,
			orgID, p.Name, p.Description, p.Engine, p.Category, p.SpecYAML, p.Enabled, p.Mode)
		return err
	case "policy_delete":
		// Tombstone: the master deleted this policy. Remove the joint's fed copy.
		// Scoped to cfg_type='fed' so a local user policy that happens to share a
		// name is never collaterally deleted.
		_, err := pool.Exec(ctx,
			`DELETE FROM policies WHERE org_id=$1 AND name=$2 AND cfg_type='fed'`, orgID, p.Name)
		return err
	case "group":
		criteria := p.Criteria
		if len(criteria) == 0 {
			criteria = json.RawMessage("[]")
		}
		_, err := pool.Exec(ctx, `
INSERT INTO groups (org_id, name, kind, comment, criteria, cfg_type)
VALUES ($1,$2,'federated',$3,$4,'fed')
ON CONFLICT (org_id, name) DO UPDATE SET
    kind='federated', comment=EXCLUDED.comment, criteria=EXCLUDED.criteria, cfg_type='fed', updated_at=NOW()`,
			orgID, p.Name, p.Comment, []byte(criteria))
		return err
	case "group_delete":
		_, err := pool.Exec(ctx,
			`DELETE FROM groups WHERE org_id=$1 AND name=$2 AND cfg_type='fed'`, orgID, p.Name)
		return err
	case "admission_policy":
		// Admission-deny policies are ordinary rows in `policies` (engine
		// 'constellation-admission'); they replicate exactly like a 'policy' but
		// carry a distinct revision kind so the log mirrors NeuVector's separate
		// FedAdmCtrlDenyRulesType. Read-only enforcement is the shared policyIsFed
		// path on the policies CRUD — no separate guard needed.
		_, err := pool.Exec(ctx, `
INSERT INTO policies (org_id, name, description, engine, category, spec_yaml, enabled, mode, version, cfg_type)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,'fed')
ON CONFLICT (org_id, name, version) DO UPDATE SET
    description=EXCLUDED.description, engine=EXCLUDED.engine, category=EXCLUDED.category,
    spec_yaml=EXCLUDED.spec_yaml, enabled=EXCLUDED.enabled, mode=EXCLUDED.mode,
    cfg_type='fed', updated_at=NOW()`,
			orgID, p.Name, p.Description, p.Engine, p.Category, p.SpecYAML, p.Enabled, p.Mode)
		return err
	case "admission_policy_delete":
		_, err := pool.Exec(ctx,
			`DELETE FROM policies WHERE org_id=$1 AND name=$2 AND cfg_type='fed'`, orgID, p.Name)
		return err
	case "response_rule":
		// v1 response-rule overrides are keyed by a catalog rule_id (org_id,rule_id);
		// the master ships the chosen mode/enabled/reason. Materialize it as a fed
		// (read-only) override row; ON CONFLICT keeps a re-pulled revision idempotent.
		_, err := pool.Exec(ctx, `
INSERT INTO response_rule_overrides (org_id, rule_id, mode, enabled, reason, cfg_type)
VALUES ($1,$2,$3,$4,$5,'fed')
ON CONFLICT (org_id, rule_id) DO UPDATE SET
    mode=EXCLUDED.mode, enabled=EXCLUDED.enabled, reason=EXCLUDED.reason,
    cfg_type='fed', updated_at=NOW()`,
			orgID, p.ID, p.Mode, p.Enabled, p.OverrideReason)
		return err
	case "response_rule_delete":
		// Tombstone: master cleared the override. Drop the joint's fed copy so the
		// catalog default takes over again. Scoped to cfg_type='fed' so a local
		// override on the same rule_id is never collaterally removed.
		_, err := pool.Exec(ctx,
			`DELETE FROM response_rule_overrides WHERE org_id=$1 AND rule_id=$2 AND cfg_type='fed'`, orgID, p.ID)
		return err
	case fedKindFileProfile, fedKindHostProcessProfile:
		// P2-3 runtime profiles: file-monitor and host-process profiles federate as
		// fleet-wide templates. The master ships the agent-bundle row verbatim; the
		// joint stores it opaquely in the generic fed_runtime_profiles table keyed by
		// (kind, rule_key) and its agents apply it read-only across every cluster.
		// rev.RuleID is the stable master key. ON CONFLICT keeps a re-pulled revision
		// idempotent.
		payload := rev.Payload
		if len(payload) == 0 {
			payload = json.RawMessage("{}")
		}
		_, err := pool.Exec(ctx, `
INSERT INTO fed_runtime_profiles (org_id, rule_kind, rule_key, payload, cfg_type)
VALUES ($1,$2,$3,$4,'fed')
ON CONFLICT (org_id, rule_kind, rule_key) DO UPDATE SET
    payload=EXCLUDED.payload, cfg_type='fed', updated_at=NOW()`,
			orgID, rev.Kind, rev.RuleID, []byte(payload))
		return err
	case fedKindFileProfile + "_delete", fedKindHostProcessProfile + "_delete":
		// Tombstone: the master removed this runtime profile. Drop the joint's fed
		// copy. The `_delete` suffix is trimmed to recover the base rule_kind the
		// live row was stored under. Scoped to cfg_type='fed'.
		baseKind := strings.TrimSuffix(rev.Kind, "_delete")
		_, err := pool.Exec(ctx,
			`DELETE FROM fed_runtime_profiles WHERE org_id=$1 AND rule_kind=$2 AND rule_key=$3 AND cfg_type='fed'`,
			orgID, baseKind, rev.RuleID)
		return err
	default:
		return nil
	}
}

// ReconcileFedSyncLoop runs ReconcileFedSync shortly after start and on interval.
// No-op when masterURL is empty (standalone/master controllers). Mirrors
// ReconcileCVEEnrichmentLoop.
func ReconcileFedSyncLoop(ctx context.Context, pool *pgxpool.Pool, sealer auth.Sealer, masterURL, token string, interval time.Duration, logger *slog.Logger) {
	if strings.TrimSpace(masterURL) == "" {
		return // not a joint / master URL not configured: nothing to do
	}
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 60 * time.Second
	}
	client := &http.Client{Timeout: 30 * time.Second}
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if err := ReconcileFedSync(ctx, pool, sealer, client, masterURL, token, logger); err != nil {
			logger.Warn("fed sync reconcile failed", slog.String("err", err.Error()))
		}
		timer.Reset(interval)
	}
}

// ── ARC-1 exported seams ─────────────────────────────────────────────────────
//
// The policy domain moved to internal/handler/policy (ARC-1) but still mutates
// federated rules through the master-side revision machinery that lives here in
// the parent (also used by groups.go). These thin wrappers expose the
// package-private helpers without moving them, mirroring sqlx.ParseClusterIDParam.

// FedSyncPayload is the exported alias of the rule body shipped on a federated
// revision. The policy sub-package constructs these directly.
type FedSyncPayload = fedSyncPayload

// ErrFedReadOnly returns the sentinel error for rejecting local mutation of a
// fed (master-authored, read-only) row.
func ErrFedReadOnly() error { return errFedReadOnly }

// PolicyIsFed reports whether the policy id/org is a fed (read-only) row.
func PolicyIsFed(ctx context.Context, pool *pgxpool.Pool, id, orgID uuid.UUID) (bool, error) {
	return policyIsFed(ctx, pool, id, orgID)
}

// ResponseRuleOverrideIsFed reports whether the v1 response-rule override for the
// given catalog ruleID/org is a fed (read-only) row.
func ResponseRuleOverrideIsFed(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, ruleID string) (bool, error) {
	return responseRuleOverrideIsFed(ctx, pool, orgID, ruleID)
}

// LogFedRevision records a master-side revision best-effort (warn-on-error).
func LogFedRevision(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, kind, ruleID string, payload any) {
	logFedRevision(ctx, pool, orgID, kind, ruleID, payload)
}

// P2-3 exported revision-kind constants for the runtime-profile domains. The
// file-profile and host-process handlers author federated rules by calling
// LogFedRevision(ctx, pool, orgID, FedKind*, key, body) on a master mutation (and
// FedKind*+"_delete" on removal). Kept here beside applyFedRevision so the master
// (author) and joint (apply) sides share one source of truth.
const (
	FedKindFileProfile        = fedKindFileProfile
	FedKindHostProcessProfile = fedKindHostProcessProfile
)

// PurgeFedRows deletes every master-authored (cfg_type='fed') row this org
// replicated while it was a joint (or that it authored while master). Called on
// leave/demote so orphaned fed rows do not become permanently uneditable zombies
// once the federation link is gone — the read-only guards keep rejecting local
// edits of cfg_type='fed' rows forever otherwise, and no master remains to sync
// or tombstone them. Mirrors NeuVector purging the fed. keyspace on leave/demote.
//
// Best-effort and idempotent: a standalone org (never federated) simply deletes
// zero rows. Errors are returned so the caller can surface/log them, but a purge
// failure must not block the membership transition itself.
func PurgeFedRows(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	return purgeFedRows(ctx, pool, orgID)
}

func purgeFedRows(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	// Every table that carries cfg_type='fed' rows. fed_runtime_profiles (P2-3) is
	// exclusively fed so an unqualified org delete is equivalent, but the cfg_type
	// predicate is kept uniform across all statements.
	stmts := []string{
		`DELETE FROM policies WHERE org_id=$1 AND cfg_type='fed'`,
		`DELETE FROM groups WHERE org_id=$1 AND cfg_type='fed'`,
		`DELETE FROM response_rule_overrides WHERE org_id=$1 AND cfg_type='fed'`,
		`DELETE FROM fed_runtime_profiles WHERE org_id=$1 AND cfg_type='fed'`,
	}
	for _, q := range stmts {
		if _, err := pool.Exec(ctx, q, orgID); err != nil {
			return err
		}
	}
	// Drop the joint's local sync cursor too, so a future re-join replays the new
	// master's log from revision 0 instead of resuming a stale `since`.
	_, err := pool.Exec(ctx, `DELETE FROM fed_sync_state WHERE org_id=$1`, orgID)
	return err
}
