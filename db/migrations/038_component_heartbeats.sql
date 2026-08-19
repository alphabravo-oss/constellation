-- +goose Up
-- +goose StatementBegin
-- Wave N6: per-component health + version observability. Each Constellation
-- binary (api, scanner, admission, operator, runtime-agent, archiver, frontend,
-- discoverer, registry-walker) POSTs a heartbeat every 30s to
-- /api/v1/heartbeats. The handler upserts on (org_id, cluster_id, component,
-- hostname) so a multi-replica deployment still produces one row per replica
-- (hostname is the disambiguator).
--
-- Restart inference: when a new heartbeat arrives with uptime_seconds LESS
-- than the row's prior uptime_seconds, the handler bumps restart_count. This
-- avoids needing a separate Kubernetes-events-pulling agent — the rolling
-- pod itself reports the discontinuity.
--
-- Cluster scoping: control-plane components (api, archiver) heartbeat without
-- a cluster_id (it stays NULL); data-plane components (scanner, runtime-agent,
-- operator, discoverer) include the cluster they live in so version drift can
-- be computed per-cluster.
CREATE TABLE IF NOT EXISTS component_heartbeats (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id            UUID REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id        UUID REFERENCES clusters(id) ON DELETE SET NULL,
    component         TEXT NOT NULL,
    version           TEXT,
    commit            TEXT,
    build_time        TIMESTAMPTZ,
    hostname          TEXT NOT NULL DEFAULT '',
    uptime_seconds    BIGINT NOT NULL DEFAULT 0,
    restart_count     INT NOT NULL DEFAULT 0,
    last_error        TEXT,
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, component, hostname)
);

-- The N6 drift scoring scans by (org_id, cluster_id) + sorts by last_seen_at
-- to find the freshest commit per component; a composite index supports both
-- the cluster rollup and the staleness scan without a sort step.
CREATE INDEX IF NOT EXISTS idx_component_heartbeats_org_cluster_seen
    ON component_heartbeats(org_id, cluster_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_component_heartbeats_component_seen
    ON component_heartbeats(component, last_seen_at DESC);

-- Component restart events. Append-only log of "this hostname's uptime went
-- backwards" — used to render the System Health crashloop timeline and to
-- drive the >3-in-1h notifier rule.
CREATE TABLE IF NOT EXISTS component_restart_events (
    id            BIGSERIAL PRIMARY KEY,
    org_id        UUID REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE SET NULL,
    component     TEXT NOT NULL,
    hostname      TEXT NOT NULL DEFAULT '',
    prev_uptime_s BIGINT NOT NULL DEFAULT 0,
    new_uptime_s  BIGINT NOT NULL DEFAULT 0,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reason        TEXT
);

CREATE INDEX IF NOT EXISTS idx_component_restart_events_recent
    ON component_restart_events(org_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_component_restart_events_component_recent
    ON component_restart_events(component, hostname, detected_at DESC);

-- License metadata lives on org_settings.settings JSONB. We don't need a new
-- table — but we do want fresh installs to default to "community" so the UI
-- doesn't render an expiry banner against a NULL. The merge below preserves
-- any existing settings keys and only fills in 'license' when absent.
INSERT INTO org_settings (org_id, settings)
SELECT id, jsonb_build_object(
    'license', jsonb_build_object(
        'kind', 'community',
        'issued_at', to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
        'expires_at', NULL,
        'signed_by', 'self',
        'customer_id', NULL,
        'seats', NULL
    )
)
  FROM orgs
ON CONFLICT (org_id) DO UPDATE
   SET settings = org_settings.settings || jsonb_build_object(
        'license', COALESCE(org_settings.settings->'license',
            jsonb_build_object(
                'kind', 'community',
                'issued_at', to_char(NOW(), 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
                'expires_at', NULL,
                'signed_by', 'self',
                'customer_id', NULL,
                'seats', NULL
            )
        )
   );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_component_restart_events_component_recent;
DROP INDEX IF EXISTS idx_component_restart_events_recent;
DROP TABLE IF EXISTS component_restart_events;
DROP INDEX IF EXISTS idx_component_heartbeats_component_seen;
DROP INDEX IF EXISTS idx_component_heartbeats_org_cluster_seen;
DROP TABLE IF EXISTS component_heartbeats;
-- License keys left in org_settings (downgrades shouldn't drop org-level
-- settings the operator may have edited). Operators can remove them manually
-- if absolutely required.
-- +goose StatementEnd
