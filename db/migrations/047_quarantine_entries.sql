-- +goose Up
-- +goose StatementBegin
-- Wave E4: quarantine_entries — the admission webhook's runtime-driven
-- deny list. Three layers:
--
--   scope='workload'   — block this Deployment/StatefulSet/DaemonSet
--                        in namespace N. Match key is namespace + workload.
--   scope='image'      — block any pod whose container image starts with
--                        this prefix (registry/repo[:tag]). Use this when
--                        the same compromised image is deployed under
--                        multiple workload names.
--   scope='namespace'  — block any new pod in namespace N. The blunt
--                        instrument; reserved for active incident
--                        response ("contain the namespace, investigate").
--
-- Manual path: API + RBAC verb manage_quarantine. Auto-quarantine path
-- (runtime_threats ingestion at severity >= threshold writing an entry
-- with origin='auto') depends on workload attribution from ep_mac /
-- src_ip → namespace/workload. Until the pod resolver lands (C2), the
-- origin column is provisioned for that future wave but only 'manual'
-- entries get written. The webhook is fully wired and serves the
-- manual-add workflow today.
--
-- The webhook process polls this table every 5s (Helm-configurable). A
-- pod CREATE matching any active, non-expired row is denied with the
-- canonical message "quarantined by constellation: <reason>". The deny
-- emits an audit_events 'admission.deny' row whose target_id points
-- back to the matched quarantine_entries.id, so the chain links a
-- specific runtime alert → quarantine entry → admission deny.
CREATE TABLE IF NOT EXISTS quarantine_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    cluster_id      UUID NOT NULL,
    scope           TEXT NOT NULL
                    CHECK (scope IN ('workload','image','namespace')),
    -- Match key. Semantics depend on scope:
    --   workload:  "<namespace>/<workload-name>" (e.g. "prod/api-server")
    --   image:     image-ref prefix (e.g. "ghcr.io/acme/api@sha256:")
    --   namespace: bare namespace name (e.g. "prod")
    match_key       TEXT NOT NULL,
    reason          TEXT NOT NULL,
    -- 'auto' = inserted by runtime auto-trigger, 'manual' = API.
    origin          TEXT NOT NULL
                    CHECK (origin IN ('auto','manual')),
    -- Optional pointer to the triggering record. For auto-quarantines
    -- this is the runtime_threats.id; for manual it can be null or
    -- carry the finding id the operator was looking at when they
    -- pressed the button.
    source_kind     TEXT,
    source_id       UUID,
    created_by      UUID,   -- user_id for manual; null for auto
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Expiry. NULL = forever (until manually lifted). The auto-trigger
    -- defaults to NOW() + 24h so a noisy auto-quarantine fades unless
    -- an operator explicitly promotes it.
    expires_at      TIMESTAMPTZ,
    -- Lift state. We don't hard-delete entries (audit trail) — instead
    -- a row is marked lifted_at and excluded from the active query.
    lifted_at       TIMESTAMPTZ,
    lifted_by       UUID,
    lifted_reason   TEXT
);

-- The webhook's hot-path lookup. Active = not lifted, not expired.
-- Composite index lets the poller's "everything for this cluster"
-- query stay sargable.
CREATE INDEX IF NOT EXISTS idx_quarantine_active
    ON quarantine_entries(org_id, cluster_id, scope, match_key)
    WHERE lifted_at IS NULL;

-- For the chronological list UI.
CREATE INDEX IF NOT EXISTS idx_quarantine_by_created
    ON quarantine_entries(org_id, cluster_id, created_at DESC);

-- Same (scope, match_key) shouldn't have multiple active entries —
-- collapse duplicate auto-triggers into one. Lifted rows are allowed
-- to repeat because that represents history.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_quarantine_active_target
    ON quarantine_entries(org_id, cluster_id, scope, match_key)
    WHERE lifted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS uniq_quarantine_active_target;
DROP INDEX IF EXISTS idx_quarantine_by_created;
DROP INDEX IF EXISTS idx_quarantine_active;
DROP TABLE IF EXISTS quarantine_entries;
-- +goose StatementEnd
