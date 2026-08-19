-- +goose Up
-- +goose StatementBegin
-- A1 — admin-configurable password policy + session/idle timeout.
--
-- Historically the password strength/lifecycle policy was HARDCODED in
-- internal/auth.DefaultPasswordProfile (12ch / 3-class / 90d / 5-history) and the
-- session absolute-TTL + idle window were deploy-time env only (JWT_TTL,
-- SESSION_IDLE_TIMEOUT). This table surfaces them as a per-org, RBAC-gated,
-- runtime-mutable policy (mirrors NeuVector's CLUSPwdProfile). One row per org holds
-- the whole policy in a single validated JSONB blob (`policy`) so new knobs can be
-- added without a schema migration; a typed Go struct (internal/auth.SecurityPolicy)
-- is the validating gatekeeper for every read and write.
--
-- The hardcoded defaults remain the FALLBACK: an org with no row (or a transient DB
-- error at load time) resolves to DefaultPasswordProfile + the env/JWT timeouts, so
-- login/validation never hard-fails on a missing policy. `revision` is bumped on every
-- successful PUT for optimistic concurrency (mirrors system_config).
CREATE TABLE IF NOT EXISTS auth_policy (
    org_id     UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    policy     JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision   BIGINT NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by UUID
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auth_policy;
-- +goose StatementEnd
