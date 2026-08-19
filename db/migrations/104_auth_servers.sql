-- +goose Up
-- +goose StatementBegin
-- B4 — DB-backed auth-provider (IdP) CRUD. Today LDAP/SAML/OIDC providers are
-- single-instance, wired at process start from env/Helm; RoleMapping is Helm-only.
-- This table makes them runtime-mutable rows: each row is one configured identity
-- provider (type ldap|saml|oidc) with its provider-specific config (secrets included)
-- in a single validated JSONB blob, plus the group->role mapping (role_mapping JSONB)
-- that the existing JIT/SSO provisioning resolves at login. auth_order orders the
-- providers (lower first) so the active provider of each type is deterministic.
--
-- Env/Helm providers become BOOTSTRAP DEFAULTS the server seeds on first boot if no
-- row of that type exists yet; after that the DB row is the source of truth. `revision`
-- is bumped on every CRUD mutation so the in-process provider set polls it and hot-reloads
-- the live verifier set WITHOUT a restart (mirrors B1's system_config + A5's session keys).
CREATE TABLE IF NOT EXISTS auth_servers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    type         TEXT NOT NULL CHECK (type IN ('ldap', 'saml', 'oidc')),
    name         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    auth_order   INTEGER NOT NULL DEFAULT 100,
    config       JSONB NOT NULL DEFAULT '{}'::jsonb,
    role_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    revision     BIGINT NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by   UUID,
    UNIQUE (org_id, name)
);
CREATE INDEX IF NOT EXISTS auth_servers_org_order_idx ON auth_servers (org_id, auth_order, created_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS auth_servers;
-- +goose StatementEnd
