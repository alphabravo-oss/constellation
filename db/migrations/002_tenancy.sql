-- +goose Up
-- +goose StatementBegin
CREATE TABLE orgs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    region       TEXT NOT NULL DEFAULT 'us-east-1',
    ai_enabled   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE clusters (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    distro       TEXT NOT NULL DEFAULT 'kubernetes',  -- "kubernetes" | "eks" | "gke" | "aks" | "openshift" | "rke" | "k3s" | "microk8s" | "talos"
    cloud_provider TEXT,                              -- "aws" | "gcp" | "azure" | "onprem"
    region       TEXT,
    state        TEXT NOT NULL DEFAULT 'pending',     -- "pending" | "connected" | "disconnected"
    agent_version TEXT,
    last_heartbeat_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE TABLE projects (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   UUID REFERENCES clusters(id) ON DELETE SET NULL,
    name         TEXT NOT NULL,
    namespace_selector JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    email         TEXT NOT NULL,
    display_name  TEXT NOT NULL,
    password_hash TEXT,                          -- Argon2id encoded; NULL for OIDC-only users
    oidc_subject  TEXT,                          -- IdP "sub" claim, for OIDC-linked accounts
    oidc_issuer   TEXT,
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, email),
    UNIQUE (oidc_issuer, oidc_subject)
);

-- Astronomer identity <-> Constellation subject mapping.
CREATE TABLE astronomer_identity_map (
    astronomer_user_id TEXT PRIMARY KEY,
    user_id            UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id             UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE role_assignments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL,                  -- "Auditor" | "Analyst" | "ClusterAdmin" | "SecurityAdmin" | "GlobalAdmin"
    scope_org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    scope_cluster_id UUID REFERENCES clusters(id) ON DELETE CASCADE,
    scope_project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_role_assignments_user ON role_assignments(user_id);
CREATE INDEX idx_role_assignments_scope ON role_assignments(scope_org_id, scope_cluster_id, scope_project_id);

CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,           -- sha256 of the bearer token
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS role_assignments;
DROP TABLE IF EXISTS astronomer_identity_map;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS projects;
DROP TABLE IF EXISTS clusters;
DROP TABLE IF EXISTS orgs;
-- +goose StatementEnd
