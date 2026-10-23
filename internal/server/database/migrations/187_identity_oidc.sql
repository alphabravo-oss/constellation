-- +goose Up
-- +goose StatementBegin
-- Identity is configured by the deployment. Old passwords, provider types and
-- refreshable local sessions must never survive the OIDC cutover.
DROP TABLE IF EXISTS sso_role_mappings;
DROP TABLE IF EXISTS auth_servers;
DROP TABLE IF EXISTS auth_policy;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS astronomer_identity_map;
DROP TABLE IF EXISTS browser_refresh_tokens;
DROP TABLE IF EXISTS user_sessions;
DROP TABLE IF EXISTS session_signing_keys;
ALTER TABLE orgs DROP COLUMN IF EXISTS jit_provisioning;
ALTER TABLE users
 DROP COLUMN IF EXISTS password_hash,
 DROP COLUMN IF EXISTS password_changed_at,
 DROP COLUMN IF EXISTS must_change_password,
 DROP COLUMN IF EXISTS failed_login_count,
 DROP COLUMN IF EXISTS block_login_since;
ALTER TABLE users ADD COLUMN last_login_at timestamptz;
CREATE TABLE identity_sessions (
 token_hash text PRIMARY KEY,
 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 roles jsonb NOT NULL,
 session_epoch bigint NOT NULL,
 kind text NOT NULL CHECK (kind IN ('oidc','break-glass')),
 expires_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX identity_sessions_expiry_idx ON identity_sessions(expires_at);
CREATE INDEX identity_sessions_user_idx ON identity_sessions(user_id);
CREATE TABLE oidc_login_attempts (
 state_hash text PRIMARY KEY,
 binding_hash text NOT NULL,
 verifier text NOT NULL,
 nonce text NOT NULL,
 expires_at timestamptz NOT NULL
);
CREATE INDEX oidc_login_expiry_idx ON oidc_login_attempts(expires_at);
CREATE TABLE break_glass_guard (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 window_start timestamptz NOT NULL DEFAULT now(),
 attempts integer NOT NULL DEFAULT 0,
 last_totp_step bigint NOT NULL DEFAULT 0
);
INSERT INTO break_glass_guard(singleton) VALUES(true);
-- +goose StatementEnd
