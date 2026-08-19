-- +goose Up
-- +goose StatementBegin
-- Per-org gate for SSO JIT (just-in-time) provisioning: when TRUE, an external-IdP
-- login (SAML/LDAP/OIDC) for an identity that has no linked user auto-creates one and
-- seeds/reconciles its role_assignments from the IdP-asserted, mapped roles. Defaults
-- FALSE to preserve the existing provision-by-admin behaviour (403 when no user linked).
ALTER TABLE orgs ADD COLUMN IF NOT EXISTS jit_provisioning BOOLEAN NOT NULL DEFAULT FALSE;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE orgs DROP COLUMN IF EXISTS jit_provisioning;
-- +goose StatementEnd
