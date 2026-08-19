-- +goose Up
-- +goose StatementBegin
-- Org-defined custom RBAC roles: a named, org-scoped bundle of user-grantable
-- verbs. A custom role is assigned to a user by putting its name in
-- role_assignments.role (same machinery as the built-in roles); resolution adds
-- the row's verbs via rbac.AuthorizeWithCustom. The CRUD handler rejects any
-- non-user-grantable (service-principal) verb at write time, and the authz layer
-- refuses to grant such verbs from a custom role even if a row is tampered.
CREATE TABLE IF NOT EXISTS custom_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    verbs       TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS custom_roles;
-- +goose StatementEnd
