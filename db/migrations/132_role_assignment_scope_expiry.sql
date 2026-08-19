-- +goose Up
-- +goose StatementBegin
-- P0-11 / P0-09: make role_assignments carry expiry and binding provenance so that
-- admin-created role bindings mirror their REQUESTED scope + expiry into the enforced
-- table instead of silently granting org-wide and permanent.
--
--   expires_at  — when set, loadRoleAssignments (the single per-request assignment loader)
--                 filters the row out once now() passes it, so an expiring binding stops
--                 authorizing at the next request without a background reaper.
--   binding_id  — the role_bindings row this assignment was mirrored from (NULL for JIT/SSO
--                 and admin-seeded rows). Lets DeleteRoleBinding remove exactly the rows a
--                 binding created (ON DELETE CASCADE is the belt-and-suspenders backstop) and
--                 lets create/delete stay symmetric for multi-scope bindings.
ALTER TABLE role_assignments
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS binding_id UUID REFERENCES role_bindings(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_role_assignments_binding ON role_assignments(binding_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_role_assignments_binding;
ALTER TABLE role_assignments
    DROP COLUMN IF EXISTS binding_id,
    DROP COLUMN IF EXISTS expires_at;
-- +goose StatementEnd
