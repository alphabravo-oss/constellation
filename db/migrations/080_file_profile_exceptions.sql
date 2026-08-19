-- Workload-scoped file profile exceptions. These are explicit, audited allow
-- entries that sit beside file monitor rules instead of being hidden inside a
-- block rule's application allowlist.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS file_profile_exceptions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    workload_id   TEXT NOT NULL,
    rule_id       UUID REFERENCES file_profile_rules(id) ON DELETE SET NULL,
    filter        TEXT NOT NULL,
    path          TEXT NOT NULL,
    regex         TEXT NOT NULL DEFAULT '',
    recursive     BOOLEAN NOT NULL DEFAULT FALSE,
    applications  TEXT[] NOT NULL DEFAULT '{}',
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    description   TEXT NOT NULL DEFAULT '',
    expires_at    TIMESTAMPTZ,
    created_by    UUID REFERENCES users(id),
    updated_by    UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_profile_exceptions_workload
    ON file_profile_exceptions(org_id, cluster_id, workload_id, enabled, updated_at DESC);

CREATE INDEX IF NOT EXISTS idx_file_profile_exceptions_rule
    ON file_profile_exceptions(org_id, cluster_id, rule_id)
    WHERE rule_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_file_profile_exceptions_expiry
    ON file_profile_exceptions(org_id, cluster_id, expires_at)
    WHERE expires_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_file_profile_exceptions_expiry;
DROP INDEX IF EXISTS idx_file_profile_exceptions_rule;
DROP INDEX IF EXISTS idx_file_profile_exceptions_workload;
DROP TABLE IF EXISTS file_profile_exceptions;
-- +goose StatementEnd
