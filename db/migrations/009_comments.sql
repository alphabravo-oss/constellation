-- +goose Up
-- +goose StatementBegin
-- Finding comments thread.
--
-- One row per comment. Soft-delete (deleted_at) instead of hard-delete so the audit log
-- stays consistent with retrievable bodies; the UI filters deleted_at IS NOT NULL.
CREATE TABLE finding_comments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id UUID NOT NULL,
    org_id     UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    author_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

CREATE INDEX idx_finding_comments_finding_created ON finding_comments(finding_id, created_at DESC) WHERE deleted_at IS NULL;
CREATE INDEX idx_finding_comments_org             ON finding_comments(org_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS finding_comments;
-- +goose StatementEnd
