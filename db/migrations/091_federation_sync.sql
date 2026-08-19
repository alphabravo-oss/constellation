-- +goose Up
-- +goose StatementBegin
-- G3a/G3b federation sync support.
--
-- cfg_type on policies mirrors groups.cfg_type so a joint can mark rules pulled
-- from its master as 'fed' (read-only, master-authored). 'user' is the local
-- default; 'fed' rows are owned by the poller and replaced on each sync.
ALTER TABLE policies ADD COLUMN IF NOT EXISTS cfg_type TEXT NOT NULL DEFAULT 'user';

-- A joint tracks how far it has consumed its master's fed_rule_revisions log so
-- the next GET /sync?since= only fetches new revisions. One row per org.
CREATE TABLE IF NOT EXISTS fed_sync_state (
    org_id               UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    last_synced_revision BIGINT NOT NULL DEFAULT 0,
    last_synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- A joint may receive a master-authored rule whose id collides with nothing
-- locally; the poller upserts fed policies/groups by (org_id, name) so re-pulling
-- a revision is idempotent. Existing UNIQUE(org_id,name,version) on policies and
-- the groups UNIQUE already cover the conflict targets used by the poller.
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS fed_sync_state;
ALTER TABLE policies DROP COLUMN IF EXISTS cfg_type;
-- +goose StatementEnd
