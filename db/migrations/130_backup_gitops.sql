-- +goose Up
-- +goose StatementBegin
-- backup-gitops subsystem (roadmap A9 + B5).
--
-- A9 — scheduled-backup executor + retention. The backup_schedules table (migration 037)
-- already carries the cron + S3 destination, but had no retention knobs. Add them so the
-- leader-gated executor can prune old backups after a successful run. NULL/0 means "keep
-- everything" (a safe no-op default: retention only prunes when an operator opts in).
--
--   retention_keep_last     keep only the N most-recent succeeded org-backups for the org;
--                           older ones are pruned (row + local artifact removed). 0/NULL disables.
--   retention_max_age_days  additionally prune succeeded org-backups older than this many days.
--                           0/NULL disables.
ALTER TABLE backup_schedules
    ADD COLUMN IF NOT EXISTS retention_keep_last    INT,
    ADD COLUMN IF NOT EXISTS retention_max_age_days INT;

-- B5 — Git connector for config-as-code. Stores the per-org connector that config export
-- is pushed to (GitHub or Azure DevOps). The PAT is AES-GCM-sealed with the registry KEK
-- (pkg/registry/secrets), never stored in cleartext. Modeled on NeuVector's
-- controller/remote_repository/{github.go,azure_devops.go}.
--
-- provider            'github' | 'azure_devops'
-- github_owner        GitHub: repository owner/org username
-- github_repo         GitHub: repository name
-- azure_org           Azure DevOps: organization name
-- azure_project       Azure DevOps: project name
-- azure_repo          Azure DevOps: repository name
-- branch              target branch (e.g. "main")
-- default_file_path   path within the repo the exported config is committed to
-- committer_name      commit author name (GitHub API committer)
-- committer_email     commit author email
-- pat_sealed          AES-GCM-sealed personal access token (NULL until configured)
-- enabled             connector is eligible for push; defaults false (opt-in)
CREATE TABLE IF NOT EXISTS git_connectors (
    org_id            UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL DEFAULT 'github'
                      CHECK (provider IN ('github', 'azure_devops')),
    github_owner      TEXT,
    github_repo       TEXT,
    azure_org         TEXT,
    azure_project     TEXT,
    azure_repo        TEXT,
    branch            TEXT NOT NULL DEFAULT 'main',
    default_file_path TEXT NOT NULL DEFAULT 'constellation/config.yaml',
    committer_name    TEXT NOT NULL DEFAULT 'constellation-bot',
    committer_email   TEXT NOT NULL DEFAULT 'bot@constellation.local',
    pat_sealed        BYTEA,
    enabled           BOOLEAN NOT NULL DEFAULT false,
    last_push_at      TIMESTAMPTZ,
    last_status       TEXT,
    last_error        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS git_connectors;
ALTER TABLE backup_schedules
    DROP COLUMN IF EXISTS retention_max_age_days,
    DROP COLUMN IF EXISTS retention_keep_last;
-- +goose StatementEnd
