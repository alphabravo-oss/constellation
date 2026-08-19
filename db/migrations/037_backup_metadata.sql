-- +goose Up
-- +goose StatementBegin
-- Wave N5 — Backup / Restore. Extend the catalog from migration 010 so the operator UI
-- can show what was captured, whether it was signed, and where to retrieve it.
--
-- mode               'org-backup' (signed JSON tarball) or 'pg-dump' (legacy logical dump).
-- format_version     semver of the tarball schema (e.g. "constellation-orgbackup/v1").
-- signed             true if a cosign signature is present alongside the artifact.
-- signer_identity    Fulcio cert subject (keyless) OR sha256:<hex> of public key (static-key).
-- tables_included    sorted list of table names exported into the tarball (org-backup mode).
-- size_bytes         duplicated here as well as in the existing column for "list" convenience;
--                    we keep both because pg-dump rows already populated the original.
-- s3_uri             s3://bucket/key when archived to object store.
-- org_id             the org whose contents are in this backup (NULL for legacy pg-dump rows).
ALTER TABLE backups
    ADD COLUMN IF NOT EXISTS mode             TEXT        NOT NULL DEFAULT 'org-backup'
        CHECK (mode IN ('org-backup', 'pg-dump')),
    ADD COLUMN IF NOT EXISTS format_version   TEXT,
    ADD COLUMN IF NOT EXISTS signed           BOOLEAN     NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS signer_identity  TEXT,
    ADD COLUMN IF NOT EXISTS tables_included  TEXT[],
    ADD COLUMN IF NOT EXISTS s3_uri           TEXT,
    ADD COLUMN IF NOT EXISTS org_id           UUID
        REFERENCES orgs(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS local_path       TEXT;

CREATE INDEX IF NOT EXISTS idx_backups_org_started ON backups(org_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_backups_mode_started ON backups(mode, started_at DESC);

-- Schedule table — one row per org. Cron string + S3 destination + last-run snapshot.
CREATE TABLE IF NOT EXISTS backup_schedules (
    org_id        UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE CASCADE,
    cron_expr     TEXT NOT NULL DEFAULT '0 3 * * *',  -- nightly @ 03:00 UTC by default
    enabled       BOOLEAN NOT NULL DEFAULT true,
    s3_bucket     TEXT,
    s3_prefix     TEXT,
    s3_endpoint   TEXT,                                -- empty -> AWS regional default
    sign_mode     TEXT NOT NULL DEFAULT 'static-key'
                  CHECK (sign_mode IN ('static-key', 'keyless', 'none')),
    last_run_at   TIMESTAMPTZ,
    last_status   TEXT,
    last_error    TEXT,
    next_run_at   TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS backup_schedules;
ALTER TABLE backups
    DROP COLUMN IF EXISTS local_path,
    DROP COLUMN IF EXISTS org_id,
    DROP COLUMN IF EXISTS s3_uri,
    DROP COLUMN IF EXISTS tables_included,
    DROP COLUMN IF EXISTS signer_identity,
    DROP COLUMN IF EXISTS signed,
    DROP COLUMN IF EXISTS format_version,
    DROP COLUMN IF EXISTS mode;
-- +goose StatementEnd
