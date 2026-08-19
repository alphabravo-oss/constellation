-- +goose Up
-- +goose StatementBegin
-- Wave N2: container registries — production CRUD + auto-discover.
--
-- Each row is a configured container registry the Constellation control plane
-- can reach. The walker daemon (cmd/constellation-registry-walker) reads this
-- table on an interval, decrypts auth_secret per row, calls the matching
-- internal/registry adapter's ListImages, diffs against last-seen images, and
-- enqueues scan_jobs for any newly-discovered tags.
--
-- auth_secret is opaque AES-256-GCM ciphertext (KEK from $CONSTELLATION_KEK or
-- bootstrapped to org_settings on first use). Never queried by the DB.
CREATE TABLE IF NOT EXISTS registries (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    kind             TEXT NOT NULL,        -- docker-hub | ghcr | ecr | gcr | acr | quay | harbor | gitlab | jfrog
    endpoint         TEXT NOT NULL,
    auth_kind        TEXT NOT NULL,        -- static | aws-iam-role | gcp-service-account | azure-managed-id | none
    auth_secret      BYTEA,                -- AES-256-GCM ciphertext (nonce || ct || tag); NULL when auth_kind='none'
    scan_cadence     TEXT NOT NULL DEFAULT 'manual',  -- manual | hourly | 6h | daily | weekly
    image_globs      TEXT[] NOT NULL DEFAULT '{}',
    last_sync_at     TIMESTAMPTZ,
    last_sync_status TEXT,                 -- ok | failed | partial
    last_sync_error  TEXT,
    images_seen      INT NOT NULL DEFAULT 0,
    created_by       UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, name)
);

CREATE INDEX IF NOT EXISTS idx_registries_next_sync
    ON registries(scan_cadence, last_sync_at)
    WHERE scan_cadence <> 'manual';

-- Discovered images per registry (one row per repository).
-- Used by GET /api/v1/registries/{id}/images and the walker's diff.
CREATE TABLE IF NOT EXISTS registry_images (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    registry_id     UUID NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    repository      TEXT NOT NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',
    last_pushed_at  TEXT,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (registry_id, repository)
);

CREATE INDEX IF NOT EXISTS idx_registry_images_org ON registry_images(org_id, last_seen_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_registry_images_org;
DROP TABLE IF EXISTS registry_images;
DROP INDEX IF EXISTS idx_registries_next_sync;
DROP TABLE IF EXISTS registries;
-- +goose StatementEnd
