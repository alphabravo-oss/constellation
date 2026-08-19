-- +goose Up
-- +goose StatementBegin
CREATE TABLE assets (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id    UUID REFERENCES clusters(id) ON DELETE SET NULL,
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    kind          TEXT NOT NULL,            -- "image" | "workload" | "iac-resource" | "ml-model" | "cloud-resource"
    name          TEXT NOT NULL,
    digest        TEXT,
    labels        JSONB NOT NULL DEFAULT '{}'::jsonb,
    ai_workload   BOOLEAN NOT NULL DEFAULT FALSE,
    criticality   TEXT NOT NULL DEFAULT 'medium',
    embedding     vector(1536),             -- nullable; populated by Abbot embedding worker when AI is enabled
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, kind, name, digest)
);

CREATE INDEX idx_assets_org_kind ON assets(org_id, kind);
CREATE INDEX idx_assets_cluster ON assets(cluster_id) WHERE cluster_id IS NOT NULL;
CREATE INDEX idx_assets_labels ON assets USING GIN (labels);
CREATE INDEX idx_assets_ai_workload ON assets(org_id) WHERE ai_workload = TRUE;

CREATE TABLE images (
    asset_id      UUID PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    registry      TEXT NOT NULL,            -- "docker.io" | "ghcr.io" | ...
    repository    TEXT NOT NULL,
    tag           TEXT,
    digest        TEXT NOT NULL,            -- sha256:...
    layers        JSONB NOT NULL DEFAULT '[]'::jsonb,
    architectures JSONB NOT NULL DEFAULT '[]'::jsonb,
    size_bytes    BIGINT,
    signed        BOOLEAN NOT NULL DEFAULT FALSE,
    signature_info JSONB NOT NULL DEFAULT '{}'::jsonb,
    sbom_id       UUID,                     -- populated when SBOM is generated
    pulled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_images_digest ON images(digest);
CREATE INDEX idx_images_registry_repo ON images(registry, repository);

CREATE TABLE sbom_documents (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id     UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    format       TEXT NOT NULL,             -- "spdx-2.3" | "cyclonedx-1.6" | "cyclonedx-ml-bom"
    document     JSONB NOT NULL,
    sha256       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_asset ON sbom_documents(asset_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS sbom_documents;
DROP TABLE IF EXISTS images;
DROP TABLE IF EXISTS assets;
-- +goose StatementEnd
