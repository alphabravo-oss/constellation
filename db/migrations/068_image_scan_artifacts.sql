-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS image_scan_artifacts (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    image_scan_result_id  UUID NOT NULL REFERENCES image_scan_results(id) ON DELETE CASCADE,
    artifact_type         TEXT NOT NULL,
    format                TEXT NOT NULL,
    payload               JSONB NOT NULL,
    sha256                TEXT NOT NULL,
    package_count         INT NOT NULL DEFAULT 0,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (artifact_type IN ('package-inventory', 'sbom')),
    CHECK (format IN ('constellation-package-inventory-v1', 'spdx-2.3', 'cyclonedx-1.6'))
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_image_scan_artifacts_result_type_format
    ON image_scan_artifacts(org_id, image_scan_result_id, artifact_type, format);

CREATE INDEX IF NOT EXISTS idx_image_scan_artifacts_result
    ON image_scan_artifacts(org_id, image_scan_result_id, created_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_image_scan_artifacts_result;
DROP INDEX IF EXISTS uniq_image_scan_artifacts_result_type_format;
DROP TABLE IF EXISTS image_scan_artifacts;
-- +goose StatementEnd
