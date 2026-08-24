-- +goose Up
-- Add the config-checks artifact format emitted by scanner image config checks.
-- Migration 154 added the artifact type but missed the format CHECK entry, so
-- image scans with config checks failed during report completion.
-- +goose StatementBegin
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
      FROM pg_constraint
     WHERE conrelid = 'image_scan_artifacts'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%format%'
     LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE image_scan_artifacts DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_format_check
    CHECK (format IN (
        'constellation-package-inventory-v1',
        'spdx-2.3',
        'cyclonedx-1.6',
        'constellation-image-secrets-v1',
        'constellation-image-signature-v1',
        'constellation-image-layers-v1',
        'constellation-image-file-risk-v1',
        'constellation-image-config-checks-v1'
    ));

-- +goose Down
ALTER TABLE image_scan_artifacts DROP CONSTRAINT IF EXISTS image_scan_artifacts_format_check;
ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_format_check
    CHECK (format IN (
        'constellation-package-inventory-v1',
        'spdx-2.3',
        'cyclonedx-1.6',
        'constellation-image-secrets-v1',
        'constellation-image-signature-v1',
        'constellation-image-layers-v1',
        'constellation-image-file-risk-v1'
    ));
