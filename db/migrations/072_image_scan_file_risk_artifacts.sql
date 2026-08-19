-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
      FROM pg_constraint
     WHERE conrelid = 'image_scan_artifacts'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%artifact_type%'
     LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE image_scan_artifacts DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

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

ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_artifact_type_check
    CHECK (artifact_type IN ('package-inventory', 'sbom', 'secret-scan', 'signature-scan', 'layer-metadata', 'file-risk'));

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
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DO $$
DECLARE
    constraint_name text;
BEGIN
    SELECT conname INTO constraint_name
      FROM pg_constraint
     WHERE conrelid = 'image_scan_artifacts'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%artifact_type%'
     LIMIT 1;

    IF constraint_name IS NOT NULL THEN
        EXECUTE format('ALTER TABLE image_scan_artifacts DROP CONSTRAINT %I', constraint_name);
    END IF;
END $$;

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

ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_artifact_type_check
    CHECK (artifact_type IN ('package-inventory', 'sbom', 'secret-scan', 'signature-scan', 'layer-metadata'));

ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_format_check
    CHECK (format IN (
        'constellation-package-inventory-v1',
        'spdx-2.3',
        'cyclonedx-1.6',
        'constellation-image-secrets-v1',
        'constellation-image-signature-v1',
        'constellation-image-layers-v1'
    ));
-- +goose StatementEnd
