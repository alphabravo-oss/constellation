-- +goose Up
-- Add 'config-checks' to the image_scan_artifacts.artifact_type CHECK constraint.
-- The scanner has emitted a 'config-checks' artifact since commit 6965f0a (CIS-Docker
-- image config checks) but no migration ever widened the constraint, so every scan
-- producing that artifact failed its ENTIRE report insert on the check constraint
-- (SQLSTATE 23514). This aligns the DB with the six-plus-one types the code writes.
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
-- +goose StatementEnd

ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_artifact_type_check
    CHECK (artifact_type IN (
        'package-inventory', 'sbom', 'secret-scan', 'signature-scan',
        'layer-metadata', 'file-risk', 'config-checks'
    ));

-- +goose Down
ALTER TABLE image_scan_artifacts DROP CONSTRAINT IF EXISTS image_scan_artifacts_artifact_type_check;
ALTER TABLE image_scan_artifacts
    ADD CONSTRAINT image_scan_artifacts_artifact_type_check
    CHECK (artifact_type IN (
        'package-inventory', 'sbom', 'secret-scan', 'signature-scan',
        'layer-metadata', 'file-risk'
    ));
