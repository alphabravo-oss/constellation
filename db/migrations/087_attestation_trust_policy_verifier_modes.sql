-- +goose Up
-- +goose StatementBegin
ALTER TABLE scan_attestation_trust_policies
    ADD COLUMN IF NOT EXISTS verifier_mode TEXT NOT NULL DEFAULT 'keyless',
    ADD COLUMN IF NOT EXISTS public_key_pem TEXT NOT NULL DEFAULT '';

ALTER TABLE scan_attestation_trust_policies
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_allowed_identities_check,
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_allowed_issuers_check,
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_verifier_mode_check,
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_trust_material_check;

ALTER TABLE scan_attestation_trust_policies
    ADD CONSTRAINT scan_attestation_trust_policies_verifier_mode_check
        CHECK (verifier_mode IN ('keyless', 'public-key')),
    ADD CONSTRAINT scan_attestation_trust_policies_trust_material_check
        CHECK (
            (verifier_mode = 'keyless'
                AND cardinality(allowed_identities) > 0
                AND cardinality(allowed_issuers) > 0
                AND public_key_pem = '')
            OR
            (verifier_mode = 'public-key'
                AND public_key_pem <> '')
        );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_attestation_trust_policies
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_trust_material_check,
    DROP CONSTRAINT IF EXISTS scan_attestation_trust_policies_verifier_mode_check;

UPDATE scan_attestation_trust_policies
   SET allowed_identities = ARRAY['.*']::text[]
 WHERE cardinality(allowed_identities) = 0;

UPDATE scan_attestation_trust_policies
   SET allowed_issuers = ARRAY['.*']::text[]
 WHERE cardinality(allowed_issuers) = 0;

ALTER TABLE scan_attestation_trust_policies
    ADD CONSTRAINT scan_attestation_trust_policies_allowed_identities_check
        CHECK (cardinality(allowed_identities) > 0),
    ADD CONSTRAINT scan_attestation_trust_policies_allowed_issuers_check
        CHECK (cardinality(allowed_issuers) > 0);

ALTER TABLE scan_attestation_trust_policies
    DROP COLUMN IF EXISTS public_key_pem,
    DROP COLUMN IF EXISTS verifier_mode;
-- +goose StatementEnd
