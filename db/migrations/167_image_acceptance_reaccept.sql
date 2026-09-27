-- +goose Up
-- +goose StatementBegin
ALTER TABLE image_acceptances
    DROP CONSTRAINT image_acceptances_org_id_image_digest_accepted_until_key;

CREATE UNIQUE INDEX image_acceptances_active_expiry_key
    ON image_acceptances (org_id, image_digest, accepted_until)
    WHERE revoked_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX image_acceptances_active_expiry_key;

ALTER TABLE image_acceptances
    ADD CONSTRAINT image_acceptances_org_id_image_digest_accepted_until_key
    UNIQUE (org_id, image_digest, accepted_until);
-- +goose StatementEnd
