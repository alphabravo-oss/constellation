-- +goose Up
-- +goose StatementBegin
ALTER TABLE group_dpi_sensor_bindings
    VALIDATE CONSTRAINT group_dpi_bindings_org_group_fk;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE group_dpi_sensor_bindings
    DROP CONSTRAINT group_dpi_bindings_org_group_fk;

ALTER TABLE group_dpi_sensor_bindings
    ADD CONSTRAINT group_dpi_bindings_org_group_fk
    FOREIGN KEY (org_id, group_id) REFERENCES groups(org_id, id)
    ON DELETE CASCADE NOT VALID;
-- +goose StatementEnd
