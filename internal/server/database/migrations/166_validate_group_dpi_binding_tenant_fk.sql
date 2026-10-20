-- +goose Up
-- +goose StatementBegin
ALTER TABLE group_dpi_sensor_bindings
    VALIDATE CONSTRAINT group_dpi_bindings_org_group_fk;
-- +goose StatementEnd
