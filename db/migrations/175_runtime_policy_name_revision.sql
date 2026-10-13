-- +goose Up
-- +goose StatementBegin
-- Include name-only legacy writes in the same reviewed version contract.
-- Existing rules/mode/default-action/direction behavior is unchanged.
CREATE OR REPLACE FUNCTION runtime_policies_bump_version() RETURNS trigger AS $$
BEGIN
    IF NEW.rules IS DISTINCT FROM OLD.rules
       OR NEW.mode IS DISTINCT FROM OLD.mode
       OR NEW.def_action IS DISTINCT FROM OLD.def_action
       OR NEW.apply_dir IS DISTINCT FROM OLD.apply_dir
       OR NEW.name IS DISTINCT FROM OLD.name THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION runtime_policies_bump_version() RETURNS trigger AS $$
BEGIN
    IF NEW.rules IS DISTINCT FROM OLD.rules
       OR NEW.mode IS DISTINCT FROM OLD.mode
       OR NEW.def_action IS DISTINCT FROM OLD.def_action
       OR NEW.apply_dir IS DISTINCT FROM OLD.apply_dir THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
