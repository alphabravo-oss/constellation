-- +goose Up
-- +goose StatementBegin
-- Exact UTF-8 FNV-1a equivalent of network.ruleID; the pair remains the true
-- rule identity. This permits bounded SQL sorting in legacy evaluation order.
CREATE FUNCTION network_rule_display_id(from_ep text, to_ep text) RETURNS bigint
LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE AS $$
DECLARE
    input_bytes bytea := convert_to(from_ep, 'UTF8') || decode('00','hex') || convert_to(to_ep, 'UTF8');
    hash_value bigint := 2166136261;
    position integer;
BEGIN
    FOR position IN 0..length(input_bytes)-1 LOOP
        hash_value := ((hash_value # get_byte(input_bytes,position)::bigint) * 16777619) % 4294967296;
    END LOOP;
    RETURN 1000 + hash_value % 1000000;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION network_rule_display_id(text,text);
