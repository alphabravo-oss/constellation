-- Operator-controlled evaluation order for enforcing response rules (NV parity). NeuVector
-- response rules are an ordered list (insert before/after/first/last) so operators control
-- precedence; response_rules_v2 had no priority and the runtime loaded them in indeterminate
-- DB order while the UI sorted alphabetically. Add a priority column that drives BOTH the
-- list and the runtime evaluation order.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE response_rules_v2 ADD COLUMN IF NOT EXISTS priority INTEGER NOT NULL DEFAULT 1000;

-- Seed a stable order from the current alphabetical listing so existing rules keep a
-- deterministic, non-colliding precedence operators can then reorder.
WITH ordered AS (
    SELECT id, (ROW_NUMBER() OVER (PARTITION BY org_id ORDER BY name)) * 10 AS p
      FROM response_rules_v2
)
UPDATE response_rules_v2 r SET priority = o.p FROM ordered o WHERE o.id = r.id;

CREATE INDEX IF NOT EXISTS idx_response_rules_v2_org_priority
    ON response_rules_v2(org_id, priority);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_response_rules_v2_org_priority;
ALTER TABLE response_rules_v2 DROP COLUMN IF EXISTS priority;
-- +goose StatementEnd
