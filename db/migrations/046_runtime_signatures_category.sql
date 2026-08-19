-- +goose Up
-- +goose StatementBegin
-- Wave D4: extend runtime_dlp_rules to also hold user-authored DPI
-- signatures (attack-pattern PCRE rules). Both feed dp's hyperscan engine
-- via the same ctrl_bld_dlp RPC (Wave A1) — the only thing that changes
-- is the semantic framing:
--
--   category='dlp'        — typically applies on egress, looks for
--                           sensitive payloads leaving the workload
--                           (credit cards, AWS keys, tokens)
--   category='signature'  — typically applies bidirectionally, looks
--                           for attack patterns (RCE strings, custom
--                           malware indicators, lateral-movement)
--
-- The wire RPC + threat row shape are identical; the column distinguishes
-- the UI surface. dp_rule_id keeps the same single sequence so a threat's
-- id maps unambiguously back to one row regardless of category.
ALTER TABLE runtime_dlp_rules
    ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'dlp'
        CHECK (category IN ('dlp', 'signature')),
    ADD COLUMN IF NOT EXISTS apply_dir SMALLINT NOT NULL DEFAULT 1
        CHECK (apply_dir IN (1, 2, 3));  -- 1=egress, 2=ingress, 3=both

-- Lookup the agent's sync poller uses: "rules for this cluster, by category".
-- Filtering by category in the API endpoint hits this index.
CREATE INDEX IF NOT EXISTS idx_runtime_dlp_rules_category
  ON runtime_dlp_rules(org_id, cluster_id, category, mode);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_runtime_dlp_rules_category;
ALTER TABLE runtime_dlp_rules
    DROP COLUMN IF EXISTS apply_dir,
    DROP COLUMN IF EXISTS category;
-- +goose StatementEnd
