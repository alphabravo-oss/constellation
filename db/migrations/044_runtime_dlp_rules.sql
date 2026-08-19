-- +goose Up
-- +goose StatementBegin
-- Wave C4: user-authored DLP regex rules.
--
-- dp's DLP engine (third_party/neuvector/dp/dpi/sig/dpi_sigopt_pcre.c) is
-- already wired up by the C source — it accepts PCRE patterns compiled
-- into hyperscan and fires on payload matches the same way the built-in
-- signature engine does. Wave A1 added the wire RPC (BuildDLPRules); this
-- migration adds the persistence surface so operators can author rules
-- in the UI.
--
-- Each row is one named ruleset. Patterns are JSONB so the editor can
-- evolve the rule shape without a migration each time. Severity drives
-- the matching THRT_ID range in the threat row dp emits.
--
-- dp_rule_id is the uint32 dp sees on the wire (mirrors A6's
-- dp_policy_id pattern): a per-org sequence guarantees no collisions
-- in dp's hash table.
CREATE SEQUENCE IF NOT EXISTS runtime_dlp_rules_dp_id_seq
    AS BIGINT
    INCREMENT BY 1
    MINVALUE 9000  -- start above NeuVector's reserved range (THRT_ID_* tops out at 2028)
    NO CYCLE;

CREATE TABLE IF NOT EXISTS runtime_dlp_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    cluster_id      UUID NOT NULL,
    name            TEXT NOT NULL,
    dp_rule_id      BIGINT NOT NULL DEFAULT nextval('runtime_dlp_rules_dp_id_seq'),
    severity        SMALLINT NOT NULL DEFAULT 5
                    CHECK (severity BETWEEN 1 AND 9),
    mode            TEXT NOT NULL DEFAULT 'monitor'
                    CHECK (mode IN ('monitor', 'enforce', 'disabled')),
    patterns        JSONB NOT NULL DEFAULT '[]'::jsonb,  -- []string of PCRE
    description     TEXT,
    version         BIGINT NOT NULL DEFAULT 1,
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by      UUID,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, name),
    UNIQUE (dp_rule_id)
);

CREATE INDEX IF NOT EXISTS idx_runtime_dlp_rules_cluster_mode
  ON runtime_dlp_rules(org_id, cluster_id, mode);

-- Same bump-version trigger pattern as runtime_policies.
CREATE OR REPLACE FUNCTION runtime_dlp_rules_bump_version() RETURNS trigger AS $$
BEGIN
    IF NEW.patterns IS DISTINCT FROM OLD.patterns
       OR NEW.mode IS DISTINCT FROM OLD.mode
       OR NEW.severity IS DISTINCT FROM OLD.severity THEN
        NEW.version := OLD.version + 1;
        NEW.updated_at := NOW();
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_runtime_dlp_rules_bump_version
    BEFORE UPDATE ON runtime_dlp_rules
    FOR EACH ROW EXECUTE FUNCTION runtime_dlp_rules_bump_version();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_runtime_dlp_rules_bump_version ON runtime_dlp_rules;
DROP FUNCTION IF EXISTS runtime_dlp_rules_bump_version();
DROP TABLE IF EXISTS runtime_dlp_rules;
DROP SEQUENCE IF EXISTS runtime_dlp_rules_dp_id_seq;
-- +goose StatementEnd
