-- +goose Up
-- +goose StatementBegin
-- Wave A6: bridge the impedance gap between runtime_policies.id (UUID, our
-- public identity) and network_flows.policy_id (BIGINT, what dp echoes
-- back on every DPMsgConnect).
--
-- The plan:
--   1. Allocate a process-wide unique BIGINT per policy from a sequence.
--   2. The agent stamps every rule pushed to dp with that BIGINT as its
--      wire PolicyRule.ID (dp's policy table accepts duplicate IDs across
--      rules — match criteria are 5-tuple + L7 + direction, ID is just a
--      tag for verdict attribution).
--   3. dp's DPMsgConnect emits the matched rule's ID. The agent stores
--      it in network_flows.policy_id.
--   4. The rollback watcher (Wave A5) and any future "which policy dropped
--      this?" query joins on dp_policy_id.
--
-- Why a sequence (not a UUID hash):
--   - 32-bit hash collisions kick in at ~65k policies; sequences never
--     collide.
--   - Sequences are cheap (Postgres reserves blocks per backend) and atomic.
--   - dp's wire field is uint32 — bigger than our realistic policy count
--     by orders of magnitude. The sequence cap is well-clear.
--
-- For existing rows (none in prod yet, but defensive): assign new sequence
-- values during the migration so we never have a NULL dp_policy_id.

CREATE SEQUENCE IF NOT EXISTS runtime_policies_dp_id_seq
    AS BIGINT
    INCREMENT BY 1
    MINVALUE 1
    NO CYCLE;

ALTER TABLE runtime_policies
    ADD COLUMN IF NOT EXISTS dp_policy_id BIGINT;

-- Backfill any pre-existing rows.
UPDATE runtime_policies
   SET dp_policy_id = nextval('runtime_policies_dp_id_seq')
 WHERE dp_policy_id IS NULL;

-- Now lock the column down: NOT NULL + DEFAULT for new inserts + UNIQUE
-- so collisions surface fast in tests.
ALTER TABLE runtime_policies
    ALTER COLUMN dp_policy_id SET NOT NULL,
    ALTER COLUMN dp_policy_id SET DEFAULT nextval('runtime_policies_dp_id_seq'),
    ADD CONSTRAINT runtime_policies_dp_policy_id_unique UNIQUE (dp_policy_id);

-- Index for the rollback watcher's hot query: "count denies per policy
-- in the last 60s". The composite ordering matches the WHERE → ORDER → LIMIT
-- shape we use; index-only would require a covering index on `at` which
-- we already have on network_flows, so this index just speeds up the
-- policy-side of the join.
CREATE INDEX IF NOT EXISTS idx_runtime_policies_dp_policy_id
  ON runtime_policies(dp_policy_id);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_runtime_policies_dp_policy_id;
ALTER TABLE runtime_policies
    DROP CONSTRAINT IF EXISTS runtime_policies_dp_policy_id_unique,
    DROP COLUMN IF EXISTS dp_policy_id;
DROP SEQUENCE IF EXISTS runtime_policies_dp_id_seq;
-- +goose StatementEnd
