-- +goose Up
-- +goose StatementBegin
-- Wave A2: runtime_policies stores per-workload dp policy bundles.
--
-- One row = one named policy attached to one workload. Mode controls how
-- dp interprets the rules; the agent's state machine (Wave A5) decides
-- which mode each rule's Action is stamped with before pushing to dp:
--
--   monitor  → dp computes the verdict, logs it on the flow row, ALLOWS
--              the packet anyway. Safe default.
--   enforce  → dp drops packets whose verdict is `deny`. The marquee
--              IPS behavior.
--   disabled → rules not pushed; workload has no dp-side policy.
--
-- Rules are stored as JSONB so the editor can evolve the rule shape
-- without a schema migration each time. The wire format pushed to dp is
-- internal/runtime/dp.WorkloadPolicy — see that struct for fields.
--
-- Versioning is monotonic per (workload, name): every update bumps version
-- by 1. The agent uses version to skip pushes when nothing changed
-- (it caches "last pushed version per workload" in memory).
CREATE TABLE IF NOT EXISTS runtime_policies (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL,
    cluster_id   UUID NOT NULL,
    workload     TEXT NOT NULL,          -- "<ns>/<deployment>" or "<ns>/*"
    namespace    TEXT NOT NULL,
    name         TEXT NOT NULL,          -- operator-friendly label
    mode         TEXT NOT NULL DEFAULT 'monitor'
                 CHECK (mode IN ('monitor', 'enforce', 'disabled')),
    def_action   SMALLINT NOT NULL DEFAULT 2,  -- 2 = PolicyActionAllow
    apply_dir    SMALLINT NOT NULL DEFAULT 3,  -- 3 = ApplyDirBoth
    rules        JSONB    NOT NULL DEFAULT '[]'::jsonb,
    version      BIGINT   NOT NULL DEFAULT 1,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by   UUID,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, cluster_id, workload, name)
);

-- Lookup: "list all policies for this cluster/namespace, by mode".
CREATE INDEX IF NOT EXISTS idx_runtime_policies_cluster_ns_mode
  ON runtime_policies(org_id, cluster_id, namespace, mode);

-- Lookup: "which workloads have at least one enforce-mode policy?"
-- (Used by the runtime-agent to decide which veths need iptables rules.)
CREATE INDEX IF NOT EXISTS idx_runtime_policies_workload_enforce
  ON runtime_policies(org_id, cluster_id, workload)
  WHERE mode = 'enforce';

-- bump-version trigger: every UPDATE that changes rules or mode increments
-- version + sets updated_at. This is a defensive belt; the handler should
-- also bump version explicitly, but a misbehaving caller can't bypass it.
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

CREATE TRIGGER trg_runtime_policies_bump_version
    BEFORE UPDATE ON runtime_policies
    FOR EACH ROW EXECUTE FUNCTION runtime_policies_bump_version();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_runtime_policies_bump_version ON runtime_policies;
DROP FUNCTION IF EXISTS runtime_policies_bump_version();
DROP TABLE IF EXISTS runtime_policies;
-- +goose StatementEnd
