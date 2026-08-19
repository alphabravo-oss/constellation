-- +goose Up
-- +goose StatementBegin
-- P1-2: cluster-wide network-policy master switch + default action.
--
-- Until now the only enforcement knob was per-policy `mode` (monitor|enforce)
-- on runtime_policies. Staged rollout ("put the WHOLE cluster in observe-only
-- while we watch") and the emergency "stop blocking everything NOW" both
-- required touching every row. This table adds one cluster-scoped override that
-- the policy bundle path honours, and it WINS over per-rule mode:
--
--   enforcement_override = 'none'    -> passthrough; each policy keeps its mode
--                        = 'observe' -> force every policy to monitor (never block)
--                        = 'enforce' -> force every policy to enforce
--
--   default_action       = 'unset'  -> passthrough; each policy keeps def_action
--                        = 'allow'   -> matched-no-rule allows, cluster-wide
--                        = 'deny'    -> matched-no-rule denies, cluster-wide
--
-- SAFETY: both columns default to the passthrough value, so an org that never
-- touches this table sees byte-for-byte unchanged behaviour and nothing is
-- forced into enforce. Mirrors NeuVector's setAdmCtrlStateInCluster
-- (Enable + DefaultAction as a single cluster-level state).
CREATE TABLE IF NOT EXISTS netpolicy_settings (
    org_id               UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id           UUID NOT NULL,
    enforcement_override TEXT NOT NULL DEFAULT 'none'
        CHECK (enforcement_override IN ('none','observe','enforce')),
    default_action       TEXT NOT NULL DEFAULT 'unset'
        CHECK (default_action IN ('unset','allow','deny')),
    updated_by           UUID,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS netpolicy_settings;
-- +goose StatementEnd
