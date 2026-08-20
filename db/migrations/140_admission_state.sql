-- Global admission-control state per cluster (NeuVector parity). NV exposes an
-- Admission Control page with a global enable flag, monitor/protect mode, default action,
-- and webhook failure policy. Constellation had only declarative admission policies with
-- no global enable or monitor/protect toggle. This table holds that state so the console
-- can surface (and an operator can flip) the mode, mirroring RESTAdmissionState.
--
-- ponytail: the row is the source of truth the console reads/writes now; gating the live
-- admission webhook on protect vs monitor is a follow-up — mode defaults to 'monitor' so
-- nothing starts blocking on upgrade (protect has crash-looped the single-node box before).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS admission_state (
    org_id         UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id     UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    enabled        BOOLEAN NOT NULL DEFAULT FALSE,
    mode           TEXT NOT NULL DEFAULT 'monitor' CHECK (mode IN ('monitor', 'protect')),
    default_action TEXT NOT NULL DEFAULT 'allow' CHECK (default_action IN ('allow', 'deny')),
    failure_policy TEXT NOT NULL DEFAULT 'ignore' CHECK (failure_policy IN ('ignore', 'fail')),
    updated_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admission_state;
-- +goose StatementEnd
