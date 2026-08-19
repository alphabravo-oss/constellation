-- +goose Up
-- +goose StatementBegin
-- P1-18: deliver admission-deny notifications (NeuVector EventAdmCtrl -> webhookAudit
-- + logAudit parity). The constellation-admission webhook pod writes 'admission.deny'
-- audit rows directly to the DB but has no notify dispatcher, so org webhook receivers
-- and the syslog/SIEM mirror never saw Constellation's own admission denies. The API
-- runs a leader-gated poller (RunAdmissionNotifyDispatcher) that fans each new
-- admission.deny audit row out through notify.Dispatcher. This single-row table holds
-- the poller's cursor (the highest audit_events.id already dispatched) so denies are
-- delivered exactly once and never replayed on restart. Mirrors the single-row
-- watermark pattern used by network_flow_rollup_state.
CREATE TABLE IF NOT EXISTS admission_notify_state (
    id                 boolean     PRIMARY KEY DEFAULT true,  -- single-row guard
    last_dispatched_id bigint      NOT NULL DEFAULT 0,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT admission_notify_state_singleton CHECK (id)
);

-- Seed the cursor at the current audit head so pre-existing denies are NOT replayed as
-- fresh notifications the first time the poller runs.
INSERT INTO admission_notify_state (id, last_dispatched_id)
VALUES (true, COALESCE((SELECT max(id) FROM audit_events), 0))
ON CONFLICT (id) DO NOTHING;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS admission_notify_state;
-- +goose StatementEnd
