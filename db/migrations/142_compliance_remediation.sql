-- Persist per-control remediation guidance on compliance checks (NV parity). kube-bench /
-- docker-bench parse a Remediation string per control, but the ingest dropped it because
-- compliance_checks had no column for it. NeuVector shows remediation inline on every
-- failing control; surface it here.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE compliance_checks ADD COLUMN IF NOT EXISTS remediation TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE compliance_checks DROP COLUMN IF EXISTS remediation;
-- +goose StatementEnd
