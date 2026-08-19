-- Persist the full rendered alert event on each receiver_deliveries row so a retried
-- delivery can replay the EXACT original body.
--
-- Before this, persistPending stored only event_type/severity/idempotency_key, so the
-- retry sweeper could only rebuild an empty "(retry) <kind>" stub: retried Slack /
-- PagerDuty / webhook POSTs were content-free, and because the per-attempt HMAC is
-- computed over the request body, the signature on a retry covered the wrong (empty)
-- body. The dispatcher now marshals the whole notify.Event into this JSONB column and the
-- sweeper unmarshals it to reconstruct the identical event on every retry.
--
-- Nullable + no backfill: legacy rows written before this column keep a NULL payload and
-- the sweeper falls back to the minimal reconstruction for them.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE receiver_deliveries
    ADD COLUMN IF NOT EXISTS payload JSONB;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE receiver_deliveries
    DROP COLUMN IF EXISTS payload;
-- +goose StatementEnd
