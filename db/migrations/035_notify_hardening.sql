-- +goose Up
-- +goose StatementBegin
-- Wave N3: harden notifier delivery. New columns on `receivers` carry the per-receiver
-- HMAC key (rotated by operators), a token-bucket rate limit, a Go-template selector for
-- message bodies, and a paused flag the operator can flip from the UI. `receiver_deliveries`
-- gains the idempotency key (so retries reuse it), attempt counter + next_retry_at for the
-- backoff scheduler, signed_at for forensics, and final_state for the terminal verdict.
ALTER TABLE receivers
    ADD COLUMN IF NOT EXISTS secret_key      TEXT,
    ADD COLUMN IF NOT EXISTS rate_per_min    INT  NOT NULL DEFAULT 60,
    ADD COLUMN IF NOT EXISTS template_id     TEXT NOT NULL DEFAULT 'default',
    ADD COLUMN IF NOT EXISTS status_message  TEXT,
    ADD COLUMN IF NOT EXISTS paused          BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE receiver_deliveries
    ADD COLUMN IF NOT EXISTS idempotency_key UUID,
    ADD COLUMN IF NOT EXISTS next_retry_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS signed_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS final_state     TEXT;

-- Partial index on the retry queue: only rows that haven't reached a terminal state.
CREATE INDEX IF NOT EXISTS idx_receiver_deliveries_pending
    ON receiver_deliveries(next_retry_at)
    WHERE final_state IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_receiver_deliveries_pending;
ALTER TABLE receiver_deliveries
    DROP COLUMN IF EXISTS final_state,
    DROP COLUMN IF EXISTS signed_at,
    DROP COLUMN IF EXISTS next_retry_at,
    DROP COLUMN IF EXISTS idempotency_key;
ALTER TABLE receivers
    DROP COLUMN IF EXISTS paused,
    DROP COLUMN IF EXISTS status_message,
    DROP COLUMN IF EXISTS template_id,
    DROP COLUMN IF EXISTS rate_per_min,
    DROP COLUMN IF EXISTS secret_key;
-- +goose StatementEnd
