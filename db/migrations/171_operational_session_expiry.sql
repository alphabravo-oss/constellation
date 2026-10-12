-- +goose Up
-- +goose StatementBegin
-- Only newly issued tracked sessions receive an authoritative expiry. Do not
-- infer deadlines for legacy tokens from last_seen_at or invalidate their rows.
ALTER TABLE user_sessions ADD COLUMN expires_at TIMESTAMPTZ;
CREATE INDEX user_sessions_expiry_idx ON user_sessions(expires_at, session_id)
    WHERE expires_at IS NOT NULL;
CREATE INDEX network_sessions_stale_idx ON network_sessions(updated_at);
CREATE INDEX network_session_kills_expiry_idx ON network_session_kills(requested_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX network_session_kills_expiry_idx;
DROP INDEX network_sessions_stale_idx;
DROP INDEX user_sessions_expiry_idx;
ALTER TABLE user_sessions DROP COLUMN expires_at;
-- +goose StatementEnd
