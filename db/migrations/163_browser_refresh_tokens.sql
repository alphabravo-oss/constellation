-- +goose Up
-- +goose StatementBegin
CREATE TABLE browser_refresh_tokens (
    token_hash TEXT PRIMARY KEY CHECK (length(token_hash) = 64),
    session_id UUID NOT NULL REFERENCES user_sessions(session_id) ON DELETE CASCADE,
    session_epoch BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX browser_refresh_tokens_session_idx ON browser_refresh_tokens(session_id);
CREATE INDEX browser_refresh_tokens_expiry_idx ON browser_refresh_tokens(expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE browser_refresh_tokens;
-- +goose StatementEnd
