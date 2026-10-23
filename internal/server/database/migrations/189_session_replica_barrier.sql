-- +goose Up
-- +goose StatementBegin
CREATE TABLE identity_session_replicas (
 id uuid PRIMARY KEY,
 revision bigint NOT NULL,
 last_seen timestamptz NOT NULL DEFAULT now()
);
-- NOTIFY is delivered after commit. Polling remains the fail-closed fallback.
CREATE OR REPLACE FUNCTION bump_identity_session_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE identity_session_revision SET revision=revision+1 WHERE singleton;
 PERFORM pg_notify('constellation_identity_sessions','');
 RETURN NULL;
END $$;
-- +goose StatementEnd
