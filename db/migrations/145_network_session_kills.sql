-- Pending live-session kill requests (NV session-kill: DELETE /v1/session → dp ctrl_clear_session).
-- A kill targets a specific (cluster,node,session_id). The runtime-agent picks pending kills up
-- on its next session-snapshot upload and issues dp ctrl_clear_session; the row is consumed then.

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS network_session_kills (
    org_id       UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id   UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    node         TEXT NOT NULL DEFAULT '',
    session_id   BIGINT NOT NULL,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    requested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, node, session_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_session_kills;
-- +goose StatementEnd
