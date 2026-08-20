-- Live per-connection session table (NeuVector RESTSession parity). The runtime-agent's
-- data-plane (dp) maintains a ctrl_list_session snapshot; the agent uploads it periodically
-- and the ingest REPLACES the rows for that (cluster,node) — this table always reflects the
-- CURRENT live connections, not history. Rows for a node vanish when its snapshot no longer
-- lists them or the node stops reporting (GC'd by updated_at staleness).

-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS network_sessions (
    org_id      UUID NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    cluster_id  UUID NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
    node        TEXT NOT NULL DEFAULT '',
    id          BIGINT NOT NULL,              -- dp session id (unique within a node snapshot)
    ep_mac      TEXT NOT NULL DEFAULT '',
    workload_id TEXT NOT NULL DEFAULT '',     -- resolved "ns/name" when known
    ether_type  INTEGER NOT NULL DEFAULT 0,
    ip_proto    SMALLINT NOT NULL DEFAULT 0,
    application INTEGER NOT NULL DEFAULT 0,    -- dp L7 application id
    client_mac  TEXT NOT NULL DEFAULT '',
    server_mac  TEXT NOT NULL DEFAULT '',
    client_ip   TEXT NOT NULL DEFAULT '',
    server_ip   TEXT NOT NULL DEFAULT '',
    client_port INTEGER NOT NULL DEFAULT 0,
    server_port INTEGER NOT NULL DEFAULT 0,
    icmp_code   SMALLINT NOT NULL DEFAULT 0,
    icmp_type   SMALLINT NOT NULL DEFAULT 0,
    client_pkts  BIGINT NOT NULL DEFAULT 0,
    server_pkts  BIGINT NOT NULL DEFAULT 0,
    client_bytes BIGINT NOT NULL DEFAULT 0,
    server_bytes BIGINT NOT NULL DEFAULT 0,
    client_asm_pkts  BIGINT NOT NULL DEFAULT 0,
    server_asm_pkts  BIGINT NOT NULL DEFAULT 0,
    client_asm_bytes BIGINT NOT NULL DEFAULT 0,
    server_asm_bytes BIGINT NOT NULL DEFAULT 0,
    client_state SMALLINT NOT NULL DEFAULT 0,  -- dp TCP state enum
    server_state SMALLINT NOT NULL DEFAULT 0,
    idle        INTEGER NOT NULL DEFAULT 0,     -- seconds
    age         INTEGER NOT NULL DEFAULT 0,     -- seconds
    life        INTEGER NOT NULL DEFAULT 0,
    threat_id   BIGINT NOT NULL DEFAULT 0,
    policy_id   BIGINT NOT NULL DEFAULT 0,
    policy_action SMALLINT NOT NULL DEFAULT 0,
    severity    SMALLINT NOT NULL DEFAULT 0,
    ingress     BOOLEAN NOT NULL DEFAULT FALSE,
    tap         BOOLEAN NOT NULL DEFAULT FALSE,
    mid_stream  BOOLEAN NOT NULL DEFAULT FALSE,
    xff_ip      TEXT NOT NULL DEFAULT '',
    xff_app     INTEGER NOT NULL DEFAULT 0,
    xff_port    INTEGER NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, cluster_id, node, id)
);
CREATE INDEX IF NOT EXISTS idx_network_sessions_updated
    ON network_sessions(org_id, cluster_id, updated_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS network_sessions;
-- +goose StatementEnd
