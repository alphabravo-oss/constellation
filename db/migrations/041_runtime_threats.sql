-- +goose Up
-- +goose StatementBegin
-- Wave 5: runtime_threats stores DPI signature hits emitted by the NeuVector
-- dp data-plane.
--
-- One row per DPMsgThreatLog the agent uploads. dp emits a threat when one
-- of its signature engines (Hyperscan-based pattern matcher in
-- third_party/neuvector/dp/dpi/sig/) trips on payload bytes, or when one of
-- the protocol parsers detects a protocol-level violation (HTTP smuggling,
-- DNS tunnelling, SQL injection, SSL Heartbleed, etc — full list in
-- third_party/neuvector/defs.h THRT_ID_*).
--
-- Notably the row carries the captured packet bytes (up to ~2 KB on the wire
-- — see DPLOG_MAX_PKT_LEN). We store that as bytea for forensics; the UI can
-- pretty-print it via tcpdump-style formatting downstream.
--
-- This table is NOT partitioned. Threat volume is typically orders of
-- magnitude lower than flow volume (a flow is per connection bucket; a
-- threat is per signature hit). A future migration can partition by `at`
-- if any one cluster crosses ~1M rows.
CREATE TABLE IF NOT EXISTS runtime_threats (
    id              UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    org_id          UUID NOT NULL,
    cluster_id      UUID NOT NULL,
    node            TEXT,
    ep_mac          TEXT,

    -- Identity of the threat itself.
    threat_id       INTEGER NOT NULL,                    -- THRT_ID_* (defs.h:2000+)
    severity        SMALLINT NOT NULL,                   -- 1..9 scale
    action          SMALLINT NOT NULL DEFAULT 0,         -- DP_THREAT_ACTION_*
    application     INTEGER,                             -- L7 app id (0 = unknown)
    msg             TEXT,                                -- human-readable description
    dlp_name_hash   BIGINT,                              -- DLP rule hash, if from DLP engine

    -- Where it was seen. ep_mac is the workload identity dp tagged the
    -- session with; src_/dst_ describe the offending packet's 5-tuple.
    ip_proto        SMALLINT,
    ether_type      INTEGER,
    src_ip          TEXT,
    src_port        INTEGER,
    dst_ip          TEXT,
    dst_port        INTEGER,
    icmp_code       SMALLINT,
    icmp_type       SMALLINT,

    -- Captured packet — up to ~2 KB. dp's DPLOG_MAX_PKT_LEN = 2048.
    -- pkt_len is bytes copied into `packet`; cap_len is bytes seen on wire
    -- (may be larger if dp truncated). Both null for non-packet threats.
    packet          BYTEA,
    pkt_len         INTEGER,
    cap_len         INTEGER,

    pkt_ingress     BOOLEAN NOT NULL DEFAULT FALSE,      -- offending packet inbound
    sess_ingress    BOOLEAN NOT NULL DEFAULT FALSE,      -- session was inbound to workload
    tap_mode        BOOLEAN NOT NULL DEFAULT TRUE,       -- dp was in TAP mode (always true today)

    reported_at     TIMESTAMPTZ NOT NULL,                -- when dp emitted it
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW()   -- server ingest time
);

CREATE INDEX IF NOT EXISTS idx_threats_org_at
  ON runtime_threats(org_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_org_severity_at
  ON runtime_threats(org_id, severity, at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_org_threat_at
  ON runtime_threats(org_id, threat_id, at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_org_epmac_at
  ON runtime_threats(org_id, ep_mac, at DESC) WHERE ep_mac IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS runtime_threats;
-- +goose StatementEnd
