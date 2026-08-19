-- +goose Up
-- +goose StatementBegin
-- Wave C3: cross-cluster pcap capture requests.
--
-- An operator clicks "capture 30s" on a workload (typically from the threat
-- drilldown). That creates a row here in `pending`. The runtime-agent on
-- the relevant node periodically polls for pending captures targeting its
-- cluster, spawns `tcpdump -i <host-veth> -w …` for `duration_s`, kills
-- it, multipart-uploads the resulting .pcap back to the API, and writes
-- the row's status to `completed`. UI shows a download link.
--
-- File storage: the API server keeps each pcap on its local disk under
-- `<dataDir>/pcaps/<id>.pcap`. We don't ship S3/GCS today — Wave C3's
-- size cap (100 MB per capture) keeps this practical for the operator
-- use-case ("grab a sample now, not a 6-week packet log").
CREATE TABLE IF NOT EXISTS runtime_pcap_captures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    cluster_id      UUID NOT NULL,
    workload        TEXT NOT NULL,         -- "<ns>/<deployment>" target
    namespace       TEXT NOT NULL,
    requested_by    UUID NOT NULL,
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- How long the agent should keep tcpdump running. Capped at 60s
    -- server-side via the handler — see runtime_pcap.go.
    duration_s      SMALLINT NOT NULL DEFAULT 30,
    -- Optional 5-tuple filter so the operator captures only the relevant
    -- conversation, not the whole pod's traffic. Empty fields mean "any".
    src_ip          INET,
    dst_ip          INET,
    dst_port        INTEGER,
    protocol        TEXT,                  -- "tcp" | "udp" | "icmp" | NULL=any

    -- State machine.
    status          TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'running', 'completed', 'failed', 'expired')),
    -- Agent that claimed this capture, by NODE name (one capture per node
    -- since the host-veth is node-local). The discoverer doesn't have a
    -- direct workload→node mapping; agents self-pick based on whether
    -- they have a veth matching the workload's pod.
    claimed_by_node TEXT,
    claimed_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,

    -- Storage.
    file_size_bytes BIGINT,        -- non-null when status='completed'
    file_path       TEXT,          -- server-local path
    sha256          TEXT,          -- of the uploaded bytes
    packet_count    BIGINT,        -- best-effort count from tcpdump -c output

    -- TTL: stale rows are sweep-deletable once expires_at < NOW(). Default
    -- 7 days; operators with longer-retention needs configure via Helm.
    expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '7 days')
);

CREATE INDEX IF NOT EXISTS idx_runtime_pcap_org_status_requested
  ON runtime_pcap_captures(org_id, status, requested_at DESC);

-- Hot query for the agent's poll loop: "any pending captures for my cluster?"
CREATE INDEX IF NOT EXISTS idx_runtime_pcap_pending_by_cluster
  ON runtime_pcap_captures(cluster_id, status)
  WHERE status = 'pending';

-- Sweep helper.
CREATE INDEX IF NOT EXISTS idx_runtime_pcap_expires_at
  ON runtime_pcap_captures(expires_at)
  WHERE expires_at IS NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS runtime_pcap_captures;
-- +goose StatementEnd
