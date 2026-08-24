-- +goose Up
-- +goose StatementBegin
-- Expose the runtime-agent's richer sniffer controls through the queued PCAP
-- request model. The agent already understands these JSON fields; persisting
-- them here removes the API/UI gap and keeps capture requests auditable.
ALTER TABLE runtime_pcap_captures
  ADD COLUMN IF NOT EXISTS bpf_filter TEXT,
  ADD COLUMN IF NOT EXISTS capture_interface TEXT,
  ADD COLUMN IF NOT EXISTS file_count INTEGER,
  ADD COLUMN IF NOT EXISTS file_size_mb INTEGER;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'runtime_pcap_bpf_filter_len'
  ) THEN
    ALTER TABLE runtime_pcap_captures
      ADD CONSTRAINT runtime_pcap_bpf_filter_len
      CHECK (bpf_filter IS NULL OR length(bpf_filter) <= 1024);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'runtime_pcap_interface_len'
  ) THEN
    ALTER TABLE runtime_pcap_captures
      ADD CONSTRAINT runtime_pcap_interface_len
      CHECK (capture_interface IS NULL OR length(capture_interface) <= 15);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'runtime_pcap_file_count_range'
  ) THEN
    ALTER TABLE runtime_pcap_captures
      ADD CONSTRAINT runtime_pcap_file_count_range
      CHECK (file_count IS NULL OR file_count BETWEEN 1 AND 20);
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'runtime_pcap_file_size_mb_range'
  ) THEN
    ALTER TABLE runtime_pcap_captures
      ADD CONSTRAINT runtime_pcap_file_size_mb_range
      CHECK (file_size_mb IS NULL OR file_size_mb BETWEEN 1 AND 100);
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_runtime_pcap_org_cluster_requested
  ON runtime_pcap_captures(org_id, cluster_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_runtime_pcap_org_cluster_workload_requested
  ON runtime_pcap_captures(org_id, cluster_id, workload, requested_at DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_runtime_pcap_org_cluster_workload_requested;
DROP INDEX IF EXISTS idx_runtime_pcap_org_cluster_requested;

ALTER TABLE runtime_pcap_captures
  DROP CONSTRAINT IF EXISTS runtime_pcap_file_size_mb_range,
  DROP CONSTRAINT IF EXISTS runtime_pcap_file_count_range,
  DROP CONSTRAINT IF EXISTS runtime_pcap_interface_len,
  DROP CONSTRAINT IF EXISTS runtime_pcap_bpf_filter_len,
  DROP COLUMN IF EXISTS file_size_mb,
  DROP COLUMN IF EXISTS file_count,
  DROP COLUMN IF EXISTS capture_interface,
  DROP COLUMN IF EXISTS bpf_filter;
-- +goose StatementEnd
