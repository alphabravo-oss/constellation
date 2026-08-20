-- +goose Up
-- +goose StatementBegin
-- DB-GROWTH: turn on the age-based retention that bounds the three unbounded stores
-- (raw network flows, runtime events, finished scan jobs). These knobs already exist in
-- syscfg but shipped as 0 (= keep forever), so nothing was pruning. Seed sane defaults
-- on any existing system_config row that has not set them, and bump the revision so the
-- in-process syscfg provider reloads and the retention loops / partition manager pick the
-- values up without a restart. COALESCE preserves any value an operator already chose.
--
-- Defaults (NeuVector-style short raw retention; the durable signal lives in the
-- aggregates — network_flow_rollups — and in findings, not the raw rows):
--   network_flow_retention_days = 14   (raw flows; the hourly rollup is kept regardless)
--   events_retention_days       = 30   (runtime events; forensic window)
--   scan_job_retention_days     = 7    (finished scan-job queue history)
UPDATE system_config
   SET config = config || jsonb_build_object(
         'network_flow_retention_days', COALESCE(NULLIF(config->>'network_flow_retention_days','')::int, 14),
         'events_retention_days',       COALESCE(NULLIF(config->>'events_retention_days','')::int, 30),
         'scan_job_retention_days',     COALESCE(NULLIF(config->>'scan_job_retention_days','')::int, 7)
       ),
       revision = revision + 1,
       updated_at = now();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE system_config
   SET config = config - 'network_flow_retention_days' - 'events_retention_days' - 'scan_job_retention_days',
       revision = revision + 1,
       updated_at = now();
-- +goose StatementEnd
