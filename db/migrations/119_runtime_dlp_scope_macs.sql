-- +goose Up
-- +goose StatementBegin
-- P1-5 (per-workload/group scoping): let a DLP/signature rule apply to a
-- selected set of workloads instead of every tapped MAC on the cluster.
--
-- dp's DLP primitive already accepts a per-workload MAC list (ctrl_bld_dlp /
-- ctrl_cfg_dlp WorkloadMac). This column carries the optional scope from the
-- control plane through the agent bundle to dlp_sync, which intersects it with
-- the MACs it actually taps. NULL / empty ⇒ "apply to every workload" (the
-- existing fleet-wide behaviour), so this is backward compatible.
--
-- Stored as a JSONB array of lowercase MAC strings. Group-based scoping resolves
-- to the same MAC list upstream (the control plane expands a group selector into
-- member MACs before serving the bundle), so the wire shape stays a flat list.
ALTER TABLE runtime_dlp_rules
    ADD COLUMN IF NOT EXISTS scope_macs JSONB;  -- NULL ⇒ all workloads
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE runtime_dlp_rules
    DROP COLUMN IF EXISTS scope_macs;
-- +goose StatementEnd
