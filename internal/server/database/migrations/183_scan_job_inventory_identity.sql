-- +goose Up
-- Capture the inventory handed to the worker at claim time. Do not backfill old
-- jobs from mutable scan_targets: that would falsely certify historical scans.
ALTER TABLE scan_jobs ADD COLUMN claimed_inventory_hash text;
