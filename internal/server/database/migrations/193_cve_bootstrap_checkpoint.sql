-- +goose Up
-- Keep feed state bounded to three installation-wide cursors. Bootstrap progress
-- must never replace or delay the current NVD incremental cursor.
ALTER TABLE cve_feed_checkpoints DROP CONSTRAINT cve_feed_checkpoints_feed_check;
ALTER TABLE cve_feed_checkpoints ADD CONSTRAINT cve_feed_checkpoints_feed_check
 CHECK (feed IN ('kev-epss', 'nvd', 'nvd-bootstrap'));
