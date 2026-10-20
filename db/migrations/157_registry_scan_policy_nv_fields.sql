-- +goose Up
-- +goose StatementBegin
ALTER TABLE registries
    ALTER COLUMN scan_policy SET DEFAULT '{
      "include_repos": ["*"],
      "exclude_repos": [],
      "tag_selection": "all",
      "max_age": "",
      "rescan_interval": "",
      "rescan_after_db_update": true,
      "repo_limit": 0,
      "tag_limit": 0,
      "custom_interval": "",
      "cron": "",
      "ignore_proxy": false,
      "scan_layers": true,
      "block_promotion_threshold": "critical"
    }'::jsonb;

UPDATE registries
   SET scan_policy = '{
      "rescan_after_db_update": true,
      "repo_limit": 0,
      "tag_limit": 0,
      "custom_interval": "",
      "cron": "",
      "ignore_proxy": false,
      "scan_layers": true
    }'::jsonb || scan_policy;
-- +goose StatementEnd
