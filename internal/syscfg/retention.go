package syscfg

import (
	"context"
	"encoding/json"
	"fmt"
)

// EffectiveRetentionDays returns the conservative installation-wide window for
// shared retention workers. The longest org window wins; any explicit hold (0)
// disables expiry. Read one DB snapshot rather than a stale/defaulting provider
// cache. On any read/validation error callers must skip deletion.
func EffectiveRetentionDays(ctx context.Context, s store, pick func(Config) int) (int, error) {
	rows, err := s.Query(ctx, `SELECT c.config FROM orgs o LEFT JOIN system_config c ON c.org_id=o.id`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	longest := 0
	hold := false
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return 0, err
		}
		cfg := Default()
		if raw != nil {
			cfg, err = unmarshalStoredConfig(raw)
			if err != nil {
				return 0, fmt.Errorf("invalid retention config")
			}
		}
		if err := cfg.Validate(); err != nil {
			return 0, err
		}
		days := pick(cfg)
		if days == 0 {
			hold = true
		}
		if days > longest {
			longest = days
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if hold {
		return 0, nil
	}
	return longest, nil
}
