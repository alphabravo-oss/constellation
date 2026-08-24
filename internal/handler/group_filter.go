package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ResolveGroupFilterMembers resolves a Network Activity group filter by group
// name or id and returns its cached workload members. Empty raw filters are
// inactive. Cluster-scoped groups win over org-scoped groups with the same name.
func ResolveGroupFilterMembers(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, clusterID *uuid.UUID, raw string) ([]string, string, bool, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, "", false, nil
	}
	var (
		name       string
		membersRaw []byte
	)
	err := pool.QueryRow(ctx, `
SELECT name, COALESCE(members, '[]'::jsonb)
  FROM groups
 WHERE org_id = $1
   AND (id::text = $2 OR name = $2)
   AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)
 ORDER BY CASE
            WHEN $3::uuid IS NOT NULL AND cluster_id = $3 THEN 0
            WHEN cluster_id IS NULL THEN 1
            ELSE 2
          END,
          updated_at DESC
 LIMIT 1`, orgID, raw, clusterID).Scan(&name, &membersRaw)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, "", true, fmt.Errorf("group not found")
		}
		return nil, "", true, err
	}
	var members []string
	if err := json.Unmarshal(membersRaw, &members); err != nil {
		return nil, "", true, fmt.Errorf("decode group members: %w", err)
	}
	return members, name, true, nil
}
