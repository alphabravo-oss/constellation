package storagehealth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AuditSource is an explicitly expected webhook source. A registered cluster or
// a historical row alone does not establish that audit delivery is configured.
type AuditSource struct {
	OrgID, ClusterID uuid.UUID
}

type AuditSources struct {
	Sources []AuditSource
	MaxGap  time.Duration
}

// ParseAuditSources accepts comma-separated orgUUID/clusterUUID pairs. Invalid
// settings fail startup rather than silently disabling an expected source.
func ParseAuditSources(raw, gap string) (AuditSources, error) {
	c := AuditSources{MaxGap: 15 * time.Minute}
	if gap != "" {
		d, err := time.ParseDuration(gap)
		if err != nil || d < time.Second || d > 30*24*time.Hour {
			return c, fmt.Errorf("kubernetes audit maximum gap must be between 1s and 720h")
		}
		c.MaxGap = d
	}
	if strings.TrimSpace(raw) == "" {
		return c, nil
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 1000 {
		return c, fmt.Errorf("at most 1000 Kubernetes audit sources may be configured")
	}
	seen := make(map[AuditSource]bool)
	for _, part := range parts {
		pair := strings.Split(strings.TrimSpace(part), "/")
		if len(pair) != 2 {
			return c, fmt.Errorf("kubernetes audit sources must be orgUUID/clusterUUID pairs")
		}
		org, orgErr := uuid.Parse(pair[0])
		cluster, clusterErr := uuid.Parse(pair[1])
		if orgErr != nil || clusterErr != nil || org == uuid.Nil || cluster == uuid.Nil {
			return c, fmt.Errorf("kubernetes audit sources require nonzero organization and cluster UUIDs")
		}
		source := AuditSource{OrgID: org, ClusterID: cluster}
		if !seen[source] {
			c.Sources = append(c.Sources, source)
			seen[source] = true
		}
	}
	return c, nil
}

type auditSourceHealth struct {
	Expected, Missing, Stale, Delayed, UnknownReported, FutureReported, OldestReceipt float64
}

// One indexed latest-row lookup per explicit source avoids scanning all audit
// JSON and prevents a busy source from concealing another source's delivery gap.
func readAuditSources(ctx context.Context, tx pgx.Tx, cfg AuditSources) (auditSourceHealth, error) {
	var out auditSourceHealth
	if len(cfg.Sources) == 0 {
		return out, nil
	}
	if len(cfg.Sources) > 1000 || cfg.MaxGap < time.Second || cfg.MaxGap > 30*24*time.Hour {
		return out, fmt.Errorf("invalid Kubernetes audit source observation limits")
	}
	orgs, clusters := make([]uuid.UUID, 0, len(cfg.Sources)), make([]uuid.UUID, 0, len(cfg.Sources))
	for _, source := range cfg.Sources {
		orgs = append(orgs, source.OrgID)
		clusters = append(clusters, source.ClusterID)
	}
	err := tx.QueryRow(ctx, `SELECT count(*)::float8,
 count(*) FILTER(WHERE e.at IS NULL)::float8,
 count(*) FILTER(WHERE e.at < now()-$3::float8*interval '1 second')::float8,
 count(*) FILTER(WHERE e.at-e.reported_at > $3::float8*interval '1 second')::float8,
 count(*) FILTER(WHERE e.at IS NOT NULL AND e.reported_at IS NULL)::float8,
 count(*) FILTER(WHERE e.reported_at > e.at+interval '5 minutes')::float8,
 COALESCE(extract(epoch FROM min(e.at)),0)::float8
 FROM unnest($1::uuid[], $2::uuid[]) s(org_id,cluster_id)
 LEFT JOIN LATERAL (
  SELECT at,reported_at FROM k8s_audit_events WHERE org_id=s.org_id AND cluster_id=s.cluster_id
  ORDER BY at DESC, id DESC LIMIT 1
 ) e ON true`, orgs, clusters, cfg.MaxGap.Seconds()).Scan(&out.Expected, &out.Missing, &out.Stale, &out.Delayed, &out.UnknownReported, &out.FutureReported, &out.OldestReceipt)
	return out, err
}
