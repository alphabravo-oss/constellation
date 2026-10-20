// Package inventorypresence classifies findings against a complete, fresh pod
// inventory. It never resolves vulnerabilities merely because a pod disappears.
package inventorypresence

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/alphabravocompany/constellation/internal/handler/platformrole"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Snapshot struct {
	Pods         map[string]string `json:"pods"`
	ImageDigests map[string]bool   `json:"image_digests"`
}

func Store(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID, observed, expires time.Time, snapshot Snapshot) error {
	pods, err := json.Marshal(snapshot.Pods)
	if err != nil {
		return err
	}
	images, err := json.Marshal(snapshot.ImageDigests)
	if err != nil {
		return err
	}
	_, err = pool.Exec(ctx, `INSERT INTO cluster_inventory_presence(org_id,cluster_id,observed_at,expires_at,pods,image_digests)
 SELECT $1,$2,$3,$4,$5::jsonb,$6::jsonb FROM clusters WHERE id=$2 AND org_id=$1
 ON CONFLICT(org_id,cluster_id) DO UPDATE SET observed_at=EXCLUDED.observed_at,expires_at=EXCLUDED.expires_at,pods=EXCLUDED.pods,image_digests=EXCLUDED.image_digests
 WHERE cluster_inventory_presence.observed_at<EXCLUDED.observed_at`, org, cluster, observed, expires, pods, images)
	return err
}

type Counts struct {
	InventoryStatus       string     `json:"inventory_status"`
	ObservedAt            *time.Time `json:"observed_at,omitempty"`
	CurrentCritical       int        `json:"current_critical"`
	CurrentHigh           int        `json:"current_high"`
	CurrentOccurrences    int        `json:"current_occurrences"`
	HistoricalOccurrences int        `json:"historical_occurrences"`
	UnverifiedOccurrences int        `json:"unverified_occurrences"`
	// LastKnown is the exposure as classified by the most recent snapshot, set
	// only when that snapshot has expired (InventoryStatus "stale") so a UI can
	// show the last-known counts with their age instead of nothing.
	LastKnown *LastKnown `json:"last_known,omitempty"`
}

// LastKnown is critical/high exposure from an expired inventory snapshot.
type LastKnown struct {
	Critical int       `json:"critical"`
	High     int       `json:"high"`
	AsOf     time.Time `json:"as_of"`
}

// Counts refer to open critical/high vulnerability findings. CVEs are unique
// within each severity; occurrences retain asset multiplicity. Unmatched images
// remain unverified because runtime configuration and manifest digests can differ.
// Snapshot lookups depend on the asset, not each vulnerability on it. Compute
// those JSONB lookups once per asset, then classify the finding's own timestamp.
const countsSQL = `WITH asset_state AS MATERIALIZED (
 SELECT a.id,a.org_id,a.cluster_id,
 a.kind='workload' AND a.name ~ '^[^/]+/pod/[^/]+$' AS is_pod,
 CASE WHEN a.kind='workload' AND a.name ~ '^[^/]+/pod/[^/]+$'
 THEN s.pods->>a.name IN ('Running','Pending','Unknown','')
 WHEN a.kind='image' THEN s.image_digests ? COALESCE(NULLIF(a.digest,''),a.name)
 ELSE false END AS is_current
 FROM assets a
 LEFT JOIN cluster_inventory_presence s ON s.org_id=a.org_id AND s.cluster_id=a.cluster_id
 WHERE a.org_id=$1 AND a.cluster_id IS NOT NULL AND ($2::uuid IS NULL OR a.cluster_id=$2)
 ), classified AS MATERIALIZED (
 SELECT c.id AS cluster_id,s.observed_at,s.expires_at,f.id AS finding_id,
 COALESCE(NULLIF(f.external_id,''),f.id::text) AS external_id,f.severity,
 CASE WHEN s.expires_at IS NULL OR s.expires_at<=NOW() OR a.cluster_id IS DISTINCT FROM c.id THEN 'unverified'
 WHEN a.is_current THEN 'current'
 WHEN a.is_pod THEN CASE WHEN f.last_seen_at>s.observed_at THEN 'unverified' ELSE 'historical' END
 ELSE 'unverified' END AS presence,
 CASE WHEN s.observed_at IS NULL OR a.cluster_id IS DISTINCT FROM c.id THEN 'unverified'
 WHEN a.is_current THEN 'current' WHEN a.is_pod THEN 'other'
 ELSE 'unverified' END AS last_presence
 FROM clusters c
 LEFT JOIN cluster_inventory_presence s ON s.org_id=c.org_id AND s.cluster_id=c.id
 LEFT JOIN findings f ON f.org_id=c.org_id AND f.cluster_id=c.id
 AND f.lifecycle='open' AND f.kind='vulnerability' AND f.severity IN ('critical','high')
 /* finding_scope */
 LEFT JOIN asset_state a ON a.id=f.asset_id AND a.org_id=f.org_id
 WHERE c.org_id=$1 AND ($2::uuid IS NULL OR c.id=$2)
 ) SELECT cluster_id,
 CASE WHEN max(expires_at) IS NULL THEN 'missing' WHEN max(expires_at)>NOW() THEN 'fresh' ELSE 'stale' END,
 max(observed_at),
 count(DISTINCT external_id) FILTER(WHERE presence='current' AND severity='critical'),
 count(DISTINCT external_id) FILTER(WHERE presence='current' AND severity='high'),
 count(finding_id) FILTER(WHERE presence='current'),count(finding_id) FILTER(WHERE presence='historical'),count(finding_id) FILTER(WHERE presence='unverified'),
 count(DISTINCT external_id) FILTER(WHERE last_presence='current' AND severity='critical'),
 count(DISTINCT external_id) FILTER(WHERE last_presence='current' AND severity='high')
 FROM classified GROUP BY cluster_id`

func Read(ctx context.Context, pool *pgxpool.Pool, org, cluster uuid.UUID) (Counts, error) {
	all, err := read(ctx, pool, org, &cluster, "all")
	return all[cluster], err
}

func ReadAll(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID) (map[uuid.UUID]Counts, error) {
	return read(ctx, pool, org, nil, "all")
}

func ReadAllScoped(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, scope string) (map[uuid.UUID]Counts, error) {
	return read(ctx, pool, org, nil, scope)
}

func read(ctx context.Context, pool *pgxpool.Pool, org uuid.UUID, cluster *uuid.UUID, scope string) (map[uuid.UUID]Counts, error) {
	predicate, err := platformrole.ScopeSQL(scope, platformrole.ConstellationFindingSQL("f"))
	if err != nil {
		return nil, err
	}
	rows, err := pool.Query(ctx, strings.Replace(countsSQL, "/* finding_scope */", "AND ("+predicate+")", 1), org, cluster)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[uuid.UUID]Counts{}
	for rows.Next() {
		var id uuid.UUID
		var c Counts
		var lastCritical, lastHigh int
		if err := rows.Scan(&id, &c.InventoryStatus, &c.ObservedAt, &c.CurrentCritical, &c.CurrentHigh, &c.CurrentOccurrences, &c.HistoricalOccurrences, &c.UnverifiedOccurrences, &lastCritical, &lastHigh); err != nil {
			return nil, err
		}
		if c.InventoryStatus == "stale" && c.ObservedAt != nil {
			c.LastKnown = &LastKnown{Critical: lastCritical, High: lastHigh, AsOf: *c.ObservedAt}
		}
		out[id] = c
	}
	return out, rows.Err()
}
