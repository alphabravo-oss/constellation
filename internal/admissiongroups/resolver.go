// Package admissiongroups resolves Constellation groups for admission rule
// match.groups scoping. It lives in internal/ so pkg/admission remains a pure
// evaluator with an injected resolver interface.
package admissiongroups

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	corev1 "k8s.io/api/core/v1"

	"github.com/alphabravocompany/constellation/pkg/group"
)

type resolvedGroup struct {
	id        string
	name      string
	clusterID string
	criteria  []group.Criterion
	members   []string
}

// Resolver maps admission pods to stored Constellation groups by id or name.
// It is intentionally cache-backed: admission hot paths should not query
// Postgres per rule per request.
type Resolver struct {
	pool      *pgxpool.Pool
	orgID     uuid.UUID
	clusterID uuid.UUID
	ttl       time.Duration

	mu         sync.RWMutex
	bySelector map[string][]resolvedGroup
	loadedAt   time.Time
}

// New constructs a group resolver. clusterID may be uuid.Nil for org-wide API
// calls; otherwise cluster-scoped groups plus org-wide groups are eligible.
func New(pool *pgxpool.Pool, orgID, clusterID uuid.UUID, ttl time.Duration) *Resolver {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Resolver{
		pool:       pool,
		orgID:      orgID,
		clusterID:  clusterID,
		ttl:        ttl,
		bySelector: map[string][]resolvedGroup{},
	}
}

// Refresh reloads the group cache from Postgres.
func (r *Resolver) Refresh(ctx context.Context) error {
	if r == nil || r.pool == nil {
		return nil
	}
	var clusterArg any
	if r.clusterID != uuid.Nil {
		clusterArg = r.clusterID
	}
	rows, err := r.pool.Query(ctx, `
SELECT id::text,
       name,
       COALESCE(cluster_id::text, '') AS cluster_id,
       COALESCE(criteria, '[]'::jsonb) AS criteria,
       COALESCE(members, '[]'::jsonb) AS members
  FROM groups
 WHERE org_id = $1
   AND ($2::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $2)`,
		r.orgID, clusterArg)
	if err != nil {
		return err
	}
	defer rows.Close()

	next := map[string][]resolvedGroup{}
	for rows.Next() {
		var row resolvedGroup
		var criteriaRaw, membersRaw []byte
		if err := rows.Scan(&row.id, &row.name, &row.clusterID, &criteriaRaw, &membersRaw); err != nil {
			return err
		}
		if err := json.Unmarshal(criteriaRaw, &row.criteria); err != nil {
			return err
		}
		if err := json.Unmarshal(membersRaw, &row.members); err != nil {
			return err
		}
		indexGroup(next, row.id, row)
		indexGroup(next, row.name, row)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	r.mu.Lock()
	r.bySelector = next
	r.loadedAt = time.Now()
	r.mu.Unlock()
	return nil
}

// Run refreshes the resolver until ctx is cancelled. A failed refresh keeps the
// previous cache so existing admission scope decisions remain available.
func (r *Resolver) Run(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if r == nil || r.pool == nil {
		return
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.Refresh(ctx); err != nil && logger != nil {
				logger.Warn("admission group resolver refresh failed", "err", err)
			}
		}
	}
}

// PodMatchesGroup reports whether pod is a member of the named/id group.
func (r *Resolver) PodMatchesGroup(ctx context.Context, selector string, pod *corev1.Pod) (bool, error) {
	selector = strings.TrimSpace(selector)
	if r == nil || r.pool == nil || selector == "" || pod == nil {
		return false, nil
	}
	groups, expired := r.snapshot(selector)
	if expired {
		if err := r.Refresh(ctx); err != nil {
			return false, err
		}
		groups, _ = r.snapshot(selector)
	}
	if len(groups) == 0 {
		return false, nil
	}
	for _, candidate := range groups {
		if groupMatchesPod(candidate, r.clusterID, pod) {
			return true, nil
		}
	}
	return false, nil
}

func (r *Resolver) snapshot(selector string) ([]resolvedGroup, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	groups := append([]resolvedGroup(nil), r.bySelector[selector]...)
	if len(groups) == 0 {
		groups = append([]resolvedGroup(nil), r.bySelector[strings.ToLower(selector)]...)
	}
	expired := r.loadedAt.IsZero() || time.Since(r.loadedAt) > r.ttl
	return groups, expired
}

func indexGroup(index map[string][]resolvedGroup, selector string, row resolvedGroup) {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return
	}
	index[selector] = append(index[selector], row)
	lower := strings.ToLower(selector)
	if lower != selector {
		index[lower] = append(index[lower], row)
	}
}

func groupMatchesPod(candidate resolvedGroup, clusterID uuid.UUID, pod *corev1.Pod) bool {
	ns := strings.TrimSpace(pod.Namespace)
	if ns == "" {
		ns = "default"
	}
	name := strings.TrimSpace(pod.Name)
	if name == "" {
		name = strings.TrimSpace(pod.GenerateName)
	}
	workloadID := ns + "/" + name
	for _, member := range candidate.members {
		member = strings.TrimSpace(member)
		if member == workloadID || member == ns+"/pod/"+name || member == name {
			return true
		}
	}
	cluster := candidate.clusterID
	if cluster == "" && clusterID != uuid.Nil {
		cluster = clusterID.String()
	}
	return (&group.Group{
		Name:     candidate.name,
		Criteria: candidate.criteria,
	}).Matches(&group.Workload{
		ID:        workloadID,
		Cluster:   cluster,
		Namespace: ns,
		Service:   name,
		Labels:    pod.Labels,
	})
}
