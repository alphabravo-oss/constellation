package policy

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/alphabravocompany/constellation/internal/admissiongroups"
	constadmission "github.com/alphabravocompany/constellation/pkg/admission"
)

func (p *Policies) admissionGroupResolver(ctx context.Context, orgID uuid.UUID, clusterArg any) (constadmission.GroupResolver, error) {
	if p == nil || p.db == nil {
		return nil, nil
	}
	resolver := admissiongroups.New(p.db.Pool(), orgID, clusterIDFromArg(clusterArg), time.Minute)
	if err := resolver.Refresh(ctx); err != nil {
		return nil, err
	}
	return resolver, nil
}

func (p *Policies) admissionGroupExists(ctx context.Context, orgID uuid.UUID, clusterArg any, selector string) (bool, error) {
	if p == nil || p.db == nil {
		return true, nil
	}
	var ok bool
	err := p.db.Pool().QueryRow(ctx, `
SELECT EXISTS (
  SELECT 1
    FROM groups
   WHERE org_id = $1
     AND (id::text = $2 OR name = $2)
     AND ($3::uuid IS NULL OR cluster_id IS NULL OR cluster_id = $3)
)`, orgID, selector, nullableClusterID(clusterArg)).Scan(&ok)
	return ok, err
}

func clusterIDFromArg(clusterArg any) uuid.UUID {
	if clusterID, ok := clusterArg.(uuid.UUID); ok {
		return clusterID
	}
	return uuid.Nil
}

func nullableClusterID(clusterArg any) any {
	if clusterID, ok := clusterArg.(uuid.UUID); ok {
		return clusterID
	}
	return nil
}
