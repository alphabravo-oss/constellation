package groupprofile

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/alphabravocompany/constellation/internal/handler/netutil"
	"github.com/alphabravocompany/constellation/pkg/group"
)

type Writer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func ModeForGroup(mode group.Mode) string {
	switch mode {
	case group.ModeDiscover:
		return "learn"
	case group.ModeMonitor:
		return "monitor"
	case group.ModeProtect:
		return "enforce"
	}
	return ""
}

func Propagate(ctx context.Context, writer Writer, orgID, clusterID uuid.UUID, members []string, mode group.Mode) error {
	return propagate(ctx, writer, orgID, clusterID, members, mode, false)
}

func PropagateAtLeast(ctx context.Context, writer Writer, orgID, clusterID uuid.UUID, members []string, mode group.Mode) error {
	return propagate(ctx, writer, orgID, clusterID, members, mode, true)
}

func propagate(ctx context.Context, writer Writer, orgID, clusterID uuid.UUID, members []string, mode group.Mode, preserveHigher bool) error {
	baselineMode := ModeForGroup(mode)
	if baselineMode == "" || len(members) == 0 {
		return nil
	}
	modeAssignment := "EXCLUDED.mode"
	if preserveHigher {
		modeAssignment = `CASE
         WHEN process_baseline_states.mode='enforce' OR EXCLUDED.mode='enforce' THEN 'enforce'
         WHEN process_baseline_states.mode='monitor' OR EXCLUDED.mode='monitor' THEN 'monitor'
         ELSE 'learn' END`
	}
	for _, workloadID := range members {
		namespace, name := netutil.SplitWorkload(workloadID)
		if _, err := writer.Exec(ctx, `
INSERT INTO process_baseline_states (org_id, cluster_id, workload_id, namespace, name, mode,
       learn_started_at, monitor_started_at, enforce_started_at, updated_at)
VALUES ($1,$2,$3,$4,$5,$6, NOW(),
        CASE WHEN $6 IN ('monitor','enforce') THEN NOW() END,
        CASE WHEN $6 = 'enforce' THEN NOW() END, NOW())
ON CONFLICT (org_id, cluster_id, workload_id) DO UPDATE SET
       mode = `+modeAssignment+`,
       monitor_started_at = CASE WHEN $6 IN ('monitor','enforce')
              THEN COALESCE(process_baseline_states.monitor_started_at, NOW())
              ELSE process_baseline_states.monitor_started_at END,
       enforce_started_at = CASE WHEN $6 = 'enforce'
              THEN COALESCE(process_baseline_states.enforce_started_at, NOW())
              ELSE process_baseline_states.enforce_started_at END,
       updated_at = NOW()`,
			orgID, clusterID, workloadID, namespace, name, baselineMode); err != nil {
			return err
		}
	}
	return nil
}
