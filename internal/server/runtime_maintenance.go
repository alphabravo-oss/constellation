package server

import (
	"context"

	"github.com/alphabravocompany/constellation/internal/handler/runtime"
)

func (s *Server) startRuntimeMaintenance(ctx context.Context) {
	// Preserve the policy rollback worker and its leader lifetime.
	store := runtime.NewRuntimePolicyStore(s.db, s.auditLog)
	watcher := runtime.NewPolicyRollbackWatcher(store, runtime.DefaultRollbackConfig(), s.tel.Logger)
	go watcher.Run(ctx)
	// Disabled unless the chart explicitly verifies a durable single/shared store.
	go runtime.RunPcapRetention(ctx, s.db, s.tel.Logger)
}
