// ClusterRouter — layout/guard for /clusters/:id/* routes.
//
// Responsibilities:
//   1. Validate :id resolves to a cluster the org can see (otherwise redirect to /clusters).
//   2. Provide a Suspense boundary so lazy-loaded sub-routes don't blank the shell.
//   3. Render <Outlet /> so the nested page receives cluster context via useCluster().
//
// We intentionally avoid creating yet-another React context — useCluster() already
// derives everything from the URL + TanStack cache, which means deeplinks Just Work.
import { Suspense } from "react";
import { Navigate, Outlet } from "react-router-dom";

import { useCluster } from "@/hooks/useCluster";

export function ClusterRouter() {
  const { clusterId, cluster, isLoading, error, allClusters } = useCluster();

  if (!clusterId) {
    return <Navigate to="/clusters" replace />;
  }

  // While the cluster list is loading we render a skeleton — the cached list
  // populates immediately on warm sessions so this rarely flashes.
  if (isLoading && !cluster) {
    return (
      <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
        Loading cluster…
      </div>
    );
  }

  // Cluster list has loaded and the :id isn't in it AND the single-fetch errored
  // → either deleted, no permissions, or bad URL. Send the user back to the picker.
  if (!cluster && error && allClusters.length > 0) {
    return <Navigate to="/clusters" replace />;
  }

  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
          Loading…
        </div>
      }
    >
      <Outlet />
    </Suspense>
  );
}
