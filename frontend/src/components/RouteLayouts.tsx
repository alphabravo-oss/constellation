import { Suspense } from "react";
import { Navigate, useLocation } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { clusters } from "@/api/client";
import { sortClustersByActivity } from "@/lib/clusters";

export function SuspenseRoute({ children }: { children: React.ReactNode }) {
  return (
    <Suspense
      fallback={
        <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
          Loading…
        </div>
      }
    >
      {children}
    </Suspense>
  );
}

export function LegacyClusterRedirect() {
  const location = useLocation();
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clusters.list(), staleTime: 30_000 });

  if (location.pathname.startsWith("/clusters")) return null;
  if (list.isPending) {
    return (
      <div className="flex items-center justify-center py-16 text-sm text-muted-foreground">
        Loading cluster…
      </div>
    );
  }

  const activeCluster = sortClustersByActivity(list.data?.clusters ?? [])[0]?.id;
  if (!activeCluster) {
    return <Navigate to="/clusters" replace />;
  }

  const legacyPath = location.pathname.replace(/^\/+/, "");
  return <Navigate to="." href={`/clusters/${activeCluster}/${legacyPath}${location.searchStr}${location.hash ? `#${location.hash}` : ""}`} replace />;
}

