import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";

import { useAuth } from "@/contexts/AuthContext";

export function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="grid h-full place-items-center text-muted-foreground text-sm">Loading…</div>;
  if (!me) {
    const target = location.pathname === "/" ? "/clusters" : `${location.pathname}${location.search}${location.hash}`;
    return <Navigate to={`/auth/login?returnTo=${encodeURIComponent(target)}`} replace state={{ from: location }} />;
  }
  return <>{children}</>;
}
