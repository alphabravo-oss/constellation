import { Navigate, useLocation } from "@tanstack/react-router";
import type { ReactNode } from "react";

import { useAuth } from "@/contexts/AuthContext";

export function RequireAuth({ children }: { children: ReactNode }) {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) return <div className="grid h-full place-items-center text-muted-foreground text-sm">Loading…</div>;
  if (!me) {
    // The protected layout may remain mounted while its login redirect settles.
    if (location.pathname === "/auth/login") return null;
    const target = location.pathname === "/" ? "/clusters" : location.href;
    return <Navigate to="/auth/login" search={{ returnTo: target }} replace />;
  }
  return <>{children}</>;
}
