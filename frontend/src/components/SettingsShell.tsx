import { Link, Outlet, useLocation } from "react-router-dom";
import { ArrowLeft } from "lucide-react";

/**
 * SettingsShell — the settings surface, Astronomer-style. The index (`/settings`)
 * is a full-width card-grid hub; every sub-page is a standalone full-width page
 * with a "Settings" breadcrumb back to the hub. No persistent sidebar — the card
 * hub IS the navigation.
 */
export function SettingsShell() {
  const { pathname } = useLocation();
  const isIndex = pathname === "/settings" || pathname === "/settings/";

  return (
    <div className="mx-auto max-w-[1600px] pb-16">
      {!isIndex && (
        <Link
          to="/settings"
          className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Settings
        </Link>
      )}
      <Outlet />
    </div>
  );
}
