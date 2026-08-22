// AppShell — cluster-first IA, Astronomer-cloned chrome.
//
// Two sidebar modes, derived from the URL:
//   1. ORG MODE (/clusters, /cve, /settings, /federation, …) → ORG_NAV.
//   2. CLUSTER MODE (/clusters/:id/*) → ClusterSwitcher + CLUSTER_NAV, every
//      item resolved against the active :id.
//
// Layout (sidebar w-60/w-16, topbar h-14, content p-6 max-w-[1600px] fade-in,
// collapsible nav groups, user menu, offline banner) mirrors /root/astronomer.
import { useEffect, useMemo, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import {
  LayoutDashboard,
  AlertTriangle,
  Boxes,
  ShieldCheck,
  Activity,
  Network,
  Database,
  ScrollText,
  Settings,
  Moon,
  Sun,
  LogOut,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  ClipboardCheck,
  HeartPulse,
  UsersRound,
  FileText,
  FileWarning,
  Bell,
  Command as CmdIcon,
  Layers,
  Compass,
  Globe2,
  BellRing,
  ArrowLeft,
  Server,
  ServerCog,
  GitMerge,
  PackageSearch,
  CloudCog,
  GitBranch,
  RadioTower,
  User,
  Search,
  WifiOff,
  Waypoints,
} from "lucide-react";
import { useAuth } from "@/contexts/AuthContext";
import { useTheme } from "@/contexts/ThemeContext";
import { cn } from "@/lib/cn";
import { CommandPaletteProvider, HotkeysHelp } from "@/components/CommandPalette";
import { Kbd } from "@/components/ui/kbd";
import { findings as findingsApi, clusters as clustersApi, runtimeThreats as runtimeThreatsApi } from "@/api/client";
import { fmtRelative } from "@/lib/format";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { ClusterSwitcher } from "@/components/ClusterSwitcher";

type NavItem = {
  /** Path fragment appended to /clusters/:id/ in cluster mode, or absolute in org mode. */
  path: string;
  icon: typeof LayoutDashboard;
  label: string;
  exact?: boolean;
};
type NavGroup = { id: string; label: string; items: NavItem[] };

// Cluster-scoped sidebar groups — every link is resolved against the active :id.
export const CLUSTER_NAV: NavGroup[] = [
  {
    id: "dashboard",
    label: "Dashboard",
    items: [
      { path: "dashboard",     icon: LayoutDashboard, label: "Dashboard", exact: true },
    ],
  },
  {
    id: "network",
    label: "Network Activity",
    items: [
      { path: "network",         icon: Network,    label: "Network Map" },
      { path: "network-rules",   icon: Waypoints,  label: "Network Rules" },
      { path: "timeline",        icon: Activity,   label: "Incident Timeline" },
    ],
  },
  {
    id: "assets",
    label: "Assets",
    items: [
      { path: "nodes",         icon: Server,          label: "Nodes" },
      { path: "containers",    icon: Boxes,           label: "Containers" },
      { path: "images",        icon: PackageSearch,   label: "Images" },
      { path: "deployments",   icon: Layers,          label: "Workloads" },
      { path: "assets",        icon: Boxes,           label: "Assets" },
      { path: "serverless",    icon: CloudCog,        label: "Serverless" },
      { path: "repositories",  icon: GitBranch,       label: "Repositories" },
      { path: "registries",    icon: Database,        label: "Registries" },
    ],
  },
  {
    id: "risks",
    label: "Security Risks",
    items: [
      { path: "findings",      icon: AlertTriangle,   label: "Findings" },
      { path: "vuln-profiles", icon: FileWarning,     label: "Vuln Profiles" },
      { path: "exceptions",    icon: FileWarning,     label: "Exceptions" },
      { path: "compliance",    icon: ShieldCheck,     label: "Compliance" },
    ],
  },
  {
    id: "runtime",
    label: "Runtime",
    items: [
      { path: "runtime",         icon: Activity,      label: "Runtime" },
      { path: "runtime/baselines", icon: GitMerge,    label: "Process Baselines" },
      { path: "runtime-signatures", icon: ShieldCheck, label: "WAF / DPI Signatures" },
      { path: "runtime-dlp",   icon: ShieldCheck,     label: "DLP Rules" },
      { path: "file-monitor",  icon: FileWarning,     label: "File Monitor" },
    ],
  },
  {
    id: "policy",
    label: "Policy",
    items: [
      { path: "admission",     icon: ShieldCheck,     label: "Admission Control" },
      { path: "policies",      icon: FileText,        label: "Policies" },
      { path: "runtime-policies", icon: ScrollText,   label: "Runtime Policies" },
      { path: "groups",        icon: UsersRound,      label: "Groups" },
    ],
  },
  {
    id: "response",
    label: "Response",
    items: [
      { path: "response-rules", icon: BellRing,       label: "Response Rules" },
      { path: "response",      icon: RadioTower,      label: "Response Catalog" },
    ],
  },
  {
    id: "activity",
    label: "Settings & Activity",
    items: [
      { path: "audit",         icon: ScrollText,      label: "Audit Log" },
      { path: "components",    icon: ServerCog,       label: "Components" },
      { path: "health",        icon: HeartPulse,      label: "Sensor Health" },
    ],
  },
];

// Org-scoped sidebar groups — absolute paths. Admin items moved into the grouped
// Settings shell (SettingsShell sub-nav) so each feature has exactly one home.
const ORG_NAV: NavGroup[] = [
  {
    id: "fleet",
    label: "Fleet",
    items: [
      { path: "/clusters",     icon: ServerCog,       label: "Clusters", exact: true },
    ],
  },
  {
    id: "security",
    label: "Security",
    items: [
      { path: "/cve",          icon: Database,        label: "CVE Database" },
      { path: "/posture",      icon: ClipboardCheck,  label: "Posture" },
      { path: "/federation",   icon: Globe2,          label: "Federation" },
    ],
  },
  {
    id: "settings",
    label: "Settings",
    items: [
      { path: "/settings",     icon: Settings,        label: "Settings" },
    ],
  },
];

const COLLAPSE_KEY = "constellation.sidebar.collapsed";
const APP_VERSION = "0.1.0";

function clusterIDFromPath(pathname: string): string | null {
  const m = pathname.match(/^\/clusters\/([^/]+)(\/|$)/);
  return m ? m[1] : null;
}

function resolveTo(item: NavItem, clusterId: string | null): string {
  return item.path.startsWith("/") ? item.path : `/clusters/${clusterId}/${item.path}`;
}

function isItemActive(item: NavItem, pathname: string, clusterId: string | null): boolean {
  const to = resolveTo(item, clusterId);
  return item.exact ? pathname === to : pathname === to || pathname.startsWith(to + "/");
}

/** navigator.onLine with live online/offline listeners. */
function useOnline(): boolean {
  const [online, setOnline] = useState(true);
  useEffect(() => {
    setOnline(navigator.onLine);
    const up = () => setOnline(true);
    const down = () => setOnline(false);
    window.addEventListener("online", up);
    window.addEventListener("offline", down);
    return () => {
      window.removeEventListener("online", up);
      window.removeEventListener("offline", down);
    };
  }, []);
  return online;
}

export function AppShell() {
  const { me, logout } = useAuth();
  const { theme, toggle } = useTheme();
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const online = useOnline();

  // Auto-collapse on narrow viewports if the user hasn't expressed a preference.
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    const stored = localStorage.getItem(COLLAPSE_KEY);
    if (stored === "1") return true;
    if (stored === "0") return false;
    if (typeof window !== "undefined" && window.innerWidth < 1024) return true;
    return false;
  });
  useEffect(() => { localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0"); }, [collapsed]);

  const [hkOpen, setHkOpen] = useState(false);
  useEffect(() => {
    const handler = () => setHkOpen(true);
    window.addEventListener("constellation:show-hotkeys", handler);
    return () => window.removeEventListener("constellation:show-hotkeys", handler);
  }, []);

  const clusterId = clusterIDFromPath(pathname);
  const inClusterMode = clusterId !== null;
  const navGroups = inClusterMode ? CLUSTER_NAV : ORG_NAV;

  // Collapsible groups (all open by default; active group always stays open).
  const [openGroups, setOpenGroups] = useState<Set<string>>(() => new Set(navGroups.map((g) => g.id)));
  useEffect(() => {
    // Ensure the group containing the active route is open after navigation.
    const active = navGroups.find((g) => g.items.some((it) => isItemActive(it, pathname, clusterId)));
    if (active && !openGroups.has(active.id)) {
      setOpenGroups((s) => new Set(s).add(active.id));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);
  function toggleGroup(id: string) {
    setOpenGroups((s) => {
      const next = new Set(s);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }

  return (
    <div className="flex h-full overflow-hidden bg-background">
      <aside
        className={cn(
          "flex flex-col h-full bg-sidebar border-r border-sidebar-border overflow-hidden transition-all duration-200 ease-in-out",
          collapsed ? "w-16" : "w-60",
        )}
        aria-label="Primary"
      >
        {/* Brand + collapse toggle (h-14) */}
        <div className="flex items-center h-14 px-4 border-b border-sidebar-border">
          {!collapsed && (
            <Link to="/clusters" className="flex items-center gap-2.5 min-w-0">
              <BrandMark />
              <div className="flex flex-col min-w-0 leading-tight">
                <span className="text-sm font-semibold text-foreground tracking-tight truncate">Constellation</span>
                <span className="text-[10px] text-muted-foreground truncate">Security Platform</span>
              </div>
            </Link>
          )}
          <button
            type="button"
            onClick={() => setCollapsed((c) => !c)}
            className={cn("nav-item", collapsed ? "w-full justify-center px-0" : "ml-auto")}
            title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
          </button>
        </div>

        {/* Cluster context header — cluster mode only. */}
        {inClusterMode && !collapsed && (
          <div className="px-2 py-2 border-b border-sidebar-border">
            <Link
              to="/clusters"
              data-testid="back-to-clusters"
              className="flex items-center gap-2 px-2 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors rounded-md hover:bg-accent/50"
            >
              <ArrowLeft className="h-3.5 w-3.5 flex-shrink-0" aria-hidden />
              <span className="truncate">All Clusters</span>
            </Link>
            <div className="px-2 mt-1 min-w-0">
              <ClusterSwitcher />
            </div>
          </div>
        )}
        {inClusterMode && collapsed && (
          <div className="px-1 py-2 border-b border-sidebar-border">
            <Link to="/clusters" data-testid="back-to-clusters" className="nav-item justify-center px-0" title="All clusters">
              <ArrowLeft className="h-4 w-4" />
            </Link>
          </div>
        )}

        <nav className="flex-1 overflow-y-auto py-2 px-1 no-scrollbar">
          {navGroups.map((group) => (
            <SidebarGroup
              key={group.id}
              group={group}
              pathname={pathname}
              clusterId={clusterId}
              collapsed={collapsed}
              open={openGroups.has(group.id)}
              onToggle={() => toggleGroup(group.id)}
            />
          ))}
        </nav>

        {/* Footer — version + attribution (Astronomer parity). */}
        <div className="mt-auto px-2 py-2 border-t border-sidebar-border">
          {!collapsed && (
            <div className="px-3 py-1 space-y-0.5">
              <p className="text-[10px] text-muted-foreground">Constellation {APP_VERSION}</p>
              <p className="text-[10px] text-muted-foreground">
                Built by{" "}
                <a
                  href="https://alphabravo.io"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="hover:text-foreground underline-offset-2 hover:underline"
                >
                  AlphaBravo
                </a>
              </p>
            </div>
          )}
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopHeader
          pathname={pathname}
          clusterId={clusterId}
          theme={theme}
          onToggleTheme={toggle}
          onLogout={logout}
          userEmail={me?.email}
          userRole={me?.roles?.[0]}
          onLaunchPalette={() => window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true }))}
          onOpenHotkeys={() => setHkOpen(true)}
          onNavigate={navigate}
        />
        {!online && (
          <div
            role="status"
            className="flex items-center gap-2 bg-status-warning/15 text-status-warning border-b border-status-warning/30 px-4 py-2 text-sm"
          >
            <WifiOff className="h-4 w-4 shrink-0" />
            You are offline. Live updates and mutations will fail until connectivity returns.
          </div>
        )}
        <main className="flex-1 min-h-0 overflow-y-auto">
          {/* Every page renders here → inherits padding, max-width, fade-in. */}
          <div className="p-6 max-w-[1600px] mx-auto animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>

      <CommandPaletteProvider />
      <HotkeysHelp open={hkOpen} onOpenChange={setHkOpen} />
    </div>
  );
}

function BrandMark() {
  // Official Constellation mark (public/constellation-mark.svg).
  return <img src="/constellation-mark.svg?v=2" alt="Constellation" className="w-7 h-7 flex-shrink-0" />;
}

function SidebarGroup({
  group,
  pathname,
  clusterId,
  collapsed,
  open,
  onToggle,
}: {
  group: NavGroup;
  pathname: string;
  clusterId: string | null;
  collapsed: boolean;
  open: boolean;
  onToggle: () => void;
}) {
  // Collapsed rail: no group header, icon-only rows.
  if (collapsed) {
    return (
      <div className="space-y-px">
        {group.items.map((item) => (
          <SidebarRow key={item.path} item={item} pathname={pathname} clusterId={clusterId} collapsed />
        ))}
      </div>
    );
  }

  return (
    <div className="mb-1">
      <button
        type="button"
        onClick={onToggle}
        className="w-full flex items-center justify-between px-3 py-2 text-sm font-semibold text-muted-foreground hover:text-foreground transition-colors"
      >
        <span className="truncate">{group.label}</span>
        {open ? <ChevronUp className="h-3.5 w-3.5 flex-shrink-0" /> : <ChevronDown className="h-3.5 w-3.5 flex-shrink-0" />}
      </button>
      {open && (
        <div className="space-y-px">
          {group.items.map((item) => (
            <SidebarRow key={item.path} item={item} pathname={pathname} clusterId={clusterId} collapsed={false} />
          ))}
        </div>
      )}
    </div>
  );
}

function SidebarRow({
  item,
  pathname,
  clusterId,
  collapsed,
}: {
  item: NavItem;
  pathname: string;
  clusterId: string | null;
  collapsed: boolean;
}) {
  const Icon = item.icon;
  const to = resolveTo(item, clusterId);
  const active = isItemActive(item, pathname, clusterId);

  if (collapsed) {
    return (
      <NavLink
        to={to}
        className={cn("nav-item group justify-center px-0", active && "active")}
        title={item.label}
      >
        <Icon className={cn("h-4 w-4 flex-shrink-0", active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground")} />
      </NavLink>
    );
  }

  return (
    <NavLink
      to={to}
      data-testid={`nav-${item.path.replace(/[\/]/g, "-")}`}
      className={cn(
        "group flex items-center gap-2 px-3 py-1.5 mx-1 rounded-md text-sm transition-colors",
        active
          ? "bg-accent text-foreground font-medium"
          : "text-muted-foreground hover:text-foreground hover:bg-accent/50",
      )}
    >
      <Icon className={cn("h-4 w-4 flex-shrink-0", active ? "text-foreground" : "text-muted-foreground group-hover:text-foreground")} />
      <span className="truncate flex-1">{item.label}</span>
    </NavLink>
  );
}

function TopHeader({
  pathname,
  clusterId,
  theme,
  onToggleTheme,
  onLogout,
  userEmail,
  userRole,
  onLaunchPalette,
  onOpenHotkeys,
  onNavigate,
}: {
  pathname: string;
  clusterId: string | null;
  theme: string;
  onToggleTheme: () => void;
  onLogout: () => void;
  userEmail?: string;
  userRole?: string;
  onLaunchPalette: () => void;
  onOpenHotkeys: () => void;
  onNavigate: (to: string) => void;
}) {
  const crumbs = useCrumbs(pathname, clusterId);
  return (
    <header
      className="sticky top-0 z-30 flex items-center justify-between h-14 px-6 border-b border-border bg-background/80 backdrop-blur-lg"
      role="banner"
    >
      {/* Left — breadcrumbs */}
      <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-sm min-w-0" data-testid="breadcrumbs">
        {crumbs.map((c, i) => (
          <div key={i} className="flex items-center gap-1.5 min-w-0">
            {i > 0 && <ChevronRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />}
            {i === crumbs.length - 1 ? (
              <span className="text-foreground font-medium truncate">{c.label}</span>
            ) : c.to ? (
              <Link to={c.to} className="text-muted-foreground hover:text-foreground transition-colors truncate">{c.label}</Link>
            ) : (
              <span className="text-muted-foreground truncate">{c.label}</span>
            )}
          </div>
        ))}
      </nav>

      {/* Center — search (opens command palette) */}
      <div className="hidden md:flex flex-1 justify-center px-6">
        <button
          type="button"
          onClick={onLaunchPalette}
          className="relative flex w-full max-w-xs items-center h-8 pl-8 pr-12 rounded-md border border-border bg-background text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          aria-label="Search resources"
        >
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <span className="truncate">Search resources…</span>
          <kbd className="absolute right-2 top-1/2 -translate-y-1/2 hidden md:inline-flex items-center px-1.5 py-0.5 rounded border border-border text-[10px] text-muted-foreground font-mono">/</kbd>
        </button>
      </div>

      {/* Right cluster */}
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onLaunchPalette}
          className="inline-flex items-center gap-1.5 h-8 px-2.5 rounded-md border border-border text-xs text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          aria-label="Open command palette"
        >
          <CmdIcon className="h-3.5 w-3.5" />
          <Kbd combo="Mod+k" />
        </button>

        <button
          type="button"
          onClick={onToggleTheme}
          className="inline-flex items-center justify-center h-8 w-8 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          title="Toggle theme"
        >
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>

        <NotificationBell onNavigate={onNavigate} />

        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <button
              type="button"
              aria-label="User menu"
              className="flex items-center gap-2 h-8 pl-1 pr-2 rounded-md hover:bg-accent transition-colors"
            >
              <span className="grid h-6 w-6 place-items-center rounded-full bg-gradient-to-br from-zinc-600 to-zinc-800">
                <User className="h-3 w-3 text-zinc-300" />
              </span>
              <ChevronDown className="h-3 w-3 text-muted-foreground" />
            </button>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              sideOffset={6}
              align="end"
              className="z-50 w-56 rounded-lg border border-border bg-popover shadow-xl overflow-hidden"
            >
              <div className="px-3 py-2.5 border-b border-border">
                <p className="text-sm font-medium text-foreground truncate">{userEmail ?? "Anonymous"}</p>
                <p className="text-xs text-muted-foreground truncate">{userRole ?? "unauthenticated"}</p>
              </div>
              <div className="p-1">
                <MenuItem onSelect={() => onNavigate("/settings")} icon={<Settings className="h-4 w-4" />}>Settings</MenuItem>
                <MenuItem onSelect={onOpenHotkeys} icon={<CmdIcon className="h-4 w-4" />} shortcut="?">Keyboard shortcuts</MenuItem>
                <MenuItem onSelect={() => onNavigate("/coverage")} icon={<Compass className="h-4 w-4" />}>Feature coverage</MenuItem>
                <DropdownMenu.Separator className="my-1 h-px bg-border" />
                <MenuItem onSelect={onLogout} icon={<LogOut className="h-4 w-4" />} destructive>Sign out</MenuItem>
              </div>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
      </div>
    </header>
  );
}

function MenuItem({
  icon,
  children,
  onSelect,
  destructive,
  shortcut,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
  onSelect: () => void;
  destructive?: boolean;
  shortcut?: string;
}) {
  return (
    <DropdownMenu.Item
      onSelect={onSelect}
      className={cn(
        "flex items-center gap-2.5 rounded-md px-3 py-2 text-sm cursor-pointer outline-none",
        "text-muted-foreground data-[highlighted]:text-foreground data-[highlighted]:bg-accent",
        destructive && "text-[color:var(--color-destructive)] data-[highlighted]:text-[color:var(--color-destructive)]",
      )}
    >
      <span className={cn(destructive ? "" : "text-muted-foreground")}>{icon}</span>
      <span className="flex-1">{children}</span>
      {shortcut && <Kbd combo={shortcut} />}
    </DropdownMenu.Item>
  );
}

function NotificationBell({ onNavigate }: { onNavigate: (to: string) => void }) {
  const q = useQuery({
    queryKey: ["bell-feed"],
    queryFn: () => findingsApi.list({ lifecycle: "open", limit: 50 }),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  // Runtime threats (DLP/WAF/IPS) so the bell isn't findings-only — surface recent
  // high-severity runtime detections alongside vuln findings.
  const rtQ = useQuery({
    queryKey: ["bell-runtime"],
    queryFn: () => runtimeThreatsApi.list({ hours: 24, severity_min: 4 }),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const items = useMemo(() => {
    const all = q.data?.findings ?? [];
    return all
      .filter((f) => f.severity === "critical" || f.severity === "high")
      .sort((a, b) => +new Date(b.last_seen_at) - +new Date(a.last_seen_at))
      .slice(0, 10);
  }, [q.data]);
  const rtItems = useMemo(() => {
    return (rtQ.data ?? [])
      .slice()
      .sort((a, b) => +new Date(b.reported_at) - +new Date(a.reported_at))
      .slice(0, 6);
  }, [rtQ.data]);
  const count = items.length + rtItems.length;

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          className="relative inline-flex items-center justify-center h-8 w-8 rounded-md text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          aria-label={`Notifications · ${count}`}
        >
          <Bell className="h-4 w-4" />
          {count > 0 && (
            <span className="absolute top-0.5 right-0.5 grid place-items-center min-w-[16px] h-4 px-1 rounded-full bg-status-error text-[10px] font-bold text-white">
              {count > 99 ? "99+" : count}
            </span>
          )}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          sideOffset={8}
          align="end"
          className="z-50 w-80 rounded-lg border border-border bg-popover shadow-xl overflow-hidden"
        >
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <h4 className="text-sm font-medium text-foreground">Attention needed</h4>
            <button
              type="button"
              onClick={() => onNavigate("/clusters")}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              view all
            </button>
          </div>
          {items.length === 0 && rtItems.length === 0 && (
            <div className="px-4 py-6 text-center text-xs text-muted-foreground">All clear. No high-severity findings or runtime threats.</div>
          )}
          {rtItems.length > 0 && (
            <ul className="max-h-40 overflow-auto border-b border-border">
              {rtItems.map((t) => (
                <li key={t.id}>
                  <button
                    type="button"
                    onClick={() => onNavigate(t.cluster_id ? `/clusters/${t.cluster_id}/runtime` : "/clusters")}
                    className="w-full text-left flex items-start gap-3 px-4 py-3 border-b border-border last:border-0 hover:bg-accent/50 transition-colors"
                  >
                    <span className="mt-0.5 rounded bg-[color-mix(in_oklab,var(--color-severity-high)_18%,transparent)] px-1 text-[9px] uppercase text-[color:var(--color-severity-high)]">runtime</span>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm truncate text-foreground">{t.threat_name || `Threat ${t.threat_id}`}</div>
                      <div className="text-xs text-muted-foreground font-mono">
                        {(t.workload_id || t.pod_name || t.namespace || "").toString().slice(0, 28)} · {fmtRelative(t.reported_at)}
                      </div>
                    </div>
                  </button>
                </li>
              ))}
            </ul>
          )}
          <ul className="max-h-80 overflow-auto">
            {items.map((f) => (
              <li key={f.id}>
                <button
                  type="button"
                  onClick={() => {
                    if (f.cluster_id) onNavigate(`/clusters/${f.cluster_id}/findings/${f.id}`);
                    else onNavigate("/clusters");
                  }}
                  className="w-full text-left flex items-start gap-3 px-4 py-3 border-b border-border last:border-0 hover:bg-accent/50 transition-colors"
                >
                  <SeverityBadge severity={f.severity} size="xs" />
                  <div className="min-w-0 flex-1">
                    <div className="text-sm truncate text-foreground">{f.title}</div>
                    <div className="text-xs text-muted-foreground font-mono">
                      {f.external_id ?? f.id.slice(0, 8)} · {fmtRelative(f.last_seen_at)}
                    </div>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

// ─────────────────────────── Crumbs ───────────────────────────

function useCrumbs(pathname: string, clusterId: string | null): Array<{ label: string; to?: string }> {
  // Cached cluster list — populated by ClustersLandingPage + ClusterSwitcher.
  const list = useQuery({
    queryKey: ["clusters"],
    queryFn: () => clustersApi.list(),
    staleTime: 30_000,
    enabled: clusterId !== null,
  });

  if (clusterId) {
    const cluster = list.data?.clusters.find((c) => c.id === clusterId);
    const out: Array<{ label: string; to?: string }> = [
      { label: "Clusters", to: "/clusters" },
      { label: cluster?.name ?? clusterId.slice(0, 8), to: `/clusters/${clusterId}/dashboard` },
    ];
    const m = pathname.match(/^\/clusters\/[^/]+\/(.+)$/);
    if (m) {
      const segs = m[1].split("/");
      out.push({ label: toTitle(segs[0]) });
      for (let i = 1; i < segs.length; i++) {
        const seg = segs[i];
        const isId = seg.includes("-") || seg.length >= 8;
        out.push({ label: isId ? seg.slice(0, 10) + (seg.length > 10 ? "…" : "") : toTitle(seg) });
      }
    }
    return out;
  }

  // Org mode
  const parts = pathname.split("/").filter(Boolean);
  if (parts.length === 0) return [{ label: "Clusters" }];
  const out: Array<{ label: string; to?: string }> = [];
  out.push({ label: toTitle(parts[0]), to: `/${parts[0]}` });
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    const isId = seg.includes("-") || seg.length >= 8;
    out.push({ label: isId ? seg.slice(0, 10) + (seg.length > 10 ? "…" : "") : toTitle(seg) });
  }
  return out;
}

function toTitle(s: string): string {
  return s.replace(/[-_]/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
