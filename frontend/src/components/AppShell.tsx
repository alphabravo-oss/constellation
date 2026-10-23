// AppShell — Constellation on the shared kit shell (C1 "Triage Desk").
//
// Sidebar: the kit's rail (organization scope) + panel (organization pages, or
// the cluster's six groups). Header: cluster scope chip + "System workloads"
// scope switch + breadcrumbs (names, never ids) · one search · theme,
// notifications, account. Content: contained, or full-bleed for dense tables,
// logs and the network map.
import { useEffect, useMemo, useRef, useState, type ComponentType, type ReactNode } from "react";
import { Outlet, useLocation, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Bell,
  ChevronDown,
  Compass,
  Keyboard,
  LogOut,
  Settings,
  User,
  type LucideProps,
} from "lucide-react";

import { useAuth } from "@/contexts/AuthContext";
import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { findings as findingsApi, clusters as clustersApi, runtimeThreats as runtimeThreatsApi } from "@/api/client";
import { findingHref, findingRowKey } from "@/lib/finding-instance";
import { fmtRelative } from "@/lib/format";
import { sortClustersByActivity } from "@/lib/clusters";
import { useCrumbLabels } from "@/lib/page-title";
import { useIncludeSystemPreference } from "@/lib/system-scope";
import { useRouteSearchParams } from "@/lib/route-search";
import { cn } from "@/lib/cn";
import { CommandPaletteProvider, HotkeysHelp, openCommandPalette } from "@/components/CommandPalette";
import { ClusterSwitcher, clusterStateTone } from "@/components/ClusterSwitcher";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  activeClusterItem,
  activeOrgItem,
  CLUSTER_NAV,
  clusterHref,
  clusterIdFromPath,
  ORG_NAV,
  segmentLabel,
} from "@/components/shell/nav-model";
import {
  AppShell as KitAppShell,
  Breadcrumbs,
  Header,
  HeaderIconButton,
  Menu,
  MenuContent,
  MenuItem,
  MenuLabel,
  MenuSeparator,
  MenuTrigger,
  Popover,
  PopoverContent,
  PopoverTrigger,
  Rail,
  RailItem,
  SearchTrigger,
  SidebarBrand,
  SidebarFrame,
  SidebarGroup,
  SidebarItem,
  StatusDot,
  ThemeToggle,
  Tooltip,
  type BreadcrumbItem,
  type ContentLayout,
  Form,
} from "@/ui";

const COLLAPSE_KEY = "constellation.sidebar.collapsed";

/** Dense tables, logs and graphs use the full content width. */
const FULL_BLEED = [
  /^\/clusters\/[^/]+\/(findings|nodes|containers|deployments|images|network|network-rules|runtime|timeline|assets|registries|audit)\/?$/,
  /^\/cve\/?$/,
  /^\/organization\/audit\/?$/,
];

function contentLayoutFor(pathname: string): ContentLayout {
  return FULL_BLEED.some((pattern) => pattern.test(pathname)) ? "full-bleed" : "contained";
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

export function AppShell({ children }: { children?: ReactNode } = {}) {
  const { pathname } = useLocation();
  const online = useOnline();
  const mainRef = useRef<HTMLElement>(null);
  const [collapsed, setCollapsed] = useState<boolean>(() => {
    try {
      const stored = localStorage.getItem(COLLAPSE_KEY);
      if (stored === "1") return true;
      if (stored === "0") return false;
    } catch {
      // Storage unavailable: fall through to the viewport default.
    }
    return typeof window !== "undefined" && window.innerWidth < 1024;
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  useEffect(() => {
    try {
      localStorage.setItem(COLLAPSE_KEY, collapsed ? "1" : "0");
    } catch {
      // Best effort.
    }
  }, [collapsed]);
  useEffect(() => {
    setMobileOpen(false);
    // Move focus to the page on navigation so keyboard users land in content.
    mainRef.current?.focus({ preventScroll: true });
  }, [pathname]);

  const [hotkeysOpen, setHotkeysOpen] = useState(false);
  useEffect(() => {
    const handler = () => setHotkeysOpen(true);
    window.addEventListener("constellation:show-hotkeys", handler);
    return () => window.removeEventListener("constellation:show-hotkeys", handler);
  }, []);

  return (
    <KitAppShell
      sidebar={
        <ConstellationSidebar
          pathname={pathname}
          collapsed={collapsed && !mobileOpen}
          mobileOpen={mobileOpen}
          onToggleCollapsed={() => setCollapsed((value) => !value)}
          onCloseMobile={() => setMobileOpen(false)}
        />
      }
      header={<TopHeader pathname={pathname} onOpenMobileNav={() => setMobileOpen(true)} onOpenHotkeys={() => setHotkeysOpen(true)} />}
      offline={!online}
      contentLayout={contentLayoutFor(pathname)}
      mainRef={mainRef}
      overlays={
        <>
          <CommandPaletteProvider />
          <HotkeysHelp open={hotkeysOpen} onOpenChange={setHotkeysOpen} />
        </>
      }
    >
      {children ?? <Outlet />}
    </KitAppShell>
  );
}

// ─────────────────────────── Sidebar ───────────────────────────

function ConstellationSidebar({
  pathname,
  collapsed,
  mobileOpen,
  onToggleCollapsed,
  onCloseMobile,
}: {
  pathname: string;
  collapsed: boolean;
  mobileOpen: boolean;
  onToggleCollapsed: () => void;
  onCloseMobile: () => void;
}) {
  const { me } = useAuth();
  const orgNav = ORG_NAV.filter(item => item.path !== "/settings" || me?.roles.some(role=>["GlobalAdmin","SecurityAdmin","ClusterAdmin"].includes(role)));
  const clusterId = clusterIdFromPath(pathname);
  const orgActive = activeOrgItem(pathname);
  const clusterActive = clusterId ? activeClusterItem(pathname, clusterId) : undefined;

  const rail = (
    <Rail className="w-(--rail-w) shrink-0">
      {orgNav.map((item) => (
        <RailItem
          key={item.path}
          to={item.path}
          icon={item.icon}
          label={item.label}
          active={orgActive?.path === item.path}
        />
      ))}
    </Rail>
  );

  const panel = clusterId ? (
    <ClusterPanel clusterId={clusterId} activePath={clusterActive?.path} />
  ) : (
    <OrgPanel pathname={pathname} activePath={orgActive?.path} />
  );

  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation"
          className="fixed inset-0 z-overlay bg-black/40 lg:hidden"
          onClick={onCloseMobile}
        />
      )}
      <SidebarFrame
        collapsed={collapsed}
        mobileOpen={mobileOpen}
        onToggleCollapsed={onToggleCollapsed}
        navLabel={clusterId ? "Cluster" : "Primary"}
        brand={<SidebarBrand to="/clusters" subtitle="by AlphaBravo" />}
        className={cn(!collapsed && "w-[calc(var(--rail-w)+var(--sidebar-w))] lg:w-[calc(var(--rail-w)+var(--sidebar-w))]")}
        context={clusterId && !collapsed ? <ClusterPanelHeader clusterId={clusterId} /> : null}
      >
        {collapsed ? (
          rail
        ) : (
          <div className="flex h-full items-stretch">
            <div className="-mb-2 -ml-2 -mt-2 flex shrink-0 flex-col border-r border-sidebar-border pt-2">{rail}</div>
            <div className="min-w-0 flex-1 pl-2">{panel}</div>
          </div>
        )}
      </SidebarFrame>
    </>
  );
}

function ClusterPanelHeader({ clusterId }: { clusterId: string }) {
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clustersApi.list(), staleTime: 30_000 });
  const cluster = list.data?.clusters.find((c) => c.id === clusterId);
  const version = cluster?.platform?.kubernetes_git_version;
  return (
    <div className="flex items-start">
      <div className="w-(--rail-w) shrink-0" />
      <div className="min-w-0 flex-1 border-b border-l border-sidebar-border px-4 py-2.5" data-testid="cluster-panel-header">
        <p className="truncate text-sm font-semibold text-foreground">{cluster?.name ?? "Cluster"}</p>
        <div className="mt-0.5 flex items-center gap-2 text-micro text-muted-foreground">
          <StatusDot tone={clusterStateTone(cluster?.state)} label={cluster?.state ? sentence(cluster.state) : "Unknown"} className="text-micro" />
          {version ? <span className="font-mono">{version}</span> : null}
        </div>
      </div>
    </div>
  );
}

function ClusterPanel({ clusterId, activePath }: { clusterId: string; activePath?: string }) {
  return (
    <div data-testid="cluster-panel">
      {CLUSTER_NAV.map((group) => (
        <SidebarGroup key={group.id} label={group.label}>
          {group.items.map((item) => (
            <SidebarItem
              key={item.path}
              to={clusterHref(clusterId, item)}
              icon={item.icon}
              label={<span data-testid={item.testId ?? `nav-${item.path.replace(/\//g, "-")}`}>{item.label}</span>}
              active={activePath === item.path}
            />
          ))}
        </SidebarGroup>
      ))}
    </div>
  );
}

function OrgPanel({ pathname, activePath }: { pathname: string; activePath?: string }) {
 const { me } = useAuth();
 const orgNav = ORG_NAV.filter(item => item.path !== "/settings" || me?.roles.some(role=>["GlobalAdmin","SecurityAdmin","ClusterAdmin"].includes(role)));
  const list = useQuery({ queryKey: ["clusters"], queryFn: () => clustersApi.list(), staleTime: 30_000 });
  const clusters = useMemo(() => sortClustersByActivity(list.data?.clusters ?? []).slice(0, 12), [list.data]);
  return (
    <div data-testid="org-panel">
      <SidebarGroup label="Organization">
        {orgNav.map((item) => (
          <SidebarItem
            key={item.path}
            to={item.path}
            icon={item.icon}
            label={<span data-testid={item.testId ?? `nav-${item.path.replace(/\//g, "-").replace(/^-/, "")}`}>{item.label}</span>}
            active={activePath === item.path}
          />
        ))}
      </SidebarGroup>
      {clusters.length > 0 && (
        <SidebarGroup label="Clusters">
          {clusters.map((cluster) => (
            <SidebarItem
              key={cluster.id}
              to={`/clusters/${cluster.id}/dashboard`}
              icon={dotIcon(clusterStateTone(cluster.state))}
              label={<span data-testid={`org-panel-cluster-${cluster.id}`}>{cluster.name}</span>}
              active={pathname.startsWith(`/clusters/${cluster.id}/`)}
            />
          ))}
        </SidebarGroup>
      )}
    </div>
  );
}

const dotIcons = new Map<string, ComponentType<LucideProps>>();
/** A status dot in the icon slot: cluster rows are instances, not destinations. */
function dotIcon(tone: string): ComponentType<LucideProps> {
  const cached = dotIcons.get(tone);
  if (cached) return cached;
  const Icon = ({ className }: LucideProps) => (
    <span aria-hidden className={cn("flex items-center justify-center", className)}>
      <span className={cn("h-2 w-2 rounded-full", `bg-status-${tone}`)} />
    </span>
  );
  dotIcons.set(tone, Icon);
  return Icon;
}

// ─────────────────────────── Header ───────────────────────────

function TopHeader({
  pathname,
  onOpenMobileNav,
  onOpenHotkeys,
}: {
  pathname: string;
  onOpenMobileNav: () => void;
  onOpenHotkeys: () => void;
}) {
  const clusterId = clusterIdFromPath(pathname);
  const crumbs = useBreadcrumbs(pathname, clusterId);
  return (
    <Header
      onOpenMobileNav={onOpenMobileNav}
      scope={
        <>
          {clusterId ? <ClusterSwitcher /> : null}
          <SystemScopeSwitch />
          {crumbs.length >= 2 ? <span aria-hidden className="mx-1 hidden h-5 w-px bg-border sm:block" /> : null}
        </>
      }
      breadcrumbs={<Breadcrumbs items={crumbs} />}
      search={
        <SearchTrigger
          onOpen={openCommandPalette}
          placeholder="Search pages, findings, assets…"
        />
      }
      actions={
        <>
          <ThemeToggle />
          <NotificationBell />
          <AccountMenu onOpenHotkeys={onOpenHotkeys} />
        </>
      }
    />
  );
}

/** Header scope switch: include Constellation/Kubernetes system workloads. */
function SystemScopeSwitch() {
  const [preference, setPreference] = useIncludeSystemPreference();
  const [params, setParams] = useRouteSearchParams();
  const explicit = params.get("include_system");
  const value = explicit === "true" ? true : explicit === "false" ? false : preference;
  const id = "header-system-scope";
  return (
    <Tooltip content="Include Constellation and Kubernetes system workloads in findings, inventories and the network map">
      <div className="flex h-8 shrink-0 items-center gap-2 rounded-md border border-border px-2" data-testid="system-scope">
        <Form.Switch
          id={id}
          size="sm"
          checked={value}
          aria-label="Include system workloads"
          data-testid="system-scope-switch"
          onCheckedChange={(next) => {
            setPreference(next);
            if (params.has("include_system") || params.has("hide_platform")) {
              setParams((current) => {
                current.delete("include_system");
                current.delete("hide_platform");
                return current;
              });
            }
          }}
        />
        <label htmlFor={id} className="hidden cursor-pointer whitespace-nowrap text-meta text-muted-foreground xl:block">
          System workloads
        </label>
      </div>
    </Tooltip>
  );
}

function useBreadcrumbs(pathname: string, clusterId: string | null): BreadcrumbItem[] {
  const labels = useCrumbLabels();
  return useMemo(() => {
    const trail: BreadcrumbItem[] = [];
    if (clusterId) {
      const base = `/clusters/${clusterId}`;
      trail.push({ label: "All clusters", to: "/clusters" });
      const rest = pathname.slice(base.length).split("/").filter(Boolean);
      const owner = activeClusterItem(pathname, clusterId);
      if (rest.length === 0) {
        trail.push({ label: "Overview" });
        return trail;
      }
      let path = base;
      rest.forEach((segment, index) => {
        path += `/${segment}`;
        const parent = rest[index - 1];
        // The first segment is the section: label it from the nav registry.
        const label =
          labels.get(path) ??
          (index === 0 && owner ? owner.label : segmentLabel(segment, parent));
        // Skip intermediate verbs ("rules", "actions") that are not pages.
        trail.push(index === rest.length - 1 ? { label } : { label, to: path });
      });
      return dedupe(trail);
    }
    const parts = pathname.split("/").filter(Boolean);
    if (parts.length === 0) return [{ label: "Clusters" }];
    let path = "";
    parts.forEach((segment, index) => {
      path += `/${segment}`;
      const parent = parts[index - 1];
      const label = labels.get(path) ?? segmentLabel(segment, parent);
      const linkable = !(segment === "organization");
      trail.push(index === parts.length - 1 ? { label } : linkable ? { label, to: path } : { label });
    });
    return dedupe(trail);
  }, [clusterId, labels, pathname]);
}

/** Collapse consecutive duplicates ("Policies › Policies"). */
function dedupe(trail: BreadcrumbItem[]): BreadcrumbItem[] {
  return trail.filter((crumb, index) => index === 0 || crumb.label !== trail[index - 1].label);
}

function sentence(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1).replace(/_/g, " ");
}

// ─────────────────────────── Account + notifications ───────────────────────────

function AccountMenu({ onOpenHotkeys }: { onOpenHotkeys: () => void }) {
  const { me, logout } = useAuth();
  const navigate = useNavigate();
  return (
    <Menu modal={false}>
      <MenuTrigger asChild>
        <button
          type="button"
          aria-label={me?.email ? `User menu ${me.email}` : "User menu"}
          data-testid="user-menu-trigger"
          className="flex h-8 items-center gap-1.5 rounded-md pl-1 pr-1.5 transition-colors hover:bg-accent focus-visible:outline-hidden focus-visible:ring-2 focus-visible:ring-ring"
        >
          <span className="flex h-6 w-6 items-center justify-center rounded-full bg-muted text-muted-foreground">
            <User className="h-3.5 w-3.5" />
          </span>
          <ChevronDown className="h-3 w-3 text-muted-foreground" />
        </button>
      </MenuTrigger>
      <MenuContent className="w-60">
        <MenuLabel className="space-y-0.5">
          <span className="block truncate text-sm font-medium text-foreground" data-testid="identity-email">
            {me?.email ?? "Signed out"}
          </span>
          <span className="block truncate text-meta font-normal" data-testid="identity-roles">
            {me?.roles?.[0] ? sentence(me.roles[0]) : "No role"}
          </span>
        </MenuLabel>
        <MenuSeparator />
        {me?.roles.some(role=>["GlobalAdmin","SecurityAdmin","ClusterAdmin"].includes(role)) && <MenuItem onSelect={() => void navigate({ href: "/settings" })}>
          <Settings className="h-4 w-4" />
          Settings
        </MenuItem>}
        <MenuItem onSelect={onOpenHotkeys}>
          <Keyboard className="h-4 w-4" />
          <span className="flex-1">Keyboard shortcuts</span>
          <kbd className="font-mono text-micro text-muted-foreground">?</kbd>
        </MenuItem>
        <MenuItem onSelect={() => void navigate({ href: "/coverage" })}>
          <Compass className="h-4 w-4" />
          Feature coverage
        </MenuItem>
        <MenuSeparator />
        <MenuItem
          data-testid="sign-out"
          onSelect={() => {
            void logout().catch(() => toast.error("Sign out could not be confirmed. Try again."));
          }}
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </MenuItem>
      </MenuContent>
    </Menu>
  );
}

function NotificationBell() {
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);
  const operator = useTablePreferencesIdentity();
  const owner = `${operator?.org_id}:${operator?.user_id}`;
  const findingsQuery = useQuery({
    queryKey: ["bell-feed", owner],
    enabled: !!operator?.org_id && !!operator?.user_id,
    queryFn: () => findingsApi.list({ lifecycle: "open", limit: 50 }),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const runtimeQuery = useQuery({
    queryKey: ["bell-runtime", owner],
    queryFn: () => runtimeThreatsApi.list({ hours: 24, severity_min: 4 }),
    staleTime: 30_000,
    refetchInterval: 60_000,
  });
  const items = useMemo(
    () =>
      (findingsQuery.data?.findings ?? [])
        .filter((f) => f.severity === "critical" || f.severity === "high")
        .sort((a, b) => +new Date(b.last_seen_at) - +new Date(a.last_seen_at))
        .slice(0, 10),
    [findingsQuery.data],
  );
  const runtimeItems = useMemo(
    () => (runtimeQuery.data ?? []).slice().sort((a, b) => +new Date(b.reported_at) - +new Date(a.reported_at)).slice(0, 6),
    [runtimeQuery.data],
  );
  const count = items.length + runtimeItems.length;
  const go = (href: string) => {
    setOpen(false);
    void navigate({ href });
  };
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <HeaderIconButton aria-label={count > 0 ? `Notifications, ${count} need attention` : "Notifications"}>
          <Bell className="h-4 w-4" />
          {count > 0 ? (
            // Count chip with theme-aware text (white on the light error tone,
            // near-black on the lighter dark-mode tone) so it clears AA in both.
            <span aria-hidden className="absolute right-0.5 top-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-status-error px-1 text-micro font-semibold text-background">
              {count > 99 ? "99+" : count}
            </span>
          ) : null}
        </HeaderIconButton>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-80 max-w-[calc(100vw-1.5rem)] overflow-hidden rounded-lg p-0">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 className="text-sm font-medium text-foreground">Needs attention</h2>
          <span className="text-meta text-muted-foreground">{count > 0 ? `${count} items` : "All clear"}</span>
        </div>
        <div className="max-h-96 overflow-y-auto">
          {count === 0 && (
            <p className="px-4 py-8 text-center text-sm text-muted-foreground">No high-severity findings or runtime threats.</p>
          )}
          {runtimeItems.map((threat) => (
            <button
              key={threat.id}
              type="button"
              onClick={() => go(threat.cluster_id ? `/clusters/${threat.cluster_id}/runtime` : "/clusters")}
              className="flex w-full items-start gap-3 border-b border-border px-4 py-3 text-left transition-colors last:border-0 hover:bg-accent/50"
            >
              <span className="mt-0.5 inline-flex h-5 shrink-0 items-center rounded-full bg-muted px-2 text-micro font-semibold text-foreground">Runtime</span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-foreground">{threat.threat_name || `Threat ${threat.threat_id}`}</span>
                <span className="block truncate text-meta text-muted-foreground">
                  {(threat.workload_id || threat.pod_name || threat.namespace || "").toString()} · {fmtRelative(threat.reported_at)}
                </span>
              </span>
            </button>
          ))}
          {items.map((finding) => (
            <button
              key={findingRowKey(finding)}
              type="button"
              onClick={() => go(finding.cluster_id || finding.source_cluster_id || finding.target_cluster_id ? findingHref(finding) : "/clusters")}
              className="flex w-full items-start gap-3 border-b border-border px-4 py-3 text-left transition-colors last:border-0 hover:bg-accent/50"
            >
              <SeverityBadge severity={finding.severity} className="mt-0.5 shrink-0" />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm text-foreground">{finding.title}</span>
                <span className="block truncate font-mono text-meta text-muted-foreground">
                  {finding.external_id ?? "Finding"} · {fmtRelative(finding.last_seen_at)}
                </span>
              </span>
            </button>
          ))}
        </div>
      </PopoverContent>
    </Popover>
  );
}
