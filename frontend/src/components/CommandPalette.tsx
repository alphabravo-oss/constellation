import { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import { Command } from "cmdk";
import {
  Search,
  LayoutDashboard,
  AlertTriangle,
  Boxes,
  Network,
  Database,
  FileText,
  ShieldCheck,
  Activity,
  Sparkles,
  ArrowRight,
  Sun,
  Moon,
  HelpCircle,
  Compass,
  Bug,
  Server,
  Settings,
  Clock,
  PackageSearch,
  Layers,
  CloudCog,
  GitBranch,
  ScanSearch,
  ClipboardCheck,
  RadioTower,
  ScrollText,
  KeyRound,
  BadgeCheck,
  Plug,
} from "lucide-react";

import { useHotkey, HOTKEY_CATALOG } from "@/lib/hotkeys";
import { useTheme } from "@/contexts/ThemeContext";
import { findings, assets, imageScanResults, nodes as nodesApi, policies, deployments as deploymentsApi, serverlessFunctions, repositoryScans } from "@/api/client";
import { Kbd } from "@/components/ui/kbd";

const RECENT_KEY = "constellation.cmdk.recent.v1";

interface RecentItem { id: string; label: string; href: string; ts: number }

function loadRecent(): RecentItem[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as RecentItem[];
  } catch { return []; }
}
function pushRecent(item: Omit<RecentItem, "ts">) {
  const cur = loadRecent().filter((i) => i.id !== item.id);
  cur.unshift({ ...item, ts: Date.now() });
  const trimmed = cur.slice(0, 8);
  try { localStorage.setItem(RECENT_KEY, JSON.stringify(trimmed)); } catch { /* noop */ }
}

/**
 * CommandPalette — Cmd+K typeahead jumping to pages and entities.
 *
 * Sources:
 *   - Static navigation
 *   - Recent items (localStorage)
 *   - Findings list (id substring or title)
 *   - Assets list (name or id)
 *   - Policies list
 *   - Quick actions (toggle theme, density, CVE lookup, etc.)
 */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { theme, toggle: toggleTheme } = useTheme();
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const clusterId = clusterIDFromPath(location.pathname);

  // Reset query when reopened, focus input on open
  useEffect(() => {
    if (open) {
      setQuery("");
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  // Load entity data lazily — only when palette is open
  const findingsQ = useQuery({
    queryKey: ["cmdk-findings", clusterId],
    queryFn: () => findings.list({ limit: 100, cluster_id: clusterId ?? undefined }),
    enabled: open,
    staleTime: 60_000,
  });
  const assetsQ = useQuery({
    queryKey: ["cmdk-assets", clusterId],
    queryFn: () => assets.list({ limit: 100, cluster_id: clusterId ?? undefined }),
    enabled: open,
    staleTime: 60_000,
  });
  const imageScansQ = useQuery({
    queryKey: ["cmdk-image-scans", clusterId],
    queryFn: () => imageScanResults.list({ cluster_id: clusterId ?? undefined, limit: 100 }),
    enabled: open && !!clusterId,
    staleTime: 60_000,
  });
  const nodesQ = useQuery({
    queryKey: ["cmdk-nodes", clusterId],
    queryFn: () => nodesApi.list(clusterId!),
    enabled: open && !!clusterId,
    staleTime: 60_000,
  });
  const policiesQ = useQuery({
    queryKey: ["cmdk-policies"],
    queryFn: () => policies.list(),
    enabled: open,
    staleTime: 60_000,
  });
  // M6: live-search workloads / serverless / repositories from the palette.
  const workloadsQ = useQuery({
    queryKey: ["cmdk-workloads", clusterId],
    queryFn: () => deploymentsApi.list({ limit: 100, cluster_id: clusterId ?? undefined }),
    enabled: open && !!clusterId,
    staleTime: 60_000,
  });
  const serverlessQ = useQuery({
    queryKey: ["cmdk-serverless"],
    queryFn: () => serverlessFunctions.list({ limit: 100 }),
    enabled: open,
    staleTime: 60_000,
  });
  const reposQ = useQuery({
    queryKey: ["cmdk-repos"],
    queryFn: () => repositoryScans.list({ limit: 100 }),
    enabled: open,
    staleTime: 60_000,
  });

  const recent = useMemo(loadRecent, [open]);

  const go = useCallback((href: string, label: string, id?: string) => {
    if (id) pushRecent({ id: id ?? href, label, href });
    onOpenChange(false);
    navigate(href);
  }, [navigate, onOpenChange]);
  const resolveHref = useCallback((href: string) => {
    if (clusterId && isClusterHref(href)) return `/clusters/${clusterId}${href}`;
    return href;
  }, [clusterId]);

  const isCVE = /^cve-\d{4}-\d+$/i.test(query.trim());

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-background/60 backdrop-blur-sm" />
        <Dialog.Content
          className="fixed left-1/2 top-[16%] z-50 w-[min(640px,92vw)] -translate-x-1/2 rounded-lg border border-border bg-popover shadow-[var(--elev-popover)] overflow-hidden"
          aria-label="Command palette"
          onOpenAutoFocus={(e) => e.preventDefault()}
        >
          <Dialog.Title className="sr-only">Command palette</Dialog.Title>
          <Dialog.Description className="sr-only">
            Type to search pages, findings, assets, workloads, serverless, repos, or run a quick action.
          </Dialog.Description>
          <Command shouldFilter loop className="flex flex-col">
            <div className="flex items-center gap-2 border-b border-border px-3 py-2.5">
              <Search className="h-4 w-4 text-muted-foreground" />
              <Command.Input
                ref={inputRef}
                value={query}
                onValueChange={setQuery}
                placeholder="Search pages, findings, CVEs, nodes, assets, workloads..."
                className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground/70"
              />
              <Kbd combo="Escape" />
            </div>
            <Command.List className="max-h-[420px] overflow-y-auto p-2">
              <Command.Empty>
                <div className="px-3 py-8 text-center text-xs text-muted-foreground">
                  No matches. Try a CVE ID, finding ID prefix, or page name.
                </div>
              </Command.Empty>

              {isCVE && (
                <Group heading="CVE Database">
                  <Item icon={<Bug />} onSelect={() => go(`/cve/${query.trim().toUpperCase()}`, query.trim().toUpperCase(), query.trim())}>
                    Open <span className="text-mono ml-1">{query.trim().toUpperCase()}</span>
                  </Item>
                </Group>
              )}

              {!query && recent.length > 0 && (
                <Group heading="Recent">
                  {recent.map((r) => (
                    <Item key={r.id} icon={<Clock />} onSelect={() => go(r.href, r.label, r.id)}>
                      <span className="flex-1 truncate">{r.label}</span>
                    </Item>
                  ))}
                </Group>
              )}

              <Group heading="Navigate">
                {NAV_ITEMS.map((n) => (
                  <Item key={n.href} icon={n.icon} onSelect={() => go(resolveHref(n.href), n.label)} shortcut={n.shortcut}>
                    <span>{n.label}</span>
                  </Item>
                ))}
              </Group>

              <Group heading="Quick Actions">
                <Item icon={theme === "dark" ? <Sun /> : <Moon />} onSelect={() => { toggleTheme(); onOpenChange(false); }}>
                  Toggle theme · currently <span className="text-mono ml-1">{theme}</span>
                </Item>
                <Item icon={<HelpCircle />} onSelect={() => { onOpenChange(false); window.dispatchEvent(new CustomEvent("constellation:show-hotkeys")); }} shortcut="?">
                  Show keyboard shortcuts
                </Item>
                <Item icon={<Compass />} onSelect={() => go("/posture", "Posture")}>
                  View posture
                </Item>
              </Group>

              {findingsQ.data?.findings && findingsQ.data.findings.length > 0 && (
                <Group heading="Findings">
                  {findingsQ.data.findings.slice(0, 8).map((f) => (
                    <Item key={f.id} icon={<AlertTriangle />} onSelect={() => go(f.cluster_id ? `/clusters/${f.cluster_id}/findings/${f.id}` : resolveHref(`/findings/${f.id}`), f.title, f.id)}>
                      <span className="flex-1 truncate">{f.title}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{f.external_id ?? f.id.slice(0, 6)}</span>
                    </Item>
                  ))}
                </Group>
              )}

              {imageScansQ.data?.image_scan_results && imageScansQ.data.image_scan_results.length > 0 && clusterId && (
                <Group heading="Images">
                  {imageScansQ.data.image_scan_results.slice(0, 6).map((image) => (
                    <Item key={image.id} icon={<PackageSearch />} onSelect={() => go(`/clusters/${clusterId}/images/${image.id}`, image.image_repository || image.image_digest, image.id)}>
                      <span className="flex-1 truncate">{image.image_repository || image.image_ref || image.image_digest}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{image.critical_count + image.high_count} high+</span>
                    </Item>
                  ))}
                </Group>
              )}

              {nodesQ.data?.items && nodesQ.data.items.length > 0 && clusterId && (
                <Group heading="Nodes">
                  {nodesQ.data.items.slice(0, 6).map((node) => (
                    <Item key={node.node} icon={<Server />} onSelect={() => go(`/clusters/${clusterId}/nodes/${encodeURIComponent(node.node)}`, node.node, `node:${node.node}`)}>
                      <span className="flex-1 truncate">{node.node}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{node.critical_vulns + node.high_vulns} high+</span>
                    </Item>
                  ))}
                </Group>
              )}

              {assetsQ.data?.assets && assetsQ.data.assets.length > 0 && (
                <Group heading="Assets">
                  {assetsQ.data.assets.slice(0, 6).map((a) => (
                    <Item key={a.id} icon={<Boxes />} onSelect={() => go(resolveHref(`/assets/${a.id}`), a.name, a.id)}>
                      <span className="flex-1 truncate">{a.name}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{a.kind}</span>
                    </Item>
                  ))}
                </Group>
              )}

              {policiesQ.data?.policies && policiesQ.data.policies.length > 0 && (
                <Group heading="Policies">
                  {policiesQ.data.policies.slice(0, 6).map((p) => (
                    <Item key={p.id} icon={<FileText />} onSelect={() => go(resolveHref("/policies"), p.name, p.id)}>
                      <span className="flex-1 truncate">{p.name}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{p.mode}</span>
                    </Item>
                  ))}
                </Group>
              )}

              {workloadsQ.data?.deployments && workloadsQ.data.deployments.length > 0 && clusterId && (
                <Group heading="Workloads">
                  {workloadsQ.data.deployments.slice(0, 6).map((d) => (
                    <Item key={d.id} icon={<Layers />} onSelect={() => go(`/clusters/${clusterId}/deployments/${d.id}`, d.name, d.id)}>
                      <span className="flex-1 truncate">{d.name}</span>
                      <span className="ml-2 text-[10px] text-mono text-muted-foreground">{d.namespace}</span>
                    </Item>
                  ))}
                </Group>
              )}

              {serverlessQ.data?.serverless_functions && serverlessQ.data.serverless_functions.length > 0 && clusterId && (
                <Group heading="Serverless">
                  {serverlessQ.data.serverless_functions.slice(0, 6).map((fn) => (
                    <Item key={fn.id} icon={<CloudCog />} onSelect={() => go(`/clusters/${clusterId}/serverless/${fn.id}`, fn.function_name || fn.id, fn.id)}>
                      <span className="flex-1 truncate">{fn.function_name || fn.id}</span>
                      {fn.provider && <span className="ml-2 text-[10px] text-mono text-muted-foreground">{fn.provider}</span>}
                    </Item>
                  ))}
                </Group>
              )}

              {reposQ.data?.repository_scans && reposQ.data.repository_scans.length > 0 && clusterId && (
                <Group heading="Repositories">
                  {reposQ.data.repository_scans.slice(0, 6).map((rp) => (
                    <Item key={rp.id} icon={<GitBranch />} onSelect={() => go(`/clusters/${clusterId}/repositories`, rp.repository_ref, rp.id)}>
                      <span className="flex-1 truncate">{rp.repository_ref}</span>
                    </Item>
                  ))}
                </Group>
              )}
            </Command.List>
            <div className="flex items-center justify-between gap-2 border-t border-border px-3 py-2 text-[10px] text-muted-foreground">
              <div className="flex items-center gap-3">
                <span className="flex items-center gap-1"><Kbd combo="ArrowUp" /><Kbd combo="ArrowDown" /> navigate</span>
                <span className="flex items-center gap-1"><Kbd combo="Enter" /> open</span>
              </div>
              <span>Press <Kbd combo="?" /> for all shortcuts</span>
            </div>
          </Command>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function Group({ heading, children }: { heading: string; children: React.ReactNode }) {
  return (
    <Command.Group
      heading={heading}
      className="
        text-muted-foreground
        [&_[cmdk-group-heading]]:px-2
        [&_[cmdk-group-heading]]:py-1.5
        [&_[cmdk-group-heading]]:text-[10px]
        [&_[cmdk-group-heading]]:uppercase
        [&_[cmdk-group-heading]]:tracking-wider
      "
    >
      {children}
    </Command.Group>
  );
}

function Item({
  icon,
  children,
  onSelect,
  shortcut,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
  onSelect: () => void;
  shortcut?: string;
}) {
  return (
    <Command.Item
      onSelect={onSelect}
      className="
        flex items-center gap-2 px-2 py-1.5 rounded text-sm text-foreground cursor-pointer
        data-[selected=true]:bg-accent
      "
    >
      <span className="flex h-5 w-5 items-center justify-center text-muted-foreground [&_svg]:h-3.5 [&_svg]:w-3.5">{icon}</span>
      <span className="flex-1 flex items-center min-w-0">{children}</span>
      {shortcut && <Kbd combo={shortcut} />}
      <ArrowRight className="h-3 w-3 text-muted-foreground/40" />
    </Command.Item>
  );
}

const NAV_ITEMS: Array<{ icon: React.ReactNode; label: string; href: string; shortcut?: string }> = [
  { icon: <LayoutDashboard />, label: "Dashboard",   href: "/dashboard",  shortcut: "g d" },
  { icon: <AlertTriangle />,   label: "Findings",    href: "/findings",   shortcut: "g f" },
  { icon: <Server />,          label: "Nodes",       href: "/nodes",      shortcut: "g h" },
  { icon: <PackageSearch />,   label: "Images",      href: "/images",     shortcut: "g i" },
  { icon: <Boxes />,           label: "Assets",      href: "/assets",     shortcut: "g a" },
  { icon: <ShieldCheck />,     label: "Compliance",  href: "/compliance", shortcut: "g c" },
  { icon: <Network />,         label: "Network Map", href: "/network",    shortcut: "g n" },
  { icon: <FileText />,        label: "Policies",    href: "/policies",   shortcut: "g p" },
  { icon: <ScrollText />,      label: "Runtime Policies", href: "/runtime-policies" },
  { icon: <RadioTower />,      label: "Response Catalog", href: "/response" },
  { icon: <Activity />,        label: "Runtime",     href: "/runtime",    shortcut: "g r" },
  { icon: <Database />,        label: "CVE Database", href: "/cve",       shortcut: "g v" },
  { icon: <ScanSearch />,      label: "Scanner & CVE Sources", href: "/settings/scanner" },
  { icon: <KeyRound />,        label: "API Tokens",  href: "/settings/api-tokens" },
  { icon: <BadgeCheck />,      label: "Attestation Trust", href: "/settings/attestation-trust" },
  { icon: <Plug />,            label: "Connectors",  href: "/settings/connectors" },
  { icon: <Server />,          label: "System Health", href: "/settings/health" },
  { icon: <ClipboardCheck />,  label: "Posture",     href: "/posture" },
  { icon: <Sparkles />,        label: "Federation",  href: "/federation" },
  { icon: <Settings />,        label: "Settings",    href: "/settings" },
];

const CLUSTER_HREFS = new Set(["/dashboard", "/findings", "/nodes", "/images", "/assets", "/compliance", "/network", "/policies", "/runtime", "/runtime-policies", "/response"]);
const CLUSTER_HREF_PREFIXES = ["/findings/", "/nodes/", "/images/", "/assets/", "/deployments/", "/risk/"];

function isClusterHref(href: string): boolean {
  return CLUSTER_HREFS.has(href) || CLUSTER_HREF_PREFIXES.some((prefix) => href.startsWith(prefix));
}

function clusterIDFromPath(pathname: string): string | null {
  const m = pathname.match(/^\/clusters\/([^/]+)(\/|$)/);
  return m ? m[1] : null;
}

/**
 * Provider — install the global Cmd+K hotkey and render the palette.
 * Mount once near the top of AppShell.
 */
export function CommandPaletteProvider() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const clusterId = clusterIDFromPath(location.pathname);
  const clusterHref = useCallback((href: string) => (clusterId && isClusterHref(href) ? `/clusters/${clusterId}${href}` : href), [clusterId]);

  useHotkey("Mod+k", () => setOpen((o) => !o), { description: "Open command palette", allowInEditable: true });

  // Global hotkey: hotkey nav
  useHotkey("g d", () => navigate(clusterHref("/dashboard")));
  useHotkey("g f", () => navigate(clusterHref("/findings")));
  useHotkey("g h", () => navigate(clusterHref("/nodes")));
  useHotkey("g i", () => navigate(clusterHref("/images")));
  useHotkey("g a", () => navigate(clusterHref("/assets")));
  useHotkey("g c", () => navigate(clusterHref("/compliance")));
  useHotkey("g n", () => navigate(clusterHref("/network")));
  useHotkey("g p", () => navigate(clusterHref("/policies")));
  useHotkey("g r", () => navigate(clusterHref("/runtime")));
  useHotkey("g v", () => navigate("/cve"));

  // ? — show hotkey help (broadcast event AppShell listens to)
  useHotkey("?", () => window.dispatchEvent(new CustomEvent("constellation:show-hotkeys")));

  return <CommandPalette open={open} onOpenChange={setOpen} />;
}

/**
 * HotkeysHelp — modal listing all global shortcuts.
 */
export function HotkeysHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const groups = useMemo(() => {
    const g: Record<string, typeof HOTKEY_CATALOG> = {};
    for (const h of HOTKEY_CATALOG) { (g[h.group] ??= []).push(h); }
    return g;
  }, []);
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-background/60 backdrop-blur-sm" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[min(480px,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-popover p-5 shadow-[var(--elev-popover)]">
          <Dialog.Title className="text-display text-base font-semibold tracking-tight">Keyboard shortcuts</Dialog.Title>
          <Dialog.Description className="text-xs text-muted-foreground mt-0.5">All global shortcuts in Constellation.</Dialog.Description>
          <div className="mt-4 space-y-4">
            {Object.entries(groups).map(([g, items]) => (
              <div key={g}>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground mb-1.5">{g}</div>
                <ul className="space-y-1">
                  {items.map((it) => (
                    <li key={it.combo} className="flex items-center justify-between gap-3 text-sm">
                      <span>{it.label}</span>
                      <Kbd combo={it.combo} />
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
