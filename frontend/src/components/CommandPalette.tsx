// Command palette — the kit's single palette style (sentence-case groups,
// description lines, hotkey hints). `/` and ⌘K open it from anywhere; the
// header SearchTrigger opens the same dialog.
import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Dialog as DialogPrimitive } from "radix-ui";
import {
  ArrowLeftRight,
  Boxes,
  Bug,
  CircleHelp,
  Clock,
  CloudCog,
  Crosshair,
  Earth,
  FileClock,
  GitBranch,
  KeyRound,
  Layers,
  Moon,
  PackageSearch,
  Plug,
  Plus,
  ScrollText,
  Server,
  ShieldEllipsis,
  SlidersHorizontal,
  Sun,
  ToggleLeft,
  type LucideIcon,
} from "lucide-react";

import { useTablePreferencesIdentity } from "@/contexts/TablePreferencesContext";
import { useTheme } from "@/contexts/ThemeContext";
import { findingHref, findingRowKey } from "@/lib/finding-instance";
import { useHotkey, HOTKEY_CATALOG } from "@/lib/hotkeys";
import { tokenize } from "@/lib/kbd";
import { setIncludeSystemPreference, useIncludeSystemPreference } from "@/lib/system-scope";
import { findings, assets, imageScanResults, nodes as nodesApi, policies, deployments as deploymentsApi, serverlessFunctions, repositoryScans } from "@/api/client";
import { CLUSTER_NAV_ITEMS, clusterIdFromPath, ORG_NAV } from "@/components/shell/nav-model";
import { CommandGroup, CommandItem, CommandPalette as KitCommandPalette, Kbd } from "@/ui";

const RECENT_KEY = "constellation.cmdk.recent.v1";
const OPEN_EVENT = "constellation:open-palette";

/** Open the palette from anywhere (header search, buttons). */
export function openCommandPalette() {
  window.dispatchEvent(new CustomEvent(OPEN_EVENT));
}

interface RecentItem { id: string; label: string; href: string; ts: number }

function loadRecent(key: string): RecentItem[] {
  if (typeof localStorage === "undefined") return [];
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return [];
    const rows: unknown = JSON.parse(raw);
    return Array.isArray(rows)
      ? rows.filter((row): row is RecentItem => !!row && typeof row === "object" && typeof row.id === "string" && typeof row.label === "string" && typeof row.href === "string" && row.href.startsWith("/") && !row.href.startsWith("//"))
      : [];
  } catch {
    return [];
  }
}

function pushRecent(key: string, item: Omit<RecentItem, "ts">) {
  const current = loadRecent(key).filter((i) => i.id !== item.id);
  current.unshift({ ...item, ts: Date.now() });
  try {
    localStorage.setItem(key, JSON.stringify(current.slice(0, 8)));
  } catch {
    // Recent items are a convenience.
  }
}

interface PageEntry { label: string; href: string; icon: LucideIcon | React.ComponentType<{ className?: string }>; description?: string; keywords?: string[]; hotkey?: string }

/** Pages that are not in the sidebar but remain one search away. */
const MORE_CLUSTER_PAGES: Array<Omit<PageEntry, "href"> & { path: string }> = [
  { path: "assets", label: "Assets", icon: Boxes, description: "Risk-ranked inventory across images, workloads and cloud resources", hotkey: "G A" },
  { path: "repositories", label: "Repositories", icon: GitBranch, description: "Source repository scans" },
  { path: "audit", label: "Cluster audit log", icon: FileClock, description: "Changes made in this cluster" },
  { path: "policy", label: "Policy transfer", icon: ShieldEllipsis, description: "Import and export policy families as YAML" },
  { path: "neuvector", label: "NeuVector switchboard", icon: ArrowLeftRight, description: "NeuVector concepts mapped to Constellation", keywords: ["nv", "migration"] },
];

const SETTINGS_PAGES: PageEntry[] = [
  { label: "Access control", href: "/settings/access", icon: KeyRound, keywords: ["users", "roles", "sso", "service accounts"] },
  { label: "API tokens", href: "/settings/api-tokens", icon: KeyRound, keywords: ["tokens", "automation"] },
  { label: "Integrations", href: "/settings/integrations", icon: Plug, keywords: ["alerts", "receivers", "routing", "webhooks"] },
  { label: "Connectors", href: "/settings/connectors", icon: Plug, keywords: ["registry", "cloud account"] },
  { label: "Scanner and CVE sources", href: "/settings/scanner", icon: Bug, keywords: ["vulndb", "nvd", "feeds"] },
  { label: "System health", href: "/settings/health", icon: Server, keywords: ["controllers", "heartbeat"] },
  { label: "Effective configuration", href: "/settings/effective-config", icon: SlidersHorizontal, keywords: ["sysconfig"] },
  { label: "Federation", href: "/federation", icon: Earth, keywords: ["multi cluster", "peers"] },
  { label: "Migration", href: "/settings/migration", icon: ArrowLeftRight, keywords: ["neuvector", "imports"] },
];

const NAV_HOTKEYS: Record<string, string> = {
  dashboard: "G D",
  findings: "G F",
  nodes: "G H",
  images: "G I",
  compliance: "G C",
  network: "G N",
  admission: "G P",
  runtime: "G R",
  "/cve": "G V",
};

export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const operator = useTablePreferencesIdentity();
  const owner = `${operator?.org_id}:${operator?.user_id}`;
  const recentKey = `${RECENT_KEY}:${owner}`;
  const navigate = useNavigate();
  const location = useLocation();
  const { theme, toggle: toggleTheme } = useTheme();
  const [includeSystem] = useIncludeSystemPreference();
  const [query, setQuery] = useState("");
  const clusterId = clusterIdFromPath(location.pathname);

  useEffect(() => {
    if (open) setQuery("");
  }, [open]);

  const findingsQ = useQuery({
    queryKey: ["cmdk-findings", owner, clusterId],
    queryFn: () => findings.list({ limit: 100, cluster_id: clusterId ?? undefined }),
    enabled: open && !!operator?.org_id && !!operator?.user_id,
    staleTime: 60_000,
  });
  const assetsQ = useQuery({ queryKey: ["cmdk-assets", clusterId], queryFn: () => assets.list({ limit: 100, cluster_id: clusterId ?? undefined }), enabled: open, staleTime: 60_000 });
  const imageScansQ = useQuery({ queryKey: ["cmdk-image-scans", clusterId], queryFn: () => imageScanResults.list({ cluster_id: clusterId ?? undefined, limit: 100 }), enabled: open && !!clusterId, staleTime: 60_000 });
  const nodesQ = useQuery({ queryKey: ["cmdk-nodes", clusterId], queryFn: () => nodesApi.list(clusterId!), enabled: open && !!clusterId, staleTime: 60_000 });
  const policiesQ = useQuery({ queryKey: ["cmdk-policies"], queryFn: () => policies.list(), enabled: open, staleTime: 60_000 });
  const workloadsQ = useQuery({ queryKey: ["cmdk-workloads", clusterId], queryFn: () => deploymentsApi.list({ limit: 100, cluster_id: clusterId ?? undefined }), enabled: open && !!clusterId, staleTime: 60_000 });
  const serverlessQ = useQuery({ queryKey: ["cmdk-serverless"], queryFn: () => serverlessFunctions.list({ limit: 100 }), enabled: open, staleTime: 60_000 });
  const reposQ = useQuery({ queryKey: ["cmdk-repos"], queryFn: () => repositoryScans.list({ limit: 100 }), enabled: open, staleTime: 60_000 });

  const recent = useMemo(() => (open ? loadRecent(recentKey) : []), [open, recentKey]);

  const go = useCallback((href: string, label: string, id?: string) => {
    if (id) pushRecent(recentKey, { id, label, href });
    onOpenChange(false);
    void navigate({ href });
  }, [navigate, onOpenChange, recentKey]);

  const trimmed = query.trim();
  const isCVE = /^cve-\d{4}-\d+$/i.test(trimmed);
  const clusterPages: PageEntry[] = clusterId
    ? [
        ...CLUSTER_NAV_ITEMS.map((item) => ({ label: item.label, href: `/clusters/${clusterId}/${item.path}`, icon: item.icon, keywords: item.keywords, hotkey: NAV_HOTKEYS[item.path] })),
        ...MORE_CLUSTER_PAGES.map((page) => ({ ...page, href: `/clusters/${clusterId}/${page.path}` })),
      ]
    : [];
  const orgPages: PageEntry[] = ORG_NAV.map((item) => ({ label: item.label, href: item.path, icon: item.icon, keywords: item.keywords, hotkey: NAV_HOTKEYS[item.path] }));

  return (
    <KitCommandPalette
      open={open}
      onOpenChange={onOpenChange}
      value={query}
      onValueChange={setQuery}
      placeholder="Search pages, findings, CVEs, nodes, workloads…"
      footer={<span className="flex items-center gap-1.5"><Kbd>?</Kbd> all shortcuts</span>}
    >
      {isCVE && (
        <CommandGroup heading="CVE database">
          <CommandItem value={`open ${trimmed}`} icon={Bug} title={`Open ${trimmed.toUpperCase()}`} onSelect={() => go(`/cve/${trimmed.toUpperCase()}`, trimmed.toUpperCase(), trimmed)} />
        </CommandGroup>
      )}
      {!trimmed && recent.length > 0 && (
        <CommandGroup heading="Recent">
          {recent.map((item) => (
            <CommandItem key={item.id} value={`recent ${item.label} ${item.id}`} icon={Clock} title={item.label} onSelect={() => go(item.href, item.label, item.id)} />
          ))}
        </CommandGroup>
      )}
      {clusterPages.length > 0 && (
        <CommandGroup heading="This cluster">
          {clusterPages.map((page) => (
            <CommandItem key={page.href} value={[page.label, page.href, ...(page.keywords ?? [])].join(" ")} icon={page.icon} title={page.label} description={page.description} hotkey={page.hotkey} onSelect={() => go(page.href, page.label)} />
          ))}
        </CommandGroup>
      )}
      <CommandGroup heading="Organization">
        {orgPages.map((page) => (
          <CommandItem key={page.href} value={[page.label, page.href, ...(page.keywords ?? [])].join(" ")} icon={page.icon} title={page.label} hotkey={page.hotkey} onSelect={() => go(page.href, page.label)} />
        ))}
      </CommandGroup>
      <CommandGroup heading="Actions">
        <CommandItem value="register cluster connect add" icon={Plus} title="Register cluster" onSelect={() => go("/settings/clusters/new", "Register cluster")} />
        <CommandItem
          value="include system workloads scope platform"
          icon={ToggleLeft}
          title={includeSystem ? "Hide system workloads" : "Include system workloads"}
          description="Header scope for findings, inventories and the network map"
          onSelect={() => { setIncludeSystemPreference(!includeSystem); onOpenChange(false); }}
        />
        <CommandItem value="toggle theme dark light system" icon={theme === "dark" ? Sun : Moon} title="Switch theme" description={`Current: ${theme}`} onSelect={() => { toggleTheme(); }} />
        <CommandItem value="keyboard shortcuts help" icon={CircleHelp} title="Keyboard shortcuts" hotkey="?" onSelect={() => { onOpenChange(false); window.dispatchEvent(new CustomEvent("constellation:show-hotkeys")); }} />
      </CommandGroup>
      <CommandGroup heading="Settings">
        {SETTINGS_PAGES.map((page) => (
          <CommandItem key={page.href} value={[page.label, page.href, ...(page.keywords ?? [])].join(" ")} icon={page.icon} title={page.label} onSelect={() => go(page.href, page.label)} />
        ))}
      </CommandGroup>
      {(findingsQ.data?.findings?.length ?? 0) > 0 && (
        <CommandGroup heading="Findings">
          {findingsQ.data!.findings.slice(0, 8).map((f) => (
            <CommandItem
              key={findingRowKey(f)}
              value={`${f.title} ${f.external_id ?? ""} ${findingRowKey(f)}`}
              icon={Crosshair}
              title={f.title}
              description={[f.external_id, f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1) : undefined].filter(Boolean).join(" · ")}
              onSelect={() => go(findingHref(f, f.cluster_id || clusterId || undefined), f.external_id || f.title, findingRowKey(f))}
            />
          ))}
        </CommandGroup>
      )}
      {clusterId && (imageScansQ.data?.image_scan_results?.length ?? 0) > 0 && (
        <CommandGroup heading="Images">
          {imageScansQ.data!.image_scan_results.slice(0, 6).map((image) => (
            <CommandItem key={image.id} value={`image ${image.image_repository ?? ""} ${image.image_ref ?? ""} ${image.id}`} icon={PackageSearch} title={image.image_repository || image.image_ref || image.image_digest} description={`${image.critical_count + image.high_count} critical or high`} onSelect={() => go(`/clusters/${clusterId}/images/${image.id}`, image.image_repository || image.image_digest, image.id)} />
          ))}
        </CommandGroup>
      )}
      {clusterId && (nodesQ.data?.items?.length ?? 0) > 0 && (
        <CommandGroup heading="Nodes">
          {nodesQ.data!.items.slice(0, 6).map((node) => (
            <CommandItem key={node.node} value={`node host ${node.node}`} icon={Server} title={node.node} description={`${node.critical_vulns + node.high_vulns} critical or high`} onSelect={() => go(`/clusters/${clusterId}/nodes/${encodeURIComponent(node.node)}`, node.node, `node:${node.node}`)} />
          ))}
        </CommandGroup>
      )}
      {(assetsQ.data?.assets?.length ?? 0) > 0 && (
        <CommandGroup heading="Assets">
          {assetsQ.data!.assets.slice(0, 6).map((asset) => (
            <CommandItem key={asset.id} value={`asset ${asset.name} ${asset.id}`} icon={Boxes} title={asset.name} description={asset.kind} onSelect={() => go(clusterId ? `/clusters/${clusterId}/assets/${asset.id}` : "/clusters", asset.name, asset.id)} />
          ))}
        </CommandGroup>
      )}
      {clusterId && (workloadsQ.data?.deployments?.length ?? 0) > 0 && (
        <CommandGroup heading="Workloads">
          {workloadsQ.data!.deployments.slice(0, 6).map((d) => (
            <CommandItem key={d.id} value={`workload service deployment ${d.name} ${d.namespace}`} icon={Layers} title={d.name} description={d.namespace} onSelect={() => go(`/clusters/${clusterId}/deployments/${d.id}`, d.name, d.id)} />
          ))}
        </CommandGroup>
      )}
      {(policiesQ.data?.policies?.length ?? 0) > 0 && clusterId && (
        <CommandGroup heading="Policies">
          {policiesQ.data!.policies.slice(0, 6).map((p) => (
            <CommandItem key={p.id} value={`policy ${p.name}`} icon={ScrollText} title={p.name} description={p.mode} onSelect={() => go(`/clusters/${clusterId}/policies/${encodeURIComponent(p.id)}`, p.name, p.id)} />
          ))}
        </CommandGroup>
      )}
      {clusterId && (serverlessQ.data?.serverless_functions?.length ?? 0) > 0 && (
        <CommandGroup heading="Serverless">
          {serverlessQ.data!.serverless_functions.slice(0, 6).map((fn) => (
            <CommandItem key={fn.id} value={`function ${fn.function_name ?? ""} ${fn.id}`} icon={CloudCog} title={fn.function_name || "Function"} description={fn.provider} onSelect={() => go(`/clusters/${clusterId}/serverless/${fn.id}`, fn.function_name || "Function", fn.id)} />
          ))}
        </CommandGroup>
      )}
      {clusterId && (reposQ.data?.repository_scans?.length ?? 0) > 0 && (
        <CommandGroup heading="Repositories">
          {reposQ.data!.repository_scans.slice(0, 6).map((repo) => (
            <CommandItem key={repo.id} value={`repository ${repo.repository_ref}`} icon={GitBranch} title={repo.repository_ref} onSelect={() => go(`/clusters/${clusterId}/repositories`, repo.repository_ref, repo.id)} />
          ))}
        </CommandGroup>
      )}
    </KitCommandPalette>
  );
}

/** Mount once in the shell: global hotkeys + the palette. */
export function CommandPaletteProvider() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const clusterId = clusterIdFromPath(location.pathname);
  const clusterHref = useCallback((path: string) => (clusterId ? `/clusters/${clusterId}/${path}` : "/clusters"), [clusterId]);

  useEffect(() => {
    const onOpen = () => setOpen(true);
    window.addEventListener(OPEN_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_EVENT, onOpen);
  }, []);

  const toggle = useCallback(() => setOpen((value) => !value), []);
  const openPalette = useCallback((event: KeyboardEvent) => { event.preventDefault(); setOpen(true); }, []);
  useHotkey("Mod+k", toggle, { description: "Open command palette", allowInEditable: true });
  useHotkey("/", openPalette, { description: "Search" });
  useHotkey("g d", () => navigate({ href: clusterHref("dashboard") }));
  useHotkey("g f", () => navigate({ href: clusterHref("findings") }));
  useHotkey("g h", () => navigate({ href: clusterHref("nodes") }));
  useHotkey("g i", () => navigate({ href: clusterHref("images") }));
  useHotkey("g a", () => navigate({ href: clusterHref("assets") }));
  useHotkey("g c", () => navigate({ href: clusterHref("compliance") }));
  useHotkey("g n", () => navigate({ href: clusterHref("network") }));
  useHotkey("g p", () => navigate({ href: clusterHref("admission") }));
  useHotkey("g r", () => navigate({ href: clusterHref("runtime") }));
  useHotkey("g v", () => navigate({ href: "/cve" }));
  useHotkey("?", () => window.dispatchEvent(new CustomEvent("constellation:show-hotkeys")));

  return <CommandPalette open={open} onOpenChange={setOpen} />;
}

/** Modal listing all global shortcuts. */
export function HotkeysHelp({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const groups = useMemo(() => {
    const grouped: Record<string, typeof HOTKEY_CATALOG> = {};
    for (const hotkey of HOTKEY_CATALOG) (grouped[hotkey.group] ??= []).push(hotkey);
    return grouped;
  }, []);
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-overlay bg-black/50 backdrop-blur-xs" />
        <DialogPrimitive.Content className="fixed left-1/2 top-1/2 z-overlay w-[min(28rem,92vw)] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-border bg-card p-5 shadow-elev-popover outline-none">
          <DialogPrimitive.Title className="text-base font-semibold text-foreground">Keyboard shortcuts</DialogPrimitive.Title>
          <DialogPrimitive.Description className="mt-0.5 text-meta text-muted-foreground">Global shortcuts in Constellation.</DialogPrimitive.Description>
          <div className="mt-4 space-y-4">
            {Object.entries(groups).map(([group, items]) => (
              <div key={group}>
                <p className="mb-1.5 text-meta font-semibold text-muted-foreground">{group}</p>
                <ul className="space-y-1">
                  {items.map((item) => (
                    <li key={item.combo} className="flex items-center justify-between gap-3 text-sm">
                      <span>{item.label}</span>
                      <span className="flex items-center gap-1">{tokenize(item.combo).map((key, index) => <Kbd key={`${key}-${index}`}>{key}</Kbd>)}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
