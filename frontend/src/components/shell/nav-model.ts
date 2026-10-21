// Constellation navigation model (C1 "Triage Desk").
//
// Two levels, the kit's rail + panel: the rail carries the organization scope
// (Clusters, CVE database, Posture, Audit log, Settings); inside a cluster the
// panel carries six always-visible groups. One distinct security icon per item
// across the whole sidebar; labels are sentence case; no counts.
import {
  Activity,
  Bug,
  ClipboardCheck,
  CloudCog,
  Container,
  Crosshair,
  Database,
  FileSearch,
  Fingerprint,
  Layers,
  ListFilter,
  Network,
  PackageSearch,
  Radar,
  RadioTower,
  ScanSearch,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  ShieldEllipsis,
  ShieldHalf,
  ShieldOff,
  Siren,
  Waypoints,
} from "lucide-react";
import type { NavIcon } from "@/ui";

export interface NavItem {
  /** Absolute path (org) or a path relative to /clusters/:id/ (cluster). */
  path: string;
  label: string;
  icon: NavIcon;
  /** Other cluster-relative paths that make this item active (tabbed hubs). */
  also?: string[];
  exact?: boolean;
  /** Command-palette search terms. */
  keywords?: string[];
  testId?: string;
}

export interface NavGroup {
  id: string;
  /** Omitted for single-destination groups (rendered flat). */
  label?: string;
  items: NavItem[];
}

export const ORG_NAV: NavItem[] = [
  { path: "/clusters", label: "Clusters", icon: Radar, exact: true, keywords: ["fleet", "scope", "register"], testId: "nav-clusters" },
  { path: "/cve", label: "CVE database", icon: Bug, keywords: ["vulnerability database", "nvd", "kev", "epss"] },
  { path: "/posture", label: "Posture", icon: ShieldCheck, also: ["/coverage"], keywords: ["coverage", "configuration posture"] },
  { path: "/organization/audit", label: "Audit log", icon: ScrollText, keywords: ["activity", "history"] },
  { path: "/settings", label: "Settings", icon: Settings, also: ["/federation"], keywords: ["configuration", "admin", "access control", "api tokens", "integrations"] },
];

export const CLUSTER_NAV: NavGroup[] = [
  {
    id: "overview",
    items: [{ path: "dashboard", label: "Overview", icon: ShieldHalf, exact: true, keywords: ["dashboard", "risk", "home"] }],
  },
  {
    id: "inventory",
    label: "Inventory",
    items: [
      { path: "nodes", label: "Nodes", icon: Server, also: ["hosts"], keywords: ["hosts", "host"] },
      { path: "deployments", label: "Workloads", icon: Layers, also: ["services", "workloads", "assets", "repositories"], keywords: ["deployments", "services", "assets"] },
      { path: "containers", label: "Containers", icon: Container, keywords: ["pods"] },
      { path: "images", label: "Images", icon: PackageSearch, keywords: ["image scans", "sbom"] },
      { path: "registries", label: "Registries", icon: Database, also: ["registry"], keywords: ["registry scans"] },
      { path: "serverless", label: "Serverless", icon: CloudCog, keywords: ["functions", "lambda"] },
    ],
  },
  {
    id: "vulnerabilities",
    label: "Vulnerabilities",
    items: [
      { path: "findings", label: "Findings", icon: Crosshair, also: ["cve", "risk"], keywords: ["vulnerabilities", "cve", "risk"] },
      { path: "vuln-profiles", label: "Vulnerability profiles", icon: ListFilter, also: ["vulnerability-profiles"], keywords: ["vuln profiles", "suppression"] },
      { path: "exceptions", label: "Exceptions", icon: ShieldOff, keywords: ["accepted risk", "waivers"] },
    ],
  },
  {
    id: "runtime",
    label: "Runtime",
    items: [
      { path: "runtime", label: "Activity", icon: Activity, exact: true, keywords: ["runtime events", "threats", "process"] },
      { path: "runtime/baselines", label: "Process baselines", icon: Fingerprint, keywords: ["process profiles", "learned"] },
      { path: "file-monitor", label: "File monitor", icon: FileSearch, keywords: ["file access", "fim"] },
      { path: "runtime-signatures", label: "Signatures", icon: ScanSearch, also: ["runtime-dlp", "waf", "dlp"], keywords: ["dpi", "waf", "dlp", "patterns"] },
    ],
  },
  {
    id: "network",
    label: "Network",
    items: [
      { path: "network", label: "Map", icon: Network, also: ["network-activity"], keywords: ["network map", "conversations", "sessions", "pcap"] },
      { path: "network-rules", label: "Rules", icon: Waypoints, keywords: ["network rules", "allow", "deny"] },
      { path: "timeline", label: "Incidents", icon: Siren, also: ["events", "activity", "incidents", "security-events"], keywords: ["incident timeline", "security events"] },
    ],
  },
  {
    id: "governance",
    items: [
      {
        path: "admission",
        label: "Policies",
        icon: ShieldEllipsis,
        also: ["admission-control", "policies", "policy", "runtime-policies", "groups", "response-rules", "response"],
        keywords: ["admission", "runtime policies", "response rules", "groups", "enforcement"],
        testId: "nav-policies",
      },
      { path: "compliance", label: "Compliance", icon: ClipboardCheck, keywords: ["cis", "benchmarks", "evidence"] },
      { path: "components", label: "Agents", icon: RadioTower, also: ["health", "agents", "controllers", "enforcers", "scanners"], keywords: ["sensor health", "components", "enforcers", "scanners"] },
    ],
  },
];

/** Total cluster-panel destinations (C1 target: ~18 + Agents). */
export const CLUSTER_NAV_ITEMS = CLUSTER_NAV.flatMap((group) => group.items);

export function clusterIdFromPath(pathname: string): string | null {
  const match = pathname.match(/^\/clusters\/([^/]+)(\/|$)/);
  return match && match[1] !== "new" ? match[1] : null;
}

export function clusterHref(clusterId: string, item: NavItem): string {
  return item.path.startsWith("/") ? item.path : `/clusters/${clusterId}/${item.path}`;
}

/** The cluster nav item that owns `pathname` (longest match wins). */
export function activeClusterItem(pathname: string, clusterId: string): NavItem | undefined {
  const rest = pathname.slice(`/clusters/${clusterId}/`.length);
  let best: { item: NavItem; length: number } | undefined;
  for (const item of CLUSTER_NAV_ITEMS) {
    for (const candidate of [item.path, ...(item.also ?? [])]) {
      const hit = item.exact && candidate === item.path
        ? rest === candidate
        : rest === candidate || rest.startsWith(`${candidate}/`);
      if (hit && (!best || candidate.length > best.length)) best = { item, length: candidate.length };
    }
  }
  if (!best && rest === "") return CLUSTER_NAV_ITEMS[0];
  return best?.item;
}

export function activeOrgItem(pathname: string): NavItem | undefined {
  if (clusterIdFromPath(pathname)) return ORG_NAV[0];
  return ORG_NAV.find((item) =>
    [item.path, ...(item.also ?? [])].some((path) => pathname === path || pathname.startsWith(`${path}/`)),
  );
}

/** Human labels for path segments that are not nav items. */
const SEGMENT_LABELS: Record<string, string> = {
  dashboard: "Overview",
  assets: "Assets",
  repositories: "Repositories",
  audit: "Audit log",
  "audit-log": "Audit log",
  policy: "Policy transfer",
  neuvector: "NeuVector switchboard",
  settings: "Settings",
  new: "New",
  edit: "Edit",
  views: "Saved views",
  import: "Import",
  baselines: "Process baselines",
  rules: "Rules",
  actions: "Action",
  benchmarks: "Benchmarks",
  exemptions: "Exemptions",
  schedules: "Schedules",
  retry: "Retry",
  revoke: "Revoke",
  "image-acceptance": "Image acceptance",
  scope: "Scope",
  pcap: "Packet capture",
  dpi: "DPI settings",
  cve: "CVE database",
  posture: "Posture",
  coverage: "Coverage",
  federation: "Federation",
  organization: "Organization",
  access: "Access control",
  "api-tokens": "API tokens",
  "identity": "Single sign-on",
  "attestation-trust": "Attestation trust",
  health: "System health",
  scanner: "Scanner and CVE sources",
  nvd: "NVD",
  databases: "Databases",
  network: "Network and proxy",
  "effective-config": "Effective configuration",
  retention: "Data retention",
  backup: "Backup",
  destination: "Destination",
  schedule: "Schedule",
  restore: "Restore",
  integrations: "Integrations",
  routes: "Routes",
  routing: "Routing",
  smtp: "SMTP",
  receivers: "Receivers",
  connectors: "Connectors",
  migration: "Migration",
  clusters: "Clusters",
  bundles: "Bundles",
  rotate: "Rotate",
  bindings: "Role bindings",
  "service-accounts": "Service accounts",
  users: "Users",
  roles: "Roles",
  sso: "Single sign-on",
};

/** Entity noun for an id segment under a collection segment. */
const ENTITY_NOUNS: Record<string, string> = {
  findings: "Finding",
  assets: "Asset",
  deployments: "Workload",
  images: "Image",
  registries: "Registry",
  groups: "Group",
  serverless: "Function",
  baselines: "Baseline",
  rules: "Rule",
  "response-rules": "Response rule",
  response: "Response rule",
  "runtime-policies": "Runtime policy",
  "runtime-dlp": "DLP rule",
  "runtime-signatures": "Signature",
  "file-monitor": "File rule",
  "network-rules": "Network rule",
  "vuln-profiles": "Profile",
  policies: "Policy",
  receivers: "Receiver",
  connectors: "Connector",
  sso: "Provider",
  "attestation-trust": "Trust policy",
  risk: "Risk",
  bundles: "Bundle",
};

export function looksLikeId(segment: string): boolean {
  return (
    /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(segment) ||
    (/^[0-9a-z_-]{10,}$/i.test(segment) && /\d/.test(segment) && !/^cve-/i.test(segment))
  );
}

export function sentenceCase(value: string): string {
  const words = value.replace(/[-_]+/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

export function segmentLabel(segment: string, parent?: string): string {
  const decoded = safeDecode(segment);
  if (/^cve-\d{4}-\d+$/i.test(decoded)) return decoded.toUpperCase();
  if (looksLikeId(decoded)) return (parent && ENTITY_NOUNS[parent]) || "Details";
  const item = CLUSTER_NAV_ITEMS.find((candidate) => candidate.path === segment);
  if (item) return item.label;
  return SEGMENT_LABELS[segment] ?? (parent && ENTITY_NOUNS[parent] && /\d/.test(decoded) ? ENTITY_NOUNS[parent] : sentenceCase(decoded));
}

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
