import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { enterprise, groupsApi, networkRules, runtimeDLP, runtimeSignatures, vulnProfiles, type DLPRule, type Group, type MigrationImportListItem, type MigrationImportPage, type MigrationUnsupported, type NetworkRule, type VulnProfile } from "@/api/client";
import { PolicyCenterPage } from "./PolicyCenterPage";

vi.mock("@/hooks/useCluster", () => ({
  useCluster: () => ({
    clusterId: "cluster-1",
    cluster: { id: "cluster-1", name: "Test Cluster" },
    isLoading: false,
    error: null,
    allClusters: [],
  }),
}));

let root: Root | undefined;
let host: HTMLDivElement | undefined;
let queryClient: QueryClient | undefined;

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.spyOn(enterprise, "migrationImportsPage").mockResolvedValue({ imports: [], has_more: false });
  vi.spyOn(runtimeDLP, "list").mockResolvedValue([]);
  vi.spyOn(runtimeSignatures, "list").mockResolvedValue([]);
  vi.spyOn(groupsApi, "list").mockResolvedValue({ groups: [] });
  vi.spyOn(vulnProfiles, "list").mockResolvedValue({ profiles: [] });
  vi.spyOn(networkRules, "list").mockResolvedValue({ cluster_id: "cluster-1", rules: [], summary: { total: 0, allow: 0, deny: 0, learned: 0, disabled: 0 } });
});

afterEach(() => {
  if (root) {
    act(() => root?.unmount());
  }
  queryClient?.clear();
  host?.remove();
  root = undefined;
  host = undefined;
  queryClient = undefined;
  document.body.innerHTML = "";
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("PolicyCenterPage", () => {
  it("shows latest listed changes only for families with timestamps", async () => {
    vi.mocked(runtimeDLP.list).mockResolvedValue([
      { updated_at: "2026-09-24T10:00:00Z" } as DLPRule,
      { updated_at: "2026-09-25T11:00:00Z" } as DLPRule,
    ]);
    vi.mocked(runtimeSignatures.list).mockResolvedValue([{ updated_at: "2026-09-23T12:00:00Z" } as DLPRule]);
    vi.mocked(groupsApi.list).mockResolvedValue({ groups: [{ updated_at: "2026-09-22T13:00:00Z" } as Group] });
    vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [{ updated_at: "2026-09-21T14:00:00Z" } as VulnProfile] });
    render(<PolicyCenterPage />);
    await settle();

    expect(changeTime("dlp")).toBe("2026-09-25T11:00:00.000Z");
    expect(changeTime("signatures")).toBe("2026-09-23T12:00:00.000Z");
    expect(changeTime("groups")).toBe("2026-09-22T13:00:00.000Z");
    expect(changeTime("vuln-profiles")).toBe("2026-09-21T14:00:00.000Z");
    expect(changeText("dlp")).toContain("Active listed cluster rules only");
    expect(changeText("signatures")).toContain("Active listed cluster signatures only");
    expect(changeText("groups")).toContain("Visible cluster and org-wide groups");
    expect(changeText("vuln-profiles")).toContain("Visible cluster and org-wide profiles");
    expect(familyElement("groups").textContent).toContain("cluster + org scoped");
    expect(runtimeDLP.list).toHaveBeenCalledWith("cluster-1");
    expect(runtimeSignatures.list).toHaveBeenCalledWith("cluster-1");
    expect(groupsApi.list).toHaveBeenCalledWith({ cluster_id: "cluster-1" });
    expect(vulnProfiles.list).toHaveBeenCalledWith({ cluster_id: "cluster-1" });
    expect(queryClient?.getQueryData(["groups", "cluster-1"])).toBeUndefined();
    expect(networkRules.list).toHaveBeenCalledWith("cluster-1");
    expect(familyElement("network-rules").textContent).toContain("Listed matches: 0");
    expect(familyElement("network-rules").textContent).toContain("Last listed match: Never");
  });

  it("does not invent change times for empty, invalid, or failed lists", async () => {
    vi.mocked(runtimeSignatures.list).mockResolvedValue([{ updated_at: "not-a-date" } as DLPRule]);
    vi.mocked(groupsApi.list).mockRejectedValue(new Error("unavailable"));
    render(<PolicyCenterPage />);
    await settle();

    expect(changeText("dlp")).toContain("No listed items");
    expect(changeText("signatures")).toContain("Unavailable");
    expect(changeText("groups")).toContain("Unavailable");
    expect(changeTime("dlp")).toBeNull();
    expect(changeTime("signatures")).toBeNull();
    expect(changeTime("groups")).toBeNull();
  });

  it("shows only listed network match totals and last-hit time", async () => {
    vi.mocked(networkRules.list).mockResolvedValue({ cluster_id: "cluster-1", rules: [
      { match_counter: 7, last_match_timestamp: 1700000000 } as NetworkRule,
      { match_counter: 3, last_match_timestamp: 1700000100 } as NetworkRule,
    ], summary: { total: 2, allow: 2, deny: 0, learned: 2, disabled: 0 } });
    render(<PolicyCenterPage />);
    await settle();

    const stats = familyElement("network-rules").querySelector('[data-testid="policy-family-network-rules-match-stats"]');
    expect(stats?.textContent).toContain("Listed matches: 10");
    expect(stats?.querySelector("time")?.getAttribute("datetime")).toBe("2023-11-14T22:15:00.000Z");
    expect(stats?.textContent).toContain("do not prove enforcement health");
  });

  it("does not present invalid network counters as trustworthy hits", async () => {
    vi.mocked(networkRules.list).mockResolvedValue({ cluster_id: "cluster-1", rules: [
      { match_counter: -1, last_match_timestamp: -1 } as NetworkRule,
    ], summary: { total: 1, allow: 1, deny: 0, learned: 1, disabled: 0 } });
    render(<PolicyCenterPage />);
    await settle();

    const stats = familyElement("network-rules").querySelector('[data-testid="policy-family-network-rules-match-stats"]');
    expect(stats?.textContent).toContain("Listed matches: Unavailable");
    expect(stats?.textContent).toContain("Last listed match: Unavailable");
  });

  it("renders mode vocabulary and portable policy family controls", () => {
    render(<PolicyCenterPage />);

    expect(text()).toContain("Discover");
    expect(text()).toContain("Learn");
    expect(text()).toContain("Monitor");
    expect(text()).toContain("Protect");
    expect(text()).toContain("Enforce");

    for (const slug of ["network-rules", "runtime-dlp", "runtime-signatures", "vuln-profiles", "groups"]) {
      const family = familyElement(slug);
      expect(family.textContent).toContain("yaml");
      expect(portableText(slug)).toContain("Import");
      expect(portableText(slug)).toContain("Export");
      expect(family.querySelectorAll('input[type="file"]')).toHaveLength(1);
    }
  });

  it("shows migration only as migration and omits unsupported family imports", () => {
    render(<PolicyCenterPage />);

    const migrationLinks = host?.querySelectorAll<HTMLAnchorElement>('a[href="/settings/migration"]');
    expect(migrationLinks).toHaveLength(1);
    expect(migrationLinks?.[0].textContent).toBe("Migration Imports");

    for (const slug of ["admission", "runtime-policies", "runtime-baselines", "file-monitor", "response-rules", "policies", "response"]) {
      const family = familyElement(slug);
      expect(family.textContent).not.toContain("importable");
      expect(family.textContent).not.toContain("Import");
      expect(family.querySelector('[data-testid$="-portable"]')).toBeNull();
    }
  });

  it("places saved NeuVector diagnostics beside matching families without claiming cluster ownership", async () => {
    vi.mocked(enterprise.migrationImportsPage).mockResolvedValue({ imports: [
      savedImport([
        diagnostic("network_rule", "blocked-flow"),
        diagnostic("group_criterion", "frontend"),
        diagnostic("process_profile", "worker"),
        diagnostic("file_profile", "config"),
        diagnostic("vulnerability_profile", "CVE set"),
        diagnostic("dpi_pattern", "secret", { category: "dlp" }),
        diagnostic("dpi_rule", "http", { category: "waf" }),
        diagnostic("waf_group_scope", "edge"),
      ]),
      savedImport([diagnostic("network_rule", "other-source")], "stackrox"),
    ], has_more: false });
    render(<PolicyCenterPage />);
    await settle();

    expect(familyElement("network-rules").textContent).toContain("blocked-flow");
    expect(familyElement("groups").textContent).toContain("frontend");
    expect(familyElement("runtime-baselines").textContent).toContain("worker");
    expect(familyElement("file-monitor").textContent).toContain("config");
    expect(familyElement("vuln-profiles").textContent).toContain("CVE set");
    expect(familyElement("runtime-dlp").textContent).toContain("secret");
    expect(familyElement("runtime-signatures").textContent).toContain("http");
    expect(familyElement("runtime-signatures").textContent).toContain("edge");
    expect(familyElement("network-rules").textContent).toContain("Review manually");
    expect(familyElement("network-rules").textContent).toContain("org history");
    expect(familyElement("network-rules").textContent).toContain("import-1");
    expect(familyElement("network-rules").textContent).toContain("Target: unknown or unspecified");
    expect(text()).toContain("missing IDs remain unknown or unspecified");
    expect(text()).not.toContain("other-source");
    expect(familyElement("runtime-dlp").textContent).not.toContain("http");
  });

  it("keeps unknown and ambiguous kinds in the general diagnostic area", async () => {
    vi.mocked(enterprise.migrationImportsPage).mockResolvedValue({ imports: [
      savedImport([
        diagnostic("unknown_future_kind", "future"),
        diagnostic("dpi_pattern", "ambiguous"),
        diagnostic("registry", "registry-record"),
      ]),
    ], has_more: false });
    render(<PolicyCenterPage />);
    await settle();

    const general = host?.querySelector('[data-testid="migration-general-diagnostics"]');
    expect(general?.textContent).toContain("unknown_future_kind · future");
    expect(general?.textContent).toContain("dpi_pattern · ambiguous");
    expect(general?.textContent).toContain("registry · registry-record");
    expect(general?.textContent).toContain("Review manually");
    expect(familyElement("runtime-dlp").textContent).not.toContain("ambiguous");
    expect(familyElement("runtime-signatures").textContent).not.toContain("ambiguous");
  });

  it("shows loading, empty, and error states for saved diagnostics", async () => {
    let resolveImports!: (page: MigrationImportPage) => void;
    vi.mocked(enterprise.migrationImportsPage).mockImplementation(() => new Promise((resolve) => { resolveImports = resolve; }));
    render(<PolicyCenterPage />);
    expect(text()).toContain("Loading migration diagnostics");

    await act(async () => resolveImports({ imports: [], has_more: false }));
    await settle();
    expect(text()).toContain("No saved NeuVector unsupported diagnostics");

    vi.mocked(enterprise.migrationImportsPage).mockRejectedValue(new Error("unavailable"));
    await act(async () => { await queryClient?.invalidateQueries({ queryKey: ["migration-imports-pages"] }); });
    await settle();
    expect(host?.querySelector('[role="alert"]')?.textContent).toContain("Could not refresh migration diagnostics");
    expect(text()).not.toContain("No saved NeuVector unsupported diagnostics");
  });

  it("reports an initial history failure without claiming an empty history", async () => {
    vi.mocked(enterprise.migrationImportsPage).mockRejectedValue(new Error("unavailable"));
    render(<PolicyCenterPage />);
    await settle();

    expect(host?.querySelector('[role="alert"]')?.textContent).toContain("Migration diagnostics are unavailable");
    expect(text()).not.toContain("No saved NeuVector unsupported diagnostics");
  });

  it("separates selected, unknown, and other-cluster diagnostics across bounded pages", async () => {
    vi.mocked(enterprise.migrationImportsPage)
      .mockResolvedValueOnce({ imports: [
        { ...savedImport([diagnostic("network_rule", "selected")], "neuvector", "cluster-1"), id: "selected-import" },
        { ...savedImport([diagnostic("network_rule", "legacy")]), id: "legacy-import" },
        { ...savedImport([diagnostic("network_rule", "sibling")], "neuvector", "cluster-2"), id: "sibling-import" },
      ], has_more: true, next_cursor: "cursor-25" })
      .mockResolvedValueOnce({ imports: [
        { ...savedImport([diagnostic("group", "next-page")], "neuvector", "cluster-1"), id: "next-import" },
      ], has_more: false });
    render(<PolicyCenterPage />);
    await settle();

    expect(familyElement("network-rules").textContent).toContain("selected");
    expect(familyElement("network-rules").textContent).toContain("Target: selected cluster");
    expect(familyElement("network-rules").textContent).toContain("legacy");
    expect(familyElement("network-rules").textContent).toContain("Target: unknown or unspecified");
    expect(familyElement("network-rules").textContent).not.toContain("sibling");
    expect(host?.querySelector('[data-testid="migration-other-cluster-diagnostics"]')?.textContent).toContain("Target: other cluster (cluster-2)");
    expect(host?.querySelector('[data-testid="migration-other-cluster-diagnostics"]')?.textContent).toContain("sibling");
    expect(enterprise.migrationImportsPage).toHaveBeenCalledWith({ limit: 25 });

    const button = Array.from(host?.querySelectorAll("button") ?? []).find((candidate) => candidate.textContent === "Load more imports");
    expect(button).toBeTruthy();
    await act(async () => { button?.click(); });
    await settle();

    expect(enterprise.migrationImportsPage).toHaveBeenCalledWith({ limit: 25, cursor: "cursor-25" });
    expect(familyElement("groups").textContent).toContain("next-page");
    expect(text()).not.toContain("Load more imports");
  });

  it("keeps loaded diagnostics visible when another page fails", async () => {
    vi.mocked(enterprise.migrationImportsPage)
      .mockResolvedValueOnce({ imports: [savedImport([diagnostic("network_rule", "saved")], "neuvector", "cluster-1")], has_more: true, next_cursor: "cursor-25" })
      .mockRejectedValueOnce(new Error("next page unavailable"));
    render(<PolicyCenterPage />);
    await settle();

    const button = Array.from(host?.querySelectorAll("button") ?? []).find((candidate) => candidate.textContent === "Load more imports");
    await act(async () => { button?.click(); });
    await settle();

    expect(familyElement("network-rules").textContent).toContain("saved");
    expect(host?.querySelector('[role="alert"]')?.textContent).toContain("Could not load more migration history");
    expect(text()).toContain("Load more imports");
  });
});

function diagnostic(kind: string, name: string, source?: Record<string, unknown>): MigrationUnsupported {
  return { kind, name, reason: "Unsupported source semantics", suggestion: "Review manually", source };
}

function savedImport(unsupported: MigrationUnsupported[], source = "neuvector", targetClusterId?: string): MigrationImportListItem {
  return {
    id: "import-1", source, status: "previewed", target_cluster_id: targetClusterId, unsupported, created_at: "2026-09-26T00:00:00Z",
    summary: { source, total: 0, create: 0, update: 0, enforce: 0, monitor: 0, enabled: 0,
      file_profiles: 0, process_profiles: 0, groups: 0, dpi_rules: 0, dpi_bindings: 0,
      network_rules: 0, unsupported: unsupported.length, engines: {}, categories: {},
      read_only: true, rollback_hint: "" },
  };
}

async function settle() {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 10)); });
    if (queryClient?.isFetching() === 0) return;
  }
  throw new Error("Policy Center queries did not settle");
}

function render(ui: ReactNode) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  act(() => {
    root?.render(
      <QueryClientProvider client={queryClient!}>
        <MemoryRouter>{ui}</MemoryRouter>
      </QueryClientProvider>,
    );
  });
}

function text() {
  return host?.textContent ?? "";
}

function portableText(slug: string) {
  return host?.querySelector(`[data-testid="policy-family-${slug}-portable"]`)?.textContent ?? "";
}

function changeText(family: string) {
  return host?.querySelector(`[data-testid="policy-family-${family}-last-changed"]`)?.textContent ?? "";
}

function changeTime(family: string) {
  return host?.querySelector(`[data-testid="policy-family-${family}-last-changed"] time`)?.getAttribute("datetime") ?? null;
}

function familyElement(slug: string) {
  const family = host?.querySelector<HTMLElement>(`[data-testid="policy-family-${slug}"]`);
  if (!family) throw new Error(`Missing policy family ${slug}`);
  return family;
}
