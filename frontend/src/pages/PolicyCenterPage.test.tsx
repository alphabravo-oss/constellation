import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { enterprise, type MigrationImportListItem, type MigrationUnsupported } from "@/api/client";
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
  vi.spyOn(enterprise, "migrationImports").mockResolvedValue([]);
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
    vi.mocked(enterprise.migrationImports).mockResolvedValue([
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
    ]);
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
    expect(text()).toContain("do not identify a target cluster");
    expect(text()).not.toContain("other-source");
    expect(familyElement("runtime-dlp").textContent).not.toContain("http");
  });

  it("keeps unknown and ambiguous kinds in the general diagnostic area", async () => {
    vi.mocked(enterprise.migrationImports).mockResolvedValue([
      savedImport([
        diagnostic("unknown_future_kind", "future"),
        diagnostic("dpi_pattern", "ambiguous"),
        diagnostic("registry", "registry-record"),
      ]),
    ]);
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
    let resolveImports!: (imports: MigrationImportListItem[]) => void;
    vi.mocked(enterprise.migrationImports).mockImplementation(() => new Promise((resolve) => { resolveImports = resolve; }));
    render(<PolicyCenterPage />);
    expect(text()).toContain("Loading migration diagnostics");

    await act(async () => resolveImports([]));
    await settle();
    expect(text()).toContain("No saved NeuVector unsupported diagnostics");

    vi.mocked(enterprise.migrationImports).mockRejectedValue(new Error("unavailable"));
    await act(async () => { await queryClient?.invalidateQueries({ queryKey: ["migration-imports"] }); });
    await settle();
    expect(host?.querySelector('[role="alert"]')?.textContent).toContain("Migration diagnostics are unavailable");
    expect(text()).not.toContain("No saved NeuVector unsupported diagnostics");
  });
});

function diagnostic(kind: string, name: string, source?: Record<string, unknown>): MigrationUnsupported {
  return { kind, name, reason: "Unsupported source semantics", suggestion: "Review manually", source };
}

function savedImport(unsupported: MigrationUnsupported[], source = "neuvector"): MigrationImportListItem {
  return {
    id: "import-1", source, status: "previewed", unsupported, created_at: "2026-09-26T00:00:00Z",
    summary: { source, total: 0, create: 0, update: 0, enforce: 0, monitor: 0, enabled: 0,
      file_profiles: 0, process_profiles: 0, groups: 0, dpi_rules: 0, dpi_bindings: 0,
      network_rules: 0, unsupported: unsupported.length, engines: {}, categories: {},
      read_only: true, rollback_hint: "" },
  };
}

async function settle() {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
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

function familyElement(slug: string) {
  const family = host?.querySelector<HTMLElement>(`[data-testid="policy-family-${slug}"]`);
  if (!family) throw new Error(`Missing policy family ${slug}`);
  return family;
}
