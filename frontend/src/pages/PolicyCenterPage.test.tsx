import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, expect, it, vi } from "vitest";

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
});

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
