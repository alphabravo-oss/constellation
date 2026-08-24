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

    expect(portableText("network-rules")).toContain("Import");
    expect(portableText("network-rules")).toContain("Export");
    expect(portableText("runtime-dlp")).toContain("Import");
    expect(portableText("runtime-dlp")).toContain("Export");
    expect(portableText("runtime-signatures")).toContain("Import");
    expect(portableText("runtime-signatures")).toContain("Export");
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
