import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { clusterInitBundles, type ClusterInitBundleMint } from "@/api/client";
import { RegisterClusterPage } from "./RegisterClusterPage";

const route = vi.hoisted(() => ({ bundleId: undefined as string | undefined, navigate: vi.fn(), blocker: vi.fn() }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => route.navigate, useParams: () => ({ bundleId: route.bundleId }), useBlocker: route.blocker, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
vi.mock("@/api/client", () => ({ clusterInitBundles: { list: vi.fn(), create: vi.fn(), rotate: vi.fn() } }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); route.bundleId = undefined; });
async function renderPage() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><RegisterClusterPage /></QueryClientProvider>));
  await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector("form")).not.toBeNull(); });
}
it("cancels new registration without creating a cluster", async () => {
  await renderPage();
  expect(host.querySelector("details")?.open).toBe(false);
  await act(async () => [...host.querySelectorAll("button")].find((b) => b.textContent === "Cancel" || b.getAttribute("aria-label") === "Cancel")!.click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters" });
  expect(clusterInitBundles.create).not.toHaveBeenCalled();
});
it("rotates only on submit and retains the one-time result", async () => {
  route.bundleId = "bundle";
  vi.mocked(clusterInitBundles.list).mockResolvedValue([]).mockResolvedValueOnce([{ id: "bundle", name: "Production", status: "active" }] as Awaited<ReturnType<typeof clusterInitBundles.list>>);
  vi.mocked(clusterInitBundles.rotate).mockResolvedValue({ id: "replacement", name: "Production", cluster_id: "cluster", yaml: "test-only-bundle", import_url: "https://example.test/import", expires_at: "2026-11-01T00:00:00Z" } as ClusterInitBundleMint);
  await renderPage();
  expect(clusterInitBundles.rotate).not.toHaveBeenCalled();
  await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector('[data-testid="bundle-yaml"]')?.textContent).toBe("test-only-bundle"); });
  expect(clusterInitBundles.rotate).toHaveBeenCalledExactlyOnceWith("bundle");
  expect(clusterInitBundles.create).not.toHaveBeenCalled();
  expect(route.blocker).toHaveBeenLastCalledWith(expect.objectContaining({ enableBeforeUnload: true }));
});
