import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { registries, type RegistryDTO } from "@/api/client";
import { RegistryImagesPage } from "./RegistryImagesPage";

vi.mock("@/api/client", () => ({ registries: { get: vi.fn(), images: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster" }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ regId: "registry" }), Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });

it.each(["registry", "images"])("does not describe a failed %s request as empty inventory", async (failed) => {
  vi.mocked(registries.get).mockResolvedValue({ name: "Registry" } as RegistryDTO);
  vi.mocked(registries.images).mockResolvedValue({ images: [], total: 0, limit: 100, offset: 0 });
  if (failed === "registry") vi.mocked(registries.get).mockRejectedValue(new Error("not found"));
  else vi.mocked(registries.images).mockRejectedValue(new Error("unavailable"));
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><RegistryImagesPage /></QueryClientProvider>));
  await vi.waitFor(async () => {
    await act(async () => {});
    expect(host.textContent).toContain("Image inventory is unavailable");
  });
  expect(host.textContent).not.toContain("No images discovered");
});
