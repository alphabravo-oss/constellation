import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { registries, type RegistryDTO } from "@/api/client";
import { RegistryFormPage } from "./RegistryFormPage";

const route = vi.hoisted(() => ({ regId: undefined as string | undefined, navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ registries: { get: vi.fn(), create: vi.fn(), update: vi.fn(), test: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", isLoading: false }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ regId: route.regId }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); route.regId = undefined; });
async function renderForm() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><RegistryFormPage /></QueryClientProvider>));
  await vi.waitFor(async () => {
    await act(async () => {});
    expect(host.querySelector("form")).not.toBeNull();
  });
}
function savedRegistry() {
  route.regId = "registry";
  vi.mocked(registries.get).mockResolvedValue({ id: "registry", name: "Private registry", kind: "generic-v2", endpoint: "https://registry.example.test", auth_kind: "static", has_secret: true, scan_cadence: "daily", image_globs: ["team/*"] } as RegistryDTO);
}
it("opens a dedicated new form with advanced disclosure and cancels without saving", async () => {
  await renderForm();
  expect(host.querySelector('[data-testid="registry-form"]')).not.toBeNull();
  expect(host.querySelector('[role="dialog"]')).toBeNull();
  expect(host.querySelector("details")?.open).toBe(false);
  expect([...host.querySelectorAll("button")].some((button) => button.textContent?.trim() === "Test")).toBe(false);
  await act(async () => [...host.querySelectorAll("button")].find((button) => button.textContent === "Cancel")!.click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/registries" });
  expect(registries.create).not.toHaveBeenCalled();
  expect(registries.test).not.toHaveBeenCalled();
});
it("loads the saved registry and preserves untouched credentials on save", async () => {
  savedRegistry(); vi.mocked(registries.update).mockResolvedValue();
  await renderForm();
  expect((host.querySelector("input[required]") as HTMLInputElement).value).toBe("Private registry");
  expect((host.querySelector('input[type="password"]') as HTMLInputElement).value).toBe("");
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  expect(registries.update).toHaveBeenCalledWith("registry", expect.objectContaining({ name: "Private registry", credentials: undefined, endpoint: "https://registry.example.test" }));
  expect(registries.create).not.toHaveBeenCalled();
  expect(registries.test).not.toHaveBeenCalled();
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/registries" });
});
it("keeps a failed save on the form without echoing a transport error", async () => {
  savedRegistry(); vi.mocked(registries.update).mockRejectedValue(new Error("sensitive-value"));
  await renderForm();
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await vi.waitFor(async () => {
    await act(async () => {});
    expect(host.querySelector('[role="alert"]')).not.toBeNull();
  });
  expect(host.querySelector('[role="alert"]')?.textContent).toContain("Could not save registry");
  expect(host.textContent).not.toContain("sensitive-value");
  expect(route.navigate).not.toHaveBeenCalled();
});
