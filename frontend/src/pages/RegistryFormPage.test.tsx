import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { registries, type RegistryDTO } from "@/api/client";
import { RegistryFormPage } from "./RegistryFormPage";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";

const route = vi.hoisted(() => ({ regId: undefined as string | undefined, orgId: "org", userId: "user", navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ registries: { get: vi.fn(), create: vi.fn(), update: vi.fn(), test: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", isLoading: false }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ regId: route.regId }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); route.regId = undefined; route.orgId = "org"; route.userId = "user"; });
async function renderForm(page: ReactNode = <RegistryFormPage />) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}>{page}</QueryClientProvider>));
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

function ownedRegistryForm() {
  return <TablePreferencesProvider identity={{ org_id: route.orgId, user_id: route.userId }}><RegistryFormPage /></TablePreferencesProvider>;
}
async function rerenderOwnedRegistry() {
  await act(async () => root.render(<QueryClientProvider client={client}>{ownedRegistryForm()}</QueryClientProvider>));
}
async function registrySettled(check: () => void) {
  await vi.waitFor(async () => { await act(async () => {}); check(); });
}
async function editRegistryName(value: string) {
  const input = host.querySelector<HTMLInputElement>("input[required]")!;
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}

it.each(["registry", "owner"])("preserves a fresh registry draft after a pending save leaves and returns to its %s", async context => {
  savedRegistry();
  vi.mocked(registries.get).mockImplementation(async id => ({ id, name: `Registry ${id}`, kind: "generic-v2", endpoint: "https://registry.example.test", auth_kind: "static", has_secret: true, scan_cadence: "daily", image_globs: [] } as RegistryDTO));
  let complete!: () => void;
  vi.mocked(registries.update).mockImplementation(() => new Promise<void>(resolve => { complete = resolve; }));
  await renderForm(ownedRegistryForm()); await editRegistryName("Original pending edit");
  await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  await registrySettled(() => expect(registries.update).toHaveBeenCalledTimes(1));
  if (context === "registry") route.regId = "another-registry"; else route.userId = "another-user";
  await rerenderOwnedRegistry();
  await registrySettled(() => expect(host.querySelector<HTMLInputElement>("input[required]")?.value).toBe(`Registry ${route.regId}`));
  route.regId = "registry"; route.userId = "user"; await rerenderOwnedRegistry();
  await registrySettled(() => expect(host.querySelector<HTMLInputElement>("input[required]")?.value).toBe("Registry registry"));
  await editRegistryName("A fresh registry draft");
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await act(async () => complete()); await registrySettled(() => expect(client.isMutating()).toBe(0));
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector<HTMLInputElement>("input[required]")!.value).toBe("A fresh registry draft");
  expect(registries.update).toHaveBeenCalledTimes(1);
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["registries"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["registry", "registry"] });
});

it("does not redirect another workspace when a pending registry save completes after editor unmount", async () => {
  savedRegistry(); let complete!: () => void;
  vi.mocked(registries.update).mockImplementation(() => new Promise<void>(resolve => { complete = resolve; }));
  await renderForm(ownedRegistryForm());
  await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  await registrySettled(() => expect(registries.update).toHaveBeenCalledTimes(1));
  await act(async () => root.render(<QueryClientProvider client={client}><p>Another workspace</p></QueryClientProvider>));
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await act(async () => complete()); await registrySettled(() => expect(client.isMutating()).toBe(0));
  expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).toBe("Another workspace");
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["registries"] });
});

it("preserves a reopened registry draft after its pending editor unmounts during a same-target load error", async () => {
  savedRegistry(); let complete!: () => void;
  vi.mocked(registries.update).mockImplementation(() => new Promise<void>(resolve => { complete = resolve; }));
  await renderForm(ownedRegistryForm());
  await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })));
  await registrySettled(() => expect(registries.update).toHaveBeenCalledTimes(1));
  const current = client.getQueryData<RegistryDTO>(["registry", "registry"])!;
  await act(async () => client.getQueryCache().find({ queryKey: ["registry", "registry"], exact: true })!.setState({ status: "error", error: new Error("Temporary load failure") }));
  await registrySettled(() => expect(host.querySelector("form")).toBeNull());
  await act(async () => client.setQueryData(["registry", "registry"], { ...current }));
  await registrySettled(() => expect(host.querySelector<HTMLInputElement>("input[required]")?.value).toBe(current.name));
  await editRegistryName("A reopened registry draft");
  await act(async () => complete()); await registrySettled(() => expect(client.isMutating()).toBe(0));
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector<HTMLInputElement>("input[required]")!.value).toBe("A reopened registry draft");
});
