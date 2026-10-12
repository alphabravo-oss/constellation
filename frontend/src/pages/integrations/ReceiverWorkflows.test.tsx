/* global HTMLSelectElement */
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { receivers, type Receiver } from "@/api/client";
import { ReceiverFormPage } from "./ReceiverFormPage";

const route = vi.hoisted(() => ({ id: "receiver", navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ receivers: { list: vi.fn(), create: vi.fn(), patch: vi.fn(), testFire: vi.fn(), rotateSecret: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: route.id || undefined }), useNavigate: () => route.navigate, Link: ({ children, to, ...props }: { children: ReactNode; to?: string }) => <a href={to} {...props}>{children}</a> }));
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const receiver: Receiver = { id: "receiver", name: "Saved destination", kind: "webhook", endpoint: "https://hooks.example.test/receiver", rate_per_min: 42, template_id: "custom-layout", owner: "Security team", environment: "staging", supported_events: ["finding.escalated", "runtime."], config: { headers: { region: "primary" }, vendor_setting: "retained" }, status: "pending", created_at: "2026-10-12T10:00:00Z", paused: true, secret_ref: "fixture-secret-reference" };
const response = (item: Receiver = receiver) => ({ receivers: [item], delivery_history: [] });
let root: Root; let host: HTMLDivElement; let client: QueryClient;
afterEach(() => { expect(receivers.testFire).not.toHaveBeenCalled(); expect(receivers.rotateSecret).not.toHaveBeenCalled(); act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks(); route.id = "receiver"; });
async function renderPage(beforeRender?: (client: QueryClient) => void) { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); beforeRender?.(client); await act(async () => root.render(<QueryClientProvider client={client}><ReceiverFormPage /></QueryClientProvider>)); }
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><ReceiverFormPage /></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
function saveButton() { return host.querySelector<HTMLButtonElement>('[data-testid="create-receiver-save"]')!; }
function button(name: string) { return [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === name)!; }
async function input(selector: string, value: string) { const control = host.querySelector<HTMLInputElement>(selector)!; await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(control, value); control.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function textarea(selector: string, value: string) { const control = host.querySelector<HTMLTextAreaElement>(selector)!; await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(control, value); control.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function select(selector: string, value: string) { const control = host.querySelector<HTMLSelectElement>(selector)!; await act(async () => { control.value = value; control.dispatchEvent(new Event("change", { bubbles: true })); }); }

it.each(["failed", "missing", "duplicate"])("does not render an editable receiver for a %s exact-ID load", async (scenario) => {
  if (scenario === "failed") vi.mocked(receivers.list).mockRejectedValue(new Error("private backend details"));
  else vi.mocked(receivers.list).mockResolvedValue({ receivers: scenario === "missing" ? [{ ...receiver, id: "other-organization-record" }] : [receiver, receiver], delivery_history: [] });
  await renderPage(); await settled(() => expect(host.querySelector('[role="alert"]')).not.toBeNull());
  expect(host.querySelector("form")).toBeNull(); expect(receivers.patch).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private backend details");
});
it("loads the saved receiver and leaves its immutable kind and custom template intact", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Saved destination");
  expect(host.querySelector<HTMLSelectElement>("#receiver-kind")?.disabled).toBe(true);
  expect(host.querySelector<HTMLSelectElement>("#receiver-template")?.value).toBe("custom-layout");
  expect(host.querySelector<HTMLInputElement>("#receiver-rate")?.value).toBe("42");
  expect(host.querySelector<HTMLTextAreaElement>("#receiver-events")?.value).toBe("finding.escalated\nruntime.");
  expect(host.querySelector("details")?.open).toBe(false);
  expect(saveButton().disabled).toBe(true); expect(receivers.patch).not.toHaveBeenCalled();
});
it("patches only a changed name without clearing filters, unknown config, status, or secrets", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Renamed destination"); await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/settings/integrations" }));
  expect(receivers.patch).toHaveBeenCalledWith("receiver", { name: "Renamed destination" });
});
it("stages rate and template until Save", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-rate", "120"); await select("#receiver-template", "compact");
  expect(receivers.patch).not.toHaveBeenCalled(); await submit(); await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { rate_per_min: 120, template_id: "compact" }));
});
it.each(["array", "string"])("reads %s email recipients and preserves untouched configuration on a name-only update", async (shape) => {
  const email = { ...receiver, kind: "email", endpoint: "mailto:old@example.test", config: { to: shape === "array" ? ["old@example.test"] : "old@example.test", cc: ["security@example.test"], custom_delivery: { priority: "high" } } };
  vi.mocked(receivers.list).mockResolvedValue(response(email)); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("#receiver-recipients")).not.toBeNull());
  expect(host.querySelector<HTMLTextAreaElement>("#receiver-recipients")?.value).toBe("old@example.test"); await input("#receiver-name", "Renamed email"); await submit();
  await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { name: "Renamed email" }));
});
it.each(["array", "string"])("merges changed %s email recipients and keeps the mailto summary consistent", async (shape) => {
  const email = { ...receiver, kind: "email", endpoint: "mailto:old@example.test", config: { to: shape === "array" ? ["old@example.test"] : "old@example.test", cc: ["security@example.test"], custom_delivery: { priority: "high" } } };
  vi.mocked(receivers.list).mockResolvedValue(response(email)); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("#receiver-recipients")).not.toBeNull()); await textarea("#receiver-recipients", "new@example.test, second@example.test"); await submit();
  await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { config: { ...email.config, to: shape === "array" ? ["new@example.test", "second@example.test"] : "new@example.test, second@example.test" }, endpoint: "mailto:new@example.test,second@example.test" }));
});
it("retains a recipient draft while merging the freshest unedited config keys", async () => {
  const email = { ...receiver, kind: "email", endpoint: "mailto:old@example.test", config: { to: ["old@example.test"], region: "old" } };
  vi.mocked(receivers.list).mockResolvedValue(response(email)); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await textarea("#receiver-recipients", "draft@example.test");
  await act(async () => { client.setQueryData(["receiver-editor", "receiver"], response({ ...email, config: { ...email.config, region: "new", new_key: "retained" } })); await new Promise((resolve) => setTimeout(resolve, 0)); });
  await settled(() => expect(host.querySelector<HTMLTextAreaElement>("#receiver-recipients")?.value).toBe("draft@example.test")); await submit();
  await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { config: { to: ["draft@example.test"], region: "new", new_key: "retained" }, endpoint: "mailto:draft@example.test" }));
});
it("preserves edited values through a background refresh and a failed save", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); vi.mocked(receivers.patch).mockRejectedValue(new Error("private backend details"));
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Draft destination"); await input("#receiver-rate", "90");
  await act(async () => client.setQueryData(["receiver-editor", "receiver"], response({ ...receiver, name: "Remote rename", rate_per_min: 100, template_id: "verbose" })));
  expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Draft destination"); expect(host.querySelector<HTMLInputElement>("#receiver-rate")?.value).toBe("90"); expect(host.querySelector<HTMLSelectElement>("#receiver-template")?.value).toBe("custom-layout");
  await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expect(receivers.patch).toHaveBeenCalledWith("receiver", { name: "Draft destination", rate_per_min: 90 }); expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private backend details");
});
it.each(["missing", "failed"])("keeps the draft visible and blocks Save when a refresh is %s", async (scenario) => {
  vi.mocked(receivers.list).mockResolvedValueOnce(response()); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Retained draft");
  if (scenario === "missing") await act(async () => client.setQueryData(["receiver-editor", "receiver"], { receivers: [], delivery_history: [] }));
  else { vi.mocked(receivers.list).mockRejectedValue(new Error("private details")); await act(async () => client.invalidateQueries({ queryKey: ["receiver-editor", "receiver"] })); }
  await settled(() => expect(saveButton().disabled).toBe(true)); expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Retained draft"); await submit(); expect(receivers.patch).not.toHaveBeenCalled();
});
it.each(["", "0", "-1", "1.5", "2147483648"])("blocks invalid rate %s without coercing or discarding the draft", async (value) => {
  vi.mocked(receivers.list).mockResolvedValue(response()); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Draft destination"); await input("#receiver-rate", value); await submit();
  expect(host.querySelector<HTMLInputElement>("#receiver-rate")?.value).toBe(value); expect(saveButton().disabled).toBe(true); expect(receivers.patch).not.toHaveBeenCalled();
});
it("lets an operator explicitly clear filters while preserving unrelated fields", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await textarea("#receiver-events", ""); await submit(); await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { supported_events: [] }));
});
it("cancels a new draft without any API writes", async () => {
  route.id = ""; await renderPage(); expect(receivers.list).not.toHaveBeenCalled(); await act(async () => button("Cancel").click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/settings/integrations" }); expect(receivers.create).not.toHaveBeenCalled();
});
it("creates one receiver and keeps its one-time secret reveal separate from another create", async () => {
  route.id = ""; vi.mocked(receivers.create).mockResolvedValue({ id: "created", secret_key: "one-time-fixture-value" }); await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "https://hooks.example.test/new"); await submit();
  await settled(() => expect(host.querySelector('[data-testid="receiver-secret-key"]')?.textContent).toBe("one-time-fixture-value")); expect(host.querySelector("form")).toBeNull(); expect(receivers.create).toHaveBeenCalledTimes(1); expect(receivers.create).toHaveBeenCalledWith({ name: "New destination", kind: "slack", endpoint: "https://hooks.example.test/new", rate_per_min: 60, template_id: "default", owner: "", environment: "production", supported_events: [] });
  await act(async () => button("Done").click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/settings/integrations" });
});
it("preserves a failed create draft", async () => {
  route.id = ""; vi.mocked(receivers.create).mockRejectedValue(new Error("private details")); await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "https://hooks.example.test/new"); await submit();
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("New destination"); expect(host.querySelector("form")).not.toBeNull(); expect(host.textContent).not.toContain("private details");
});
it("never claims Copy succeeded when the clipboard rejects it", async () => {
  route.id = ""; vi.mocked(receivers.create).mockResolvedValue({ id: "created", secret_key: "one-time-fixture-value" }); vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("Permission denied")); await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "https://hooks.example.test/new"); await submit();
  await settled(() => expect(button("Copy")).toBeDefined()); await act(async () => button("Copy").click()); await settled(() => expect(host.textContent).toContain("Could not copy the secret")); expect(button("Copied")).toBeUndefined();
});
it("claims Copied only after a successful clipboard write", async () => {
  route.id = ""; vi.mocked(receivers.create).mockResolvedValue({ id: "created", secret_key: "one-time-fixture-value" }); const copy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue(); await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "https://hooks.example.test/new"); await submit();
  await settled(() => expect(button("Copy")).toBeDefined()); await act(async () => button("Copy").click()); await settled(() => expect(button("Copied")).toBeDefined()); expect(copy).toHaveBeenCalledWith("one-time-fixture-value");
});
it("resets the editor when navigating to a different exact receiver ID", async () => {
  vi.mocked(receivers.list).mockResolvedValueOnce(response()).mockResolvedValueOnce(response({ ...receiver, id: "other", name: "Other destination" })); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Unsaved first draft"); route.id = "other"; await rerender(); await settled(() => expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Other destination"));
});
it("waits for a fresh settled initial load before freezing an existing cached receiver", async () => {
  let resolveList!: (value: ReturnType<typeof response>) => void;
  vi.mocked(receivers.list).mockReturnValue(new Promise((resolve) => { resolveList = resolve; }));
  await renderPage((queryClient) => queryClient.setQueryData(["receiver-editor", "receiver"], response({ ...receiver, name: "Old cached name" })));
  expect(host.querySelector("form")).toBeNull();
  expect(host.textContent).toContain("Loading receiver");
  await act(async () => resolveList(response({ ...receiver, name: "Fresh saved name" })));
  await settled(() => expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Fresh saved name"));
});
it("keeps creation complete even if the backend does not return a secret", async () => {
  route.id = ""; vi.mocked(receivers.create).mockResolvedValue({ id: "created", secret_key: "" });
  await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "https://hooks.example.test/new"); await submit();
  await settled(() => expect(host.textContent).toContain("The receiver was created, but its secret was not returned"));
  expect(host.querySelector("form")).toBeNull(); expect(button("Copy")).toBeUndefined(); expect(receivers.create).toHaveBeenCalledTimes(1);
});
it("creates email recipients as configuration with the chosen advanced filters and template", async () => {
  route.id = ""; vi.mocked(receivers.create).mockResolvedValue({ id: "created", secret_key: "one-time-fixture-value" });
  await renderPage(); await input("#receiver-name", "Email destination"); await select("#receiver-kind", "email"); await textarea("#receiver-recipients", "first@example.test\nsecond@example.test"); await textarea("#receiver-events", "finding.escalated\nruntime."); await select("#receiver-template", "compact"); await submit();
  await settled(() => expect(receivers.create).toHaveBeenCalledWith({ name: "Email destination", kind: "email", config: { to: ["first@example.test", "second@example.test"] }, supported_events: ["finding.escalated", "runtime."], template_id: "compact", rate_per_min: 60, owner: "", environment: "production" }));
});
it("rejects an HTTP destination on create while preserving the typed value", async () => {
  route.id = ""; await renderPage(); await input("#receiver-name", "New destination"); await input("#receiver-endpoint", "http://example.test/hook"); await submit();
  expect(saveButton().disabled).toBe(true); expect(host.querySelector<HTMLInputElement>("#receiver-endpoint")?.value).toBe("http://example.test/hook"); expect(receivers.create).not.toHaveBeenCalled();
});
it("merges the latest exact-ID cache even when Save occurs before the observer rerenders", async () => {
  const email = { ...receiver, kind: "email", endpoint: "mailto:old@example.test", config: { to: ["old@example.test"], region: "old" } };
  vi.mocked(receivers.list).mockResolvedValue(response(email)); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await textarea("#receiver-recipients", "draft@example.test");
  await act(async () => {
    client.setQueryData(["receiver-editor", "receiver"], response({ ...email, config: { ...email.config, region: "new", new_key: "retained" } }));
    host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { config: { to: ["draft@example.test"], region: "new", new_key: "retained" }, endpoint: "mailto:draft@example.test" }));
});
it("does not patch a record removed from the latest cache before the observer rerenders", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response()); await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Retained draft");
  await act(async () => {
    client.setQueryData(["receiver-editor", "receiver"], { receivers: [], delivery_history: [] });
    host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expect(receivers.patch).not.toHaveBeenCalled(); expect(host.querySelector<HTMLInputElement>("#receiver-name")?.value).toBe("Retained draft");
});
it("leaves unusual unedited event identifiers untouched during a name-only patch", async () => {
  vi.mocked(receivers.list).mockResolvedValue(response({ ...receiver, supported_events: ["finding.escalated", "vendor,event", " retained-prefix "] })); vi.mocked(receivers.patch).mockResolvedValue({ status: "ok" });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#receiver-name", "Renamed destination"); await submit();
  await settled(() => expect(receivers.patch).toHaveBeenCalledWith("receiver", { name: "Renamed destination" }));
});
