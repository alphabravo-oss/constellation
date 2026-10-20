import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { runtimeDLP, runtimeSignatures, dpiGroupBindings, groupsApi, type DLPRule, type Group } from "@/api/client";
import { RuntimeDLPFormPage } from "./RuntimeDLPFormPage";
import { RuntimeSignatureFormPage } from "./RuntimeSignatureFormPage";
import { RuntimeDLPPage } from "./RuntimeDLPPage";
import { RuntimeSignaturesPage } from "./RuntimeSignaturesPage";
import { DPIGroupBindingFormPage } from "./DPIGroupBindingFormPage";
import { DPIGroupBindingsPanel } from "@/components/DPIGroupBindingsPanel";

const route = vi.hoisted(() => ({ id: "cluster", ruleId: "rule" as string | undefined, search: "filter=a&filter=b", navigate: vi.fn() }));
vi.mock("@/api/client", () => {
  const rules = () => ({ list: vi.fn(), get: vi.fn(), create: vi.fn(), update: vi.fn(), promote: vi.fn(), demote: vi.fn(), remove: vi.fn() });
  return { runtimeDLP: rules(), runtimeSignatures: rules(), groupsApi: { list: vi.fn() }, dpiGroupBindings: { list: vi.fn(), bind: vi.fn(), unbind: vi.fn() } };
});
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: route.id, ruleId: route.ruleId, sigId: route.ruleId }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
vi.mock("@/components/ImportExportButtons", () => ({ ImportExportButtons: () => <span>Import/export</span> }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const rule = { id: "rule", cluster_id: "cluster", name: "Original rule", severity: 5, category: "dlp", mode: "monitor", apply_dir: 2, patterns: [{ pattern: "secret", op: "regex", context: "body" }], description: "Original description" } as DLPRule;
const group = { id: "group", name: "prod/api", kind: "container", members: ["api"], policy_mode: "monitor", profile_mode: "monitor" } as unknown as Group;
beforeEach(() => {
  route.id = "cluster"; route.ruleId = "rule"; route.search = "filter=a&filter=b";
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] }); vi.mocked(dpiGroupBindings.list).mockResolvedValue([]);
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
async function renderPage(node: ReactNode) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}>{node}</QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function submit() { await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }
async function click(label: string) {
  const button = [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label || b.getAttribute("aria-label") === label);
  expect(button).toBeDefined(); await act(async () => button!.click());
}
async function edit(selector: string, value: string) {
  const input = host.querySelector<HTMLInputElement | HTMLTextAreaElement>(selector)!;
  const prototype = input.tagName === "TEXTAREA" ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  await act(async () => { Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}
const variants = [
  { name: "DLP", api: runtimeDLP, Form: RuntimeDLPFormPage, List: RuntimeDLPPage, category: "dlp", key: "runtime-dlp-rule", slug: "runtime-dlp", test: "runtime-dlp" },
  { name: "signature", api: runtimeSignatures, Form: RuntimeSignatureFormPage, List: RuntimeSignaturesPage, category: "waf", key: "runtime-signature", slug: "runtime-signatures", test: "runtime-signatures" },
] as const;
describe.each(variants)("$name workflow", ({ api, Form, List, category, key, slug, test }) => {
  it.each(["failed", "other-cluster", "other-kind", "other-id"])("blocks a %s edit load", async (scenario) => {
    if (scenario === "failed") vi.mocked(api.get).mockRejectedValue(new Error("private transport details"));
    else vi.mocked(api.get).mockResolvedValue({ ...rule, category, ...(scenario === "other-cluster" ? { cluster_id: "other" } : scenario === "other-kind" ? { category: category === "dlp" ? "signature" : "dlp" } : { id: "other" }) });
    await renderPage(<Form />); await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster"));
    expect(host.querySelector("form")).toBeNull(); expect(api.update).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private transport details");
  });
  it("retains draft and pattern metadata through refresh and failed save", async () => {
    vi.mocked(api.get).mockResolvedValue({ ...rule, category }); vi.mocked(api.update).mockRejectedValue(new Error("private transport details"));
    await renderPage(<Form />); await settled(() => expect(host.querySelector("textarea")?.value).toBe("secret"));
    await edit("textarea", "secret\nnew-pattern");
    await act(async () => { client.setQueryData([key, "cluster", "rule"], { ...rule, category, description: "Changed elsewhere", patterns: [{ pattern: "secret", op: "changed", context: "header" }] }); });
    expect(host.querySelector<HTMLTextAreaElement>("textarea")!.value).toBe("secret\nnew-pattern"); expect(host.querySelector("details")?.open).toBe(false);
    await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
    expect(api.update).toHaveBeenCalledWith("rule", { patterns: [rule.patterns[0], "new-pattern"], severity: 5, description: "Original description" });
    expect(host.textContent).not.toContain("private transport details"); expect(route.navigate).not.toHaveBeenCalled();
  });
  it("keeps the loaded form mounted after refresh failure", async () => {
    vi.mocked(api.get).mockResolvedValueOnce({ ...rule, category }).mockRejectedValue(new Error("offline"));
    await renderPage(<Form />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    await act(async () => { await client.invalidateQueries({ queryKey: [key, "cluster", "rule"] }); });
    await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expect(host.querySelector("textarea")?.value).toBe("secret");
  });
  it("returns Save, Cancel, and Back to the scoped list with repeated filters", async () => {
    vi.mocked(api.get).mockResolvedValue({ ...rule, category }); vi.mocked(api.update).mockResolvedValue({ ...rule, category });
    await renderPage(<Form />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    const backTo = `/clusters/cluster/${slug}?${route.search}`; expect(host.querySelector("a")?.getAttribute("href")).toBe(backTo);
    await click("Cancel"); expect(route.navigate).toHaveBeenCalledWith({ href: backTo }); expect(api.update).not.toHaveBeenCalled();
    await submit(); await settled(() => expect(route.navigate).toHaveBeenCalledTimes(2)); expect(route.navigate).toHaveBeenLastCalledWith({ href: backTo });
  });
  it("validates new rules and creates monitor configuration", async () => {
    route.ruleId = undefined; vi.mocked(api.create).mockResolvedValue({ ...rule, category });
    await renderPage(<Form />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
    await edit(`#${test}-name`, "   "); await edit("textarea", "secret"); await submit(); expect(api.create).not.toHaveBeenCalled();
    await edit(`#${test}-name`, "  new-rule  "); await submit(); await settled(() => expect(api.create).toHaveBeenCalled());
    expect(api.create).toHaveBeenCalledWith({ cluster_id: "cluster", name: "new-rule", severity: 5, patterns: ["secret"], description: "", mode: "monitor", ...(category === "waf" ? { apply_dir: 3 } : {}) });
  });
  it("shows unknown counts on a failed list load", async () => {
    vi.mocked(api.list).mockRejectedValue(new Error("offline")); await renderPage(<List />);
    await settled(() => expect(host.textContent).toContain("could not be refreshed")); expect(host.textContent).toContain("—");
    expect(host.textContent).not.toContain("No DLP rules yet"); expect(host.textContent).not.toContain("No signatures yet");
    expect(host.querySelector("form")).toBeNull(); expect(host.querySelector("details")?.open).toBe(false);
  });
  it("puts the table before Advanced and reports failed promotion", async () => {
    vi.mocked(api.list).mockResolvedValue([{ ...rule, category }]); vi.mocked(api.promote).mockRejectedValue(new Error("private"));
    await renderPage(<List />); await settled(() => expect(host.querySelector("table")).not.toBeNull());
    expect(host.textContent).toContain("configured for enforcement"); expect(host.querySelector("form")).toBeNull();
    expect(host.querySelector("table")!.compareDocumentPosition(host.querySelector("details")!) & window.Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    await click("Promote"); await settled(() => expect(host.textContent).toContain("Could not update this configuration")); expect(route.navigate).not.toHaveBeenCalled();
    await act(async () => host.querySelector<HTMLButtonElement>(`[data-testid="${test}-new"]`)!.click()); expect(route.navigate).toHaveBeenCalledWith({ href: `/clusters/cluster/${slug}/new?${route.search}` });
  });
});
describe("detector group scope", () => {
  it("navigates from the scope list to a dedicated form", async () => {
    await renderPage(<DPIGroupBindingsPanel clusterId="cluster" kind="waf" title="Scope" description="Configured detector groups" />);
    await settled(() => expect(host.textContent).toContain("0 configured groups")); expect(host.querySelector("form")).toBeNull();
    await click("Add group"); expect(route.navigate).toHaveBeenCalledWith({ href: `/clusters/cluster/runtime-signatures/scope/new?${route.search}` });
  });
  it("blocks authoring when scope failed to load", async () => {
    vi.mocked(dpiGroupBindings.list).mockRejectedValue(new Error("private")); await renderPage(<DPIGroupBindingFormPage kind="dlp" />);
    await settled(() => expect(host.textContent).toContain("could not be loaded")); expect(host.querySelector("form")).toBeNull(); expect(dpiGroupBindings.bind).not.toHaveBeenCalled();
  });
  it("retains selected group after failed Save and scopes Cancel", async () => {
    vi.mocked(dpiGroupBindings.bind).mockRejectedValue(new Error("private")); await renderPage(<DPIGroupBindingFormPage kind="waf" />);
    await settled(() => expect(host.querySelector("form")).not.toBeNull());
    await act(async () => { host.querySelector<HTMLInputElement>("input")!.dispatchEvent(new window.FocusEvent("focusin", { bubbles: true })); });
    const option = [...host.querySelectorAll("button")].find((b) => b.textContent?.includes("prod/api")); expect(option).toBeDefined(); await act(async () => option!.click());
    await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expect(dpiGroupBindings.bind).toHaveBeenCalledWith({ group_id: "group", sensor_kind: "waf" });
    expect(host.querySelector<HTMLInputElement>("input")!.value).toBe("prod/api"); await click("Cancel"); expect(route.navigate).toHaveBeenCalledWith({ href: `/clusters/cluster/runtime-signatures?${route.search}` });
  });
});

it.each(variants)("blocks $name authoring without a cluster", async ({ api, Form }) => {
  route.id = ""; route.ruleId = undefined; route.search = "";
  await renderPage(<Form />); expect(host.textContent).toContain("Select a cluster"); expect(host.querySelector("form")).toBeNull(); expect(api.create).not.toHaveBeenCalled(); expect(api.get).not.toHaveBeenCalled();
});

it("waits for all scope removals before refreshing a partially failed result", async () => {
  const rows = ["one", "two"].map((id) => ({ id, org_id: "org", group_id: "group", sensor_kind: "dlp" as const, sensor_id: "" }));
  vi.mocked(dpiGroupBindings.list).mockResolvedValueOnce(rows).mockResolvedValue([]);
  let finish!: () => void;
  vi.mocked(dpiGroupBindings.unbind).mockRejectedValueOnce(new Error("private")).mockImplementationOnce(() => new Promise((resolve) => { finish = () => resolve({ deleted: "two" }); }));
  const originalConfirm = Object.getOwnPropertyDescriptor(window, "confirm");
  Object.defineProperty(window, "confirm", { configurable: true, writable: true, value: vi.fn(() => true) });
  try {
    await renderPage(<DPIGroupBindingsPanel clusterId="cluster" kind="dlp" title="Scope" description="Configured detector groups" />);
    await settled(() => expect(host.textContent).toContain("1 configured groups")); await click("Remove");
    await settled(() => expect(dpiGroupBindings.unbind).toHaveBeenCalledTimes(2)); expect(dpiGroupBindings.list).toHaveBeenCalledTimes(1);
    await act(async () => finish());
    await settled(() => expect(host.textContent).toContain("Could not fully remove")); await settled(() => expect(dpiGroupBindings.list).toHaveBeenCalledTimes(2));
    expect(host.textContent).not.toContain("private");
  } finally { if (originalConfirm) Object.defineProperty(window, "confirm", originalConfirm); else Reflect.deleteProperty(window, "confirm"); }
});
