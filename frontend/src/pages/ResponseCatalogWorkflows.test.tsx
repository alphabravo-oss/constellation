import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { responseRules, responseRulesV2, type ResponseRule, type ResponseRulePreview } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { ResponsePage } from "./ResponsePage";
import { ResponseRulesPage } from "./ResponseRulesPage";
import { ResponseCatalogOverrideFormPage } from "./ResponseCatalogOverrideFormPage";

/** Kit Select keeps a hidden native mirror right before its trigger. */
function nativeSelect(root: ParentNode, selector: string): HTMLSelectElement | null {
  const element = root.querySelector(selector);
  if (!element) return null;
  if (element.tagName === "SELECT") return element as HTMLSelectElement;
  const previous = element.previousElementSibling;
  return previous?.tagName === "SELECT" ? previous as HTMLSelectElement : null;
}
const route = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, loading: false, ruleId: "rule" as string | undefined, search: "", navigate: vi.fn(), setParams: vi.fn() }));
vi.mock("@/api/client", () => ({ responseRules: { list: vi.fn(), preview: vi.fn(), update: vi.fn() }, responseRulesV2: { list: vi.fn(), delete: vi.fn(), reorder: vi.fn(), exportYaml: vi.fn(), importYaml: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, cluster: route.cluster, isLoading: route.loading }) }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setParams] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ ruleId: route.ruleId }), useNavigate: () => route.navigate, Link: ({ children, href }: { children: ReactNode; href?: string }) => <a href={href}>{children}</a> }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const rule: ResponseRule = { id: "rule", name: "Shell started", description: "Watch for shells", event_type: "process", match: "process.name=shell", actions: ["alert"], mode: "monitor", enabled: false, default_mode: "monitor", default_enabled: true, severity: "high", source: "Built-in", override_reason: "Approved audit reason", managed: true, drifted: true };
const preview: ResponseRulePreview = { rule_id: "rule", current_mode: "monitor", next_mode: "monitor", current_enabled: false, next_enabled: false, actions: ["alert"], persists: false, requires_privileged_agent: true, impact: "No runtime behavior change.", warnings: ["Agent required"] };
const catalog = { rules: [rule], summary: { total: 1, enabled: 0, monitor: 1, enforce: 0, disabled: 1, managed: 1 } };
let owner = { org_id: "org", user_id: "user" };
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => { owner = { org_id: "org", user_id: "user" }; route.clusterId = "cluster"; route.cluster = { id: "cluster" }; route.loading = false; route.ruleId = "rule"; route.search = ""; vi.mocked(responseRules.list).mockResolvedValue(catalog); vi.mocked(responseRulesV2.list).mockResolvedValue({ rules: [] }); vi.mocked(responseRules.preview).mockResolvedValue({ preview }); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
async function renderPage(page = "form") {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await rerenderPage(page);
}
async function rerenderPage(page = "form") { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}>{page === "outside" ? <p>Outside response override</p> : page === "form" ? <ResponseCatalogOverrideFormPage /> : page === "v2" ? <ResponseRulesPage /> : <ResponsePage />}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function button(label: string) { return [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label || b.getAttribute("aria-label") === label || b.getAttribute("data-export-label") === label)!; }
async function click(label: string) { await act(async () => button(label).click()); }
async function change(selector: string, value: string) { await act(async () => { const input = (nativeSelect(host, selector) ?? host.querySelector<HTMLSelectElement | HTMLTextAreaElement | HTMLInputElement>(selector))!; const proto = input instanceof HTMLSelectElement ? HTMLSelectElement.prototype : input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function ready() { await settled(() => expect(button("Preview")?.disabled).toBe(false)); }
async function runPreview() { await click("Preview"); await settled(() => expect(button("Save").disabled).toBe(false)); }

it.each(["form", "catalog", "v2"])("does not query %s until the cluster resolves", async (page) => {
  route.loading = true; await renderPage(page); expect(responseRules.list).not.toHaveBeenCalled(); expect(responseRulesV2.list).not.toHaveBeenCalled();
});
it.each(["form", "catalog", "v2"])("blocks %s when the cluster cannot be resolved", async (page) => {
  route.cluster = undefined; await renderPage(page); expect(host.textContent).toContain("selected cluster could not be loaded"); expect(responseRules.list).not.toHaveBeenCalled(); expect(responseRulesV2.list).not.toHaveBeenCalled(); expect(host.querySelector("form")).toBeNull();
});
it.each(["failed", "missing"])("does not hydrate a %s built-in rule", async (scenario) => {
  if (scenario === "failed") vi.mocked(responseRules.list).mockRejectedValue(new Error("private transport")); else route.ruleId = "unknown";
  await renderPage(); await settled(() => expect(host.textContent).toContain("could not be loaded from the organization catalog")); expect(host.querySelector("form")).toBeNull(); expect(host.textContent).not.toContain("private transport"); expect(responseRules.update).not.toHaveBeenCalled();
});
it("hydrates the saved rule and requires a matching organization preview", async () => {
  await renderPage(); await ready(); expect(nativeSelect(host, "#response-override-mode")?.value).toBe("monitor"); expect(host.querySelector('[role="switch"]')?.getAttribute("aria-checked")).toBe("false"); expect(button("Save").disabled).toBe(true); expect(host.textContent).toContain("changes organization-wide settings"); expect(host.querySelector("details")?.open).toBe(false);
  await runPreview(); expect(responseRules.preview).toHaveBeenCalledWith("rule", { mode: "monitor", enabled: false, reason: "Approved audit reason" }); expect(host.textContent).toContain("Agent required");
});
it.each(["mode", "enabled", "reason"])("requires a fresh preview when %s changes", async (field) => {
  await renderPage(); await ready(); await runPreview();
  if (field === "enabled") await act(async () => host.querySelector<HTMLButtonElement>('[role="switch"]')!.click()); else await change(field === "mode" ? "#response-override-mode" : "textarea", field === "mode" ? "learn" : "Changed audit reason");
  expect(button("Save").disabled).toBe(true); expect(responseRules.update).not.toHaveBeenCalled();
});
it.each(["wrong-rule", "wrong-mode", "wrong-enabled", "persisted"])("rejects a %s preview response", async (scenario) => {
  vi.mocked(responseRules.preview).mockResolvedValue({ preview: { ...preview, ...(scenario === "wrong-rule" ? { rule_id: "other" } : scenario === "wrong-mode" ? { next_mode: "enforce" } : scenario === "wrong-enabled" ? { next_enabled: true } : { persists: true }) } });
  await renderPage(); await ready(); await click("Preview"); await settled(() => expect(host.textContent).toContain("Could not preview this override. Your draft is preserved")); expect(button("Save").disabled).toBe(true);
});
it("retains the draft but invalidates preview when saved catalog data changes", async () => {
  await renderPage(); await ready(); await change("textarea", "Unsaved audit draft"); await runPreview();
  await act(async () => { client.setQueryData(["response-rules"], { ...catalog, rules: [{ ...rule, mode: "enforce", enabled: true, override_reason: "Remote reason" }] }); });
  await settled(() => expect(button("Save").disabled).toBe(true)); expect(host.querySelector("textarea")?.value).toBe("Unsaved audit draft"); expect(nativeSelect(host, "#response-override-mode")?.value).toBe("monitor");
});
it("preserves failed-save drafts and sends the previewed saved-rule settings", async () => {
  vi.mocked(responseRules.update).mockRejectedValue(new Error("private transport")); await renderPage(); await ready(); await change("textarea", "Current audit draft"); await runPreview(); await click("Save"); await settled(() => expect(host.textContent).toContain("Could not save this override. Your draft is preserved"));
  expect(responseRules.update).toHaveBeenCalledWith("rule", { mode: "monitor", enabled: false, reason: "Current audit draft" }); expect(host.querySelector("textarea")?.value).toBe("Current audit draft"); expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private transport");
});
it("keeps a draft when catalog refresh fails and blocks writes until refresh succeeds", async () => {
  await renderPage(); await ready(); await change("textarea", "Draft awaiting refresh"); await runPreview(); vi.mocked(responseRules.list).mockRejectedValue(new Error("private"));
  await act(async () => { await client.invalidateQueries({ queryKey: ["response-rules"] }); }); await settled(() => expect(host.textContent).toContain("Refresh before previewing or saving")); expect(button("Save").disabled).toBe(true); expect(button("Preview").disabled).toBe(true); expect(host.querySelector("textarea")?.value).toBe("Draft awaiting refresh");
});
it("returns to the filtered catalog after saving or cancelling", async () => {
  route.search = "event=process&q=shell"; vi.mocked(responseRules.update).mockResolvedValue({ rule, preview: { ...preview, persists: true } }); await renderPage(); await ready(); await click("Cancel"); expect(responseRules.update).not.toHaveBeenCalled(); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/response?event=process&q=shell" });
  route.navigate.mockClear(); await runPreview(); await click("Save"); await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/response?event=process&q=shell" }));
});
it("requires a nonblank audit reason before previewing or saving", async () => {
  await renderPage(); await ready(); await change("textarea", "   "); expect(button("Preview").disabled).toBe(true); expect(button("Save").disabled).toBe(true); await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); expect(responseRules.update).not.toHaveBeenCalled();
});
it("uses URL filters and dedicated catalog edit links, separate from V2 authoring", async () => {
  route.search = "event=process&q=shell&context=keep"; vi.mocked(responseRules.list).mockResolvedValue({ ...catalog, rules: [rule, { ...rule, id: "network-rule", name: "Network rule", event_type: "network" }] });
  await renderPage("catalog"); await settled(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1)); expect(host.querySelector("form")).toBeNull(); expect(host.textContent).not.toContain("Network rule"); expect(responseRules.list).toHaveBeenCalledWith();
  await act(async () => host.querySelector<HTMLButtonElement>('[aria-label="Edit override for Shell started"]')!.click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/response/rule/edit?event=process&q=shell&context=keep" });
  await click("Authored response rules"); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/response-rules" }); await change("input", "new search"); const updater = route.setParams.mock.calls[0][0] as (current: URLSearchParams) => URLSearchParams; expect(updater(new URLSearchParams(route.search)).get("q")).toBe("new search"); expect(updater(new URLSearchParams(route.search)).get("context")).toBe("keep"); expect(responseRules.update).not.toHaveBeenCalled();
});
it("does not treat a failed catalog load as an empty successful list", async () => {
  vi.mocked(responseRules.list).mockRejectedValue(new Error("private transport")); await renderPage("catalog"); await settled(() => expect(host.textContent).toContain("Could not load the organization response catalog")); expect(host.textContent).not.toContain("No built-in response rules"); expect(host.textContent).not.toContain("private transport");
});
it("disables V2 authoring and import actions after a list failure", async () => {
  vi.mocked(responseRulesV2.list).mockRejectedValue(new Error("private transport")); await renderPage("v2"); await settled(() => expect(host.textContent).toContain("Could not load response rules")); expect(responseRulesV2.list).toHaveBeenCalledWith({ cluster_id: "cluster" }); expect(button("New rule").disabled).toBe(true); expect(button("Import").closest("fieldset")?.disabled).toBe(true); expect(host.textContent).not.toContain("private transport");
});

async function beginHeldOverrideWrite() {
  let complete!: () => void;
  vi.mocked(responseRules.list).mockResolvedValue({ ...catalog, rules: [rule, { ...rule, id: "other-rule", name: "Other built-in rule", override_reason: "Other rule reason" }], summary: { ...catalog.summary, total: 2 } });
  vi.mocked(responseRules.update).mockImplementation(() => new Promise(resolve => { complete = () => resolve({ rule, preview: { ...preview, persists: true } }); }));
  await renderPage(); await ready(); await change("textarea", "Original held reason"); await runPreview(); await click("Save");
  await settled(() => { expect(responseRules.update).toHaveBeenCalledTimes(1); expect(client.isMutating()).toBe(1); });
  expect(responseRules.update).toHaveBeenCalledWith("rule", { mode: "monitor", enabled: false, reason: "Original held reason" });
  return complete;
}
async function finishOverrideWrite(complete: () => void) {
  await act(async () => complete());
  await settled(() => expect(client.isMutating()).toBe(0));
}
async function laterOverrideDraft(reason: string) {
  await ready();
  expect(host.querySelector("textarea")?.value).toBe("Approved audit reason");
  await change("textarea", reason);
  expect(button("Save").disabled).toBe(true);
}

it("keeps a later override draft after a held save completes across a rule roundtrip", async () => {
  const complete = await beginHeldOverrideWrite();
  route.ruleId = "other-rule"; await rerenderPage(); await ready();
  expect(host.querySelector("textarea")?.value).toBe("Other rule reason");
  route.ruleId = "rule"; await rerenderPage(); await laterOverrideDraft("Later rule visit reason");
  await finishOverrideWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector("textarea")?.value).toBe("Later rule visit reason");
  expect(responseRules.update).toHaveBeenCalledTimes(1);
  expect(host.querySelector('[data-testid="response-rule-preview-card"]')).toBeNull();
});

it("keeps a later override draft after a held save completes across an owner roundtrip", async () => {
  const complete = await beginHeldOverrideWrite();
  owner = { org_id: "other-org", user_id: "other-user" }; await rerenderPage(); await ready();
  expect(host.querySelector("textarea")?.value).toBe("Approved audit reason");
  owner = { org_id: "org", user_id: "user" }; await rerenderPage(); await laterOverrideDraft("Later owner visit reason");
  await finishOverrideWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector("textarea")?.value).toBe("Later owner visit reason");
  expect(responseRules.update).toHaveBeenCalledTimes(1);
  expect(host.querySelector('[data-testid="response-rule-preview-card"]')).toBeNull();
});

it("does not navigate after leaving a pending override and retains catalog invalidation", async () => {
  const complete = await beginHeldOverrideWrite();
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await rerenderPage("outside"); await finishOverrideWrite(complete);
  expect(host.textContent).toBe("Outside response override");
  expect(route.navigate).not.toHaveBeenCalled();
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["response-rules"] });
});
