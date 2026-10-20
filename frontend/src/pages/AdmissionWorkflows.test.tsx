import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { policies, type AdmissionState } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { AdmissionSettingsPage } from "./AdmissionSettingsPage";
import { AdmissionRuleFormPage } from "./AdmissionRuleFormPage";

/** Kit Select keeps a hidden native mirror right before its trigger. */
function nativeSelect(root: ParentNode, selector: string): HTMLSelectElement | null {
  const element = root.querySelector(selector);
  if (!element) return null;
  if (element.tagName === "SELECT") return element as HTMLSelectElement;
  const previous = element.previousElementSibling;
  return previous?.tagName === "SELECT" ? previous as HTMLSelectElement : null;
}

const route = vi.hoisted(() => ({ navigate: vi.fn(), clusterId: "cluster" }));
vi.mock("@/api/client", () => ({ policies: { admissionState: vi.fn(), updateAdmissionState: vi.fn(), admissionOptions: vi.fn(), createAdmissionRule: vi.fn(), admissionRules: vi.fn().mockResolvedValue({ rules: [] }), admissionProfiles: vi.fn(), admissionDryRunHistory: vi.fn().mockResolvedValue({ history: [] }), importAdmissionProfile: vi.fn() }, componentsInventory: { list: vi.fn().mockResolvedValue({ components: [] }) } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId }) }));
vi.mock("@/components/GroupPicker", () => ({ GroupPicker: () => <input /> }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let owner = { org_id: "org", user_id: "user" };
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const state: AdmissionState = { cluster_id: "cluster", enabled: true, mode: "monitor", default_action: "allow", failure_policy: "ignore" };
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  owner = { org_id: "org", user_id: "user" }; route.clusterId = "cluster";
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function renderPage(page: ReactNode) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await rerenderPage(page);
}
async function rerenderPage(page: ReactNode = <AdmissionSettingsPage />) { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}>{page}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function change(selector: string, value: string) { await act(async () => { const input = (nativeSelect(host, selector) ?? host.querySelector<HTMLInputElement | HTMLSelectElement>(selector))!; Object.getOwnPropertyDescriptor(input instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function click(label: string) { await act(async () => { [...host.querySelectorAll("button")].find((button) => button.textContent?.trim() === label || button.getAttribute("aria-label") === label)!.click(); }); }
it.each(["failed", "foreign"])("does not edit %s admission settings", async (scenario) => {
  if (scenario === "failed") vi.mocked(policies.admissionState).mockRejectedValue(new Error("private"));
  else vi.mocked(policies.admissionState).mockResolvedValue({ ...state, cluster_id: "other" });
  await renderPage(<AdmissionSettingsPage />); await settled(() => expect(host.textContent).toContain("Could not load admission settings")); expect(host.querySelector("form")).toBeNull();
});
it("stages settings without autosaving and preserves them through refresh/save failure", async () => {
  vi.mocked(policies.admissionState).mockResolvedValue(state);
  vi.mocked(policies.updateAdmissionState).mockRejectedValue(new Error("private"));
  await renderPage(<AdmissionSettingsPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await change("#admission-mode", "protect"); expect(policies.updateAdmissionState).not.toHaveBeenCalled();
  await act(async () => { client.setQueryData(["admission-settings-editor", "cluster"], state); });
  expect(nativeSelect(host, "#admission-mode")?.value).toBe("protect");
  await click("Save changes"); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(policies.updateAdmissionState).toHaveBeenCalledWith({ enabled: true, mode: "protect", default_action: "allow", failure_policy: "ignore" }, { cluster_id: "cluster" });
  expect(host.textContent).not.toContain("private");
  vi.mocked(policies.updateAdmissionState).mockResolvedValue({ ...state, mode: "protect" });
  await click("Save changes");
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/admission" }));
  expect(policies.updateAdmissionState).toHaveBeenCalledTimes(2);
});
it("validates criterion values and keeps failed admission drafts", async () => {
  vi.mocked(policies.admissionOptions).mockResolvedValue({ criteria: [{ key: "cve_count", label: "CVE count", value_type: "int", help: "Count" }], rule_modes: ["monitor", "enforce"], severities: [], pss_levels: [] });
  vi.mocked(policies.createAdmissionRule).mockRejectedValue(new Error("private"));
  await renderPage(<AdmissionRuleFormPage />); await settled(() => expect(host.textContent).toContain("CVE count"));
  await change("#admission-rule-name", "test-rule"); await change('[aria-label="Criterion 1 type"]', "cve_count");
  await change('[aria-label="Criterion 1 value"]', "1.5");
  expect(host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled).toBe(true);
  await change('[aria-label="Criterion 1 value"]', "2"); await click("Create rule");
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(policies.createAdmissionRule).toHaveBeenCalledWith({ name: "test-rule", mode: "monitor", group: undefined, criteria: [{ key: "cve_count", value: "2" }] }, { cluster_id: "cluster" });
  expect(host.textContent).not.toContain("private");
});

async function beginHeldAdmissionWrite() {
  let complete!: (value: AdmissionState) => void;
  vi.mocked(policies.admissionState).mockImplementation(async params => ({ ...state, cluster_id: params?.cluster_id ?? "cluster" }));
  vi.mocked(policies.updateAdmissionState).mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  await renderPage(<AdmissionSettingsPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await change("#admission-mode", "protect"); await click("Save changes");
  await settled(() => { expect(policies.updateAdmissionState).toHaveBeenCalledTimes(1); expect(client.isMutating()).toBe(1); });
  expect(policies.updateAdmissionState).toHaveBeenCalledWith({ enabled: true, mode: "protect", default_action: "allow", failure_policy: "ignore" }, { cluster_id: "cluster" });
  return () => complete({ ...state, mode: "protect" });
}
async function finishAdmissionWrite(complete: () => void) {
  await act(async () => complete());
  await settled(() => expect(client.isMutating()).toBe(0));
}
async function laterAdmissionDraft() {
  await settled(() => expect(nativeSelect(host, "#admission-mode")?.value).toBe("monitor"));
  await change("#admission-default", "deny");
  expect(nativeSelect(host, "#admission-default")?.value).toBe("deny");
}

it("keeps a later admission settings draft after a held write completes across a cluster roundtrip", async () => {
  const complete = await beginHeldAdmissionWrite();
  route.clusterId = "other"; await rerenderPage();
  await settled(() => expect(policies.admissionState).toHaveBeenCalledWith({ cluster_id: "other" }));
  await settled(() => expect(nativeSelect(host, "#admission-mode")?.value).toBe("monitor"));
  route.clusterId = "cluster"; await rerenderPage(); await laterAdmissionDraft();
  await finishAdmissionWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(nativeSelect(host, "#admission-default")?.value).toBe("deny");
  expect(policies.updateAdmissionState).toHaveBeenCalledTimes(1);
});

it("keeps a later admission settings draft after a held write completes across an owner roundtrip", async () => {
  const complete = await beginHeldAdmissionWrite();
  owner = { org_id: "other-org", user_id: "other-user" }; await rerenderPage();
  await settled(() => expect(nativeSelect(host, "#admission-mode")?.value).toBe("monitor"));
  owner = { org_id: "org", user_id: "user" }; await rerenderPage(); await laterAdmissionDraft();
  await finishAdmissionWrite(complete);
  expect(route.navigate).not.toHaveBeenCalled();
  expect(nativeSelect(host, "#admission-default")?.value).toBe("deny");
  expect(policies.updateAdmissionState).toHaveBeenCalledTimes(1);
});

it("does not navigate after leaving pending admission settings and retains its invalidation", async () => {
  const complete = await beginHeldAdmissionWrite();
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await rerenderPage(<p>Outside admission settings</p>); await finishAdmissionWrite(complete);
  expect(host.textContent).toBe("Outside admission settings");
  expect(route.navigate).not.toHaveBeenCalled();
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["admission-state", "cluster"] });
});
