/* global HTMLSelectElement */
import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { policies, type AdmissionState } from "@/api/client";
import { AdmissionSettingsPage } from "./AdmissionSettingsPage";
import { AdmissionRuleFormPage } from "./AdmissionRuleFormPage";

const route = vi.hoisted(() => ({ navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ policies: { admissionState: vi.fn(), updateAdmissionState: vi.fn(), admissionOptions: vi.fn(), createAdmissionRule: vi.fn(), admissionRules: vi.fn().mockResolvedValue({ rules: [] }), admissionProfiles: vi.fn(), admissionDryRunHistory: vi.fn().mockResolvedValue({ history: [] }), importAdmissionProfile: vi.fn() }, componentsInventory: { list: vi.fn().mockResolvedValue({ components: [] }) } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster" }) }));
vi.mock("@/components/GroupPicker", () => ({ GroupPicker: () => <input /> }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const state: AdmissionState = { cluster_id: "cluster", enabled: true, mode: "monitor", default_action: "allow", failure_policy: "ignore" };
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function renderPage(page: ReactNode) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}>{page}</QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function change(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!; Object.getOwnPropertyDescriptor(input instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function click(label: string) { await act(async () => { [...host.querySelectorAll("button")].find((button) => button.textContent?.trim() === label)!.click(); }); }
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
  expect(host.querySelector<HTMLSelectElement>("#admission-mode")?.value).toBe("protect");
  await click("Save changes"); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(policies.updateAdmissionState).toHaveBeenCalledWith({ enabled: true, mode: "protect", default_action: "allow", failure_policy: "ignore" }, { cluster_id: "cluster" });
  expect(host.textContent).not.toContain("private");
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
