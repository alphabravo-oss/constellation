import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { policies, type AdmissionProfile, type AdmissionProfileBundle, type AdmissionProfileImportResponse } from "@/api/client";
import { AdmissionProfileImportPage } from "./AdmissionProfileImportPage";
import { TestRouter } from "@/test/router";

const cluster = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => cluster }));
vi.mock("@/api/client", () => ({ policies: { list: vi.fn(), admissionProfiles: vi.fn(), importAdmissionProfile: vi.fn(), exportAdmissionProfile: vi.fn() } }));
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const profile: AdmissionProfile = { id: "baseline", name: "Baseline", description: "Baseline rules", failure_policy: "Ignore", rules: [{ name: "non-root", description: "Use a non-root user", engine: "admission", category: "security", enabled: true, mode: "monitor", spec_yaml: "requireVulnDBBundle: true" }] };
const bundle: AdmissionProfileBundle = { api_version: "constellation.alphabravo.io/v1alpha1", kind: "AdmissionProfileBundle", profile };
const preview: AdmissionProfileImportResponse = { profile_id: "baseline", dry_run: true, imported: 0, policies: [{ ...profile.rules[0], rule_name: "non-root", policy_name: "baseline/non-root" }] };
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => { cluster.clusterId = "cluster"; cluster.cluster = { id: "cluster" }; cluster.isLoading = false; vi.mocked(policies.admissionProfiles).mockResolvedValue({ profiles: [profile] }); vi.mocked(policies.list).mockResolvedValue({ policies: [] }); vi.mocked(policies.importAdmissionProfile).mockResolvedValue(preview); });
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); localStorage.clear(); });
async function renderPage(search = "") {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  history = createMemoryHistory({ initialEntries: [`/clusters/cluster/admission/import${search}`] });
  await act(async () => root.render(<QueryClientProvider client={client}><TestRouter history={history}><AdmissionProfileImportPage /></TestRouter></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function button(label: string) { return [...host.querySelectorAll("button")].find((b) => b.textContent?.trim() === label || b.getAttribute("aria-label") === label)!; }
async function click(label: string) { await act(async () => button(label).click()); }
async function change(selector: string, value: string) { await act(async () => { const input = host.querySelector<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>(selector)!; const proto = input instanceof HTMLSelectElement ? HTMLSelectElement.prototype : input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(proto, "value")!.set!.call(input, value); input.dispatchEvent(new Event(input instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function ready() { await settled(() => expect(button("Preview")?.disabled).toBe(false)); }
async function runPreview() { await click("Preview"); await settled(() => expect(button("Import profile").disabled).toBe(false)); }

it.each(["loading", "missing"])("does not fetch import data for a %s cluster", async (scenario) => {
  if (scenario === "loading") cluster.isLoading = true; else { cluster.clusterId = undefined; cluster.cluster = undefined; }
  await renderPage(); await settled(() => expect(host.querySelector("form")).toBeNull()); expect(policies.list).not.toHaveBeenCalled(); expect(policies.admissionProfiles).not.toHaveBeenCalled();
});
it("compares organization policies and requires a preview before import", async () => {
  await renderPage(); await ready(); expect(policies.list).toHaveBeenCalledWith(); expect(button("Import profile").disabled).toBe(true); expect(host.textContent).toContain("applies across the organization");
  await runPreview(); expect(policies.importAdmissionProfile).toHaveBeenCalledWith({ profile_id: "baseline", dry_run: true });
  expect(host.querySelector("details")?.open).toBe(false); expect(host.textContent).toContain("VulnDB");
});
it.each(["mode", "enabled", "profile"])("requires another preview after changing %s", async (field) => {
  vi.mocked(policies.admissionProfiles).mockResolvedValue({ profiles: [profile, { ...profile, id: "restricted", name: "Restricted" }] });
  await renderPage(); await ready(); await runPreview();
  await change(`#admission-profile${field === "profile" ? "" : `-${field}`}`, field === "mode" ? "enforce" : field === "enabled" ? "disabled" : "restricted");
  expect(button("Import profile").disabled).toBe(true); expect(policies.importAdmissionProfile).toHaveBeenCalledTimes(1);
});
it("rejects an invalid bundle and preserves pasted JSON after preview failure", async () => {
  await renderPage("?tab=bundle"); await settled(() => expect(host.querySelector("textarea")).not.toBeNull()); await change("textarea", "{broken"); expect(host.textContent).toContain("Bundle JSON is invalid"); expect(button("Preview").disabled).toBe(true);
  vi.mocked(policies.importAdmissionProfile).mockRejectedValue(new Error("private transport error")); await change("textarea", JSON.stringify(bundle)); await ready(); await click("Preview");
  await settled(() => expect(host.textContent).toContain("Could not preview this profile. Your draft is preserved")); expect(host.querySelector("textarea")?.value).toBe(JSON.stringify(bundle)); expect(host.textContent).not.toContain("private transport error"); expect(button("Import profile").disabled).toBe(true);
});
it("requires a new preview when bundle content changes", async () => {
  await renderPage("?tab=bundle"); await settled(() => expect(host.querySelector("textarea")).not.toBeNull()); await change("textarea", JSON.stringify(bundle)); await ready(); await runPreview();
  expect(policies.importAdmissionProfile).toHaveBeenCalledWith({ bundle, dry_run: true });
  await change("textarea", JSON.stringify({ ...bundle, profile: { ...profile, name: "Edited" } })); expect(button("Import profile").disabled).toBe(true);
});
it("invalidates preview when a catalog refresh changes the profile", async () => {
  await renderPage(); await ready(); await runPreview(); await act(async () => { client.setQueryData(["admission-profiles"], { profiles: [{ ...profile, description: "Updated profile" }] }); }); await settled(() => expect(button("Import profile").disabled).toBe(true));
});
it("preserves form options after a failed import", async () => {
  await renderPage(); await ready(); await change("#admission-profile-mode", "enforce"); await runPreview(); vi.mocked(policies.importAdmissionProfile).mockRejectedValue(new Error("private")); await click("Import profile");
  await settled(() => expect(host.textContent).toContain("Could not import this profile. Your draft is preserved")); expect(host.querySelector<HTMLSelectElement>("#admission-profile-mode")?.value).toBe("enforce"); expect(history.location.pathname).toContain("/admission/import"); expect(host.textContent).not.toContain("private");
});
it("imports the previewed options and returns to admission", async () => {
  await renderPage(); await ready(); await change("#admission-profile-mode", "monitor"); await change("#admission-profile-enabled", "disabled"); await runPreview(); vi.mocked(policies.importAdmissionProfile).mockResolvedValue({ ...preview, dry_run: false, imported: 1 }); await click("Import profile");
  await settled(() => expect(history.location.pathname).toBe("/clusters/cluster/admission")); expect(policies.importAdmissionProfile).toHaveBeenLastCalledWith({ profile_id: "baseline", mode: "monitor", enabled: false, dry_run: false });
});
it("keeps bundle text when installed-policy comparison fails", async () => {
  await renderPage("?tab=bundle"); await settled(() => expect(host.querySelector("textarea")).not.toBeNull()); await change("textarea", JSON.stringify(bundle)); await ready();
  vi.mocked(policies.list).mockRejectedValue(new Error("private")); await act(async () => { await client.invalidateQueries({ queryKey: ["policies", "organization-import-comparison"] }); });
  await settled(() => expect(host.textContent).toContain("Could not load installed policies for comparison")); expect(host.querySelector("textarea")?.value).toBe(JSON.stringify(bundle)); expect(button("Preview").disabled).toBe(true);
});
it("downloads catalog bundles without changing the selected source", async () => {
  const clickDownload = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {}); const createUrl = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); const revokeUrl = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  vi.mocked(policies.exportAdmissionProfile).mockResolvedValue(bundle); await renderPage(); await ready(); await click("Export bundle"); await settled(() => expect(clickDownload).toHaveBeenCalled()); expect(policies.exportAdmissionProfile).toHaveBeenCalledWith("baseline"); expect(createUrl).toHaveBeenCalled(); expect(revokeUrl).toHaveBeenCalledWith("blob:export"); expect(host.querySelector("textarea")).toBeNull(); clickDownload.mockRestore(); createUrl.mockRestore(); revokeUrl.mockRestore();
});
