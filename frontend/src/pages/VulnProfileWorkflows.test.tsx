import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { vulnProfiles, type VulnProfile } from "@/api/client";
import { VulnProfileFormPage } from "./VulnProfileFormPage";
import { VulnProfilePage } from "./VulnProfilePage";

const route = vi.hoisted(() => ({ profileId: "profile", clusterId: "cluster" as string | undefined, resolvedClusterId: "cluster" as string | undefined, clusterLoading: false, clusterError: null as Error | null, search: "", navigate: vi.fn(), setSearch: vi.fn() }));
vi.mock("@/api/client", () => ({ vulnProfiles: { list: vi.fn(), update: vi.fn(), create: vi.fn(), delete: vi.fn(), importYaml: vi.fn(), exportYaml: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, isLoading: route.clusterLoading, cluster: route.resolvedClusterId ? { id: route.resolvedClusterId } : undefined, error: route.clusterError }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ profileId: route.profileId || undefined }), useNavigate: () => route.navigate, Link: ({ children, href, to: _to, ...props }: { children: ReactNode; href?: string; to?: string }) => <a href={href} {...props}>{children}</a> }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setSearch] }));
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const profile: VulnProfile = { id: "profile", name: "Saved profile", description: "Saved description", active: true, domain_scope: { clusters: ["cluster"], namespaces: ["production"] }, entries: [
  { name: "Defer known CVEs", action: "suppress", name_regex: "^CVE-2026-.*$", images: ["registry/team/*"], days_to_fix: 30, score_floor: 7.5, severity_floor: "high", comment: "Investigating" },
  { name: "Recent critical", action: "escalate", reserved: "_recent", recent_days: 14, severity_floor: "critical" },
] };
let root: Root; let host: HTMLDivElement; let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks(); route.profileId = "profile"; route.clusterId = "cluster"; route.resolvedClusterId = "cluster"; route.clusterLoading = false; route.clusterError = null; route.search = ""; });
async function renderPage(page: ReactNode) { host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); await act(async () => root.render(<QueryClientProvider client={client}>{page}</QueryClientProvider>)); }
async function rerenderForm() { await act(async () => root.render(<QueryClientProvider client={client}><VulnProfileFormPage /></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
function button(text: string) { return [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === text || item.getAttribute("aria-label") === text)!; }
async function input(selector: string, value: string) { const control = host.querySelector<HTMLInputElement>(selector)!; await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(control, value); control.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function textarea(selector: string, value: string) { const control = host.querySelector<HTMLTextAreaElement>(selector)!; await act(async () => { Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(control, value); control.dispatchEvent(new Event("input", { bubbles: true })); }); }

it.each(["failed", "missing", "duplicate"])("blocks unsafe %s editor loads without rendering a writable form", async (scenario) => {
  if (scenario === "failed") vi.mocked(vulnProfiles.list).mockRejectedValue(new Error("private details"));
  else vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: scenario === "missing" ? [{ ...profile, id: "out-of-scope" }] : [profile, profile] });
  await renderPage(<VulnProfileFormPage />);
  await settled(() => expect(host.querySelector('[role="alert"]')).not.toBeNull());
  expect(host.querySelector("form")).toBeNull();
  expect(vulnProfiles.list).toHaveBeenCalledWith({ cluster_id: "cluster" });
  expect(host.textContent).not.toContain("private details");
});
it("loads structured fields and preserves all backend entry and scope fields on save", async () => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] }); vi.mocked(vulnProfiles.update).mockResolvedValue({ id: "profile" });
  await renderPage(<VulnProfileFormPage />);
  await settled(() => expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("Saved profile"));
  expect([...host.querySelectorAll("details")].every((item) => !item.open)).toBe(true);
  expect(host.querySelector<HTMLInputElement>("#profile-entry-score-0")?.value).toBe("7.5");
  expect(host.querySelector<HTMLTextAreaElement>("#profile-scope-namespaces")?.value).toBe("production");
  await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/vuln-profiles" }));
  const { id: _id, ...body } = profile;
  expect(vulnProfiles.update).toHaveBeenCalledWith("profile", body);
});
it("keeps edited fields and ordered entries after background refresh and failed save", async () => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] }); vi.mocked(vulnProfiles.update).mockRejectedValue(new Error("private details"));
  await renderPage(<VulnProfileFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await input("#profile-name", "Draft profile"); await textarea("#profile-entry-comment-0", "Draft decision");
  await act(async () => client.setQueryData(["vuln-profile-editor", "cluster", "profile"], { profiles: [{ ...profile, entries: [], description: "Changed remotely" }] }));
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("Draft profile");
  expect(host.querySelector<HTMLTextAreaElement>("#profile-entry-comment-0")?.value).toBe("Draft decision");
  await submit(); await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(vulnProfiles.update).toHaveBeenCalledWith("profile", expect.objectContaining({ entries: [expect.objectContaining({ comment: "Draft decision" }), profile.entries[1]] }));
  expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private details");
});
it.each(["missing", "failed"])("preserves the draft and disables saving after a %s refresh", async (scenario) => {
  vi.mocked(vulnProfiles.list).mockResolvedValueOnce({ profiles: [profile] });
  await renderPage(<VulnProfileFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input("#profile-name", "Draft profile");
  if (scenario === "missing") await act(async () => client.setQueryData(["vuln-profile-editor", "cluster", "profile"], { profiles: [] }));
  else { vi.mocked(vulnProfiles.list).mockRejectedValue(new Error("private details")); await act(async () => client.invalidateQueries({ queryKey: ["vuln-profile-editor", "cluster", "profile"] })); }
  await settled(() => expect(button("Save").disabled).toBe(true));
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("Draft profile"); await submit(); expect(vulnProfiles.update).not.toHaveBeenCalled();
});
it.each([["#profile-entry-days-0", "1.5"], ["#profile-entry-days-0", "-1"], ["#profile-entry-score-0", "10.1"], ["#profile-entry-recent-1", "0.5"]])("blocks invalid numeric field %s = %s without dropping the draft", async (selector, value) => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] });
  await renderPage(<VulnProfileFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await input(selector, value); await submit();
  expect(button("Save").disabled).toBe(true); expect(vulnProfiles.update).not.toHaveBeenCalled(); expect(host.querySelector<HTMLInputElement>(selector)?.value).toBe(value);
});
it("saves reordered entries in first-match evaluation order", async () => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] }); vi.mocked(vulnProfiles.update).mockResolvedValue({ id: "profile" });
  await renderPage(<VulnProfileFormPage />); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Move rule 2 up"]')!.click()); await submit();
  await settled(() => expect(vulnProfiles.update).toHaveBeenCalledWith("profile", expect.objectContaining({ entries: [profile.entries[1], profile.entries[0]] })));
});
it("creates a scoped inactive profile with reserved recent semantics and no immediate writes", async () => {
  route.profileId = ""; vi.mocked(vulnProfiles.create).mockResolvedValue({ id: "new-profile" });
  await renderPage(<VulnProfileFormPage />); expect(vulnProfiles.list).not.toHaveBeenCalled(); expect(vulnProfiles.create).not.toHaveBeenCalled();
  await input("#profile-name", "New profile"); await submit();
  await settled(() => expect(vulnProfiles.create).toHaveBeenCalledWith({ name: "New profile", description: "", active: false, entries: [{ name: "_recent", reserved: "_recent", recent_days: 14, severity_floor: "critical", action: "escalate" }], domain_scope: {} }, { cluster_id: "cluster" }));
});
it("supports adding and removing ordered rules and updating the domain scope", async () => {
  route.profileId = ""; vi.mocked(vulnProfiles.create).mockResolvedValue({ id: "new-profile" });
  await renderPage(<VulnProfileFormPage />); await input("#profile-name", "Custom profile");
  await act(async () => { button("Add rule").click(); });
  await input("#profile-entry-name-1", "Accept reviewed CVEs"); await textarea("#profile-scope-namespaces", "production\nstaging");
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Remove rule 1"]')!.click()); await submit();
  await settled(() => expect(vulnProfiles.create).toHaveBeenCalledWith(expect.objectContaining({ entries: [{ name: "Accept reviewed CVEs", action: "suppress" }], domain_scope: { namespaces: ["production", "staging"] } }), { cluster_id: "cluster" }));
});
it("preserves an empty saved rules array", async () => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [{ ...profile, entries: [] }] }); vi.mocked(vulnProfiles.update).mockResolvedValue({ id: "profile" });
  await renderPage(<VulnProfileFormPage />); await settled(() => expect(host.textContent).toContain("No rules yet")); await submit();
  await settled(() => expect(vulnProfiles.update).toHaveBeenCalledWith("profile", expect.objectContaining({ entries: [] })));
});
it("cancels without saving and exposes a back link to the cluster list", async () => {
  route.profileId = ""; await renderPage(<VulnProfileFormPage />);
  expect(host.querySelector('a[href="/clusters/cluster/vuln-profiles"]')).not.toBeNull();
  await act(async () => button("Cancel").click()); expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/vuln-profiles" }); expect(vulnProfiles.create).not.toHaveBeenCalled();
});
it.each([<VulnProfileFormPage />, <VulnProfilePage />])("never fetches profiles without an available cluster", async (page) => {
  route.clusterId = undefined; await renderPage(page); expect(vulnProfiles.list).not.toHaveBeenCalled(); expect(host.textContent).toContain("Select an available cluster");
});
it("renders navigation and shared table controls on the list and reports failed deletion", async () => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] }); vi.mocked(vulnProfiles.delete).mockRejectedValue(new Error("private details")); window.confirm = vi.fn(() => true);
  await renderPage(<VulnProfilePage />); await settled(() => expect(host.querySelector('a[href="/clusters/cluster/vuln-profiles/profile/edit"]')).not.toBeNull());
  expect(host.querySelector('a[href="/clusters/cluster/vuln-profiles/new"]')).not.toBeNull(); expect(host.querySelector("form")).toBeNull();
  expect(host.querySelector('button[aria-label="Columns"]')).not.toBeNull(); expect(host.querySelector('button[aria-label="compact density"]')).not.toBeNull(); expect(button("Export CSV")).toBeDefined();
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Delete Saved profile"]')!.click()); await settled(() => expect(host.textContent).toContain("Could not delete this vulnerability profile")); expect(host.textContent).not.toContain("private details");
});
it("distinguishes failed queries from a successful empty profiles list", async () => {
  vi.mocked(vulnProfiles.list).mockRejectedValue(new Error("private details")); await renderPage(<VulnProfilePage />);
  await settled(() => expect(host.textContent).toContain("Vulnerability profiles could not be loaded")); expect(host.textContent).not.toContain("No vulnerability profiles yet"); expect(button("Retry")).toBeDefined();
});
it("honors URL profile search and deep-linked transfer tools with explicit export failure", async () => {
  route.search = "tab=transfer"; vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] }); vi.mocked(vulnProfiles.exportYaml).mockRejectedValue(new Error("private details"));
  await renderPage(<VulnProfilePage />); await settled(() => expect(button("Export")).toBeDefined()); await act(async () => button("Export").click());
  await settled(() => expect(host.textContent).toContain("Could not export vulnerability profiles")); expect(vulnProfiles.exportYaml).toHaveBeenCalledWith({ cluster_id: "cluster" });
});
it("filters the primary workspace using the URL query", async () => {
  route.search = "q=no-match"; vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] });
  await renderPage(<VulnProfilePage />); await settled(() => expect(host.textContent).toContain("No matching profiles")); expect(host.querySelector('a[href="/clusters/cluster/vuln-profiles/profile/edit"]')).toBeNull();
});
it.each(["wrong", "missing", "error-with-stale"])("blocks an initial editor when cluster resolution is %s", async (scenario) => {
  if (scenario === "wrong") route.resolvedClusterId = "another-cluster";
  if (scenario === "missing") route.resolvedClusterId = undefined;
  if (scenario === "error-with-stale") route.clusterError = new Error("private scope details");
  await renderPage(<VulnProfileFormPage />);
  expect(host.textContent).toContain("selected cluster could not be resolved");
  expect(host.querySelector("form")).toBeNull();
  expect(vulnProfiles.list).not.toHaveBeenCalled();
  expect(vulnProfiles.create).not.toHaveBeenCalled();
  expect(host.textContent).not.toContain("private scope details");
});
it("requires resolved cluster identity before presenting a new profile form", async () => {
  route.profileId = ""; route.resolvedClusterId = undefined;
  await renderPage(<VulnProfileFormPage />);
  expect(host.querySelector("form")).toBeNull();
  route.resolvedClusterId = "cluster";
  await rerenderForm();
  expect(host.querySelector("form")).not.toBeNull();
  expect(vulnProfiles.list).not.toHaveBeenCalled();
});
it.each(["missing", "wrong", "error-with-stale", "loading"])("preserves an edited draft and pauses writes during transient %s cluster scope", async (scenario) => {
  vi.mocked(vulnProfiles.list).mockResolvedValue({ profiles: [profile] });
  vi.mocked(vulnProfiles.update).mockResolvedValue({ id: "profile" });
  await renderPage(<VulnProfileFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await input("#profile-name", "My retained draft");
  if (scenario === "missing") route.resolvedClusterId = undefined;
  if (scenario === "wrong") route.resolvedClusterId = "another-cluster";
  if (scenario === "error-with-stale") route.clusterError = new Error("private scope details");
  if (scenario === "loading") route.clusterLoading = true;
  await rerenderForm();
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("My retained draft");
  expect(host.textContent).toContain("saving is paused until the cluster resolves");
  expect(button("Save").disabled).toBe(true);
  const callsBeforeRetry = vi.mocked(vulnProfiles.list).mock.calls.length;
  await act(async () => client.invalidateQueries({ queryKey: ["vuln-profile-editor", "cluster", "profile"] }));
  expect(vulnProfiles.list).toHaveBeenCalledTimes(callsBeforeRetry);
  await submit();
  expect(vulnProfiles.update).not.toHaveBeenCalled();
  route.resolvedClusterId = "cluster"; route.clusterError = null; route.clusterLoading = false;
  await rerenderForm();
  await settled(() => expect(button("Save").disabled).toBe(false));
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("My retained draft");
  await submit();
  await settled(() => expect(vulnProfiles.update).toHaveBeenCalledWith("profile", expect.objectContaining({ name: "My retained draft" })));
});
it("preserves a new draft during a stale-cluster error and retries cluster resolution", async () => {
  route.profileId = "";
  await renderPage(<VulnProfileFormPage />);
  await input("#profile-name", "New retained draft");
  route.clusterError = new Error("private scope details");
  await rerenderForm();
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("New retained draft");
  expect(button("Save").disabled).toBe(true);
  await submit();
  expect(vulnProfiles.create).not.toHaveBeenCalled();
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await act(async () => button("Retry cluster").click());
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["clusters"] });
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["cluster", "cluster"] });
  route.clusterError = null;
  await rerenderForm();
  expect(host.querySelector<HTMLInputElement>("#profile-name")?.value).toBe("New retained draft");
  expect(button("Save").disabled).toBe(false);
});
