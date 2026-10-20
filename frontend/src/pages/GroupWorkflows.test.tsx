import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { groupsApi, policies, type Group, type GroupUsage } from "@/api/client";
import { GroupFormPage } from "./GroupFormPage";
import { GroupDetailPage } from "./GroupDetailPage";
import { GroupsPage } from "./GroupsPage";
import { GroupSettingsPage } from "./GroupSettingsPage";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";

const route = vi.hoisted(() => ({ groupId: "group", orgId: "org", userId: "user", clusterId: "cluster" as string | undefined, resolvedClusterId: "cluster" as string | undefined, clusterLoading: false, clusterError: null as Error | null, search: "", navigate: vi.fn(), setSearch: vi.fn() }));
vi.mock("@/api/client", () => ({ policies: { serviceModeDefaults: vi.fn(), updateServiceModeDefaults: vi.fn() }, groupsApi: { list: vi.fn(), usage: vi.fn(), update: vi.fn(), create: vi.fn(), delete: vi.fn(), promote: vi.fn(), exportYaml: vi.fn(), importYaml: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: route.clusterId, isLoading: route.clusterLoading, cluster: route.resolvedClusterId ? { id: route.resolvedClusterId } : undefined, error: route.clusterError }) }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ groupId: route.groupId || undefined }), useNavigate: () => route.navigate, Link: ({ children, href, to: _to, ...props }: { children: ReactNode; href?: string; to?: string }) => <a href={href} {...props}>{children}</a> }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), route.setSearch] }));
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const group: Group = { id: "group", name: "Saved group", kind: "ground", comment: "Saved description", criteria: [{ key: "namespace", op: "eq", value: "production" }], members: ["production/api"], learned_from: "", cfg_type: "user", policy_mode: "monitor", profile_mode: "discover" };
const usage: GroupUsage = { group_id: "group", group_name: "Saved group", summary: { total_references: 1, blocking_references: 1, network_rules: 1, dpi_sensor_bindings: 0, process_profiles: 0, file_profiles: 0, response_rules: 0, admission_rules: 0, derived_references: 0, member_targets: 1, delete_blocked: true }, references: [{ id: "rule", family: "network", name: "Allow API", kind: "rule", blocking: true, route: "/clusters/cluster/network-rules" }], coverage: [] };
beforeEach(() => { vi.mocked(policies.serviceModeDefaults).mockResolvedValue({ cluster_id: "cluster", policy_mode: "monitor", profile_mode: "discover" }); });
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => {
  act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); vi.restoreAllMocks();
  route.groupId = "group"; route.orgId = "org"; route.userId = "user"; route.clusterId = "cluster"; route.resolvedClusterId = "cluster"; route.clusterLoading = false; route.clusterError = null; route.search = "";
});
async function renderPage(page: ReactNode, beforeRender?: (queryClient: QueryClient) => void | Promise<void>) {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await beforeRender?.(client);
  await act(async () => root.render(<QueryClientProvider client={client}>{page}</QueryClientProvider>));
}
async function rerenderPage(page: ReactNode) { await act(async () => root.render(<QueryClientProvider client={client}>{page}</QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function submit() { await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }
function button(text: string) { return [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === text)!; }
async function changeInput(selector: string, value: string) {
  const input = host.querySelector<HTMLInputElement>(selector)!;
  await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("input", { bubbles: true })); });
}

function ownedGroupForm() {
  return <TablePreferencesProvider identity={{ org_id: route.orgId, user_id: route.userId }}><GroupFormPage /></TablePreferencesProvider>;
}

it.each(["group", "owner"])("preserves a fresh group draft after a pending save leaves and returns to its %s", async context => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group, { ...group, id: "another-group", name: "Another group" }] });
  let complete!: (value: Awaited<ReturnType<typeof groupsApi.update>>) => void;
  vi.mocked(groupsApi.update).mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  await renderPage(ownedGroupForm()); await settled(() => expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe(group.name));
  await changeInput("#group-name", "Original pending edit"); await submit();
  await settled(() => expect(groupsApi.update).toHaveBeenCalledTimes(1));
  if (context === "group") route.groupId = "another-group"; else route.userId = "another-user";
  await rerenderPage(ownedGroupForm());
  await settled(() => expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe(context === "group" ? "Another group" : group.name));
  route.groupId = "group"; route.userId = "user"; await rerenderPage(ownedGroupForm());
  await settled(() => expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe(group.name));
  await changeInput("#group-name", "A fresh group draft");
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await act(async () => complete({ id: group.id })); await settled(() => expect(client.isMutating()).toBe(0));
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.querySelector<HTMLInputElement>("#group-name")!.value).toBe("A fresh group draft");
  expect(groupsApi.update).toHaveBeenCalledTimes(1);
  for (const family of ["groups", "group-usage", "dashboard"]) expect(invalidate).toHaveBeenCalledWith({ queryKey: [family, "cluster"] });
});

it("does not redirect another workspace when a pending group save completes after editor unmount", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  let complete!: (value: Awaited<ReturnType<typeof groupsApi.update>>) => void;
  vi.mocked(groupsApi.update).mockImplementation(() => new Promise(resolve => { complete = resolve; }));
  await renderPage(ownedGroupForm()); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await submit();
  await settled(() => expect(groupsApi.update).toHaveBeenCalledTimes(1));
  await rerenderPage(<p>Another workspace</p>);
  const invalidate = vi.spyOn(client, "invalidateQueries");
  await act(async () => complete({ id: group.id })); await settled(() => expect(client.isMutating()).toBe(0));
  expect(route.navigate).not.toHaveBeenCalled(); expect(host.textContent).toBe("Another workspace");
  expect(invalidate).toHaveBeenCalledWith({ queryKey: ["groups", "cluster"] });
});

it.each(["failed", "missing", "duplicate"])("blocks an editor when its scoped load is %s", async (scenario) => {
  if (scenario === "failed") vi.mocked(groupsApi.list).mockRejectedValue(new Error("private backend details"));
  else vi.mocked(groupsApi.list).mockResolvedValue({ groups: scenario === "missing" ? [{ ...group, id: "another-cluster-group" }] : [group, group] });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector('[role="alert"]')).not.toBeNull());
  expect(groupsApi.list).toHaveBeenCalledWith({ cluster_id: "cluster" });
  expect(host.querySelector("form")).toBeNull();
  expect(host.textContent).not.toContain("private backend details");
});
it("loads saved configuration, saves through the scoped API, and preserves computed members and source", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.update).mockResolvedValue({ id: "group" });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe(group.name));
  expect(host.querySelector("details")?.open).toBe(false);
  await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/groups" }));
  const { id: _id, ...body } = group;
  expect(groupsApi.update).toHaveBeenCalledWith("group", body, { cluster_id: "cluster" });
  expect(groupsApi.create).not.toHaveBeenCalled();
});
it("preserves typed selectors and comments after refresh and failed save", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.update).mockRejectedValue(new Error("private backend details"));
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await changeInput("#group-value-0", "staging");
  await act(async () => client.setQueryData(["group-editor", "cluster", "group"], { groups: [{ ...group, comment: "Changed remotely", criteria: [] }] }));
  expect(host.querySelector<HTMLInputElement>("#group-value-0")?.value).toBe("staging");
  expect(host.querySelector<HTMLTextAreaElement>("#group-comment")?.value).toBe("Saved description");
  await submit();
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(groupsApi.update).toHaveBeenCalledWith("group", expect.objectContaining({ criteria: [{ key: "namespace", op: "eq", value: "staging" }] }), { cluster_id: "cluster" });
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.textContent).not.toContain("private backend details");
});
it("keeps a draft visible and disables saves after a background refresh loses the record", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await changeInput("#group-name", "My draft");
  await act(async () => client.setQueryData(["group-editor", "cluster", "group"], { groups: [] }));
  expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe("My draft");
  await settled(() => expect(host.textContent).toContain("Your draft is preserved; retry before saving"));
  expect(button("Save").disabled).toBe(true);
  await submit();
  expect(groupsApi.update).not.toHaveBeenCalled();
});
it("shows a policy conflict without losing the form", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.update).mockRejectedValue({ response: { status: 409 } });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await submit();
  await settled(() => expect(host.textContent).toContain("Remove blocking references"));
  expect(host.querySelector("form")).not.toBeNull();
  expect(route.navigate).not.toHaveBeenCalled();
});
it("creates a scoped group from structured fields and cancels without writes", async () => {
  route.groupId = "";
  vi.mocked(groupsApi.create).mockResolvedValue({ id: "new-group" });
  await renderPage(<GroupFormPage />);
  expect(groupsApi.list).not.toHaveBeenCalled();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.querySelector<HTMLSelectElement>("#group-profile-mode")?.value).toBe("discover");
  await changeInput("#group-name", "New group");
  await changeInput("#group-value-0", "staging");
  await submit();
  await settled(() => expect(groupsApi.create).toHaveBeenCalledWith(expect.objectContaining({ name: "New group", cfg_type: "user", kind: "ground", members: [], criteria: [{ key: "namespace", op: "eq", value: "staging" }] }), { cluster_id: "cluster" }));
  await act(async () => button("Cancel").click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/groups" });
  expect(groupsApi.update).not.toHaveBeenCalled();
});
it("cancels a new draft without saving", async () => {
  route.groupId = "";
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => button("Cancel").click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/groups" });
  expect(groupsApi.create).not.toHaveBeenCalled();
});
it("blocks editing configuration managed by federation", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [{ ...group, cfg_type: "fed", kind: "federated" }] });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.textContent).toContain("cannot be edited here"));
  expect(host.querySelector("form")).toBeNull();
});
it.each([<GroupFormPage />, <GroupDetailPage />, <GroupsPage />, <GroupSettingsPage />])("avoids an unscoped groups request when no cluster is selected", async (page) => {
  route.clusterId = undefined;
  await renderPage(page);
  expect(groupsApi.list).not.toHaveBeenCalled();
  expect(groupsApi.usage).not.toHaveBeenCalled();
  expect(host.textContent).toContain("Select an available cluster");
});
it("deep-links to policy usage and displays blocking dependencies through shared table controls", async () => {
  route.search = "tab=usage";
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.usage).mockResolvedValue(usage);
  await renderPage(<GroupDetailPage />);
  await settled(() => expect(host.textContent).toContain("Deletion is blocked by 1 policy reference"));
  expect(groupsApi.usage).toHaveBeenCalledWith("group", { cluster_id: "cluster" });
  expect(host.querySelector('a[href="/clusters/cluster/network-rules"]')?.textContent).toBe("Allow API");
  expect(host.querySelector('button[aria-label="Columns"]')).not.toBeNull();
  expect(host.querySelector('button[aria-label="compact density"]')).not.toBeNull();
});
it("shows usage failures with retry and never claims the group has zero references", async () => {
  route.search = "tab=usage";
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.usage).mockRejectedValue(new Error("private details"));
  await renderPage(<GroupDetailPage />);
  await settled(() => expect(host.textContent).toContain("Policy usage could not be loaded"));
  expect(host.textContent).toContain("Usage unavailable");
  expect(host.textContent).not.toContain("No policy references currently block deletion");
  expect(host.textContent).not.toContain("private details");
});
it("promotes a mode with cluster scope and renders mutation errors", async () => {
  route.search = "tab=configuration";
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.usage).mockResolvedValue(usage);
  vi.mocked(groupsApi.update).mockRejectedValue(new Error("private details"));
  await renderPage(<GroupDetailPage />);
  await settled(() => expect(button("Move to protect")).toBeDefined());
  await act(async () => button("Move to protect").click());
  await settled(() => expect(host.textContent).toContain("Could not change this group's mode"));
  expect(groupsApi.update).toHaveBeenCalledWith("group", expect.objectContaining({ policy_mode: "protect", profile_mode: "discover" }), { cluster_id: "cluster" });
});
it("keeps the list a navigation workspace and reports referenced deletion conflicts", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  vi.mocked(groupsApi.delete).mockRejectedValue({ response: { status: 409 } });
  window.confirm = vi.fn(() => true);
  await renderPage(<GroupsPage />);
  await settled(() => expect(host.querySelector('a[href="/clusters/cluster/groups/group/edit"]')).not.toBeNull());
  expect(host.querySelector('a[href="/clusters/cluster/groups/new"]')).not.toBeNull();
  expect(host.querySelector("form")).toBeNull();
  await act(async () => host.querySelector<HTMLButtonElement>('button[aria-label="Delete Saved group"]')!.click());
  await settled(() => expect(host.textContent).toContain("cannot be deleted while policy references"));
});
it("renders a failed groups query as an error with retry rather than an empty list", async () => {
  vi.mocked(groupsApi.list).mockRejectedValue(new Error("private details"));
  await renderPage(<GroupsPage />);
  await settled(() => expect(host.textContent).toContain("Groups could not be loaded"));
  expect(host.textContent).not.toContain("No groups yet");
  expect(button("Retry")).toBeDefined();
});
it.each(["failed", "wrong-cluster", "invalid-mode"])("blocks group settings with a %s load", async (scenario) => {
  if (scenario === "failed") vi.mocked(policies.serviceModeDefaults).mockRejectedValue(new Error("private details"));
  else vi.mocked(policies.serviceModeDefaults).mockResolvedValue({ cluster_id: scenario === "wrong-cluster" ? "other" : "cluster", policy_mode: scenario === "invalid-mode" ? "unknown" : "monitor", profile_mode: "discover" });
  await renderPage(<GroupSettingsPage />);
  await settled(() => expect(host.textContent).toContain("Group settings could not be loaded for the selected cluster"));
  expect(host.querySelector("form")).toBeNull();
  expect(host.textContent).not.toContain("private details");
  expect(policies.serviceModeDefaults).toHaveBeenCalledWith({ cluster_id: "cluster" });
});
it("saves group defaults through explicit Save and scoped API", async () => {
  vi.mocked(policies.updateServiceModeDefaults).mockResolvedValue({ cluster_id: "cluster", policy_mode: "protect", profile_mode: "discover" });
  await renderPage(<GroupSettingsPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { const select = host.querySelector<HTMLSelectElement>("#default-network-mode")!; select.value = "protect"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  expect(policies.updateServiceModeDefaults).not.toHaveBeenCalled();
  await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/groups" }));
  expect(policies.updateServiceModeDefaults).toHaveBeenCalledWith({ policy_mode: "protect", profile_mode: "discover" }, { cluster_id: "cluster" });
});
it("preserves group settings draft after refresh and failed save", async () => {
  vi.mocked(policies.updateServiceModeDefaults).mockRejectedValue(new Error("private details"));
  await renderPage(<GroupSettingsPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { const select = host.querySelector<HTMLSelectElement>("#default-network-mode")!; select.value = "protect"; select.dispatchEvent(new Event("change", { bubbles: true })); client.setQueryData(["service-mode-defaults", "cluster"], { cluster_id: "cluster", policy_mode: "discover", profile_mode: "monitor" }); });
  expect(host.querySelector<HTMLSelectElement>("#default-network-mode")?.value).toBe("protect");
  expect(host.querySelector<HTMLSelectElement>("#default-profile-mode")?.value).toBe("discover");
  await submit();
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(route.navigate).not.toHaveBeenCalled();
  expect(host.textContent).not.toContain("private details");
});
it("cancels group settings without applying changes", async () => {
  await renderPage(<GroupSettingsPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => button("Cancel").click());
  expect(policies.updateServiceModeDefaults).not.toHaveBeenCalled();
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/groups" });
});
it("keeps an edited group draft visible after a refresh request fails", async () => {
  vi.mocked(groupsApi.list).mockResolvedValueOnce({ groups: [group] }).mockRejectedValue(new Error("private details"));
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await changeInput("#group-name", "Draft name");
  await act(async () => client.invalidateQueries({ queryKey: ["group-editor", "cluster", "group"] }));
  await settled(() => expect(button("Save").disabled).toBe(true));
  expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe("Draft name");
  expect(host.textContent).toContain("Your draft is preserved; retry before saving");
  expect(host.textContent).not.toContain("private details");
});
it("keeps settings draft visible if the response loses cluster scope and blocks another save", async () => {
  await renderPage(<GroupSettingsPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { const select = host.querySelector<HTMLSelectElement>("#default-network-mode")!; select.value = "protect"; select.dispatchEvent(new Event("change", { bubbles: true })); client.setQueryData(["service-mode-defaults", "cluster"], { cluster_id: "other", policy_mode: "monitor", profile_mode: "monitor" }); });
  await settled(() => expect(button("Save").disabled).toBe(true));
  expect(host.querySelector<HTMLSelectElement>("#default-network-mode")?.value).toBe("protect");
  await submit();
  expect(policies.updateServiceModeDefaults).not.toHaveBeenCalled();
});
it("preserves no selectors when a saved group has a null criteria array", async () => {
  vi.mocked(groupsApi.list).mockResolvedValue({ groups: [{ ...group, criteria: null } as unknown as Group] });
  vi.mocked(groupsApi.update).mockResolvedValue({ id: "group" });
  await renderPage(<GroupFormPage />);
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.querySelector("#group-key-0")).toBeNull();
  expect(host.textContent).toContain("Without selectors this group will have no matching members");
  await submit();
  await settled(() => expect(groupsApi.update).toHaveBeenCalledWith("group", expect.objectContaining({ criteria: [] }), { cluster_id: "cluster" }));
});
const authoringKinds = ["create", "edit", "settings"] as const;
type AuthoringKind = typeof authoringKinds[number];
function authoringPage(kind: AuthoringKind) { route.groupId = kind === "create" ? "" : "group"; return kind === "settings" ? <GroupSettingsPage /> : <GroupFormPage />; }
async function draftAuthoring(kind: AuthoringKind) {
  if (kind === "settings") await act(async () => { const select = host.querySelector<HTMLSelectElement>("#default-network-mode")!; select.value = "protect"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  else await changeInput("#group-name", "Retained authoring draft");
}
function expectAuthoringDraft(kind: AuthoringKind) {
  if (kind === "settings") expect(host.querySelector<HTMLSelectElement>("#default-network-mode")?.value).toBe("protect");
  else expect(host.querySelector<HTMLInputElement>("#group-name")?.value).toBe("Retained authoring draft");
}
function expectNoAuthoringWrite() { expect(groupsApi.create).not.toHaveBeenCalled(); expect(groupsApi.update).not.toHaveBeenCalled(); expect(policies.updateServiceModeDefaults).not.toHaveBeenCalled(); }

it.each(authoringKinds.flatMap((kind) => ["missing", "foreign", "error-with-stale", "loading"].map((scenario) => [kind, scenario] as const)))("blocks initial %s authoring while cluster resolution is %s", async (kind, scenario) => {
  const page = authoringPage(kind);
  if (scenario === "missing") route.resolvedClusterId = undefined;
  if (scenario === "foreign") route.resolvedClusterId = "other";
  if (scenario === "error-with-stale") route.clusterError = new Error("private scope details");
  if (scenario === "loading") route.clusterLoading = true;
  await renderPage(page);
  expect(host.querySelector("form")).toBeNull(); expect(groupsApi.list).not.toHaveBeenCalled(); expect(policies.serviceModeDefaults).not.toHaveBeenCalled(); expectNoAuthoringWrite(); expect(host.textContent).not.toContain("private scope details");
});
it.each(authoringKinds)("does not expose %s authoring while an old cached cluster is refreshing", async (kind) => {
  const page = authoringPage(kind); vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  let resolveRegistry!: (value: { clusters: Array<{ id: string }> }) => void;
  await renderPage(page, (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    void queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((resolve) => { resolveRegistry = resolve; }) }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(host.textContent).toContain("Loading cluster"); expect(groupsApi.list).not.toHaveBeenCalled(); expect(policies.serviceModeDefaults).not.toHaveBeenCalled();
  await act(async () => resolveRegistry({ clusters: [{ id: "cluster" }] }));
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
});
it.each(authoringKinds)("blocks %s authoring when cached cluster identity is foreign", async (kind) => {
  await renderPage(authoringPage(kind), (queryClient) => { queryClient.setQueryData(["cluster", "cluster"], { id: "foreign" }); });
  expect(host.querySelector("form")).toBeNull(); expect(groupsApi.list).not.toHaveBeenCalled(); expect(policies.serviceModeDefaults).not.toHaveBeenCalled(); expect(host.textContent).toContain("selected cluster could not be resolved");
});
it.each(authoringKinds)("blocks %s authoring when cached registry failed despite a stale active cluster", async (kind) => {
  await renderPage(authoringPage(kind), async (queryClient) => {
    queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
    await queryClient.fetchQuery({ queryKey: ["clusters"], queryFn: () => Promise.reject(new Error("private registry details")), retry: false }).catch(() => {});
  });
  expect(host.querySelector("form")).toBeNull(); expect(groupsApi.list).not.toHaveBeenCalled(); expect(policies.serviceModeDefaults).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("private registry details");
});
it.each(authoringKinds.flatMap((kind) => ["missing", "foreign", "error-with-stale", "loading"].map((scenario) => [kind, scenario] as const)))("preserves %s draft and pauses Save during transient %s scope", async (kind, scenario) => {
  const page = authoringPage(kind); vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  await renderPage(page); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await draftAuthoring(kind);
  if (scenario === "missing") route.resolvedClusterId = undefined;
  if (scenario === "foreign") route.resolvedClusterId = "other";
  if (scenario === "error-with-stale") route.clusterError = new Error("private scope details");
  if (scenario === "loading") route.clusterLoading = true;
  await rerenderPage(authoringPage(kind)); expectAuthoringDraft(kind); expect(button("Save").disabled).toBe(true); expect(host.textContent).toContain("saving is paused until the cluster resolves");
  await submit(); expectNoAuthoringWrite();
  route.resolvedClusterId = "cluster"; route.clusterError = null; route.clusterLoading = false;
  await rerenderPage(authoringPage(kind)); await settled(() => expect(button("Save").disabled).toBe(false)); expectAuthoringDraft(kind);
});
it.each(authoringKinds)("preserves %s draft during actual background registry fetching", async (kind) => {
  const page = authoringPage(kind); vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  await renderPage(page, (queryClient) => { queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] }); });
  await settled(() => expect(host.querySelector("form")).not.toBeNull()); await draftAuthoring(kind);
  let resolveRegistry!: (value: { clusters: Array<{ id: string }> }) => void;
  await act(async () => { void client.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((resolve) => { resolveRegistry = resolve; }) }).catch(() => {}); });
  await settled(() => expect(button("Save").disabled).toBe(true)); expectAuthoringDraft(kind); await submit(); expectNoAuthoringWrite();
  await act(async () => resolveRegistry({ clusters: [{ id: "cluster" }] }));
  await settled(() => expect(button("Save").disabled).toBe(false)); expectAuthoringDraft(kind);
});
it.each(authoringKinds)("rechecks latest cluster scope before %s writes even before observer notification", async (kind) => {
  const page = authoringPage(kind); vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  await renderPage(page, (queryClient) => { queryClient.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] }); });
  await settled(() => expect(host.querySelector("form")).not.toBeNull()); await draftAuthoring(kind);
  await act(async () => { client.setQueryData(["clusters"], { clusters: [] }); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expectNoAuthoringWrite(); expectAuthoringDraft(kind);
});
it.each(authoringKinds)("rechecks latest %s data before mutation when the backing record loses scope", async (kind) => {
  const page = authoringPage(kind); vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] });
  await renderPage(page); await settled(() => expect(host.querySelector("form")).not.toBeNull()); await draftAuthoring(kind);
  await act(async () => {
    if (kind === "edit") client.setQueryData(["group-editor", "cluster", "group"], { groups: [] });
    else client.setQueryData(["service-mode-defaults", "cluster"], { cluster_id: "foreign", policy_mode: "monitor", profile_mode: "discover" });
    host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved")); expectNoAuthoringWrite(); expectAuthoringDraft(kind);
});
it.each(authoringKinds)("does not initialize a %s draft if cluster scope is lost while its initial data is loading", async (kind) => {
  let resolveData!: () => void;
  if (kind === "edit") vi.mocked(groupsApi.list).mockResolvedValue({ groups: [group] }).mockImplementationOnce(() => new Promise((resolve) => { resolveData = () => resolve({ groups: [group] }); }));
  else vi.mocked(policies.serviceModeDefaults).mockResolvedValue({ cluster_id: "cluster", policy_mode: "monitor", profile_mode: "discover" }).mockImplementationOnce(() => new Promise((resolve) => { resolveData = () => resolve({ cluster_id: "cluster", policy_mode: "monitor", profile_mode: "discover" }); }));
  await renderPage(authoringPage(kind));
  expect(host.querySelector("form")).toBeNull();
  route.clusterError = new Error("scope refresh failed");
  await rerenderPage(authoringPage(kind));
  await act(async () => resolveData());
  await settled(() => expect(host.textContent).toContain("saving is paused until the cluster resolves"));
  expect(host.querySelector("form")).toBeNull(); expectNoAuthoringWrite();
  route.clusterError = null;
  await rerenderPage(authoringPage(kind));
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
});
