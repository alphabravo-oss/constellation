import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { deployments, baselines, fileProfiles, network, quarantine, type QuarantineEntry } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { DeploymentActionFormPage } from "./DeploymentActionFormPage";
import { fixtureDeployment, fixtureFile, fixtureProcess, fixturePolicy } from "./deployment-detail/test-fixtures";
const scope = vi.hoisted(() => ({ clusterId: "cluster" as string | undefined, cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({ deployments: { get: vi.fn() }, baselines: { get: vi.fn(), setMode: vi.fn() }, fileProfiles: { get: vi.fn(), setMode: vi.fn(), createException: vi.fn(), deleteException: vi.fn(), deleteRule: vi.fn(), importBundle: vi.fn() }, network: { policyAction: vi.fn(), rollbackPolicy: vi.fn() }, quarantine: { lift: vi.fn() } }));
let owner = { org_id: "org", user_id: "user" };
let routerView: ReactNode;
let root: Root | undefined; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
beforeEach(() => { owner = { org_id: "org", user_id: "user" }; (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true; Object.assign(scope, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); const d = fixtureDeployment(); d.network_policy = fixturePolicy(); d.quarantine = { id: "quarantine", cluster_id: "cluster", scope: "workload", match_key: "payments/app", reason: "original", expires_at: "2026-10-13T00:00:00Z" } as QuarantineEntry; vi.mocked(deployments.get).mockResolvedValue(d); vi.mocked(fileProfiles.get).mockResolvedValue(fixtureFile()); vi.mocked(baselines.get).mockResolvedValue(fixtureProcess()); for (const fn of [baselines.setMode, fileProfiles.setMode, fileProfiles.createException, fileProfiles.deleteException, fileProfiles.deleteRule, fileProfiles.importBundle, network.policyAction, network.rollbackPolicy, quarantine.lift]) vi.mocked(fn).mockResolvedValue({} as never); });
afterEach(() => { act(() => root?.unmount()); root = undefined; client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function render(action = "process-mode", search = "?mode=monitor") {
 host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); history = createMemoryHistory({ initialEntries: [`/clusters/cluster/deployments/deployment/actions/${action}${search}`] });
 routerView = <TestRouter history={history} path="/clusters/$clusterId/deployments/$did/actions/$action" next={{ path: "/clusters/$clusterId/deployments/$did", element: <p data-testid="returned-deployment">Returned deployment</p> }}><DeploymentActionFormPage /></TestRouter>;
 await rerenderOwner();
}
async function rerenderOwner() { await act(async () => root!.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ ...owner }}>{routerView}</TablePreferencesProvider></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function editor() { await settled(() => expect(host.querySelector("form")).not.toBeNull()); }
function field(label: string): HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement { return [...host.querySelectorAll("label")].find(item => item.querySelector("span")?.textContent?.startsWith(label))!.querySelector("input,textarea,select")!; }
async function input(label: string, value: string) { await act(async () => { const item = field(label); const prototype = item instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : item instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, "value")!.set!.call(item, value); item.dispatchEvent(new Event(item instanceof HTMLSelectElement ? "change" : "input", { bubbles: true })); }); }
async function submit() { await act(async () => host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }))); }
const button = (label: string) => [...host.querySelectorAll("button")].find((item) => item.textContent?.trim() === label || item.getAttribute("aria-label") === label)!;
const writes = () => [baselines.setMode, fileProfiles.setMode, fileProfiles.createException, fileProfiles.deleteException, fileProfiles.deleteRule, fileProfiles.importBundle, network.policyAction, network.rollbackPolicy, quarantine.lift];
it.each(["loading", "wrong", "error"])("blocks entity/runtime queries for %s cluster scope", async condition => {
 if (condition === "loading") scope.isLoading = true; if (condition === "wrong") scope.cluster = { id: "other" }; if (condition === "error") scope.error = new Error("scope failed"); await render(); expect(deployments.get).not.toHaveBeenCalled(); expect(baselines.get).not.toHaveBeenCalled(); expect(host.querySelector("form")).toBeNull();
});
it.each(["foreign-deployment", "foreign-profile", "wrong-workload", "missing-runtime"])("does not author against %s context", async condition => {
 if (condition === "foreign-deployment") vi.mocked(deployments.get).mockResolvedValue({ ...fixtureDeployment(), cluster_id: "other" }); if (condition === "foreign-profile") vi.mocked(baselines.get).mockResolvedValue({ ...fixtureProcess(), cluster_id: "other" }); if (condition === "wrong-workload") vi.mocked(baselines.get).mockResolvedValue({ ...fixtureProcess(), workload_id: "payments/other" }); if (condition === "missing-runtime") vi.mocked(baselines.get).mockRejectedValue(new Error("missing"));
 await render(); await settled(() => expect(host.textContent).toContain("This action is not available")); expect(host.querySelector("form")).toBeNull(); for (const fn of writes()) expect(fn).not.toHaveBeenCalled();
});
it("cancels back to exact deployment tab without writes", async () => { await render(); await editor(); await input("Reason", "draft reason"); await act(async () => button("Cancel").click()); await settled(() => expect(history.location.pathname).toBe("/clusters/cluster/deployments/deployment")); expect(history.location.search).toBe("?tab=runtime"); for (const fn of writes()) expect(fn).not.toHaveBeenCalled(); });
it.each(["process-mode", "file-mode"])("saves %s to the exact canonical workload and returns without claiming enforcement", async action => {
 await render(action); await editor(); expect(button("Save mode").disabled).toBe(true); await input("Reason", "reviewed mode change"); await submit(); const fn = action === "process-mode" ? baselines.setMode : fileProfiles.setMode; await settled(() => expect(fn).toHaveBeenCalledWith("payments/app", { mode: "monitor", reason: "reviewed mode change" }, { cluster_id: "cluster" })); await settled(() => expect(host.textContent).toContain("Returned deployment")); expect(history.location.search).toBe(action === "process-mode" ? "?tab=runtime" : "?tab=files");
});
it("retains a reason across a failed profile refresh and a failed save", async () => {
 vi.mocked(baselines.setMode).mockRejectedValue(new Error("save rejected")); await render(); await editor(); await input("Reason", "retained reason"); vi.mocked(baselines.get).mockRejectedValue(new Error("refresh failed")); await act(async () => { await client.invalidateQueries({ queryKey: ["deployment-action-profile"] }); }); await settled(() => expect(host.textContent).toContain("Your draft is preserved; refresh before saving")); expect(field("Reason").value).toBe("retained reason"); expect(button("Save mode").disabled).toBe(true);
 vi.mocked(baselines.get).mockResolvedValue(fixtureProcess()); await act(async () => button("Retry").click()); await settled(() => expect(button("Save mode").disabled).toBe(false)); await submit(); await settled(() => expect(host.textContent).toContain("save rejected")); expect(field("Reason").value).toBe("retained reason"); expect(history.location.pathname).toContain("/actions/process-mode");
});
it.each(["registry", "deployment-invalidated", "deployment-error", "profile-invalidated", "profile-mode-changed", "foreign-profile"])("rechecks %s cache at submission before React can rerender", async condition => {
 await render(); await editor(); await input("Reason", "race-proof reason");
 await act(async () => {
  const dep = client.getQueryCache().find({ queryKey: ["deployment", "cluster", "deployment"], exact: true })!;
  const profile = client.getQueryCache().find({ queryKey: ["deployment-action-profile", "cluster", "deployment", "process", "payments/app"], exact: true })!;
  if (condition === "registry") client.setQueryData(["clusters"], { clusters: [{ id: "other" }] });
  if (condition === "deployment-invalidated") dep.setState({ isInvalidated: true });
  if (condition === "deployment-error") dep.setState({ status: "error", error: new Error("unavailable") });
  if (condition === "profile-invalidated") profile.setState({ isInvalidated: true });
  if (condition === "profile-mode-changed") client.setQueryData(profile.queryKey, { ...fixtureProcess(), mode: "monitor" });
  if (condition === "foreign-profile") client.setQueryData(profile.queryKey, { ...fixtureProcess(), cluster_id: "other" });
  host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
 });
 await settled(() => expect(host.querySelector('[data-testid="error-state"]')).not.toBeNull()); expect(baselines.setMode).not.toHaveBeenCalled(); expect(field("Reason").value).toBe("race-proof reason");
});
it("preserves a mode draft when the reviewed source changes and requires explicit review", async () => {
 await render(); await editor(); await input("Reason", "keep this reason"); await act(async () => client.setQueryData(["deployment-action-profile", "cluster", "deployment", "process", "payments/app"], { ...fixtureProcess(), mode: "monitor" }));
 await settled(() => expect(host.textContent).toContain("The reviewed state changed")); expect(button("Save mode").disabled).toBe(true); await act(async () => button("Review current state").click()); expect(field("Reason").value).toBe("keep this reason"); expect(button("Save mode").disabled).toBe(true); await input("Next profile mode", "enforce"); expect(button("Save mode").disabled).toBe(false);
});
it.each(["apply-policy", "demote-policy", "rollback-policy", "lift-quarantine"])("preserves %s action semantics and exact target", async action => {
 await render(action, ""); await editor(); await input("Reason", "reviewed action"); await submit();
 const fn = action === "rollback-policy" ? network.rollbackPolicy : action === "lift-quarantine" ? quarantine.lift : network.policyAction;
 await settled(() => expect(fn).toHaveBeenCalledTimes(1));
 if (action === "lift-quarantine") expect(quarantine.lift).toHaveBeenCalledWith("quarantine", { reason: "reviewed action" });
 else if (action === "rollback-policy") expect(network.rollbackPolicy).toHaveBeenCalledWith("payments/app", expect.objectContaining({ rollback_ref: "rollback", reason: "reviewed action", idempotency_key: expect.any(String) }), { cluster_id: "cluster" });
 else expect(network.policyAction).toHaveBeenCalledWith("payments/app", action === "apply-policy" ? "apply" : "demote", expect.objectContaining({ candidate_hash: "candidate", reason: "reviewed action", idempotency_key: expect.any(String) }), { cluster_id: "cluster" });
});
it("blocks stale or unapproved network candidates", async () => {
 const d = fixtureDeployment(); d.network_policy = { ...fixturePolicy(), candidate_hash: "new-hash" }; vi.mocked(deployments.get).mockResolvedValue(d); await render("apply-policy", ""); await settled(() => expect(host.textContent).toContain("This action is not available")); expect(host.querySelector("form")).toBeNull(); expect(network.policyAction).not.toHaveBeenCalled();
});
it("guards a candidate hash replacement at mutation time", async () => {
 await render("apply-policy", ""); await editor(); await input("Reason", "approval reason"); await act(async () => { const d = fixtureDeployment(); d.network_policy = { ...fixturePolicy(), candidate_hash: "changed", approved_candidate_hash: "changed" }; client.setQueryData(["deployment", "cluster", "deployment"], d); host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); await settled(() => expect(host.textContent).toContain("reviewed target changed")); expect(network.policyAction).not.toHaveBeenCalled();
});
it("adds scoped exceptions with applications and custom reason", async () => {
 await render("file-exception", ""); await editor(); await input("Path filter", "/tmp/*"); await input("Reason", "ticket 123"); await input("Applications", "shell, app, shell"); await input("Rule", "rule"); await input("Description", "exception detail"); await submit(); await settled(() => expect(fileProfiles.createException).toHaveBeenCalledWith("payments/app", { filter: "/tmp/*", rule_id: "rule", applications: ["app", "shell"], description: "exception detail", reason: "ticket 123", enabled: true }, { cluster_id: "cluster" }));
});
it.each(["file-rule-delete", "file-exception-delete"])("removes only the reviewed current resource for %s", async action => {
 await render(action, action === "file-rule-delete" ? "?rule=rule" : "?exception=exception"); await editor(); await input("Reason", "remove reviewed resource"); await submit(); const fn = action === "file-rule-delete" ? fileProfiles.deleteRule : fileProfiles.deleteException; await settled(() => expect(fn).toHaveBeenCalledWith("payments/app", action === "file-rule-delete" ? "rule" : "exception", { reason: "remove reviewed resource" }, { cluster_id: "cluster" }));
});
it("retains removal draft when the selected resource disappears", async () => {
 await render("file-rule-delete", "?rule=rule"); await editor(); await input("Reason", "removal draft"); await act(async () => client.setQueryData(["deployment-action-profile", "cluster", "deployment", "file", "payments/app"], { ...fixtureFile(), rules: [] })); await settled(() => expect(host.textContent).toContain("Your draft is preserved; refresh before saving")); expect(field("Reason").value).toBe("removal draft"); expect(button("Remove rule").disabled).toBe(true); expect(fileProfiles.deleteRule).not.toHaveBeenCalled();
});
it.each(["{}", '{"schema_version":"unsupported","rules":[]}', '{"kind":"Wrong","rules":[]}', '{"rules":"invalid"}'])("rejects unsafe bundle %s without a write", async value => {
 await render("file-bundle-import", ""); await editor(); await input("File profile bundle JSON", value); await input("Reason", "replace reviewed"); await act(async () => host.querySelector<HTMLButtonElement>('button[role="checkbox"]')!.click()); await submit(); await settled(() => expect(host.querySelectorAll('[data-testid="error-state"]').length).toBeGreaterThan(0)); expect(fileProfiles.importBundle).not.toHaveBeenCalled(); expect(field("File profile bundle JSON").value).toBe(value);
});
it("makes empty-bundle replacement and portable retargeting explicit while preserving server semantics", async () => {
 const bundle = { schema_version: "constellation-file-profile-v1", kind: "FileProfile", workload_id: "other/app", cluster_id: "other", rules: [], exceptions: [] };
 await render("file-bundle-import", ""); await editor(); await input("File profile bundle JSON", JSON.stringify(bundle)); await input("Reason", "explicit clear"); expect(host.textContent).toContain("removes every configured rule and exception"); expect(host.textContent).toContain("will be retargeted"); expect(button("Import and replace").disabled).toBe(true);
 await act(async () => host.querySelector<HTMLButtonElement>('button[role="checkbox"]')!.click()); await submit(); await settled(() => expect(fileProfiles.importBundle).toHaveBeenCalledWith("payments/app", { bundle, reason: "explicit clear", replace: true }, { cluster_id: "cluster" }));
});
it("prevents duplicate synchronous submissions", async () => {
 let done!: () => void; vi.mocked(baselines.setMode).mockImplementation(() => new Promise(resolve => { done = () => resolve(fixtureProcess()); })); await render(); await editor(); await input("Reason", "once"); await act(async () => { const form = host.querySelector("form")!; form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); await settled(() => expect(baselines.setMode).toHaveBeenCalledTimes(1)); await settled(() => expect(button("Submitting…")?.disabled).toBe(true)); await act(async () => done());
});

async function beginHeldDeploymentWrite() {
 let complete!: () => void;
 vi.mocked(baselines.setMode).mockImplementation(() => new Promise(resolve => { complete = () => resolve(fixtureProcess()); }));
 await render(); await editor(); await input("Reason", "Original held action"); await submit();
 await settled(() => { expect(baselines.setMode).toHaveBeenCalledTimes(1); expect(client.isMutating()).toBe(1); });
 expect(baselines.setMode).toHaveBeenCalledWith("payments/app", { mode: "monitor", reason: "Original held action" }, { cluster_id: "cluster" });
 return complete;
}
async function finishDeploymentWrite(complete: () => void) {
 await act(async () => complete());
 await settled(() => expect(client.isMutating()).toBe(0));
}
async function laterDeploymentDraft(reason: string) {
 await editor(); await settled(() => expect(field("Reason").value).toBe(""));
 await input("Reason", reason);
 expect(button("Save mode").disabled).toBe(false);
}

it("keeps a later deployment action draft after a held write completes across an action roundtrip", async () => {
 const complete = await beginHeldDeploymentWrite();
 await act(async () => history.push("/clusters/cluster/deployments/deployment/actions/file-mode?mode=monitor"));
 await settled(() => expect(host.querySelector("h1")?.textContent).toBe("Change file profile mode"));
 await editor(); await settled(() => expect(field("Reason").value).toBe(""));
 await act(async () => history.push("/clusters/cluster/deployments/deployment/actions/process-mode?mode=monitor"));
 await settled(() => expect(host.querySelector("h1")?.textContent).toBe("Change process baseline mode"));
 await laterDeploymentDraft("Later action visit reason"); await finishDeploymentWrite(complete);
 expect(history.location.pathname).toBe("/clusters/cluster/deployments/deployment/actions/process-mode");
 expect(field("Reason").value).toBe("Later action visit reason");
 expect(baselines.setMode).toHaveBeenCalledTimes(1); expect(fileProfiles.setMode).not.toHaveBeenCalled();
});

it("keeps a later deployment action draft after a held write completes across an owner roundtrip", async () => {
 const complete = await beginHeldDeploymentWrite();
 owner = { org_id: "other-org", user_id: "other-user" }; await rerenderOwner();
 await editor(); await settled(() => expect(field("Reason").value).toBe(""));
 owner = { org_id: "org", user_id: "user" }; await rerenderOwner();
 await laterDeploymentDraft("Later action owner reason"); await finishDeploymentWrite(complete);
 expect(history.location.pathname).toBe("/clusters/cluster/deployments/deployment/actions/process-mode");
 expect(field("Reason").value).toBe("Later action owner reason");
 expect(baselines.setMode).toHaveBeenCalledTimes(1);
});

it("does not navigate after leaving a pending deployment action and retains its invalidations", async () => {
 const complete = await beginHeldDeploymentWrite();
 const invalidate = vi.spyOn(client, "invalidateQueries");
 await act(async () => history.push("/clusters/cluster/deployments/elsewhere?tab=files"));
 await settled(() => expect(host.querySelector('[data-testid="returned-deployment"]')).not.toBeNull());
 await finishDeploymentWrite(complete);
 expect(history.location.pathname).toBe("/clusters/cluster/deployments/elsewhere");
 expect(history.location.search).toBe("?tab=files");
 for (const key of ["deployment", "file-monitor-detail", "file-monitor-profiles", "baseline", "network-policy-lifecycle"]) expect(invalidate).toHaveBeenCalledWith({ queryKey: [key] });
 expect(baselines.setMode).toHaveBeenCalledTimes(1);
});
