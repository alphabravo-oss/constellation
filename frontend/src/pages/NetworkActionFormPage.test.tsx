import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { network, quarantine, type NetworkMap, type NetworkPolicyLifecycle, type NetworkPolicyActionResponse } from "@/api/client";
import { NetworkActionFormPage } from "./NetworkActionFormPage";
const route = vi.hoisted(() => ({ action: "isolate", search: "workload=team%2Fapi&back=tab%3Dmap%26workload%3Dteam%252Fapi", navigate: vi.fn(), clusterId: "cluster-1", cluster: { id: "cluster-1" }, isLoading: false, error: null as Error | null }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ action: route.action }), useNavigate: () => route.navigate }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()] }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => route }));
vi.mock("@/api/client", () => ({ network: { map: vi.fn(), lifecycle: vi.fn(), policyAction: vi.fn(), enforcement: { create: vi.fn() } }, quarantine: { create: vi.fn() } }));
const map = { summary: { selected_cluster_id: "cluster-1", window_hours: 24, workloads: 2, flows: 0, cni: "cilium" }, workloads: ["api", "db"].map((name) => ({ id: `team/${name}`, name, namespace: "team", kind: "Deployment", cluster_id: "cluster-1", risk_score: 0, finding_count: 0 })), flows: [] } as NetworkMap;
const candidate = { id: "candidate", cluster_id: "cluster-1", workload: "team/api", namespace: "team", current_mode: "discover", target_mode: "monitor", candidate_hash: "hash-1", preview: { engine: "cilium", yaml: "reviewed-yaml", refs: {} }, approval_status: "pending" } as NetworkPolicyLifecycle;
const lifecycle = (item = candidate) => ({ items: [item], summary: { selected_cluster_id: "cluster-1", total: 1, ready: 1, discover: 1, monitor: 0, protect: 0, rollback_ready: 0, pending_approval: 1 } });
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => { route.action = "isolate"; route.search = "workload=team%2Fapi&back=tab%3Dmap%26workload%3Dteam%252Fapi"; route.clusterId = "cluster-1"; route.cluster = { id: "cluster-1" }; route.isLoading = false; route.error = null; vi.mocked(network.map).mockResolvedValue(map); vi.mocked(network.lifecycle).mockResolvedValue(lifecycle()); });
afterEach(() => { act(() => root?.unmount()); host?.remove(); client?.clear(); vi.resetAllMocks(); });
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function render(seed?: (client: QueryClient) => void) {
 host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); seed?.(client);
 await rerender();
}
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><NetworkActionFormPage /></QueryClientProvider>)); }
async function reason(value = "Investigating unexpected traffic") { await act(async () => { const el = host.querySelector<HTMLTextAreaElement>('#network-action-reason')!; Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(el, value); el.dispatchEvent(new Event("input", { bubbles: true })); }); }
async function submit() { await act(async () => { host.querySelector('form')!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }
const button = (label: string) => [...host.querySelectorAll<HTMLButtonElement>('button')].find((item) => item.textContent === label)!;

it("requires a reason, queues exact scoped isolation and reports queued rather than applied", async () => {
 vi.mocked(network.enforcement.create).mockResolvedValue({ id: "enforcement-1", kind: "isolate", flavor: "native" } as never);
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); expect(button("Queue isolation").disabled).toBe(true);
 await reason(); await submit(); await settled(() => expect(network.enforcement.create).toHaveBeenCalledOnce());
 expect(network.enforcement.create).toHaveBeenCalledWith({ kind: "isolate", target: "team/api", reason: "Investigating unexpected traffic" }, { cluster_id: "cluster-1" });
 await settled(() => expect(host.querySelector('[data-testid="network-action-result"]')?.textContent).toContain("pending reconciliation"));
 expect(host.querySelector<HTMLAnchorElement>('a')?.getAttribute('href')).toBe('/clusters/cluster-1/network?tab=map&workload=team%2Fapi');
});
it("retains the reason after refresh loses the target and blocks submission", async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason("Keep this reason");
 vi.mocked(network.map).mockResolvedValue({ ...map, workloads: [] }); await act(async () => { await client.refetchQueries({ queryKey: ["network-action-target"] }); });
 await settled(() => expect(button("Queue isolation").disabled).toBe(true)); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Keep this reason"); await submit(); expect(network.enforcement.create).not.toHaveBeenCalled();
});
it("preserves the reason and explicit server error on failure", async () => {
 vi.mocked(quarantine.create).mockRejectedValue({ response: { data: { error: "An active quarantine already exists" } } }); route.action = "quarantine";
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason(); await submit();
 await settled(() => expect(host.textContent).toContain("An active quarantine already exists")); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Investigating unexpected traffic");
 expect(quarantine.create).toHaveBeenCalledWith({ cluster_id: "cluster-1", scope: "workload", match_key: "team/api", reason: "Investigating unexpected traffic", expires_in_hours: 24 });
});
it("rejects Calico IP blocking and malformed immutable IP links", async () => {
 route.action = "block-ip"; route.search = "workload=team%2Fapi&ip=203.0.113.4&direction=ingress"; vi.mocked(network.map).mockResolvedValue({ ...map, summary: { ...map.summary, cni: "calico" } });
 await render(); await settled(() => expect(host.textContent).toContain("currently requires Cilium")); await reason(); await submit(); expect(network.enforcement.create).not.toHaveBeenCalled();
 route.search = "workload=team%2Fapi&ip=999.0.0.1"; await rerender(); expect(host.textContent).toContain("valid workload or peer IP");
});
it("queues IP block for its immutable workload/IP and selected direction", async () => {
 route.action = "block-ip"; route.search = "workload=team%2Fapi&ip=203.0.113.4&direction=ingress"; vi.mocked(network.enforcement.create).mockResolvedValue({ id: "block", kind: "block_ip", flavor: "cilium" } as never);
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason(); await submit(); await settled(() => expect(network.enforcement.create).toHaveBeenCalledOnce());
 expect(network.enforcement.create).toHaveBeenCalledWith({ kind: "block_ip", target: "203.0.113.4", workload: "team/api", direction: "ingress", reason: "Investigating unexpected traffic" }, { cluster_id: "cluster-1" });
});
it("binds policy approval to reviewed hash and reuses idempotency key on same-draft retry", async () => {
 route.action = "approve-policy"; vi.mocked(network.policyAction).mockRejectedValueOnce(new Error("Connection interrupted")).mockResolvedValue({ policy: candidate, action_id: "approval", action: "approve" } as NetworkPolicyActionResponse);
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason(); await submit(); await settled(() => expect(host.textContent).toContain("Connection interrupted")); await submit(); await settled(() => expect(network.policyAction).toHaveBeenCalledTimes(2));
 const first = vi.mocked(network.policyAction).mock.calls[0]; expect(first).toEqual(["team/api", "approve", { reason: "Investigating unexpected traffic", candidate_hash: "hash-1", idempotency_key: expect.any(String) }, { cluster_id: "cluster-1" }]); expect(vi.mocked(network.policyAction).mock.calls[1][2]?.idempotency_key).toBe(first[2]?.idempotency_key);
 await settled(() => expect(host.textContent).toContain("Applying the policy remains a separate action"));
});
it("requires review after candidate refresh and retains the reason", async () => {
 route.action = "approve-policy"; await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason("Retained reason");
 const updated = { ...candidate, candidate_hash: "hash-2", preview: { ...candidate.preview, yaml: "new-yaml" } }; vi.mocked(network.lifecycle).mockResolvedValue(lifecycle(updated));
 await act(async () => { await client.refetchQueries({ queryKey: ["network-action-candidate"] }); }); await settled(() => expect(button("Approve candidate").disabled).toBe(true));
 expect(host.querySelector('[data-testid="network-action-policy-preview"]')?.textContent).toBe("reviewed-yaml"); await act(async () => button("Review updated candidate").click()); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Retained reason"); expect(button("Approve candidate").disabled).toBe(false); expect(host.textContent).toContain("new-yaml");
});
it("does not capture cached target while its initial refresh is pending", async () => {
 vi.mocked(network.map).mockImplementation(() => new Promise(() => {})); await render((qc) => qc.setQueryData(["network-action-target", "cluster-1", "team/api"], map));
 await settled(() => expect(host.textContent).toContain("Loading action target")); expect(host.querySelector('form')).toBeNull(); expect(network.enforcement.create).not.toHaveBeenCalled();
});
it("pauses retained drafts during registry refresh and error", async () => {
 await render((qc) => qc.setQueryData(["clusters"], { clusters: [{ id: "cluster-1" }] })); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason("Retained reason");
 let reject!: (error: Error) => void; const pending = new Promise((_, fail) => { reject = fail; }); const fetch = client.fetchQuery({ queryKey: ["clusters"], queryFn: () => pending }).catch(() => {});
 await settled(() => expect(button("Queue isolation").disabled).toBe(true)); await submit(); expect(network.enforcement.create).not.toHaveBeenCalled();
 await act(async () => { reject(new Error("Registry unavailable")); await fetch; }); await settled(() => expect(button("Queue isolation").disabled).toBe(true)); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Retained reason");
});
it("does not issue old-target write after navigation during preflight and updates return links", async () => {
 await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason(); let release!: (map: NetworkMap) => void; vi.mocked(network.map).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await submit();
 route.search = "workload=team%2Fdb&back=tab%3Dconversations%26workload%3Dteam%252Fdb"; await rerender(); await settled(() => expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("")); await act(async () => release(map));
 expect(network.enforcement.create).not.toHaveBeenCalled(); expect([...host.querySelectorAll<HTMLAnchorElement>('a')].every((link) => link.getAttribute('href') === '/clusters/cluster-1/network?tab=conversations&workload=team%2Fdb')).toBe(true);
});
it("rejects wrong-cluster workload responses and unresolved cluster", async () => {
 vi.mocked(network.map).mockResolvedValue({ ...map, summary: { ...map.summary, selected_cluster_id: "another" } }); await render(); await settled(() => expect(host.textContent).toContain("could not be loaded in the requested cluster")); expect(host.querySelector('form')).toBeNull();
 route.cluster = { id: "another" }; await rerender(); expect(host.textContent).toContain("cluster could not be resolved");
});

it("does not capture a cached policy preview during its initial refresh", async () => {
 route.action = "approve-policy"; vi.mocked(network.lifecycle).mockImplementation(() => new Promise(() => {}));
 await render((qc) => { qc.setQueryData(["network-action-target", "cluster-1", "team/api"], map); qc.setQueryData(["network-action-candidate", "cluster-1", "team/api"], lifecycle()); });
 await settled(() => expect(host.textContent).toContain("Loading action target")); expect(host.querySelector('form')).toBeNull(); expect(network.policyAction).not.toHaveBeenCalled();
});
it("rechecks registry cache immediately before write when refresh starts during preflight", async () => {
 await render((qc) => qc.setQueryData(["clusters"], { clusters: [{ id: "cluster-1" }] })); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason("Preserved during race");
 let release!: (map: NetworkMap) => void; vi.mocked(network.map).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await submit();
 let finishRegistry!: (value: { clusters: Array<{ id: string }> }) => void;
 const registry = client.fetchQuery({ queryKey: ["clusters"], queryFn: () => new Promise<{ clusters: Array<{ id: string }> }>((resolve) => { finishRegistry = resolve; }) });
 await act(async () => { release(map); }); await settled(() => expect(host.textContent).toContain("changed or began refreshing")); expect(network.enforcement.create).not.toHaveBeenCalled(); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Preserved during race");
 await act(async () => { finishRegistry({ clusters: [{ id: "cluster-1" }] }); await registry; });
});
it("rejects a policy candidate that changes during submit preflight", async () => {
 route.action = "approve-policy"; await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason("Keep review reason");
 vi.mocked(network.lifecycle).mockResolvedValue(lifecycle({ ...candidate, candidate_hash: "changed" })); await submit();
 await settled(() => expect(host.textContent).toContain("Review the updated candidate before approving")); expect(network.policyAction).not.toHaveBeenCalled(); expect(host.querySelector<HTMLTextAreaElement>('#network-action-reason')?.value).toBe("Keep review reason");
});

it("pauses an in-flight approval when cached candidate changes before the response arrives", async () => {
 route.action = "approve-policy"; await render(); await settled(() => expect(host.querySelector('form')).not.toBeNull()); await reason();
 let release!: (value: ReturnType<typeof lifecycle>) => void; vi.mocked(network.lifecycle).mockImplementationOnce(() => new Promise((resolve) => { release = resolve; })); await submit(); await settled(() => expect(release).toBeDefined());
 await act(async () => client.setQueryData(["network-action-candidate", "cluster-1", "team/api"], lifecycle({ ...candidate, candidate_hash: "new-cached-hash" })));
 await act(async () => release(lifecycle())); await settled(() => expect(host.textContent).toContain("Review the updated candidate before approving")); expect(network.policyAction).not.toHaveBeenCalled();
});
