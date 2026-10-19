/* global HTMLSelectElement */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { deployments, type Deployment } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { DeploymentsPage } from "./DeploymentsPage";

const state = vi.hoisted(() => ({ clusterId: "cluster", cluster: { id: "cluster" } as { id: string } | undefined, isLoading: false, error: null as Error | null }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => state }));
vi.mock("@/api/client", () => ({ deployments: { list: vi.fn(), exportCsv: vi.fn() } }));
let root: Root | undefined;
let host: HTMLDivElement;
let client: QueryClient;
let history: RouterHistory;
let identity = {org_id:"org",user_id:"user"};
const row = (name: string, role?: string): Deployment => ({ id: name, namespace: "payments", name, kind: "Deployment", labels: {}, platform_role: role, risk_score: 70, risk_factors: {}, finding_count: 1, critical_count: 1, high_count: 0, first_seen_at: "2026-10-12T00:00:00Z", last_seen_at: "2026-10-12T00:00:00Z" });
const response = (rows: Deployment[], total = rows.length, platformCount = 0) => ({ deployments: rows, total, platform_count: platformCount, has_more: total > 100, limit: 100, offset: 0, summary: { total, at_risk: total, finding_count: total, critical_count: total, high_count: 0 } });

beforeEach(() => { identity={org_id:"org",user_id:"user"}; Object.assign(state, { clusterId: "cluster", cluster: { id: "cluster" }, isLoading: false, error: null }); localStorage.clear(); vi.mocked(deployments.list).mockResolvedValue(response([row("customer-0605")], 251, 650)); });
afterEach(() => { act(() => root?.unmount()); root = undefined; client?.clear(); host?.remove(); vi.restoreAllMocks(); vi.resetAllMocks(); });
async function render(url: string, previous?: string) {
 host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
 client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
 history = createMemoryHistory({ initialEntries: previous ? [previous, url] : [url] });
 await act(async () => root!.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><TestRouter history={history}><DeploymentsPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>));
 await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector('[data-testid="deployments-page"]')).not.toBeNull(); });
}
async function settled() { await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector('[data-testid="deployment-page-scope"]')).not.toBeNull(); }); }
async function input(testId: string, value: string) {
 const field = host.querySelector<HTMLInputElement>(`[data-testid="${testId}"]`)!;
 await act(async () => { Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(field, value); field.dispatchEvent(new Event("input", { bubbles: true })); });
}
const button = (label: string) => Array.from(host.querySelectorAll("button")).find((element) => element.textContent?.trim() === label)!;

it("sends URL search/namespace/visibility/page to the server and uses matching totals", async () => {
 await render("/clusters/cluster/deployments?q=customer-0605&namespace=payments&hide_platform=false&page=3"); await settled();
 expect(deployments.list).toHaveBeenLastCalledWith({ presence: "current", cluster_id: "cluster", q: "customer-0605", namespace: "payments", hide_platform: false, platform_role: undefined, limit: 100, offset: 200 });
 expect(host.querySelector('[data-testid="deployment-page-scope"]')?.textContent).toContain("201–201 of 251");
 expect(host.querySelector('[data-testid="deployments-summary"]')?.textContent).toContain("251");
 expect(host.querySelectorAll('[data-testid="deployment-row"]')).toHaveLength(1);
 expect(host.querySelector('a[href="/clusters/cluster/deployments/customer-0605"]')).not.toBeNull();
});

it("resets paging for filters and restores query state through back/forward", async () => {
 await render("/clusters/cluster/deployments?q=old&page=3", "/clusters/cluster/deployments?q=old"); await settled();
 await input("deployment-search", "new");
 await vi.waitFor(() => { expect(history.location.search).toBe("?q=new"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ q: "new", offset: 0 })); });
 await act(async () => history.back());
 await vi.waitFor(() => { expect((host.querySelector('[data-testid="deployment-search"]') as HTMLInputElement).value).toBe("old"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ q: "old", offset: 0 })); });
 await act(async () => history.forward());
 await vi.waitFor(() => expect((host.querySelector('[data-testid="deployment-search"]') as HTMLInputElement).value).toBe("new"));
 await input("namespace-filter", "billing");
 await vi.waitFor(() => { expect(history.location.search).toContain("namespace=billing"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ namespace: "billing", offset: 0 })); });
});

it("pages on the server and sends platform visibility before selection", async () => {
 await render("/clusters/cluster/deployments"); await settled();
 expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ hide_platform: true, offset: 0 }));
 await act(async () => button("Next").click());
 await vi.waitFor(() => { expect(history.location.search).toBe("?page=2"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ offset: 100 })); });
 await act(async () => (host.querySelector('[data-testid="platform-visibility-toggle"]') as HTMLButtonElement).click());
 await vi.waitFor(() => { expect(history.location.search).toBe("?hide_platform=false"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ hide_platform: false, offset: 0 })); });
});

it("exports all matching filters without carrying the displayed page offset", async () => {
 vi.mocked(deployments.exportCsv).mockResolvedValue(new Blob(["CSV"]));
 vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}); vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await render("/clusters/cluster/deployments?q=customer&namespace=payments&hide_platform=false&platform_role=none&page=2"); await settled();
 await act(async () => button("Export CSV").click());
 expect(deployments.exportCsv).toHaveBeenCalledWith({ presence: "current", cluster_id: "cluster", q: "customer", namespace: "payments", hide_platform: false, platform_role: "none" });
 expect(URL.createObjectURL).toHaveBeenCalled();
});

it.each(["loading", "unresolved", "wrong", "error"])("does not query an %s cluster", async (condition) => {
 if (condition === "loading") state.isLoading = true;
 if (condition === "unresolved") state.cluster = undefined;
 if (condition === "wrong") state.cluster = { id: "other" };
 if (condition === "error") state.error = new Error("cluster unavailable");
 await render("/clusters/cluster/deployments");
 expect(deployments.list).not.toHaveBeenCalled(); expect(button("Export CSV").disabled).toBe(true);
 expect(host.textContent).not.toContain("Loading deployment inventory");
 expect(host.textContent).toContain(condition === "error" ? "Cluster inventory is unavailable" : condition === "loading" ? "Resolving cluster" : "Select a resolved cluster");
 expect(host.querySelectorAll('[data-testid="deployment-row"]')).toHaveLength(0);
});

it("shows unavailable inventory without zero metrics or enabled export", async () => {
 vi.mocked(deployments.list).mockRejectedValue(new Error("query failed"));
 await render("/clusters/cluster/deployments");
 await vi.waitFor(() => expect(host.textContent).toContain("Could not load deployments"));
 expect(host.querySelector('[data-testid="deployments-summary"]')?.textContent).toContain("—");
 expect(host.textContent).not.toContain("No matching deployments"); expect(button("Export CSV").disabled).toBe(true);
});

it("restores a fact cohort through history and applies it to pages and full CSV", async () => {
 vi.mocked(deployments.exportCsv).mockResolvedValue(new Blob(["CSV"]));
 vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}); vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await render("/clusters/cluster/deployments?hide_platform=false&risk_fact=privileged&page=3"); await settled();
 expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ risk_fact: "privileged", hide_platform: false, offset: 200 }));
 expect(host.textContent).toContain("including zero or null values");
 await act(async () => button("Export CSV").click());
 expect(deployments.exportCsv).toHaveBeenCalledWith(expect.objectContaining({ risk_fact: "privileged", hide_platform: false }));
 const field = host.querySelector<HTMLSelectElement>('[aria-label="Recorded risk fact"]')!;
 await act(async () => { field.value = "run_as_root"; field.dispatchEvent(new Event("change", { bubbles: true })); });
 await vi.waitFor(() => { expect(history.location.search).toBe("?hide_platform=false&risk_fact=run_as_root"); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ risk_fact: "run_as_root", offset: 0 })); });
 await act(async () => history.back());
 await vi.waitFor(() => expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ risk_fact: "privileged", offset: 200 })));
});

it("preserves exact exposure-mode filters across CSV, URL paging and back/forward", async () => {
 vi.mocked(deployments.exportCsv).mockResolvedValue(new Blob(["CSV"])); vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {}); vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 await render("/clusters/cluster/deployments?hide_platform=false&risk_fact=net_exposure&group_mode=protect&page=2"); await settled();
 expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ risk_fact: "net_exposure", group_mode: "protect", hide_platform: false, offset: 100 }));
 expect(host.textContent).toContain("Unmatched workloads are excluded"); expect(host.textContent).toContain("including zero or null values");
 await act(async () => button("Export CSV").click()); expect(deployments.exportCsv).toHaveBeenCalledWith(expect.objectContaining({ risk_fact: "net_exposure", group_mode: "protect", hide_platform: false }));
 const mode = host.querySelector<HTMLSelectElement>('[aria-label="Strongest group mode"]')!;
 await act(async () => { mode.value="discover"; mode.dispatchEvent(new Event("change",{bubbles:true})); });
 await vi.waitFor(() => { expect(history.location.search).not.toContain("page="); expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode:"discover", offset:0 })); });
 await act(async () => history.back()); await vi.waitFor(() => expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode:"protect", offset:100 })));
 await act(async () => history.forward()); await vi.waitFor(() => expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({ group_mode:"discover", offset:0 })));
});

it("discards a pending export after filters change instead of downloading the old cohort",async()=>{
 let finish:(value:Blob)=>void=()=>{};vi.mocked(deployments.exportCsv).mockImplementation(()=>new Promise(resolve=>{finish=resolve;}));const click=vi.spyOn(HTMLAnchorElement.prototype,"click").mockImplementation(()=>{});const create=vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:deployment");await render("/clusters/cluster/deployments?q=old&hide_platform=false");await settled();await act(async()=>button("Export CSV").click());await input("deployment-search","new");await vi.waitFor(()=>expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({q:"new"})));await act(async()=>finish(new Blob(["Name\nold\n"])));expect(click).not.toHaveBeenCalled();expect(create).not.toHaveBeenCalled();expect(host.textContent).not.toContain("Deployment export failed");
});
it("isolates owner cache and suppresses an old owner's late export feedback",async()=>{
 let reject:(error:Error)=>void=()=>{};vi.mocked(deployments.exportCsv).mockImplementation(()=>new Promise((_resolve,fail)=>{reject=fail;}));await render("/clusters/cluster/deployments?hide_platform=false");await settled();await act(async()=>button("Export CSV").click());identity={org_id:"other",user_id:"other"};await act(async()=>root!.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><TestRouter history={history}><DeploymentsPage/></TestRouter></TablePreferencesProvider></QueryClientProvider>));await vi.waitFor(()=>expect(client.getQueryCache().findAll({queryKey:["deployments","other:other"]})).toHaveLength(1));await act(async()=>reject(new Error("private old owner failure")));expect(host.textContent).not.toContain("Deployment export failed");expect(host.textContent).not.toContain("private old owner failure");expect(client.getQueryCache().findAll({queryKey:["deployments","org:user"]})).toHaveLength(1);
});

it("preserves workload presence in filtering and distinguishes scaled-to-zero controllers", async () => {
 vi.mocked(deployments.list).mockResolvedValue(response([{...row("dormant"),inventory_presence:"scaled_to_zero"}]));
 await render("/clusters/cluster/deployments?presence=scaled_to_zero");
 expect(deployments.list).toHaveBeenCalledWith(expect.objectContaining({presence:"scaled_to_zero"}));
 await vi.waitFor(()=>expect(host.textContent).toContain("Scaled to zero"));
 const select=host.querySelector<HTMLSelectElement>('select[aria-label="Workload presence"]')!;
 expect(select.value).toBe("scaled_to_zero");
 await act(async()=>{select.value="all";select.dispatchEvent(new Event("change",{bubbles:true}));});
 await vi.waitFor(()=>expect(deployments.list).toHaveBeenLastCalledWith(expect.objectContaining({presence:"all",offset:0})));
});
