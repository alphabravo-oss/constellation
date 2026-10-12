import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PcapWorkspaceTab, ThreatPcapCapturePane } from "./NetworkMapPage";
import { runtimePcap, type PcapCapture, type RuntimeThreatDetail } from "@/api/client";
import { buildNetworkSavedViewSnapshot, type NetworkPcapSavedFilters } from "@/lib/network-saved-views";
import { TestRouter } from "@/test/router";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
vi.mock("@/api/client", () => ({ runtimePcap: { list: vi.fn(), remove: vi.fn(), download: vi.fn() } }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const snapshot = buildNetworkSavedViewSnapshot({ workspaceTab: "pcap", hours: 24, namespace: "", verdict: "", verdictsVisible: { allow: true, alert: true, block: true }, protocolFilter: [], namespaceFilter: [], hidePlatformComponents: true, hiddenKinds: [], scopeMode: "both" });
const capture = (id = "capture", cluster = "cluster"): PcapCapture => ({ id, org_id: "org", cluster_id: cluster, workload: `prod/${id}`, namespace: "prod", requested_by: "user", requested_at: "2026-10-12T00:00:00Z", duration_s: 30, status: "pending", expires_at: "2026-10-13T00:00:00Z" });
beforeEach(() => { host = document.createElement("div"); document.body.append(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); });
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.restoreAllMocks(); vi.resetAllMocks(); vi.unstubAllGlobals(); localStorage.clear(); });
async function render(filters: Partial<NetworkPcapSavedFilters> = {}, cluster = "cluster") { const history = createMemoryHistory({ initialEntries: ["/clusters/cluster/network?tab=pcap&context=keep#proof"] }); await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={{ org_id: "org", user_id: "user" }}><TestRouter history={history}><PcapWorkspaceTab clusterID={cluster} groupFilter="group" filters={{ ...snapshot.pcap_filters, ...filters }} snapshot={snapshot} onFiltersChange={vi.fn()} /></TestRouter></TablePreferencesProvider></QueryClientProvider>)); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }, { timeout: 3000 }); }
it("uses server filters and preserves context on the dedicated capture link", async () => {
 vi.mocked(runtimePcap.list).mockResolvedValue([capture()]); await render({ dst_port: "443", workload: " prod/api ", protocol: "tcp" }); await settle(() => expect(host.textContent).toContain("prod/capture"));
 expect(runtimePcap.list).toHaveBeenCalledWith(expect.objectContaining({ cluster_id: "cluster", group: "group", workload: "prod/api", dst_port: 443, protocol: "tcp" }));
 const url=new URL(host.querySelector('a[data-testid="network-pcap-new"]')!.getAttribute('href')!,"https://example.com"); expect(url.pathname).toBe('/clusters/cluster/network/pcap/new'); expect(url.searchParams.get('context')).toBe('keep'); expect(url.hash).toBe('#proof'); expect(url.searchParams.has('network_view')).toBe(true);
 expect(host.textContent).toContain('Not reported'); expect(host.querySelector('form')).toBeNull();
});
it.each(['-1','1.5','65536','text'])("does not broaden invalid port %s, even on Refresh", async port => { await render({dst_port:port}); expect(runtimePcap.list).not.toHaveBeenCalled(); const refresh=host.querySelector<HTMLButtonElement>('[data-testid="network-pcap-refresh"]')!; expect(refresh.disabled).toBe(true); await act(async()=>refresh.click()); expect(runtimePcap.list).not.toHaveBeenCalled(); expect(host.textContent).toContain('Destination port must'); });
it("withholds foreign-cluster rows",async()=>{vi.mocked(runtimePcap.list).mockResolvedValue([capture('foreign','other')]);await render();await settle(()=>expect(host.textContent).toContain('does not match'));expect(host.textContent).not.toContain('prod/foreign');expect(host.querySelector('[data-testid="network-pcap-delete"]')).toBeNull();});
it("withholds cached captures after failed refresh",async()=>{vi.mocked(runtimePcap.list).mockResolvedValue([capture()]);await render();await settle(()=>expect(host.textContent).toContain('prod/capture'));vi.mocked(runtimePcap.list).mockRejectedValue(new Error('offline'));await act(async()=>{await client.invalidateQueries({queryKey:['pcap-captures']});});await settle(()=>expect(host.textContent).toContain('could not be loaded or refreshed'));expect(host.textContent).not.toContain('prod/capture');});
it("makes every returned capture reachable through the shared table",async()=>{vi.mocked(runtimePcap.list).mockResolvedValue(Array.from({length:200},(_,i)=>capture(`capture-${i}`)));await render();await settle(()=>expect(host.textContent).toContain('200 returned capture requests'));for(let i=0;i<20&&!host.textContent?.includes('prod/capture-199');i++){const next=[...host.querySelectorAll('button')].find(b=>b.textContent==='Next');expect(next).toBeDefined();await act(async()=>next!.click());}expect(host.textContent).toContain('prod/capture-199');expect(host.textContent).toContain('CSV exports all matching loaded rows');});
it("rechecks scope before removing a displayed capture",async()=>{vi.mocked(runtimePcap.list).mockResolvedValue([capture()]);await render();await settle(()=>expect(host.textContent).toContain('prod/capture'));vi.stubGlobal('confirm',vi.fn(()=>true));await act(async()=>{client.setQueriesData({queryKey:['pcap-captures']},[capture('capture','other')]);host.querySelector<HTMLButtonElement>('[data-testid="network-pcap-delete"]')!.click();});expect(runtimePcap.remove).not.toHaveBeenCalled();});
it("does not request unscoped capture evidence",async()=>{await render({},'');expect(runtimePcap.list).not.toHaveBeenCalled();expect(host.textContent).toContain('Select a cluster');});

it("routes threat capture through the canonical form with the exact traffic tuple", async () => {
 const threat={id:"threat",cluster_id:"cluster",workload_id:"prod/api",src_ip:"10.0.0.1",dst_ip:"10.0.0.2",dst_port:443,ip_proto:6} as RuntimeThreatDetail;
 const history=createMemoryHistory({initialEntries:["/clusters/cluster/network?tab=threats&context=keep#proof"]});
 const show=async(clusterID:string)=>{await act(async()=>root.render(<TestRouter key={clusterID} history={history}><ThreatPcapCapturePane threat={threat} clusterID={clusterID} snapshot={snapshot}/></TestRouter>));};
 await show("cluster"); const link=host.querySelector<HTMLAnchorElement>('[data-testid="threat-pcap-new"]')!; const url=new URL(link.getAttribute('href')!,"https://example.com");
 expect(url.pathname).toBe('/clusters/cluster/network/pcap/new');expect(url.searchParams.get('context')).toBe('keep');expect(url.hash).toBe('#proof');expect(JSON.parse(url.searchParams.get('network_view')!).pcap_filters).toEqual(expect.objectContaining({workload:'prod/api',src_ip:'10.0.0.1',dst_ip:'10.0.0.2',dst_port:'443',protocol:'tcp'}));expect(host.querySelector('input')).toBeNull();
 await show("other");expect(host.querySelector('a')).toBeNull();expect(host.textContent).toContain('scope does not match');
});
