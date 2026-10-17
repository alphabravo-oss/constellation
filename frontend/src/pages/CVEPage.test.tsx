import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cve, downloadLookaheadCSV, type CVEResult, type CVESearchParams } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { CVEPage } from "./CVEPage";
const route = vi.hoisted(() => ({ initial: "", latest: "" }));
vi.mock("@/lib/route-search", async () => {
  const { useState } = await import("react");
  return { useRouteSearchParams: () => {
    const [params, setParams] = useState(() => new URLSearchParams(route.initial));
    return [params, (next: URLSearchParams | ((current: URLSearchParams) => URLSearchParams)) => setParams(current => {
      const result = typeof next === "function" ? next(new URLSearchParams(current)) : next;
      route.latest = result.toString(); return new URLSearchParams(result);
    })];
  } };
});
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn(), Link: ({ children, href, params }: { children: ReactNode; href?: string; params?: {id:string} }) => <a href={href ?? `/cve/${params?.id}`}>{children}</a> }));
vi.mock("@/api/client", async importOriginal => { const actual = await importOriginal<typeof import("@/api/client")>(); return { ...actual, downloadLookaheadCSV: vi.fn().mockResolvedValue({ exported: 1001, limit: 100000, truncated: false }), cve: { ...actual.cve, search: vi.fn(), stats: vi.fn(), bundle: vi.fn() } }; });
let root: Root; let host: HTMLDivElement; let client: QueryClient;
let identity = { org_id: "org", user_id: "user" };
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  route.initial = ""; route.latest = ""; identity = {org_id:"org",user_id:"user"};
  vi.mocked(cve.stats).mockResolvedValue({ total: 1000, kev_listed: 20, epss_gt_50: 30, cvss_gt_70: 40 } as Awaited<ReturnType<typeof cve.stats>>);
  vi.mocked(cve.bundle).mockResolvedValue({ available: false });
  vi.mocked(cve.search).mockImplementation(async arg => {
    const params = arg as CVESearchParams; const offset = params.offset ?? 0;
    return { results: Array.from({ length: offset === 0 ? 51 : 1 }, (_, index) => ({ cve_id: `CVE-page-${offset + index}`, cvss_base: 5, sources: [], aliases: [], kev_listed: false } as unknown as CVEResult)), limit: params.limit!, offset };
  });
});
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.clearAllMocks(); });
async function render() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><CVEPage /></TablePreferencesProvider></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function click(label: string) { await act(async () => { [...host.querySelectorAll<HTMLElement>("button,[role=button]")].find(b => b.textContent?.trim() === label)!.click(); }); }
it("uses server lookahead to navigate beyond the first fifty records", async () => {
  await render(); await settled(() => expect(host.textContent).toContain("CVE-page-49"));
  expect(host.textContent).not.toContain("CVE-page-50");
  await click("Next"); await settled(() => expect(host.textContent).toContain("CVE-page-50"));
  expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({ limit: 51, offset: 50 }));
  expect(new URLSearchParams(route.latest).get("page")).toBe("2");
  expect([...host.querySelectorAll("button")].find(b => b.textContent === "Next")?.disabled).toBe(true);
  const kevFilter = [...host.querySelectorAll<HTMLElement>("[role=button]")].find(el => el.textContent === "KEV-only")!;
  expect(kevFilter.tabIndex).toBe(0);
  await act(async () => kevFilter.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
  await settled(() => expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({ kev: true, offset: 0 })));
  expect(new URLSearchParams(route.latest).has("page")).toBe(false);
});
it("restores page, filters, and global sort from a shared URL", async () => {
  route.initial = "q=openssl&page=3&kev=true&severity=high&source=NVD&sort=published&dir=asc";
  await render(); await settled(() => expect(cve.search).toHaveBeenCalledWith(expect.objectContaining({ q: "openssl", offset: 100, kev: true, severity: "high", source: "NVD", sort: "published", dir: "asc" })));
  expect(host.querySelector<HTMLInputElement>('[data-testid="cve-search-input"]')?.value).toBe("openssl");
});
it("shows a retryable load failure instead of a false empty result", async () => {
  vi.mocked(cve.search).mockRejectedValue(new Error("private transport details"));
  await render(); await settled(() => expect(host.textContent).toContain("Could not load CVE results"));
  expect(host.textContent).not.toContain("No CVEs match"); expect(host.textContent).not.toContain("private transport details");
});
it("keeps the server order authoritative and follows sort changes in the header", async () => {
  vi.mocked(cve.search).mockResolvedValue({ results: [
    { cve_id: "CVE-server-first", cvss_base: 1, sources: [], aliases: [], kev_listed: false },
    { cve_id: "CVE-server-second", cvss_base: 9, sources: [], aliases: [], kev_listed: false },
  ] as unknown as CVEResult[], limit: 51, offset: 0 });
  await render();
  await settled(() => expect(host.querySelector('tbody tr')?.textContent).toContain("CVE-server-first"));
  expect(host.querySelector('th[data-column-id="cvss"]')?.getAttribute("aria-sort")).toBe("descending");
  await act(async () => { host.querySelector<HTMLButtonElement>('th[data-column-id="cvss"] button')?.click(); });
  await settled(() => expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({sort:"cvss",dir:"asc",offset:0})));
  await settled(() => expect(host.querySelector('th[data-column-id="cvss"]')?.getAttribute("aria-sort")).toBe("ascending"));
  expect(host.querySelector('tbody tr')?.textContent).toContain("CVE-server-first");
});

it("withholds cached headline and bundle metadata after failed refresh while results stay independently usable", async () => {
  vi.mocked(cve.bundle).mockResolvedValue({available:true,version:"old-reviewed-bundle",signed:true,imported_at:"2026-10-13T01:00:00Z"});
  await render(); await settled(()=>expect(host.textContent).toContain("old-reviewed-bundle"));
  vi.mocked(cve.stats).mockRejectedValue(new Error("transport failed")); vi.mocked(cve.bundle).mockRejectedValue(new Error("transport failed"));
  await act(async()=>{await client.invalidateQueries({queryKey:["cve","stats","org:user"]});await client.invalidateQueries({queryKey:["cve","bundle","org:user"]});});
  await settled(()=>expect(host.textContent).toContain("CVE catalog summary unavailable"));
  expect(host.textContent).not.toContain("1,000");expect(host.textContent).not.toContain("old-reviewed-bundle");expect(host.textContent).toContain("CVE bundle metadata unavailable");expect(host.textContent).toContain("CVE-page-0");
});
it("sends all reviewed filters and stable sort to matching CSV without page bounds",async()=>{
  route.initial="q=openssl&page=3&kev=true&epss_gt=0.5&cvss_gt=7&severity=high&source=NVD&sort=published&dir=asc";
  await render();await settled(()=>expect(host.textContent).toContain("CVE-page-100"));await click("Export matching CSV");
  await settled(()=>expect(downloadLookaheadCSV).toHaveBeenCalled());const [path,params,filename,guard]=vi.mocked(downloadLookaheadCSV).mock.calls.at(-1)!;
  expect(path).toBe("/cve/search.csv");expect(filename).toBe("constellation-cve-catalog.csv");expect(params).toEqual({q:"openssl",kev:"true",epss_gt:0.5,cvss_gt:7,severity:"high",source:"NVD",sort:"published",dir:"asc"});expect(guard()).toBe(true);await settled(()=>expect(host.textContent).toContain("Exported all 1,001 matching records across pages"));
});
it("hides failed cached result pages and blocks both exports until Retry succeeds",async()=>{
 await render();await settled(()=>expect(host.textContent).toContain("CVE-page-0"));vi.mocked(cve.search).mockRejectedValue(new Error("results failed"));await act(async()=>{await client.invalidateQueries({queryKey:["cve","search"]});});await settled(()=>expect(host.textContent).toContain("Could not load CVE results"));expect(host.querySelector("table")).toBeNull();expect([...host.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent==="Export matching CSV")?.disabled).toBe(true);
 vi.mocked(cve.search).mockResolvedValue({results:[{cve_id:"CVE-recovered",kev_listed:false,aliases:[],sources:[]}],limit:51,offset:0});await click("Retry");await settled(()=>expect(host.textContent).toContain("CVE-recovered"));
});
it.each([
 {results:null,limit:51,offset:0},
 {results:[{cve_id:"CVE-invalid",kev_listed:false,aliases:[],sources:[],published_at:"bad-date"}],limit:51,offset:0},
 {results:[{cve_id:"CVE-invalid",kev_listed:false,aliases:[],sources:[]}],limit:50,offset:0},
 {results:[{cve_id:"CVE-invalid",kev_listed:false,aliases:[],sources:[]}],limit:51,offset:50},
 {results:Array(2).fill({cve_id:"CVE-duplicate",kev_listed:false,aliases:[],sources:[]}),limit:51,offset:0},
])("blocks malformed or mismatched catalog evidence %j",async payload=>{vi.mocked(cve.search).mockResolvedValue(payload as Awaited<ReturnType<typeof cve.search>>);await render();await settled(()=>expect(host.textContent).toContain("Could not load CVE results"));expect(host.querySelector("table")).toBeNull();expect([...host.querySelectorAll<HTMLButtonElement>("button")].find(b=>b.textContent==="Export matching CSV")?.disabled).toBe(true);});
it("rejects a held export after a completed source refresh and after owner changes",async()=>{
 await render();await settled(()=>expect(host.textContent).toContain("CVE-page-0"));let held:()=>boolean=()=>false;let finish:(value:{exported:number;limit:number;truncated:boolean})=>void=()=>{};vi.mocked(downloadLookaheadCSV).mockImplementation((_path,_params,_filename,guard)=>{held=guard;return new Promise(resolve=>{finish=resolve;});});await click("Export matching CSV");expect(held()).toBe(true);
 await act(async()=>{await client.invalidateQueries({queryKey:["cve","search"]});});await settled(()=>expect(host.textContent).toContain("CVE-page-0"));expect(held()).toBe(false);
 identity={org_id:"other",user_id:"other"};await act(async()=>root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><CVEPage /></TablePreferencesProvider></QueryClientProvider>));await settled(()=>expect(client.getQueryCache().findAll({queryKey:["cve","search","other:other"]})).toHaveLength(1));expect(held()).toBe(false);await act(async()=>finish({exported:999,limit:100000,truncated:false}));expect(host.textContent).not.toContain("Exported all 999");
});
it("requires resolved organization/user identity before catalog requests or export",async()=>{identity={org_id:"",user_id:""};await render();expect(cve.search).not.toHaveBeenCalled();expect(cve.stats).not.toHaveBeenCalled();expect(host.textContent).toContain("Resolving operator scope");});
it("recovers an empty deep-linked page without inventing a matching count",async()=>{route.initial="page=999";vi.mocked(cve.search).mockImplementation(async params=>({results:[],limit:51,offset:(params as CVESearchParams).offset!}));await render();await settled(()=>expect(host.textContent).toContain("First page"));expect(host.textContent).not.toContain("1–0");await click("First page");await settled(()=>expect(cve.search).toHaveBeenLastCalledWith(expect.objectContaining({offset:0})));});
