import { act, useState } from "react";
import { createRoot, type Root } from "react-dom/client";
import { createMemoryHistory, type RouterHistory } from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { compliance, type ComplianceEvidenceItem, type ComplianceEvidenceParams, type ComplianceEvidenceResponse } from "@/api/client";
import { ComplianceEvidenceInventory, evidenceResponseMatches } from "./ComplianceEvidenceInventory";

/** Kit Select keeps a hidden native mirror right before its trigger. */
function nativeSelect(root: ParentNode, selector: string): HTMLSelectElement | null {
  const element = root.querySelector(selector);
  if (!element) return null;
  if (element.tagName === "SELECT") return element as HTMLSelectElement;
  const previous = element.previousElementSibling;
  return previous?.tagName === "SELECT" ? previous as HTMLSelectElement : null;
}
vi.mock("@/api/client", () => ({ compliance: { evidence: vi.fn(), exportEvidenceCSV: vi.fn() } }));
let root: Root; let host: HTMLDivElement; let client: QueryClient; let history: RouterHistory;
let identity: { org_id: string; user_id: string } | null;
let cluster: string; let ready: boolean;
let updatePage: ((value: {cluster: string; ready: boolean}) => void) | undefined;
function TestPage() { const [props, setProps] = useState({cluster, ready}); updatePage = setProps; return <ComplianceEvidenceInventory clusterId={props.cluster} ready={props.ready} active />; }
const makeRow = (index: number): ComplianceEvidenceItem => ({ id: `row-${index}`, scope: index % 2 ? "node" : "workload", source: "fixture", framework: "cis", control_id: "duplicate", title: "Repeated control", severity: "high", status: "fail", effective_status: index % 3 ? "fail" : "exempted", target_kind: "workload", target: `apps/service-${index}`, namespace: "apps", cluster_id: cluster, observed_at: "2026-10-12T00:00:00Z", evidence: `Source evidence ${index}` });
function response(request: ComplianceEvidenceParams): ComplianceEvidenceResponse {
 const all = Array.from({ length: 1205 }, (_, index) => makeRow(index)).filter(row => (!request.scope || row.scope === request.scope) && (!request.status || row.effective_status === request.status) && (!request.q || row.evidence?.includes(request.q)) && (!request.target || row.target === request.target));
 const summary = { total: all.length, pass: 0, fail: all.filter(row => row.effective_status === "fail").length, manual: 0, not_applicable: 0, exempted: all.filter(row => row.effective_status === "exempted").length };
 const offset = request.offset || 0;
 return { ...request, items: all.slice(offset, offset + 100), summary, total: all.length, limit: 100, offset, sort: request.sort || "observed", order: request.order || "desc", has_more: offset + 100 < all.length };
}
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
 vi.clearAllMocks(); localStorage.clear(); updatePage = undefined; cluster = "cluster"; ready = true; identity = { org_id: "org", user_id: "user" };
 vi.mocked(compliance.evidence).mockImplementation(async request => response(request!));
 vi.mocked(compliance.exportEvidenceCSV).mockResolvedValue({ total: 1205, exported: 1205, limit: 100000, truncated: false });
 client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } }); host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.restoreAllMocks(); localStorage.clear(); });
async function render(search = "") { history = createMemoryHistory({ initialEntries: [`/clusters/cluster/compliance?tab=evidence${search}`] }); await rerender(); }
async function rerender() { await act(async () => root.render(<QueryClientProvider client={client}><TablePreferencesProvider identity={identity}><TestRouter history={history}><TestPage /></TestRouter></TablePreferencesProvider></QueryClientProvider>)); if (updatePage) await act(async () => updatePage!({cluster, ready})); }
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
function rows() { return host.querySelectorAll('[data-testid="compliance-source-evidence-table"] tbody tr'); }
function button(text: string) { return [...host.querySelectorAll<HTMLButtonElement>("button")].find((item) => item.textContent?.trim() === text || item.getAttribute("aria-label") === text || item.getAttribute("data-export-label") === text)!; }
async function select(selector: string, value: string) { await act(async () => { const input = nativeSelect(host, selector)!; Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, "value")!.set!.call(input, value); input.dispatchEvent(new Event("change", { bubbles: true })); }); }
it("reads past the old source cap with full matching counts and independent server pages", async () => {
 await render("&evidence_page=12&status=graded&page=4&context=a&context=b"); await settle(() => expect(rows()).toHaveLength(100));
 expect(host.textContent).toContain("1,205 source evidence rows"); expect(host.textContent).toContain("Source evidence 1100"); expect(host.textContent).not.toContain("Source evidence 0");
 expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({ cluster_id: "cluster", limit: 100, offset: 1100, sort: "observed", order: "desc" }));
 await act(async () => button("Next").click()); await settle(() => expect(rows()).toHaveLength(5));
 expect(history.location.search).toContain("evidence_page=13"); expect(history.location.search).toContain("page=4");
 await act(async () => history.back()); await settle(() => expect(rows()).toHaveLength(100));
});
it("pushes source/status filters and sorting while preserving unrelated control context on Back", async () => {
 await render("&evidence_page=2&framework=all&status=graded&context=a&context=b#evidence"); await settle(() => expect(rows()).toHaveLength(100));
 await select("#evidence-scope", "node"); await settle(() => expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({ scope: "node", offset: 0 })));
 expect(new URLSearchParams(history.location.search).getAll("context")).toEqual(["a", "b"]); expect(history.location.search).toContain("status=graded"); expect(history.location.hash).toBe("#evidence");
 await select("#evidence-status", "exempted"); await settle(() => expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({ scope: "node", status: "exempted" })));
 await act(async () => history.back());
 const observedSortSelector = '[data-testid="compliance-source-evidence-table"] th[data-column-id="observed"][aria-sort="descending"] .app-table-header-button';
 await settle(() => {
  expect(nativeSelect(host, "#evidence-status")!.value).toBe("");
  expect(rows()).toHaveLength(100);
  const observedSort = host.querySelector<HTMLButtonElement>(observedSortSelector);
  expect(observedSort?.textContent?.trim()).toBe("Observed");
  expect(observedSort?.disabled).toBe(false);
 });
 await act(async () => host.querySelector<HTMLButtonElement>(observedSortSelector)!.click()); await settle(() => expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({ sort: "observed", order: "asc" })));
});
it("replaces search keystrokes with a debounced literal request rather than creating history entries", async () => {
 await render(); await settle(() => expect(rows()).toHaveLength(100));
 await act(async () => { const input = host.querySelector<HTMLInputElement>("#evidence-search")!; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")!.set!.call(input, "Source evidence 1204"); input.dispatchEvent(new Event("input", { bubbles: true })); });
 expect(history.location.search).toContain("evidence_q=Source+evidence+1204"); await settle(() => expect(rows()).toHaveLength(1));
 expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({ q: "Source evidence 1204" })); expect(history.length).toBe(1);
});
it("hides failed or refreshing cached source rows and matching export", async () => {
 await render(); await settle(() => expect(rows()).toHaveLength(100)); let reject!: (error: Error) => void;
 vi.mocked(compliance.evidence).mockImplementation(() => new Promise((_resolve, no) => { reject = no; }));
 let refresh!: Promise<void>; await act(async () => { refresh = client.invalidateQueries({ queryKey: ["compliance", "evidence"] }); });
 await settle(() => expect(rows()).toHaveLength(0)); expect(button("Export matching CSV")).toBeUndefined();
 await act(async () => { reject(new Error("private backend error")); await refresh; }); await settle(() => expect(host.textContent).toContain("Counts and export are unavailable"));
 expect(host.textContent).not.toContain("1,205"); expect(host.textContent).not.toContain("private backend error"); expect(host.textContent).not.toContain("No source evidence matches");
});
it("rejects mismatched scope/page/duplicate identities and false summary contracts", () => {
 const request: ComplianceEvidenceParams = { cluster_id: "cluster", limit: 100, offset: 0, sort: "observed", order: "desc" }; const data = response(request);
 expect(evidenceResponseMatches(data, request)).toBe(true);
 for (const changed of [{ ...data, cluster_id: "sibling" }, { ...data, offset: 100 }, { ...data, items: [data.items[0], ...data.items.slice(0, 99)] }, { ...data, summary: { ...data.summary, fail: 0 } }, { ...data, items: data.items.map((row, index) => index ? row : { ...row, cluster_id: "sibling" }) }]) expect(evidenceResponseMatches(changed, request)).toBe(false);
});
it("isolates account queries and suppresses evidence when cluster resolution or account is unavailable", async () => {
 ready = false; await render(); expect(compliance.evidence).not.toHaveBeenCalled(); expect(rows()).toHaveLength(0);
 ready = true; await rerender(); await settle(() => expect(rows()).toHaveLength(100));
 identity = { org_id: "other-org", user_id: "user" }; await rerender(); await settle(() => expect(compliance.evidence).toHaveBeenCalledTimes(2));
 expect(client.getQueryCache().getAll().map(query => query.queryKey[2])).toEqual(["org:user", "other-org:user"]);
 identity = null; await rerender(); expect(rows()).toHaveLength(0); expect(button("Export matching CSV")).toBeUndefined();
});
it("exports matching filters across pages and reports truncation or download failure", async () => {
 vi.mocked(compliance.exportEvidenceCSV).mockResolvedValueOnce({ total: 100005, exported: 100000, limit: 100000, truncated: true }).mockRejectedValueOnce(new Error("download failed"));
 await render("&evidence_scope=node&evidence_status=fail&evidence_page=2"); await settle(() => expect(rows()).toHaveLength(100));
 await act(async () => button("Export matching CSV").click()); expect(compliance.exportEvidenceCSV).toHaveBeenCalledWith(expect.objectContaining({ scope: "node", status: "fail", offset: 100 }), expect.any(Function));
 await settle(() => expect(host.textContent).toContain("Export capped at 100,000 of 100,005")); await act(async () => button("Export matching CSV").click());
 await settle(() => expect(host.textContent).toContain("Matching CSV could not be exported"));
});
it("withholds invalid URLs and unconfirmed responses instead of presenting empty compliance", async () => {
 await render("&evidence_page=9999999999"); expect(compliance.evidence).not.toHaveBeenCalled(); expect(host.textContent).toContain("requested evidence filter or page is invalid");
 await act(async () => button("Reset evidence filters").click()); await settle(() => expect(rows()).toHaveLength(100));
 vi.mocked(compliance.evidence).mockImplementation(async request => ({ ...response(request!), cluster_id: "sibling" }));
 await act(async () => button("Refresh source evidence").click()); await settle(() => expect(host.textContent).toContain("Counts and export are unavailable")); expect(rows()).toHaveLength(0);
});

it("normalizes pasted exact filters and exposes framework server sorting without borrowing controls filters", async () => {
 await render("&evidence_framework=%20all%20&evidence_namespace=%20apps%20&evidence_sort=framework&evidence_order=asc&framework=cis"); await settle(() => expect(rows()).toHaveLength(100));
 expect(compliance.evidence).toHaveBeenLastCalledWith(expect.objectContaining({framework: undefined, namespace: "apps",sort:"framework",order:"asc"}));
 expect(host.querySelector('th[aria-sort="ascending"]')!.textContent).toContain("Framework");
});
it("keeps exact digests available behind disclosure in target and evidence cells", async () => {
 const digest="sha256:"+"a".repeat(64);vi.mocked(compliance.evidence).mockImplementation(async request => {const data=response(request!);data.items[0]={...data.items[0],target:"apps/service "+digest,evidence:"image_digest="+digest+" secret_count=1"};return data;});
 await render();await settle(()=>expect(rows()).toHaveLength(100));
 const disclosures=rows()[0].querySelectorAll("details");expect(disclosures).toHaveLength(2);expect([...disclosures].every(item=>!item.open)).toBe(true);expect(rows()[0].textContent).toContain("secret_count=1");expect(rows()[0].querySelector("code")!.textContent).toBe(digest);
});

it.each(["null-row", "missing-target", "object-evidence", "null-scope-summary", "null-envelope"])("withholds malformed %s responses without crashing the evidence workspace", async scenario => {
 vi.mocked(compliance.evidence).mockImplementation(async request => {
   const data = response(request!);
   if (scenario === "null-envelope") return null as unknown as ComplianceEvidenceResponse;
   if (scenario === "null-scope-summary") return { ...data, summary: { ...data.summary, by_scope: { workload: null } } } as unknown as ComplianceEvidenceResponse;
   const malformed = scenario === "null-row" ? null : scenario === "missing-target" ? { ...data.items[0], target: undefined } : { ...data.items[0], evidence: { raw: "unexpected object" } };
   return { ...data, items: [malformed, ...data.items.slice(1)] } as unknown as ComplianceEvidenceResponse;
 });
 await render();
 await settle(() => expect(host.textContent).toContain("Counts and export are unavailable"));
 expect(rows()).toHaveLength(0);
 expect(button("Export matching CSV")).toBeUndefined();
 expect(host.textContent).not.toContain("No source evidence matches");
});

it("keeps the loaded count compact and reveals counting/export semantics through the existing disclosure",async()=>{
 await render();await settle(()=>expect(rows()).toHaveLength(100));
 const panel=host.querySelector('[data-testid="compliance-evidence-panel"]')!;
 const caption=panel.querySelector(":scope > p")!;
 expect(caption.textContent).toBe("1,205 source evidence rows match these filters.");
 const disclosures=[...panel.querySelectorAll("details")].filter(details=>details.querySelector("summary")?.textContent==="Evidence status details");
 expect(disclosures).toHaveLength(1);expect(disclosures[0].open).toBe(false);
 expect(disclosures[0].textContent).toContain("Each source record and framework mapping counts separately");
 expect(disclosures[0].textContent).toContain("matching CSV includes all fields, up to 100,000 rows");
});
