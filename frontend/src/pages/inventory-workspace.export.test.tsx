import { act } from "react";
import { flushSync } from "react-dom";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, imageScanResults, type ScanInventoryDownloadGuard, type ScanInventoryExportResult } from "@/api/client";
import { ScanInventoryExport } from "./inventory-workspace";

let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const exported = (total: number): ScanInventoryExportResult => ({ total, exported: total, limit: 100000, truncated: false });
beforeEach(() => {
 (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
 client = new QueryClient({ defaultOptions: { mutations: { retry: false } } }); host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.restoreAllMocks(); });
const tree = (context: string, download: (shouldDownload: ScanInventoryDownloadGuard) => Promise<ScanInventoryExportResult>, disabled = false) => <QueryClientProvider client={client}><ScanInventoryExport context={context} download={download} disabled={disabled} /></QueryClientProvider>;
const button = () => host.querySelector<HTMLButtonElement>("button")!;
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }

it("rejects a queued export after scope changes instead of exporting either old or newly rendered filters", async () => {
 const original = vi.fn(async () => exported(42)); const replacement = vi.fn(async () => exported(83));
 await act(async () => root.render(tree("org-a:asset-a:filters-a", original)));
 await act(async () => { button().click(); flushSync(() => root.render(tree("org-b:asset-b:filters-b", replacement))); });
 await settle(() => expect(button().disabled).toBe(false)); expect(original).not.toHaveBeenCalled(); expect(replacement).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("could not be exported");
 await act(async () => button().click()); await settle(() => expect(host.textContent).toContain("Exported all 83 matching records across pages")); expect(replacement).toHaveBeenCalledOnce();
});
it("uses the captured original callback when a same-scope rerender replaces mutation options before dispatch", async () => {
 const original = vi.fn(async () => exported(42)); const replacement = vi.fn(async () => exported(83));
 await act(async () => root.render(tree("same-scope", original)));
 await act(async () => { button().click(); flushSync(() => root.render(tree("same-scope", replacement))); });
 await settle(() => expect(host.textContent).toContain("Exported all 42 matching records across pages")); expect(original).toHaveBeenCalledOnce(); expect(replacement).not.toHaveBeenCalled();
});
it("rejects a queued export when its workspace unmounts before dispatch", async () => {
 const download = vi.fn(async () => exported(42)); await act(async () => root.render(tree("scope", download)));
 await act(async () => { button().click(); flushSync(() => root.render(<div>Another workspace</div>)); });
 await settle(() => expect(client.getMutationCache().getAll()[0].state.status).toBe("error")); expect(download).not.toHaveBeenCalled(); expect(host.textContent).toBe("Another workspace");
});
it("rejects a queued export when the current evidence becomes unavailable", async () => {
 const download = vi.fn(async () => exported(42)); await act(async () => root.render(tree("scope", download)));
 await act(async () => { button().click(); flushSync(() => root.render(tree("scope", download, true))); });
 await settle(() => expect(host.textContent).toContain("Matching CSV could not be exported")); expect(download).not.toHaveBeenCalled(); expect(button().disabled).toBe(true);
});
it("keeps late completion from a prior scope out of current export feedback", async () => {
 let complete!: (value: ScanInventoryExportResult) => void;
 const original = vi.fn(() => new Promise<ScanInventoryExportResult>(resolve => { complete = resolve; })); const replacement = vi.fn(async () => exported(83));
 await act(async () => root.render(tree("original-scope", original))); await act(async () => button().click()); await settle(() => expect(original).toHaveBeenCalledOnce());
 await act(async () => root.render(tree("replacement-scope", replacement))); await act(async () => complete(exported(42)));
 await settle(() => expect(button().disabled).toBe(false)); expect(host.textContent).not.toContain("Exported all 42"); expect(replacement).not.toHaveBeenCalled();
 await act(async () => button().click()); await settle(() => expect(host.textContent).toContain("Exported all 83"));
});
it.each(["context", "unmount", "unavailable", "context round trip", "availability round trip"])("does not dispatch a pending HTTP CSV after %s changes", async change => {
 let respond!: () => void;
 const get = vi.spyOn(api, "get").mockImplementation(() => new Promise(resolve => { respond = () => resolve({ data: new Blob(["ID\n1\n"]), headers: { "x-export-total": "42", "x-export-limit": "100000", "x-export-truncated": "false" } }); }));
 const createURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:inventory");
 const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 const download = (shouldDownload: ScanInventoryDownloadGuard) => imageScanResults.exportCSV({ cluster_id: "original-cluster" }, shouldDownload);
 await act(async () => root.render(tree("original-owner:original-cluster", download)));
 await act(async () => button().click()); await settle(() => expect(get).toHaveBeenCalledOnce());
 await act(async () => root.render(change === "unmount" ? <div>Other workspace</div> : tree(change.startsWith("context") ? "new-owner:new-cluster" : "original-owner:original-cluster", download, change.startsWith("unavailable") || change === "availability round trip")));
 if (change.endsWith("round trip")) await act(async () => root.render(tree("original-owner:original-cluster", download)));
 await act(async () => respond());
 await settle(() => expect(client.getMutationCache().getAll()[0].state.status).toBe("error"));
 expect(createURL).not.toHaveBeenCalled(); expect(click).not.toHaveBeenCalled(); expect(host.textContent).not.toContain("Exported all");
});
it("allows a pending HTTP export through a same-scope rerender with confirmed evidence", async () => {
 let respond!: () => void;
 const get = vi.spyOn(api, "get").mockImplementation(() => new Promise(resolve => { respond = () => resolve({ data: new Blob(["ID\n1\n"]), headers: { "x-export-total": "42", "x-export-limit": "100000", "x-export-truncated": "false" } }); }));
 vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:inventory"); vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
 const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
 const download = (shouldDownload: ScanInventoryDownloadGuard) => imageScanResults.exportCSV({}, shouldDownload);
 await act(async () => root.render(tree("same-scope", download))); await act(async () => button().click()); await settle(() => expect(get).toHaveBeenCalledOnce());
 await act(async () => root.render(tree("same-scope", download))); await act(async () => respond());
 await settle(() => expect(host.textContent).toContain("Exported all 42 matching records")); expect(click).toHaveBeenCalledOnce();
});
