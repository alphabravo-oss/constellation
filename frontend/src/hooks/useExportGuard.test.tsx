import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, assets } from "@/api/client";
import { exportQueryReady, useExportGuard } from "./useExportGuard";

let client: QueryClient;
let root: Root;
let host: HTMLDivElement;
let completion: Promise<unknown>;
function ExportControl() {
  const reviewed = client.getQueryData(["reviewed"]);
  const capture = useExportGuard("operator:cluster:filters", false, () => exportQueryReady(client, ["reviewed"], reviewed));
  return <button onClick={() => { completion = assets.exportCsv({ cluster_id: "cluster", search: "needle" }, capture()); }}>Export</button>;
}
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  client = new QueryClient();
  client.setQueryData(["reviewed"], { total: 42 });
  host = document.createElement("div"); document.body.append(host); root = createRoot(host);
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.restoreAllMocks(); });
it.each(["invalidation round trip", "replaced evidence", "unmount"])("checks the live source before downloading after %s", async change => {
  let respond!: () => void;
  vi.spyOn(api, "get").mockImplementation(() => new Promise(resolve => {
    respond = () => resolve({ data: new Blob(["ID\n1\n"]), headers: { "x-export-total": "1", "x-export-limit": "100000", "x-export-truncated": "false" } });
  }));
  const createURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:export");
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  await act(async () => root.render(<QueryClientProvider client={client}><ExportControl /></QueryClientProvider>));
  await act(async () => host.querySelector<HTMLButtonElement>("button")!.click());
  const rejected = expect(completion).rejects.toThrow("Refresh the inventory");
  if (change === "unmount") await act(async () => root.render(<div>Other workspace</div>));
  else {
    // No observer rerender: invalidation and recovery happen in one turn.
    const original = client.getQueryData(["reviewed"]);
    await act(async () => {
      if (change === "invalidation round trip") void client.invalidateQueries({ queryKey: ["reviewed"], refetchType: "none" });
      client.setQueryData(["reviewed"], change === "replaced evidence" ? { total: 99 } : original);
    });
    expect(client.getQueryState(["reviewed"])?.isInvalidated).toBe(false);
    expect(client.getQueryState(["reviewed"])?.status).toBe("success");
  }
  await act(async () => respond());
  await rejected;
  expect(createURL).not.toHaveBeenCalled(); expect(click).not.toHaveBeenCalled();
});
