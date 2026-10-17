import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { downloadLookaheadCSV } from "@/api/client";
import { LookaheadExport } from "./LookaheadExport";

vi.mock("@/api/client", () => ({ downloadLookaheadCSV: vi.fn() }));
let root: Root, host: HTMLDivElement, client: QueryClient;
beforeEach(() => {
  (globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  host = document.createElement("div"); document.body.append(host); root = createRoot(host); client = new QueryClient();
});
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.resetAllMocks(); });
async function render(context: string, disabled = false) {
  await act(async () => root.render(<QueryClientProvider client={client}><LookaheadExport context={context} disabled={disabled} isCurrent={() => true} path="/events.csv" params={{ action: context }} filename="events.csv" /></QueryClientProvider>));
}
async function settle(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
it("an old scope's delayed error cannot appear in a new scope", async () => {
  let reject!: (error: Error) => void;
  vi.mocked(downloadLookaheadCSV).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  await render("first"); await act(async () => host.querySelector("button")!.click());
  const guard = vi.mocked(downloadLookaheadCSV).mock.calls[0][3]; expect(guard()).toBe(true);
  await render("second"); expect(guard()).toBe(false);
  await act(async () => reject(new Error("old scope failed")));
  expect(host.querySelector('[role="alert"]')).toBeNull(); expect(host.querySelector("button")!.disabled).toBe(false);
  vi.mocked(downloadLookaheadCSV).mockResolvedValue({ exported: 100000, limit: 100000, truncated: true });
  await act(async () => host.querySelector("button")!.click());
  await settle(() => expect(host.textContent).toContain("more exist. Narrow the filters for a complete export"));
  expect(host.textContent).not.toContain("Exported all");
});
it("disables dispatch while evidence is unavailable and clears success on scope change", async () => {
  await render("first", true); expect(host.querySelector("button")!.disabled).toBe(true);
  await act(async () => host.querySelector("button")!.click()); expect(downloadLookaheadCSV).not.toHaveBeenCalled();
  await render("first"); vi.mocked(downloadLookaheadCSV).mockResolvedValue({ exported: 205, limit: 100000, truncated: false });
  await act(async () => host.querySelector("button")!.click()); await settle(() => expect(host.textContent).toContain("Exported all 205"));
  await render("second"); expect(host.querySelector('[role="status"]')).toBeNull();
});
