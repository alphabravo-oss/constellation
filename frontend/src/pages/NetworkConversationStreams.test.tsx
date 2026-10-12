import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { StreamsTab } from "./NetworkMapPage";
import { network, type ConversationEntries } from "@/api/client";

vi.mock("@/api/client", () => ({ network: { conversationEntries: vi.fn() } }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
beforeEach(() => { host = document.createElement("div"); document.body.append(host); root = createRoot(host); client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); });
afterEach(() => { act(() => root.unmount()); client.clear(); host.remove(); vi.resetAllMocks(); });
function evidence(from = "prod/api", to = "other/api"): ConversationEntries {
  return { from, to, window_hours: 24, entries: [{ protocol: "TCP", application: "HTTPS", port: 443, verdict: "block", bytes: 100, packets: 2, sessions: 1, client_bytes: 70, server_bytes: 30, severity: 4, threat_id: 0, last_seen_at: "2026-10-12T00:00:00Z" }], totals: { bytes: 100, packets: 2, sessions: 1, client_bytes: 70, server_bytes: 30 } };
}
async function render(from = "prod/api", to = "other/api") { await act(async () => root.render(<QueryClientProvider client={client}><StreamsTab clusterID="cluster" from={from} to={to} hours={24} active /></QueryClientProvider>)); }
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
it("loads the exact directed pair without relying on a sampled map flow", async () => {
  vi.mocked(network.conversationEntries).mockResolvedValue(evidence()); await render();
  await settled(() => expect(host.textContent).toContain("HTTPS"));
  expect(network.conversationEntries).toHaveBeenCalledWith({ from: "prod/api", to: "other/api", cluster_id: "cluster", hours: 24 });
  expect(host.textContent).toContain("Up to 200 returned streams");
  vi.mocked(network.conversationEntries).mockResolvedValue(evidence("other/api", "prod/api")); await render("other/api", "prod/api");
  await settled(() => expect(network.conversationEntries).toHaveBeenLastCalledWith({ from: "other/api", to: "prod/api", cluster_id: "cluster", hours: 24 }));
});
it("does not display returned evidence for another pair", async () => {
  vi.mocked(network.conversationEntries).mockResolvedValue(evidence("wrong/api")); await render();
  await settled(() => expect(host.textContent).toContain("do not match")); expect(host.textContent).not.toContain("HTTPS");
});
it("withholds cached evidence after a failed refresh and offers retry", async () => {
  vi.mocked(network.conversationEntries).mockResolvedValue(evidence()); await render(); await settled(() => expect(host.textContent).toContain("HTTPS"));
  vi.mocked(network.conversationEntries).mockRejectedValue(new Error("unavailable"));
  await act(async () => { await client.invalidateQueries({ queryKey: ["conv-entries"] }); });
  await settled(() => expect(host.textContent).toContain("could not be loaded or refreshed")); expect(host.textContent).not.toContain("HTTPS");
  expect([...host.querySelectorAll("button")].some(b => b.textContent === "Retry streams")).toBe(true);
});
