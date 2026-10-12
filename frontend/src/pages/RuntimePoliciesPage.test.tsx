import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { runtimePolicies, type RuntimePolicy } from "@/api/client";
import { RuntimePoliciesPage } from "./RuntimePoliciesPage";

vi.mock("@/api/client", () => ({ runtimePolicies: { list: vi.fn(), matchStats: vi.fn(), promote: vi.fn(), demote: vi.fn(), remove: vi.fn() } }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ id: "cluster" }), useNavigate: () => vi.fn() }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
async function renderPage(mode: "monitor" | "enforce") {
  vi.mocked(runtimePolicies.list).mockResolvedValue([{ id: "policy", name: "Policy", workload: "team/app", mode, rules: [], updated_at: "2026-10-12T00:00:00Z" } as unknown as RuntimePolicy]);
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><RuntimePoliciesPage /></QueryClientProvider>));
  await vi.waitFor(async () => { await act(async () => {}); expect(host.querySelector('[data-testid="runtime-policy-row-policy"]')).not.toBeNull(); });
}
it("blocks promotion when its match preview fails and shows a retry action", async () => {
  vi.mocked(runtimePolicies.matchStats).mockRejectedValue(new Error("unavailable"));
  await renderPage("monitor");
  await act(async () => { host.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-promote-policy"]')!.click(); });
  await vi.waitFor(async () => { await act(async () => {}); expect(document.body.textContent).toContain("Match preview could not be loaded"); });
  expect(document.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-promote-confirm"]')?.disabled).toBe(true);
  expect(document.body.textContent).toContain("Retry preview");
  expect(runtimePolicies.promote).not.toHaveBeenCalled();
});
it("shows a demotion failure instead of silently leaving the row unchanged", async () => {
  vi.mocked(runtimePolicies.demote).mockRejectedValue(new Error("private transport details"));
  await renderPage("enforce");
  await act(async () => { host.querySelector<HTMLButtonElement>('[data-testid="runtime-policy-demote-policy"]')!.click(); });
  await vi.waitFor(async () => { await act(async () => {}); expect(host.textContent).toContain("Action failed"); });
  expect(host.textContent).not.toContain("private transport details");
});
