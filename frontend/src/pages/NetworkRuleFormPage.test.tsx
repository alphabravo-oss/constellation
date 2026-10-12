import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { networkRules, type NetworkRule } from "@/api/client";
import { NetworkRuleFormPage } from "./NetworkRuleFormPage";

const route = vi.hoisted(() => ({ ruleId: "123", search: "from=team%2Fapp&to=team%2Fdb&action=allow&comment=stale", navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ networkRules: { list: vi.fn(), upsert: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster" }) }));
vi.mock("@/components/GroupPicker", () => ({ GroupPicker: ({ value, inputId, disabled, onChange }: { value: string; inputId: string; disabled: boolean; onChange: (value: string) => void }) => <input id={inputId} value={value} disabled={disabled} onChange={(e) => onChange(e.target.value)} /> }));
vi.mock("@/lib/route-search", () => ({ useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()] }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ ruleId: route.ruleId }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const rule: NetworkRule = { id: 123, from: "team/app", to: "team/db", ports: "443", applications: ["HTTPS"], action: "deny", disable: true, priority: -10, comment: "Saved comment", learned: false, cfg_type: "user_created", match_counter: 0, last_match_timestamp: 0 };
const response = { cluster_id: "cluster", rules: [rule], summary: { total: 1, allow: 0, deny: 1, learned: 0, disabled: 1 } };
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); route.ruleId = "123"; route.search = "from=team%2Fapp&to=team%2Fdb&action=allow&comment=stale"; });
async function renderPage() {
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><NetworkRuleFormPage /></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
async function submit() { await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); }); }
it("loads saved values and preserves disabled state and negative precedence when editing", async () => {
  vi.mocked(networkRules.list).mockResolvedValue(response);
  vi.mocked(networkRules.upsert).mockResolvedValue({ ok: true, id: 123, cfg_type: "user_created" });
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(host.querySelector<HTMLInputElement>("#network-rule-from")?.disabled).toBe(true);
  expect(host.querySelector("details")?.open).toBe(false);
  await submit();
  await settled(() => expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/network-rules" }));
  expect(networkRules.upsert).toHaveBeenCalledWith("cluster", { from: "team/app", to: "team/db", ports: "443", applications: ["HTTPS"], action: "deny", disable: true, priority: -10, comment: "Saved comment" });
});
it.each(["failed", "missing", "wrong-cluster", "id-collision"])("blocks editing a %s rule", async (scenario) => {
  if (scenario === "failed") vi.mocked(networkRules.list).mockRejectedValue(new Error("private details"));
  else vi.mocked(networkRules.list).mockResolvedValue({ ...response, cluster_id: scenario === "wrong-cluster" ? "other" : "cluster", rules: scenario === "missing" ? [] : [{ ...rule, from: scenario === "id-collision" ? "another/source" : rule.from }] });
  await renderPage();
  await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster"));
  expect(host.querySelector("form")).toBeNull();
  expect(host.textContent).not.toContain("private details");
});
it("retains the draft after background refresh and a failed save", async () => {
  vi.mocked(networkRules.list).mockResolvedValue(response);
  vi.mocked(networkRules.upsert).mockRejectedValue(new Error("private details"));
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { client.setQueriesData({ queryKey: ["network-rule-editor"] }, { ...response, rules: [{ ...rule, comment: "Changed remotely", disable: false, priority: 1000 }] }); });
  expect(host.querySelector<HTMLInputElement>("#network-rule-comment")?.value).toBe("Saved comment");
  await submit();
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(host.textContent).not.toContain("private details");
  expect(networkRules.upsert).toHaveBeenCalledWith("cluster", expect.objectContaining({ disable: true, priority: -10 }));
  expect(route.navigate).not.toHaveBeenCalled();
});
it("cancels a new draft without writing a rule", async () => {
  route.ruleId = ""; route.search = "action=deny";
  await renderPage();
  await act(async () => { [...host.querySelectorAll("button")].find((button) => button.textContent === "Cancel")!.click(); });
  expect(networkRules.list).not.toHaveBeenCalled();
  expect(networkRules.upsert).not.toHaveBeenCalled();
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/network-rules" });
});
it("keeps learned ports and applications read-only", async () => {
  vi.mocked(networkRules.list).mockResolvedValue({ ...response, rules: [{ ...rule, learned: true }] });
  await renderPage();
  await settled(() => expect(host.querySelector<HTMLInputElement>("#network-rule-ports")?.disabled).toBe(true));
  expect(host.querySelector<HTMLInputElement>("#network-rule-applications")?.disabled).toBe(true);
});
