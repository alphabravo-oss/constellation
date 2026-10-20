import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { responseRulesV2, type ResponseRuleV2 } from "@/api/client";
import { ResponseRuleFormPage } from "./ResponseRuleFormPage";

const route = vi.hoisted(() => ({ navigate: vi.fn() }));
vi.mock("@/api/client", () => ({ responseRulesV2: { list: vi.fn(), options: vi.fn(), update: vi.fn() } }));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => ({ clusterId: "cluster", isLoading: false }) }));
vi.mock("@/components/GroupPicker", () => ({ GroupPicker: () => <input /> }));
vi.mock("@tanstack/react-router", () => ({ useParams: () => ({ ruleId: "rule" }), useNavigate: () => route.navigate, Link: ({ children }: { children: ReactNode }) => <span>{children}</span> }));
let root: Root; let host: HTMLDivElement; let client: QueryClient;
const rule: ResponseRuleV2 = { id: "rule", name: "Saved rule", description: "", enabled: false, priority: 9, event_type: "runtime", conditions: [{ type: "name", value: "test" }], actions: [{ kind: "notify", target: "slack" }], workload_match: { namespace: "proof", labels: { app: "test" } } };
afterEach(() => { act(() => root?.unmount()); client?.clear(); host?.remove(); vi.resetAllMocks(); });
const options = { event_types: [], condition_types: [], action_kinds: [], receivers: [], webhooks: [], response_rule_options: {} };
async function renderPage(optionsResult = Promise.resolve(options)) {
  vi.mocked(responseRulesV2.options).mockReturnValue(optionsResult);
  host = document.createElement("div"); document.body.appendChild(host); root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => root.render(<QueryClientProvider client={client}><ResponseRuleFormPage /></QueryClientProvider>));
}
async function settled(check: () => void) { await vi.waitFor(async () => { await act(async () => {}); check(); }); }
it.each(["failed", "missing"])("blocks a %s edit load", async (scenario) => {
  if (scenario === "failed") vi.mocked(responseRulesV2.list).mockRejectedValue(new Error("private details"));
  else vi.mocked(responseRulesV2.list).mockResolvedValue({ rules: [] });
  await renderPage(); await settled(() => expect(host.textContent).toContain("could not be loaded for the selected cluster"));
  expect(host.querySelector("form")).toBeNull(); expect(host.textContent).not.toContain("private details");
});
it("preserves the loaded draft across refresh and save failure", async () => {
  vi.mocked(responseRulesV2.list).mockResolvedValue({ rules: [rule] });
  vi.mocked(responseRulesV2.update).mockRejectedValue(new Error("private details"));
  let resolveOptions!: (value: typeof options) => void;
  const pendingOptions = new Promise<typeof options>((resolve) => { resolveOptions = resolve; });
  await renderPage(pendingOptions); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  const save = host.querySelector<HTMLButtonElement>('button[type="submit"]')!;
  expect(save.disabled).toBe(true);
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  expect(responseRulesV2.update).not.toHaveBeenCalled();
  await act(async () => { resolveOptions(options); });
  await settled(() => expect(save.disabled).toBe(false));
  await act(async () => { client.setQueryData(["response-rule-editor", "cluster", "rule"], { rules: [{ ...rule, name: "Remote change", enabled: true }] }); });
  expect(host.querySelector<HTMLInputElement>('input[required]')?.value).toBe("Saved rule");
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  await settled(() => expect(host.textContent).toContain("Your draft is preserved"));
  expect(host.textContent).not.toContain("private details");
  expect(responseRulesV2.update).toHaveBeenCalledWith("rule", expect.objectContaining({ name: "Saved rule", enabled: false, workload_match: rule.workload_match }));
  expect(route.navigate).not.toHaveBeenCalled();
});
it("requires an action and cancels without a write", async () => {
  vi.mocked(responseRulesV2.list).mockResolvedValue({ rules: [{ ...rule, actions: [] }] });
  await renderPage(); await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => { host.querySelector("form")!.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })); });
  expect(responseRulesV2.update).not.toHaveBeenCalled();
  await act(async () => [...host.querySelectorAll("button")].find((button) => button.textContent === "Cancel" || button.getAttribute("aria-label") === "Cancel" || button.getAttribute("data-export-label") === "Cancel")!.click());
  expect(route.navigate).toHaveBeenCalledWith({ href: "/clusters/cluster/response-rules" });
});
