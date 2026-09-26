import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";

import { networkRules, type NetworkRule } from "@/api/client";
import { NetworkRulesPage } from "./NetworkRulesPage";

vi.mock("@/hooks/useCluster", () => ({
  useCluster: () => ({ clusterId: "cluster-1" }),
}));

let root: Root | undefined;
let host: HTMLDivElement | undefined;
let queryClient: QueryClient | undefined;

afterEach(() => {
  act(() => root?.unmount());
  queryClient?.clear();
  host?.remove();
  root = undefined;
  host = undefined;
  queryClient = undefined;
  vi.restoreAllMocks();
});

function rule(id: number, from: string, priority: number, matches: number): NetworkRule {
  return {
    id, from, to: "default/db", priority, match_counter: matches,
    last_match_timestamp: 0, comment: "", ports: "any", action: "allow",
    applications: [], learned: false, disable: false, cfg_type: "user_created",
  };
}

async function renderRules() {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  vi.spyOn(networkRules, "list").mockResolvedValue({
    cluster_id: "cluster-1",
    rules: [rule(1001, "default/top", 1, 1), rule(1002, "default/lower", 2, 100)],
    summary: { total: 2, allow: 2, deny: 0, learned: 0, disabled: 0 },
  });
  vi.spyOn(networkRules, "moveTop").mockResolvedValue({ ok: true, priority: 0 });
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  queryClient = client;
  await act(async () => root?.render(
    <QueryClientProvider client={client}><MemoryRouter><NetworkRulesPage /></MemoryRouter></QueryClientProvider>,
  ));
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
}

it("starts in server evaluation order rather than match-count order", async () => {
  await renderRules();
  const rows = Array.from(host?.querySelectorAll("tbody tr") ?? []);
  expect(rows).toHaveLength(2);
  expect(rows[0].textContent).toContain("default/top");
  expect(rows[1].textContent).toContain("default/lower");
  expect(rows[0].querySelector<HTMLButtonElement>('button[title="Already highest precedence"]')?.disabled).toBe(true);
  expect(rows[1].querySelector<HTMLButtonElement>('button[title="Move to top (evaluate first)"]')?.disabled).toBe(false);
  expect(host?.textContent).toContain("Column sorting changes only the view");
});

it("does not mistake the first filtered row for the highest-precedence rule", async () => {
  await renderRules();
  const search = host?.querySelector<HTMLInputElement>('input[placeholder^="Search from"]');
  expect(search).toBeTruthy();
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(search, "lower");
    search?.dispatchEvent(new Event("input", { bubbles: true }));
  });
  const rows = Array.from(host?.querySelectorAll("tbody tr") ?? []);
  expect(rows).toHaveLength(1);
  expect(rows[0].textContent).toContain("default/lower");
  const action = rows[0].querySelector<HTMLButtonElement>('button[title="Move to top (evaluate first)"]');
  expect(action?.disabled).toBe(false);
  await act(async () => action?.click());
  expect(networkRules.moveTop).toHaveBeenCalledWith("cluster-1", "default/lower", "default/db");
});
