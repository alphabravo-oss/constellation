import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { TestRouter } from "@/test/router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { networkRules, type NetworkRuleInventoryResponse } from "@/api/client";
import { downloadCsv } from "@/lib/csv";
import { NetworkRulesPage } from "./NetworkRulesPage";
import { ruleInventory, ruleRow } from "./network-rule-test-fixture";

const scope = vi.hoisted(() => ({
  clusterId: "cluster",
  cluster: { id: "cluster" },
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let root: Root,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory;
let owner = { org_id: "org", user_id: "user" };
let source = [
  ruleRow(1001, "team/top", { priority: 1 }),
  ruleRow(1002, "team/lower", { priority: 2 }),
];
beforeEach(() => {
  Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true });
  Object.assign(scope, {
    clusterId: "cluster",
    cluster: { id: "cluster" },
    isLoading: false,
    error: null,
  });
  owner = { org_id: "org", user_id: "user" };
  source = [
    ruleRow(1001, "team/top", { priority: 1 }),
    ruleRow(1002, "team/lower", { priority: 2 }),
  ];
  localStorage.clear();
  vi.spyOn(networkRules, "inventory").mockImplementation(
    async (cluster, request) => ruleInventory(cluster, source, request),
  );
  vi.spyOn(networkRules, "moveTop").mockResolvedValue({
    ok: true,
    priority: 0,
  });
  vi.spyOn(networkRules, "inventoryCSV").mockResolvedValue({
    total: 2,
    exported: 2,
    limit: 100000,
    truncated: false,
  });
});
afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.restoreAllMocks();
  localStorage.clear();
});
function tree() {
  return (
    <QueryClientProvider client={client}>
      <TablePreferencesProvider identity={{ ...owner }}>
        <TestRouter history={history}>
          <NetworkRulesPage />
        </TestRouter>
      </TablePreferencesProvider>
    </QueryClientProvider>
  );
}
async function mount(path = "/clusters/cluster/network-rules") {
  history = createMemoryHistory({ initialEntries: [path] });
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  await act(async () => root.render(tree()));
}
async function settle(check: () => void) {
  await vi.waitFor(
    async () => {
      await act(async () => {});
      check();
    },
    { timeout: 3000 },
  );
}
async function input(selector: string, value: string) {
  const element = host.querySelector<HTMLInputElement | HTMLSelectElement>(
    selector,
  )!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(
      element instanceof HTMLSelectElement
        ? HTMLSelectElement.prototype
        : HTMLInputElement.prototype,
      "value",
    )!.set!.call(element, value);
    element.dispatchEvent(
      new Event(element instanceof HTMLSelectElement ? "change" : "input", {
        bubbles: true,
      }),
    );
  });
}
async function ready() {
  await settle(() =>
    expect(
      host.querySelector('[data-testid="network-rules-table"] tbody'),
    ).not.toBeNull(),
  );
}
it("uses complete 5,205 rule summary, continues to tail pages, and searches beyond the former cap", async () => {
  source = Array.from({ length: 5205 }, (_, index) =>
    ruleRow(index + 1, `team/app-${index + 1}`, {
      comment: index === 5204 ? "tail qualification marker" : "",
      action: index % 2 ? "deny" : "allow",
    }),
  );
  await mount("/clusters/cluster/network-rules?page=53&context=dashboard");
  await ready();
  expect(host.querySelectorAll("tbody tr")).toHaveLength(5);
  expect(host.textContent).toContain("5,205 matching rules");
  expect(host.textContent).toContain("team/app-5205");
  expect(networkRules.inventory).toHaveBeenLastCalledWith(
    "cluster",
    expect.objectContaining({
      offset: 5200,
      limit: 100,
      sort: "evaluation",
      order: "asc",
    }),
  );
  await input(
    'input[aria-label="Search network rules"]',
    "tail qualification marker",
  );
  await ready();
  await settle(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1));
  expect(host.textContent).toContain("team/app-5205");
  expect(history.location.search).toContain("context=dashboard");
  expect(history.location.search).not.toContain("page=");
});
it("starts in full server evaluation order and never treats first filtered row as highest precedence", async () => {
  await mount();
  await ready();
  expect(host.querySelector("tbody tr")?.textContent).toContain("team/top");
  expect(
    host.querySelector<HTMLButtonElement>(
      'button[title="Already highest precedence"]',
    )?.disabled,
  ).toBe(true);
  await input('input[aria-label="Search network rules"]', "lower");
  await settle(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1));
  const move = host.querySelector<HTMLButtonElement>(
    'button[title="Move to top (evaluate first)"]',
  )!;
  expect(move.disabled).toBe(false);
  await act(async () => move.click());
  await settle(() =>
    expect(networkRules.moveTop).toHaveBeenCalledWith(
      "cluster",
      "team/lower",
      "team/db",
    ),
  );
});
it("applies status/sort across the server cohort and restores history with parent context", async () => {
  source[1].disable = true;
  await mount("/clusters/cluster/network-rules?context=risk");
  await ready();
  await input('select[aria-label="Status"]', "disabled");
  await ready();
  await settle(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(1));
  expect(host.textContent).toContain("team/lower");
  expect(history.location.search).toContain("status=disabled");
  await input('select[aria-label="Sort network rules"]', "matches");
  await ready();
  await settle(() =>
    expect(networkRules.inventory).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ status: "disabled", sort: "matches" }),
    ),
  );
  await act(async () => history.back());
  await ready();
  await settle(() =>
    expect(
      host.querySelector<HTMLSelectElement>(
        'select[aria-label="Sort network rules"]',
      )?.value,
    ).toBe("evaluation"),
  );
  await act(async () => history.back());
  await ready();
  await settle(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(2));
  expect(history.location.search).toContain("context=risk");
});
it("preserves exact endpoint pair and return URL on dedicated edit links", async () => {
  await mount(
    "/clusters/cluster/network-rules?status=enabled&sort=matches&order=desc&page=1&context=risk",
  );
  await ready();
  const link = new URL(
    host.querySelector<HTMLAnchorElement>('a[title="Edit"]')!.href,
  );
  expect(link.searchParams.get("from")).toBe("team/lower");
  expect(link.searchParams.get("to")).toBe("team/db");
  expect(link.searchParams.get("return_to")).toContain("context=risk");
  expect(link.pathname).toBe("/clusters/cluster/network-rules/1002/edit");
});
it("exports matching server scope with a fresh post-response guard and distinguishes page CSV", async () => {
  source = Array.from({ length: 205 }, (_, index) =>
    ruleRow(index + 1, `team/app-${index + 1}`, { action: "deny" }),
  );
  vi.mocked(networkRules.inventoryCSV).mockResolvedValue({
    total: 205,
    exported: 205,
    limit: 100000,
    truncated: false,
  });
  await mount(
    "/clusters/cluster/network-rules?page=2&action=deny&sort=matches&order=desc",
  );
  await ready();
  await act(async () =>
    [...host.querySelectorAll<HTMLButtonElement>("button")]
      .find((button) => button.textContent === "Export matching CSV" || button.getAttribute("aria-label") === "Export matching CSV")!
      .click(),
  );
  await settle(() =>
    expect(host.textContent).toContain(
      "Exported all 205 matching records across pages",
    ),
  );
  expect(networkRules.inventoryCSV).toHaveBeenCalledWith(
    "cluster",
    expect.objectContaining({
      action: "deny",
      sort: "matches",
      order: "desc",
      offset: 100,
    }),
    expect.any(Function),
  );
  const current = vi.mocked(networkRules.inventoryCSV).mock.calls[0][2]!;
  expect(current()).toBe(true);
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["network-rules-inventory"],
      refetchType: "none",
    });
  });
  expect(current()).toBe(false);
  const pageButton = [
    ...host.querySelectorAll<HTMLButtonElement>("button"),
  ].find((button) => button.textContent === "Export page CSV" || button.getAttribute("aria-label") === "Export page CSV");
  await act(async () => pageButton?.click());
  expect(downloadCsv).not.toHaveBeenCalled();
});
it.each(["scope", "summary", "null-row", "pair", "role", "duplicate"])(
  "withholds malformed %s inventory and actions",
  async (kind) => {
    vi.mocked(networkRules.inventory).mockImplementation(
      async (cluster, request) => {
        const data = ruleInventory(cluster, source, request);
        if (kind === "scope") data.cluster_id = "foreign";
        if (kind === "summary") data.summary.allow = 5;
        if (kind === "null-row")
          data.rules[0] = null as unknown as (typeof data.rules)[number];
        if (kind === "pair") data.rules[0].row_id = '["wrong","pair"]';
        if (kind === "role")
          delete (data.rules[0] as Partial<(typeof data.rules)[number]>)
            .from_platform_role;
        if (kind === "duplicate") data.rules[1] = data.rules[0];
        return data;
      },
    );
    await mount();
    await settle(() =>
      expect(host.textContent).toContain("Could not load network rules"),
    );
    expect(host.querySelector("table")).toBeNull();
    expect(host.querySelectorAll('a[title="Edit"]')).toHaveLength(0);
  },
);
it("does not render stale cached rows or successful zero counts after a failed refresh", async () => {
  await mount();
  await ready();
  vi.mocked(networkRules.inventory).mockRejectedValue(
    new Error("private details"),
  );
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["network-rules-inventory"] });
  });
  await settle(() =>
    expect(host.textContent).toContain("Could not load network rules"),
  );
  expect(host.querySelector("table")).toBeNull();
  expect(host.textContent).not.toContain("No matching network rules");
  expect(host.textContent).not.toContain("private details");
});
it("does not query unresolved clusters or expose another operator cached table", async () => {
  scope.error = new Error("unavailable");
  await mount();
  expect(networkRules.inventory).not.toHaveBeenCalled();
  scope.error = null;
  await act(async () => root.render(tree()));
  await ready();
  owner.user_id = "other";
  vi.mocked(networkRules.inventory).mockImplementation(
    () => new Promise<NetworkRuleInventoryResponse>(() => {}),
  );
  await act(async () => root.render(tree()));
  expect(host.querySelector("table")).toBeNull();
  expect(
    client.getQueriesData({
      queryKey: ["network-rules-inventory", "org:other"],
    }),
  ).toHaveLength(1);
});
it.each(["page=21474838", "sort=private", "action=maybe", "q=a&q=b"])(
  "fails closed for invalid route %s",
  async (query) => {
    await mount(`/clusters/cluster/network-rules?${query}`);
    expect(networkRules.inventory).not.toHaveBeenCalled();
    expect(host.textContent).toContain("filters or page are invalid");
  },
);

it("distinguishes endpoint pairs even when their legacy display hash IDs collide", async () => {
  source = [ruleRow(123, "team/first"), ruleRow(123, "team/second")];
  await mount();
  await ready();
  expect(host.querySelectorAll("tbody tr")).toHaveLength(2);
  const links = [
    ...host.querySelectorAll<HTMLAnchorElement>('a[title="Edit"]'),
  ].map((link) => new URL(link.href));
  expect(links.map((link) => link.searchParams.get("from"))).toEqual([
    "team/first",
    "team/second",
  ]);
  expect(links.every((link) => link.pathname.endsWith("/123/edit"))).toBe(true);
});
it("blocks stale row actions before rerender and holds duplicate writes on an uncertain receipt", async () => {
  const upsert = vi
    .spyOn(networkRules, "upsert")
    .mockResolvedValue({ ok: true, id: 999, cfg_type: "user_created" });
  await mount();
  await ready();
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["network-rules-inventory"],
      refetchType: "none",
    });
    host
      .querySelector<HTMLButtonElement>('button[title="Set to deny"]')!
      .click();
  });
  expect(upsert).not.toHaveBeenCalled();
  await act(async () => {
    await client.refetchQueries({ queryKey: ["network-rules-inventory"] });
  });
  await ready();
  await act(async () =>
    host
      .querySelector<HTMLButtonElement>('button[title="Set to deny"]')!
      .click(),
  );
  await settle(() =>
    expect(host.textContent).toContain("Reload before another write"),
  );
  expect(
    host.querySelector<HTMLButtonElement>('button[title="Set to deny"]')
      ?.disabled,
  ).toBe(true);
});
