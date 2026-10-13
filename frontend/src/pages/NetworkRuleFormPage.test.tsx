import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { networkRules, type NetworkRuleInventoryRow } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { ruleInventory } from "./network-rule-test-fixture";
import { NetworkRuleFormPage } from "./NetworkRuleFormPage";

const route = vi.hoisted(() => ({
  ruleId: "123",
  search: "from=team%2Fapp&to=team%2Fdb&action=allow&comment=stale",
  navigate: vi.fn(),
}));
vi.mock("@/api/client", () => ({
  networkRules: { inventory: vi.fn(), upsert: vi.fn() },
}));
const scope = vi.hoisted(() => ({
  clusterId: "cluster",
  cluster: { id: "cluster" },
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/components/GroupPicker", () => ({
  GroupPicker: ({
    value,
    inputId,
    disabled,
    onChange,
  }: {
    value: string;
    inputId: string;
    disabled: boolean;
    onChange: (value: string) => void;
  }) => (
    <input
      id={inputId}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    />
  ),
}));
vi.mock("@/lib/route-search", () => ({
  useRouteSearchParams: () => [new URLSearchParams(route.search), vi.fn()],
}));
vi.mock("@tanstack/react-router", () => ({
  useParams: () => ({ ruleId: route.ruleId }),
  useNavigate: () => route.navigate,
  Link: ({ children }: { children: ReactNode }) => <span>{children}</span>,
}));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
const rule: NetworkRuleInventoryRow = {
  id: 123,
  row_id: JSON.stringify(["team/app", "team/db"]),
  from_platform_role: "",
  to_platform_role: "",
  from: "team/app",
  to: "team/db",
  ports: "443",
  applications: ["HTTPS"],
  action: "deny",
  disable: true,
  priority: -10,
  comment: "Saved comment",
  learned: false,
  cfg_type: "user_created",
  match_counter: 0,
  last_match_timestamp: 0,
};
const request = {
  from: "team/app",
  to: "team/db",
  limit: 1,
  offset: 0,
  sort: "evaluation",
  order: "asc" as const,
};
const response = ruleInventory("cluster", [rule], request);
const owner = { org_id: "org", user_id: "user" };
beforeEach(() => {
  Object.assign(scope, {
    clusterId: "cluster",
    cluster: { id: "cluster" },
    isLoading: false,
    error: null,
  });
  owner.user_id = "user";
});
afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
  route.ruleId = "123";
  route.search = "from=team%2Fapp&to=team%2Fdb&action=allow&comment=stale";
});
async function renderPage() {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={{ ...owner }}>
          <NetworkRuleFormPage />
        </TablePreferencesProvider>
      </QueryClientProvider>,
    ),
  );
}
async function settled(check: () => void) {
  await vi.waitFor(
    async () => {
      await act(async () => {});
      check();
    },
    { timeout: 3000 },
  );
}
async function submit() {
  await act(async () => {
    host
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}
it("loads saved values and preserves disabled state and negative precedence when editing", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  vi.mocked(networkRules.upsert).mockResolvedValue({
    ok: true,
    id: 123,
    cfg_type: "user_created",
  });
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-from")?.disabled,
  ).toBe(true);
  expect(host.querySelector("details")?.open).toBe(false);
  await submit();
  await settled(() =>
    expect(route.navigate).toHaveBeenCalledWith({
      href: "/clusters/cluster/network-rules",
    }),
  );
  expect(networkRules.upsert).toHaveBeenCalledWith("cluster", {
    from: "team/app",
    to: "team/db",
    ports: "443",
    applications: ["HTTPS"],
    action: "deny",
    disable: true,
    priority: -10,
    comment: "Saved comment",
  });
});
it.each(["failed", "missing", "wrong-cluster", "id-collision"])(
  "blocks editing a %s rule",
  async (scenario) => {
    if (scenario === "failed")
      vi.mocked(networkRules.inventory).mockRejectedValue(
        new Error("private details"),
      );
    else
      vi.mocked(networkRules.inventory).mockResolvedValue({
        ...response,
        cluster_id: scenario === "wrong-cluster" ? "other" : "cluster",
        total: scenario === "missing" ? 0 : 1,
        summary:
          scenario === "missing"
            ? { total: 0, allow: 0, deny: 0, learned: 0, disabled: 0 }
            : response.summary,
        rules:
          scenario === "missing"
            ? []
            : [
                {
                  ...rule,
                  from:
                    scenario === "id-collision" ? "another/source" : rule.from,
                },
              ],
      });
    await renderPage();
    await settled(() =>
      expect(host.textContent).toContain(
        "could not be loaded for the selected cluster",
      ),
    );
    expect(host.querySelector("form")).toBeNull();
    expect(host.textContent).not.toContain("private details");
  },
);
it("preserves the draft after a failed save without losing configured status and priority", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  vi.mocked(networkRules.upsert).mockRejectedValue(
    new Error("private details"),
  );
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-comment")?.value,
  ).toBe("Saved comment");
  await submit();
  await settled(() =>
    expect(host.textContent).toContain("Your draft is preserved"),
  );
  expect(host.textContent).not.toContain("private details");
  expect(networkRules.upsert).toHaveBeenCalledWith(
    "cluster",
    expect.objectContaining({ disable: true, priority: -10 }),
  );
  expect(route.navigate).not.toHaveBeenCalled();
});
it("cancels a new draft without writing a rule", async () => {
  route.ruleId = "";
  route.search = "action=deny";
  await renderPage();
  await act(async () => {
    [...host.querySelectorAll("button")]
      .find((button) => button.textContent === "Cancel")!
      .click();
  });
  expect(networkRules.inventory).not.toHaveBeenCalled();
  expect(networkRules.upsert).not.toHaveBeenCalled();
  expect(route.navigate).toHaveBeenCalledWith({
    href: "/clusters/cluster/network-rules",
  });
});
it("keeps learned ports and applications read-only", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue({
    ...response,
    summary: { ...response.summary, learned: 1 },
    rules: [{ ...rule, learned: true, cfg_type: "learned_override" }],
  });
  await renderPage();
  await settled(() =>
    expect(
      host.querySelector<HTMLInputElement>("#network-rule-ports")?.disabled,
    ).toBe(true),
  );
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-applications")
      ?.disabled,
  ).toBe(true);
});

it("hydrates exact endpoint edits beyond the legacy cap and keeps the filtered return context", async () => {
  route.ruleId = "123";
  const returnURL =
    "/clusters/cluster/network-rules?page=53&status=disabled&context=risk#review";
  route.search = new URLSearchParams({
    from: rule.from,
    to: rule.to,
    return_to: returnURL,
  }).toString();
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  expect(networkRules.inventory).toHaveBeenCalledWith("cluster", request);
  expect(host.querySelector<HTMLAnchorElement>("a")?.getAttribute("href")).toBe(
    returnURL,
  );
  await act(async () =>
    [...host.querySelectorAll("button")]
      .find((button) => button.textContent === "Cancel")!
      .click(),
  );
  expect(route.navigate).toHaveBeenCalledWith({ href: returnURL });
});
it("rejects hash-only edit links rather than choosing a colliding endpoint pair", async () => {
  route.search = "";
  await renderPage();
  expect(networkRules.inventory).not.toHaveBeenCalled();
  expect(host.textContent).toContain("exact source and destination");
  expect(host.querySelector("form")).toBeNull();
});
it("retains a loaded draft when the exact pair disappears or a refresh fails", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  const input = host.querySelector<HTMLInputElement>("#network-rule-comment")!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(input, "Retained draft");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  vi.mocked(networkRules.inventory).mockRejectedValue(new Error("unavailable"));
  await act(async () => {
    await client.refetchQueries({ queryKey: ["network-rule-editor"] });
  });
  await settled(() => expect(host.textContent).toContain("saving is paused"));
  expect(input.value).toBe("Retained draft");
  await submit();
  expect(networkRules.upsert).not.toHaveBeenCalled();
});
it("requires explicit review of changed saved fields while preserving candidate draft", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  const changed = {
    ...rule,
    action: "allow" as const,
    comment: "New saved reason",
    disable: false,
    priority: 1000,
  };
  const latest = ruleInventory("cluster", [changed], request);
  await act(async () => {
    client.setQueriesData({ queryKey: ["network-rule-editor"] }, latest);
  });
  await settled(() =>
    expect(host.textContent).toContain("Review it before applying"),
  );
  await submit();
  expect(networkRules.upsert).not.toHaveBeenCalled();
  vi.mocked(networkRules.inventory).mockResolvedValue(latest);
  await act(async () =>
    [...host.querySelectorAll("button")]
      .find((button) => button.textContent === "Review saved rule")!
      .click(),
  );
  await settled(() =>
    expect(
      host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled,
    ).toBe(false),
  );
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-comment")?.value,
  ).toBe("Saved comment");
  vi.mocked(networkRules.upsert).mockResolvedValue({
    ok: true,
    id: 123,
    cfg_type: "user_created",
  });
  await submit();
  await settled(() =>
    expect(networkRules.upsert).toHaveBeenCalledWith(
      "cluster",
      expect.objectContaining({ action: "deny", disable: true, priority: -10 }),
    ),
  );
});
it("blocks stale cache dispatch before rerender and rejects pending response after refresh-to-ready", async () => {
  vi.mocked(networkRules.inventory).mockResolvedValue(response);
  await renderPage();
  await settled(() => expect(host.querySelector("form")).not.toBeNull());
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["network-rule-editor"],
      refetchType: "none",
    });
    host
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
  expect(networkRules.upsert).not.toHaveBeenCalled();
  await act(async () => {
    client.setQueriesData({ queryKey: ["network-rule-editor"] }, response);
  });
  let resolve!: (value: { ok: boolean; id: number; cfg_type: string }) => void;
  vi.mocked(networkRules.upsert).mockImplementation(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  await submit();
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["network-rule-editor"],
      refetchType: "none",
    });
    client.setQueriesData(
      { queryKey: ["network-rule-editor"] },
      { ...response },
    );
  });
  await act(async () =>
    resolve({ ok: true, id: 123, cfg_type: "user_created" }),
  );
  await settled(() =>
    expect(host.textContent).toContain("Reload before another write"),
  );
  expect(route.navigate).not.toHaveBeenCalled();
  expect(
    host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled,
  ).toBe(true);
});
it.each(["loading", "foreign", "error", "actor"])(
  "does not read or author from unavailable %s context",
  async (kind) => {
    if (kind === "loading") scope.isLoading = true;
    if (kind === "foreign") scope.cluster.id = "other";
    if (kind === "error") scope.error = new Error("scope");
    if (kind === "actor") owner.user_id = "";
    await renderPage();
    expect(networkRules.inventory).not.toHaveBeenCalled();
    expect(host.querySelector("form")).toBeNull();
    expect(host.textContent).toContain(
      "Resolve the selected cluster and operator",
    );
  },
);

it("preserves a new rule draft through cluster refresh failure and recovery", async () => {
  route.ruleId = "";
  route.search = "";
  await renderPage();
  const change = async (id: string, value: string) => {
    const input = host.querySelector<HTMLInputElement>(id)!;
    await act(async () => {
      Object.getOwnPropertyDescriptor(
        HTMLInputElement.prototype,
        "value",
      )!.set!.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
  };
  await change("#network-rule-from", "team/new");
  await change("#network-rule-to", "team/db");
  await change("#network-rule-comment", "New retained reason");
  const tree = () => (
    <QueryClientProvider client={client}>
      <TablePreferencesProvider identity={{ ...owner }}>
        <NetworkRuleFormPage />
      </TablePreferencesProvider>
    </QueryClientProvider>
  );
  scope.error = new Error("scope refresh failed");
  await act(async () => root.render(tree()));
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-comment")?.value,
  ).toBe("New retained reason");
  expect(
    host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled,
  ).toBe(true);
  await submit();
  expect(networkRules.upsert).not.toHaveBeenCalled();
  scope.error = null;
  await act(async () => root.render(tree()));
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-from")?.value,
  ).toBe("team/new");
  expect(
    host.querySelector<HTMLInputElement>("#network-rule-comment")?.value,
  ).toBe("New retained reason");
  expect(
    host.querySelector<HTMLButtonElement>('button[type="submit"]')?.disabled,
  ).toBe(false);
  expect(networkRules.inventory).not.toHaveBeenCalled();
});
