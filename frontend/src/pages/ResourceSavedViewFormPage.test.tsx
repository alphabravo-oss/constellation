import { act, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TestRouter } from "@/test/router";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { operatorStorageKey } from "@/lib/operator-preferences";
import { resourceViewKey } from "@/lib/resource-saved-views";
import {
  AssetSavedViewFormPage,
  DeploymentSavedViewFormPage,
  RuntimeSavedViewFormPage,
  ScannerSavedViewFormPage,
} from "./ResourceSavedViewFormPage";
const scope = vi.hoisted(() => ({
  clusterId: "cluster",
  cluster: { id: "cluster" } as { id: string } | undefined,
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
let root: Root,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory,
  page: ReactNode;
let identity = { org_id: "org", user_id: "user" };
beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  Object.assign(scope, {
    clusterId: "cluster",
    cluster: { id: "cluster" },
    isLoading: false,
    error: null,
  });
  identity = { org_id: "org", user_id: "user" };
});
afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function rerender() {
  identity = { ...identity };
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={identity}>
          <TestRouter history={history}>{page}</TestRouter>
        </TablePreferencesProvider>
      </QueryClientProvider>,
    ),
  );
}
async function render(content: ReactNode, url: string) {
  page = content;
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  history = createMemoryHistory({ initialEntries: [url] });
  await rerender();
}
const button = (name: string) =>
  [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === name,
  )!;
async function name(value: string) {
  const input = host.querySelector<HTMLInputElement>("#resource-view-name")!;
  await act(async () => {
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
async function submit() {
  await act(async () =>
    host
      .querySelector("form")!
      .dispatchEvent(new Event("submit", { bubbles: true, cancelable: true })),
  );
}
it.each([
  ["assets", <AssetSavedViewFormPage />, "kind=host"],
  [
    "deployments",
    <DeploymentSavedViewFormPage />,
    "risk_fact=net_exposure&hide_platform=false",
  ],
  [
    "runtime",
    <RuntimeSavedViewFormPage />,
    "tab=live&after=2026-10-13T01%3A00%3A00.123456Z",
  ],
  ["scanner", <ScannerSavedViewFormPage />, "tab=jobs&status=failed"],
] as const)(
  "synchronously saves %s filters and returns exact page/selection/context/hash",
  async (kind, component, filters) => {
    const base =
        kind === "scanner" ? "/settings/scanner" : `/clusters/cluster/${kind}`,
      query = `${filters}&page=3&selected=exact&context=one&context=two`;
    await render(component, `${base}/views/new?${query}#evidence`);
    await name("Reviewed");
    await submit();
    const raw = localStorage.getItem(
      operatorStorageKey(resourceViewKey(kind), identity)!,
    )!;
    const views = JSON.parse(raw);
    expect(views).toHaveLength(1);
    expect(views[0].name).toBe("Reviewed");
    expect(views[0].inventory).toBe(kind);
    expect(views[0].filters).not.toHaveProperty("page");
    await vi.waitFor(() => expect(history.location.pathname).toBe(base));
    expect(new URLSearchParams(history.location.search).get("page")).toBe("3");
    expect(new URLSearchParams(history.location.search).get("selected")).toBe(
      "exact",
    );
    expect(
      new URLSearchParams(history.location.search).getAll("context"),
    ).toEqual(["one", "two"]);
    expect(history.location.hash).toBe("#evidence");
  },
);
it("Cancel preserves context without writing the draft", async () => {
  await render(
    <AssetSavedViewFormPage />,
    "/clusters/cluster/assets/views/new?q=needle&page=3&selected=exact#evidence",
  );
  await name("Draft");
  await act(async () => button("Cancel").click());
  await vi.waitFor(() =>
    expect(history.location.pathname).toBe("/clusters/cluster/assets"),
  );
  expect(localStorage.length).toBe(0);
  expect(history.location.search).toContain("selected=exact");
  expect(history.location.hash).toBe("#evidence");
});
it.each(["missing", "foreign", "loading", "error"])(
  "blocks initial %s cluster scope",
  async (condition) => {
    if (condition === "missing") scope.cluster = undefined;
    if (condition === "foreign") scope.cluster = { id: "foreign" };
    if (condition === "loading") scope.isLoading = true;
    if (condition === "error") scope.error = new Error("offline");
    await render(
      <AssetSavedViewFormPage />,
      "/clusters/cluster/assets/views/new",
    );
    expect(host.querySelector("form")).toBeNull();
  },
);
it("preserves a confirmed draft through scope loss and rechecks invalidated cache at submission", async () => {
  await render(
    <AssetSavedViewFormPage />,
    "/clusters/cluster/assets/views/new?q=needle",
  );
  await name("Preserved");
  scope.error = new Error("offline");
  await rerender();
  expect(
    host.querySelector<HTMLInputElement>("#resource-view-name")!.value,
  ).toBe("Preserved");
  expect(button("Save").disabled).toBe(true);
  scope.error = null;
  await rerender();
  client.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] });
  client
    .getQueryCache()
    .find({ queryKey: ["clusters"], exact: true })!
    .setState({ isInvalidated: true });
  await submit();
  expect(localStorage.length).toBe(0);
  expect(
    host.querySelector<HTMLInputElement>("#resource-view-name")!.value,
  ).toBe("Preserved");
});
it("never reuses another cluster's confirmation for a missing scope", async () => {
  await render(
    <AssetSavedViewFormPage />,
    "/clusters/cluster/assets/views/new",
  );
  await name("Old");
  scope.clusterId = "other";
  scope.cluster = undefined;
  await rerender();
  expect(host.querySelector("form")).toBeNull();
});
it("preserves draft and honest feedback on storage failure", async () => {
  await render(
    <DeploymentSavedViewFormPage />,
    "/clusters/cluster/deployments/views/new?hide_platform=false",
  );
  await name("Draft retained");
  const original = localStorage;
  vi.stubGlobal("localStorage", {
    getItem: original.getItem.bind(original),
    setItem: () => {
      throw new Error("quota");
    },
  });
  await submit();
  expect(host.textContent).toContain("could not be stored");
  expect(
    host.querySelector<HTMLInputElement>("#resource-view-name")!.value,
  ).toBe("Draft retained");
  expect(history.location.pathname).toContain("/views/new");
  expect(button("Save").disabled).toBe(false);
});
it("requires identity while global Scanner authoring needs no navigation cluster", async () => {
  scope.cluster = undefined;
  await render(
    <ScannerSavedViewFormPage />,
    "/settings/scanner/views/new?tab=jobs",
  );
  expect(host.querySelector("form")).not.toBeNull();
  identity = { org_id: "", user_id: "" };
  await rerender();
  expect(host.querySelector("form")).toBeNull();
});
it("rejects malformed URL snapshots before opening an editor", async () => {
  await render(
    <RuntimeSavedViewFormPage />,
    "/clusters/cluster/runtime/views/new?tab=live&after=garbage",
  );
  expect(host.querySelector("form")).toBeNull();
  expect(host.textContent).toContain("filters are invalid");
});
