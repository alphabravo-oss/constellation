import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import {
  containers,
  type ContainerRow,
  type ContainerListParams,
} from "@/api/client";
import { TestRouter } from "@/test/router";
import { chooseExport, exportAvailable } from "@/test/export-menu";
import { ContainersPage } from "./ContainersPage";
const scope = vi.hoisted(() => ({
  clusterId: "cluster",
  cluster: { id: "cluster" } as { id: string } | undefined,
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({
  containers: { list: vi.fn(), exportCSV: vi.fn() },
}));
let root: Root,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory;
const row = (
  name = "tail",
  values: Partial<ContainerRow> = {},
): ContainerRow => ({
  row_id: `row-${name}`,
  id: name,
  node: "node",
  name,
  namespace: "prod",
  pod_name: "app-abc",
  image: "image",
  state: "running",
  privileged: true,
  run_as_root: true,
  risk_score: 30,
  critical: 1,
  high: 0,
  observed_at: "2026-10-12T00:00:00Z",
  ...values,
});
const response = (
  params: ContainerListParams = {},
  items = [row()],
  total = 4001,
) => ({
  cluster_id: "cluster",
  items,
  total,
  limit: 100,
  offset: params.offset ?? 0,
  has_more: (params.offset ?? 0) + items.length < total,
  sort: params.sort ?? "risk",
  order: params.order ?? "desc",
  summary: {
    total,
    running: total,
    privileged: total,
    run_as_root: total,
    platform_count: 1,
  },
});
beforeEach(() => {
  localStorage.clear();
  Object.assign(scope, {
    clusterId: "cluster",
    cluster: { id: "cluster" },
    isLoading: false,
    error: null,
  });
  vi.mocked(containers.list).mockImplementation(async (_id, params) =>
    response(params, [
      row("tail", {
        namespace: params?.namespace ?? "prod",
        node: params?.node ?? "node",
        platform_role: params?.platform_role === "core" ? "core" : undefined,
      }),
    ]),
  );
  vi.mocked(containers.exportCSV).mockResolvedValue({
    total: 4001,
    exported: 4001,
    limit: 100000,
    truncated: false,
  });
});
afterEach(() => {
  act(() => root?.unmount());
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
  vi.restoreAllMocks();
});
async function render(url: string) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  history = createMemoryHistory({ initialEntries: [url] });
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TestRouter history={history}>
          <ContainersPage />
        </TestRouter>
      </QueryClientProvider>,
    ),
  );
}
async function settled(check: () => void | Promise<void>) {
  await vi.waitFor(async () => {
    await act(async () => {});
    await check();
  });
}
const button = (label: string) =>
  [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === label,
  )!;
async function input(label: string, value: string) {
  await act(async () => {
    const field = host.querySelector<HTMLInputElement>(
      `[aria-label="${label}"]`,
    )!;
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
it("loads and exports the exact source cohort beyond the former3000 cap", async () => {
  await render(
    "/clusters/cluster/containers?q=tail&namespace=prod&node=node&hide_platform=false&platform_role=none&sort=name&order=asc&page=41#evidence",
  );
  await settled(() =>
    expect(host.textContent).toContain("4,001 matching running containers"),
  );
  expect(containers.list).toHaveBeenLastCalledWith("cluster", {
    q: "tail",
    namespace: "prod",
    node: "node",
    hide_platform: false,
    platform_role: "none",
    sort: "name",
    order: "asc",
    limit: 100,
    offset: 4000,
  });
  expect(
    host.querySelector('[data-testid="containers-page-scope"]')?.textContent,
  ).toContain("4001–4001 of 4001");
  expect(host.textContent).toContain(
    "evidence comes from the attributed workload",
  );
  await chooseExport("Matching rows", host);
  expect(containers.exportCSV).toHaveBeenCalledWith(
    "cluster",
    expect.objectContaining({
      q: "tail",
      namespace: "prod",
      node: "node",
      hide_platform: false,
      platform_role: "none",
      sort: "name",
      order: "asc",
    }),
    expect.any(Function),
  );
  expect(containers.exportCSV).toHaveBeenCalledWith(
    "cluster",
    expect.not.objectContaining({ offset: expect.anything() }),
    expect.any(Function),
  );
  await settled(() =>
    expect(host.textContent).toContain("Exported 4001 of 4001"),
  );
});
it("resets server pages for filters and restores scope through back/forward", async () => {
  await render(
    "/clusters/cluster/containers?hide_platform=false&page=41&context=keep#evidence",
  );
  await settled(() => expect(host.textContent).toContain("4,001 matching"));
  await input("Container namespace", "changed");
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ namespace: "changed", offset: 0 }),
    ),
  );
  expect(history.location.search).not.toContain("page=");
  expect(history.location.search).toContain("context=keep");
  expect(history.location.hash).toBe("#evidence");
  await settled(() => expect(button("Next").disabled).toBe(false));
  await act(async () => button("Next").click());
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ namespace: "changed", offset: 100 }),
    ),
  );
  await act(async () => history.back());
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ namespace: "changed", offset: 0 }),
    ),
  );
  await act(async () => history.forward());
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ namespace: "changed", offset: 100 }),
    ),
  );
  expect(history.location.hash).toBe("#evidence");
});
it("controls descending vulnerability sorting on the server without reordering returned rows", async () => {
  vi.mocked(containers.list).mockImplementation(async (_id, p) =>
    response(
      p,
      [
        row("source-first", { critical: 0 }),
        row("source-second", { critical: 10 }),
      ],
      2,
    ),
  );
  await render("/clusters/cluster/containers");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(2),
  );
  expect(containers.list).toHaveBeenLastCalledWith(
    "cluster",
    expect.objectContaining({ sort: "risk", order: "desc" }),
  );
  expect(host.querySelectorAll("tbody tr")[0].textContent).toContain(
    "source-first",
  );
  const header = [
    ...host.querySelectorAll<HTMLButtonElement>("thead button"),
  ].find((b) => b.textContent === "Vulns" || b.getAttribute("aria-label") === "Vulns")!;
  await act(async () => header.click());
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ sort: "risk", order: "asc" }),
    ),
  );
});
it("shows custom platform rows when selected and persists visibility in the URL", async () => {
  await render("/clusters/cluster/containers?hide_platform=true&page=2");
  await settled(() =>
    expect(host.textContent).toContain("matching running containers"),
  );
  const select = host.querySelector<HTMLSelectElement>(
    '[aria-label="Container platform role"]',
  )!;
  await act(async () => {
    select.value = "core";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({
        platform_role: "core",
        hide_platform: false,
        offset: 0,
      }),
    ),
  );
  expect(history.location.search).toContain("hide_platform=false");
  expect(
    host.querySelector('[data-testid="containers-table"]')?.textContent,
  ).toContain("Platform");
});
it("blocks stale export while search debounces or a refresh fails", async () => {
  await render("/clusters/cluster/containers");
  await settled(async () =>
    expect(await exportAvailable("Matching rows", host)).toBe(true),
  );
  await input("Search containers", "new");
  expect(await exportAvailable("Matching rows", host)).toBe(false);
  await settled(() =>
    expect(containers.list).toHaveBeenLastCalledWith(
      "cluster",
      expect.objectContaining({ q: "new", offset: 0 }),
    ),
  );
  vi.mocked(containers.list).mockRejectedValue(new Error("offline"));
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["containers"] });
  });
  await settled(() =>
    expect(host.textContent).toContain("Containers are unavailable"),
  );
  expect(host.querySelector("table")).toBeNull();
  expect(
    host
      .querySelector('[data-testid="containers-summary"]')
      ?.textContent?.match(/—/g),
  ).toHaveLength(4);
  expect(await exportAvailable("Matching rows", host)).toBe(false);
});
it.each(["sort=bad", "hide_platform=bad", "platform_role=bad", "page=-1"])(
  "rejects invalid URL filters %s without a broader query",
  async (query) => {
    await render(`/clusters/cluster/containers?${query}`);
    expect(containers.list).not.toHaveBeenCalled();
    expect(host.textContent).toContain("unavailable");
    expect(await exportAvailable("Matching rows", host)).toBe(false);
  },
);
it("keeps duplicate or missing source identity unavailable", async () => {
  vi.mocked(containers.list).mockResolvedValue(response({}, [row(), row()], 2));
  await render("/clusters/cluster/containers");
  await settled(() =>
    expect(host.textContent).toContain("Containers are unavailable"),
  );
  expect(host.querySelector("table")).toBeNull();
});
it("recovers an out-of-range page with honest zero range", async () => {
  vi.mocked(containers.list).mockImplementation(async (_id, p) =>
    response(p, [], 0),
  );
  await render("/clusters/cluster/containers?page=41");
  await settled(() => expect(button("First page")).toBeTruthy());
  expect(
    host.querySelector('[data-testid="containers-page-scope"]')?.textContent,
  ).toContain("0–0 of 0");
  expect(button("Next")).toBeUndefined();
  await act(async () => button("First page").click());
  await settled(() => expect(history.location.search).not.toContain("page="));
});
it("reports export failures without a success claim", async () => {
  vi.mocked(containers.exportCSV).mockRejectedValue(
    new Error("scope mismatch"),
  );
  await render("/clusters/cluster/containers");
  await settled(async () =>
    expect(await exportAvailable("Matching rows", host)).toBe(true),
  );
  await chooseExport("Matching rows", host);
  await settled(() =>
    expect(host.textContent).toContain("Container export failed"),
  );
  expect(host.textContent).not.toContain("Exported 4001");
});

it("shows image names and discloses hashes only on request", async () => {
  const digest = "sha256:" + "a".repeat(64);
  vi.mocked(containers.list).mockImplementation(async (_id, p) =>
    response(
      p,
      [
        row("named", { image: `registry.example/team/app:1@${digest}` }),
        row("unnamed", { image: digest }),
      ],
      2,
    ),
  );
  await render("/clusters/cluster/containers");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(2),
  );
  const cells = [
    ...host.querySelectorAll<HTMLTableCellElement>(
      'tbody td[data-column-id="image"]',
    ),
  ];
  expect(cells).toHaveLength(2);
  expect(cells[0].querySelector("span")?.textContent).toBe(
    "registry.example/team/app:1",
  );
  expect(cells[1].querySelector("span")?.textContent).toBe("Unnamed image");
  for (const cell of cells) {
    const disclosure = cell.querySelector("details")!;
    expect(disclosure.open).toBe(false);
    expect(cell.querySelector("[title]")).toBeNull();
    expect(disclosure.querySelector("summary")?.textContent).toBe(
      "Show digest",
    );
    await act(async () => {
      disclosure.open = true;
      disclosure.dispatchEvent(new Event("toggle"));
    });
    expect(disclosure.querySelector("code")?.textContent).toBe(digest);
  }
});

it("invalidates a pending container export through a scope error and recovery", async () => {
  let complete!: () => void;
  let guard!: () => boolean;
  vi.mocked(containers.exportCSV).mockImplementation((_cluster, _filters, shouldDownload) => new Promise(resolve => {
    guard = shouldDownload!;
    complete = () => resolve({ total: 4001, exported: 4001, limit: 100000, truncated: false });
  }));
  await render("/clusters/cluster/containers");
  await settled(async () => expect(await exportAvailable("Matching rows", host)).toBe(true));
  await chooseExport("Matching rows", host);
  expect(guard()).toBe(true);
  await act(async () => {
    await client.fetchQuery({ queryKey: ["clusters"], queryFn: async () => { throw new Error("Scope refresh failed"); } }).catch(() => {});
  });
  await act(async () => client.setQueryData(["clusters"], { clusters: [{ id: "cluster" }] }));
  expect(guard()).toBe(false);
  await act(async () => complete());
  await settled(async () => expect(await exportAvailable("Matching rows", host)).toBe(true));
  expect(host.textContent).not.toContain("Exported 4001");
});
