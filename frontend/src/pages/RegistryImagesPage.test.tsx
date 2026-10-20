import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import {
  registries,
  type RegistryDTO,
  type RegistryImageRow,
  type RegistryImageParams,
} from "@/api/client";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
import { RegistryImagesPage } from "./RegistryImagesPage";
const scope = vi.hoisted(() => ({
  clusterId: "cluster",
  cluster: { id: "cluster" } as { id: string } | undefined,
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/api/client", () => ({
  registries: { get: vi.fn(), images: vi.fn(), imagesCSV: vi.fn() },
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/lib/csv", () => ({ downloadCsv: vi.fn() }));
let root: Root | undefined,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory;
const row = (
  id = "image",
  extra: Partial<RegistryImageRow> = {},
): RegistryImageRow => ({
  id,
  repository: `repo-${id}`,
  tags: ["one", "two", "three", "four", "fifth"],
  digests: {},
  scanned: true,
  finding_count: 0,
  critical: 0,
  high: 0,
  first_seen_at: "",
  last_seen_at: "",
  ...extra,
});
const response = (
  p: RegistryImageParams = {},
  images = [row()],
  total = 1,
) => ({
  registry_id: "registry",
  images,
  total,
  limit: 100,
  offset: p.offset ?? 0,
  has_more: (p.offset ?? 0) + images.length < total,
  sort: p.sort ?? "findings",
  order: p.order ?? "desc",
  summary: {
    total,
    scanned: p.scan_status === "unscanned" ? 0 : total,
    unscanned: p.scan_status === "unscanned" ? total : 0,
    critical: images.reduce((sum, row) => sum + row.critical, 0),
    high: images.reduce((sum, row) => sum + row.high, 0),
  },
});
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
  vi.mocked(registries.get).mockResolvedValue({
    id: "registry",
    name: "Registry",
  } as RegistryDTO);
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(p),
  );
  vi.mocked(registries.imagesCSV).mockResolvedValue({
    total: 1,
    exported: 1,
    limit: 100000,
    truncated: false,
  });
});
afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  client?.clear();
  host?.remove();
  vi.resetAllMocks();
});
async function render(search = "", prepare?: (client: QueryClient) => void) {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  prepare?.(client);
  history = createMemoryHistory({
    initialEntries: [`/clusters/cluster/registries/registry/images${search}`],
  });
  await act(async () =>
    root!.render(
      <QueryClientProvider client={client}>
        <TestRouter
          path="/clusters/$id/registries/$regId/images"
          history={history}
        >
          <RegistryImagesPage />
        </TestRouter>
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
const button = (text: string) =>
  [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === text,
  )!;
async function select(label: string, value: string) {
  await act(async () => {
    const e = host.querySelector<HTMLSelectElement>(`[aria-label="${label}"]`)!;
    e.value = value;
    e.dispatchEvent(new Event("change", { bubbles: true }));
  });
}
async function input(value: string) {
  await act(async () => {
    const e = host.querySelector<HTMLInputElement>(
      '[aria-label="Search registry repositories"]',
    )!;
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(e, value);
    e.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
it.each(["registry", "images", "wrong-registry", "wrong-page", "wrong-scope"])(
  "does not turn failed %s evidence into empty inventory",
  async (failed) => {
    if (failed === "registry")
      vi.mocked(registries.get).mockRejectedValue(new Error("not found"));
    if (failed === "images")
      vi.mocked(registries.images).mockRejectedValue(new Error("unavailable"));
    if (failed === "wrong-registry")
      vi.mocked(registries.get).mockResolvedValue({
        id: "other",
        name: "Foreign",
      } as RegistryDTO);
    if (failed === "wrong-page")
      vi.mocked(registries.images).mockResolvedValue({
        ...response(),
        offset: 100,
      });
    if (failed === "wrong-scope")
      vi.mocked(registries.images).mockResolvedValue({
        ...response(),
        registry_id: "other",
      });
    await render();
    await settled(() => expect(host.textContent).toContain("unavailable"));
    expect(host.textContent).not.toContain("No repositories match");
    expect(host.querySelector("table")).toBeNull();
    expect(
      host.querySelector(".app-stat-grid")?.textContent?.match(/—/g),
    ).toHaveLength(4);
    if (failed.includes("registry"))
      expect(registries.images).not.toHaveBeenCalled();
  },
);
it("retains all tags, page CSV and real pagination history", async () => {
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(p, [row(p?.offset ? "later" : "first")], 101),
  );
  await render("?q=repo&context=kept#proof");
  await settled(() => expect(host.textContent).toContain("repo-first"));
  expect(host.textContent).toContain("fifth");
  await act(async () => button("Next").click());
  await settled(() => expect(host.textContent).toContain("repo-later"));
  expect(history.location.search).toContain("page=2");
  expect(history.location.hash).toBe("#proof");
  expect(registries.images).toHaveBeenLastCalledWith(
    "registry",
    expect.objectContaining({
      q: "repo",
      limit: 100,
      offset: 100,
      sort: "findings",
      order: "desc",
    }),
  );
  await act(async () => button("Export this page CSV").click());
  expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[2][0]).toContain(
    "one; two; three; four; fifth",
  );
  expect(vi.mocked(downloadCsv).mock.calls.at(-1)?.[0]).toBe(
    "registry-images-page-2",
  );
  await act(async () => history.back());
  await settled(() => expect(host.textContent).toContain("repo-first"));
  await act(async () => history.forward());
  await settled(() => expect(host.textContent).toContain("repo-later"));
});
it("uses matching summaries and exports exact filters beyond500", async () => {
  vi.mocked(registries.images).mockImplementation(async (_id, p) => ({
    ...response(p, [row("tail", { critical: 1 })], 610),
    summary: {
      total: 610,
      scanned: 610,
      unscanned: 0,
      critical: 900,
      high: 200,
    },
  }));
  await render(
    "?q=tail%25_&scan_status=scanned&severity=critical&sort=repository&order=asc&page=7#proof",
  );
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  expect(host.querySelector(".app-stat-grid")?.textContent).toContain("900");
  expect(host.querySelector(".app-stat-grid")?.textContent).toContain("200");
  expect(registries.images).toHaveBeenLastCalledWith("registry", {
    q: "tail%_",
    scan_status: "scanned",
    severity: "critical",
    sort: "repository",
    order: "asc",
    limit: 100,
    offset: 600,
  });
  await act(async () => button("Export matching CSV").click());
  expect(registries.imagesCSV).toHaveBeenCalledWith("registry", {
    q: "tail%_",
    scan_status: "scanned",
    severity: "critical",
    sort: "repository",
    order: "asc",
  }, expect.any(Function));
});
it("resets filter pages and restores filter history preserving context/hash", async () => {
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(
      p,
      [row("match", { scanned: p?.scan_status !== "unscanned" })],
      610,
    ),
  );
  await render("?page=7&context=keep#proof");
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  await select("Registry scan status", "unscanned");
  await settled(() =>
    expect(registries.images).toHaveBeenLastCalledWith(
      "registry",
      expect.objectContaining({ scan_status: "unscanned", offset: 0 }),
    ),
  );
  expect(history.location.search).not.toContain("page=");
  expect(history.location.hash).toBe("#proof");
  expect(history.location.search).toContain("context=keep");
  await act(async () => history.back());
  await settled(() =>
    expect(registries.images).toHaveBeenLastCalledWith(
      "registry",
      expect.objectContaining({ scan_status: undefined, offset: 600 }),
    ),
  );
  await act(async () => history.forward());
  await settled(() =>
    expect(registries.images).toHaveBeenLastCalledWith(
      "registry",
      expect.objectContaining({ scan_status: "unscanned", offset: 0 }),
    ),
  );
});
it("controls server vulnerability ordering and restores URL sort", async () => {
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(
      p,
      [
        row("source-first", { critical: 0 }),
        row("source-second", { critical: 10 }),
      ],
      2,
    ),
  );
  await render();
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(2),
  );
  await act(async () => button("Vulnerabilities").click());
  await settled(() =>
    expect(
      host
        .querySelector('th[data-column-id="vulnerabilities"]')
        ?.getAttribute("aria-sort"),
    ).toBe("descending"),
  );
  expect(registries.images).toHaveBeenLastCalledWith(
    "registry",
    expect.objectContaining({ sort: "vulnerabilities", order: "desc" }),
  );
  expect(host.querySelector("tbody tr")?.textContent).toContain(
    "repo-source-first",
  );
  await act(async () => button("Vulnerabilities").click());
  await settled(() =>
    expect(registries.images).toHaveBeenLastCalledWith(
      "registry",
      expect.objectContaining({ sort: "vulnerabilities", order: "asc" }),
    ),
  );
  await act(async () => history.back());
  await settled(() =>
    expect(
      host
        .querySelector('th[data-column-id="vulnerabilities"]')
        ?.getAttribute("aria-sort"),
    ).toBe("descending"),
  );
});
it("blocks stale export during debounce and failed refresh", async () => {
  await render();
  await settled(() =>
    expect(button("Export matching CSV").disabled).toBe(false),
  );
  await input("new%_");
  expect(button("Export matching CSV").disabled).toBe(true);
  expect(host.querySelector("table")).toBeNull();
  await settled(() =>
    expect(registries.images).toHaveBeenLastCalledWith(
      "registry",
      expect.objectContaining({ q: "new%_", offset: 0 }),
    ),
  );
  await settled(() =>
    expect(button("Export matching CSV").disabled).toBe(false),
  );
  vi.mocked(registries.images).mockRejectedValue(new Error("offline"));
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["registry-images"] });
  });
  await settled(() => expect(host.textContent).toContain("unavailable"));
  expect(host.querySelector("table")).toBeNull();
  expect(
    host.querySelector(".app-stat-grid")?.textContent?.match(/—/g),
  ).toHaveLength(4);
  expect(button("Export matching CSV").disabled).toBe(true);
});
it("hides inventory after a failed registry refresh", async () => {
  await render();
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  vi.mocked(registries.get).mockRejectedValue(new Error("removed"));
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["registry"] });
  });
  await settled(() =>
    expect(host.textContent).toContain("Image inventory is unavailable"),
  );
  expect(host.querySelector("table")).toBeNull();
  expect(button("Export matching CSV").disabled).toBe(true);
});
it("offers truthful first-page recovery for empty later pages", async () => {
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(p, [], 1),
  );
  await render("?page=2");
  await settled(() =>
    expect(host.textContent).toContain("No images on this page"),
  );
  expect(host.textContent).toContain("Showing 0–0 of 1");
  expect(button("Next")).toBeUndefined();
  await act(async () => button("First page").click());
  await settled(() => expect(history.location.search).not.toContain("page="));
});
it.each([
  "sort=bad",
  "order=bad",
  "scan_status=bad",
  "severity=bad",
  "page=-1",
])("blocks invalid directURL %s", async (query) => {
  await render(`?${query}`);
  await settled(() => expect(host.textContent).toContain("unavailable"));
  expect(registries.images).not.toHaveBeenCalled();
  expect(button("Export matching CSV").disabled).toBe(true);
});
it.each(["missing", "foreign", "error", "loading"])(
  "requires settled exact cluster context: %s",
  async (state) => {
    if (state === "missing") scope.cluster = undefined;
    if (state === "foreign") scope.cluster = { id: "other" };
    if (state === "error") scope.error = new Error("offline");
    if (state === "loading") scope.isLoading = true;
    await render();
    expect(registries.get).not.toHaveBeenCalled();
    expect(registries.images).not.toHaveBeenCalled();
    expect(host.querySelector("table")).toBeNull();
  },
);
it("hides stored digest until disclosure", async () => {
  const digest = "sha256:" + "a".repeat(64);
  vi.mocked(registries.images).mockImplementation(async (_id, p) =>
    response(p, [
      row("named", {
        repository: `team/app@${digest}`,
        digests: { latest: digest },
      }),
    ]),
  );
  await render();
  await settled(() => expect(host.querySelector("tbody")).not.toBeNull());
  const cell = host.querySelector('td[data-column-id="repository"]')!;
  expect(cell.querySelector("span")?.textContent).toBe("team/app");
  expect(cell.querySelector("details")?.open).toBe(false);
  expect(cell.querySelector("[title]")).toBeNull();
  expect(cell.querySelector("summary")?.textContent).toBe("Show digest");
});
it("reports matching CSV errors without success", async () => {
  vi.mocked(registries.imagesCSV).mockRejectedValue(new Error("offline"));
  await render();
  await settled(() =>
    expect(button("Export matching CSV").disabled).toBe(false),
  );
  await act(async () => button("Export matching CSV").click());
  await settled(() =>
    expect(host.textContent).toContain("Matching CSV could not be exported"),
  );
  expect(host.textContent).not.toContain("Exported all");
});

it("waits for initial registry refresh before exposing cached inventory", async () => {
  let confirm!: (registry: RegistryDTO) => void;
  vi.mocked(registries.get).mockImplementation(
    () =>
      new Promise((resolve) => {
        confirm = resolve;
      }),
  );
  await render("", (client) => {
    client.setQueryData(["registry", "undefined:undefined", "registry"], {
      id: "registry",
      name: "Cached registry",
    });
  });
  await settled(() => expect(registries.get).toHaveBeenCalled());
  expect(registries.images).not.toHaveBeenCalled();
  expect(host.querySelector("table")).toBeNull();
  expect(host.textContent).not.toContain("Cached registry");
  await act(async () =>
    confirm({ id: "registry", name: "Confirmed registry" } as RegistryDTO),
  );
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  expect(host.textContent).toContain("Confirmed registry");
});
