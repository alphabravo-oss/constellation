import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, it, expect, vi } from "vitest";
import {
  api,
  cve,
  type CVEAffectedInventoryParams,
  type CVEAffectedInventoryView,
  type CVEAffectedInventoryRows,
  type CVEAffectedInventoryResponse,
} from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
import { CVEDetailPage } from "./CVEDetailPage";
const scope = vi.hoisted(() => ({
  clusterId: "cluster-a",
  cluster: { id: "cluster-a", name: "Main" } as
    | { id: string; name: string }
    | undefined,
  isLoading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({ useCluster: () => scope }));
vi.mock("@/api/client", () => ({
  api: { get: vi.fn() },
  cve: { affectedInventory: vi.fn(), affectedInventoryCSV: vi.fn() },
}));
vi.mock("@/lib/csv", async (original) => ({
  ...(await original<typeof import("@/lib/csv")>()),
  downloadCsv: vi.fn(),
}));
let root: Root,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory | undefined;
const at = "2026-10-12T12:00:00Z",
  key = "CVE-2026-9991";
const image = (n: number): CVEAffectedInventoryRows["images"] => ({
  row_id: `image-${n}`,
  image_scan_result_id: `image-${n}`,
  image_ref: `team/app-${n}:v1`,
  image_ref_normalized: `team/app-${n}:v1`,
  image_repository: `team/app-${n}`,
  image_tag: "v1",
  image_digest: "sha256:" + "a".repeat(64),
  scanner_profile: "default",
  finding_count: 2,
  max_risk_score: 95,
  severity_counts: { critical: 2 },
  packages: [],
  last_seen_at: at,
  last_scanned_at: at,
});
function result(
  view: CVEAffectedInventoryView,
  p: CVEAffectedInventoryParams = {},
  total = view === "images"
    ? 610
    : view === "workloads"
      ? 1206
      : view === "packages"
        ? 611
        : 1,
): CVEAffectedInventoryResponse<
  CVEAffectedInventoryRows[CVEAffectedInventoryView]
> {
  const offset = p.offset ?? 0;
  const items = Array.from(
    { length: Math.max(0, Math.min(100, total - offset)) },
    (_, index) => {
      const n = offset + index;
      const scan = image(n);
      if (view === "images") return scan;
      if (view === "workloads")
        return {
          row_id: `association-${n}`,
          cluster_id: p.cluster_id ?? "cluster-a",
          cluster_name: "Main",
          deployment_id: `deployment-${n}`,
          workload_id: `prod/app-${n}`,
          namespace: p.namespace ?? "prod",
          name: `app-${n}`,
          kind: "Deployment",
          image_ref: scan.image_ref,
          image_ref_normalized: scan.image_ref_normalized,
          image_digest: scan.image_digest,
          image_evidence: [
            {
              image_ref: scan.image_ref,
              image_ref_normalized: scan.image_ref_normalized,
              image_repository: scan.image_repository,
              image_tag: "v1",
              image_digest: scan.image_digest,
            },
          ],
          finding_count: 2,
          max_risk_score: 95,
          critical_count: 2,
          high_count: 0,
          last_seen_at: at,
        };
      if (view === "clusters")
        return {
          row_id: p.cluster_id ?? `cluster-${n}`,
          cluster_id: p.cluster_id ?? `cluster-${n}`,
          name: `Cluster ${n}`,
          workload_count: 1206,
          finding_count: 2400,
          max_risk_score: 95,
        };
      return {
        row_id: `finding-${n}`,
        finding_id: `finding-${n}`,
        image_scan_result_id: scan.image_scan_result_id,
        image_ref: scan.image_ref,
        image_repository: scan.image_repository,
        image_tag: "v1",
        image_digest: scan.image_digest,
        package_name: `package-${n}`,
        package_version: "1.0",
        fixed_version: "1.1",
        severity: (p.severity ??
          "critical") as CVEAffectedInventoryRows["packages"]["severity"],
        risk_score: 95,
        last_seen_at: at,
      };
    },
  );
  return {
    cve_id: key,
    cluster_id: p.cluster_id ?? null,
    view,
    items,
    total,
    summary: {
      total,
      finding_count: view === "packages" ? total : total * 2,
      max_risk_score: total ? 95 : 0,
      image_count: view === "images" ? total : 611,
      package_count: total,
      workload_count: view === "clusters" ? 1206 : total,
      deployment_count: total,
      cluster_count: 1,
    },
    limit: 100,
    offset,
    has_more: offset + items.length < total,
    sort: p.sort ?? (view === "clusters" ? "workloads" : "risk"),
    order: p.order ?? "desc",
  };
}
beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  Object.assign(scope, {
    clusterId: "cluster-a",
    cluster: { id: "cluster-a", name: "Main" },
    isLoading: false,
    error: null,
  });
  vi.mocked(api.get).mockResolvedValue({
    data: {
      cve_id: key,
      title: "Fixture intelligence",
      description: "Evidence",
      kev_listed: false,
      aliases: [],
    },
  } as never);
  vi.mocked(cve.affectedInventory).mockImplementation(
    async (_id, view, p) => result(view, p) as never,
  );
  vi.mocked(cve.affectedInventoryCSV).mockResolvedValue({
    total: 1206,
    exported: 1206,
    limit: 100000,
    truncated: false,
  });
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => {
  act(() => root.unmount());
  history = undefined;
  client.clear();
  host.remove();
  vi.resetAllMocks();
});
async function render(search = "", global = false, owner = "org:user") {
  history ??= createMemoryHistory({
    initialEntries: [
      global
        ? `/cve/${key}${search}`
        : `/clusters/cluster-a/cve/${key}${search}`,
    ],
  });
  const [org, user] = owner.split(":");
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={{ org_id: org, user_id: user }}>
          <TestRouter
            path={global ? "/cve/$id" : "/clusters/$id/cve/$cveId"}
            history={history}
          >
            <CVEDetailPage />
          </TestRouter>
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
    { timeout: 4000 },
  );
}
const button = (text: string) =>
  [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (item) => item.textContent?.trim() === text || item.getAttribute("aria-label") === text,
  )!;
const stats = () =>
  [
    ...host.querySelectorAll(
      '[data-testid="cve-detail-stats"] [data-testid="verdict-numbers"] dd',
    ),
  ].map((item) => item.textContent);
async function tab(text: string) {
  await act(async () => {
    [...host.querySelectorAll<HTMLButtonElement>('[role="tab"]')]
      .find((item) => item.textContent === text || item.getAttribute("aria-label") === text)!
      .focus();
  });
  await settled(() =>
    expect(history!.location.search).toContain(
      `tab=${text === "Package evidence" ? "packages" : text.replace("Affected ", "")}`,
    ),
  );
}
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
it("loads source pages beyond500 with literal filters, matching summaries and exact CSV scope", async () => {
  await render(
    "?images_q=tail%25_&images_namespace=prod&images_severity=critical&images_sort=image&images_order=asc&images_page=7&context=keep#proof",
  );
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(10),
  );
  expect(stats()).toEqual(["610", "1220", "95", "610"]);
  expect(cve.affectedInventory).toHaveBeenLastCalledWith(key, "images", {
    cluster_id: "cluster-a",
    q: "tail%_",
    namespace: "prod",
    severity: "critical",
    sort: "image",
    order: "asc",
    limit: 100,
    offset: 600,
  });
  await act(async () => button("Export matching CSV").click());
  expect(cve.affectedInventoryCSV).toHaveBeenCalledWith(key, "images", {
    cluster_id: "cluster-a",
    q: "tail%_",
    namespace: "prod",
    severity: "critical",
    sort: "image",
    order: "asc",
  }, expect.any(Function));
  await act(async () => button("Export this page CSV").click());
  expect(vi.mocked(downloadCsv).mock.calls[0][2]).toHaveLength(10);
  expect(history!.location.hash).toBe("#proof");
});
it("retains independent workload/package/cluster cohorts and history", async () => {
  await render(
    "?tab=workloads&workloads_page=13&images_page=7&context=keep#proof",
  );
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(6),
  );
  expect(stats()[0]).toBe("1206");
  expect(cve.affectedInventory).toHaveBeenLastCalledWith(
    key,
    "workloads",
    expect.objectContaining({ offset: 1200 }),
  );
  await tab("Package evidence");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(100),
  );
  expect(stats()[0]).toBe("611");
  expect(host.textContent).toContain("package-99");
  await tab("Affected clusters");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(1),
  );
  expect(cve.affectedInventory).toHaveBeenLastCalledWith(
    key,
    "clusters",
    expect.anything(),
  );
  await act(async () => history!.back());
  await settled(() =>
    expect(
      host.querySelector('[data-testid="cve-package-evidence"]'),
    ).not.toBeNull(),
  );
  await act(async () => history!.back());
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(6),
  );
  expect(history!.location.search).toContain("workloads_page=13");
  expect(history!.location.search).toContain("images_page=7");
  expect(history!.location.hash).toBe("#proof");
});
it("resets only current view pages when filters/sort change and restores controlled sort", async () => {
  await render("?images_page=7&workloads_page=13&context=keep");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(10),
  );
  await input("Search affected evidence", "new%_");
  expect(button("Export matching CSV").disabled).toBe(true);
  await settled(() =>
    expect(cve.affectedInventory).toHaveBeenLastCalledWith(
      key,
      "images",
      expect.objectContaining({ q: "new%_", offset: 0 }),
    ),
  );
  expect(history!.location.search).toContain("workloads_page=13");
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  await act(async () => button("Finding instances").click());
  await settled(() =>
    expect(cve.affectedInventory).toHaveBeenLastCalledWith(
      key,
      "images",
      expect.objectContaining({ sort: "findings", order: "desc" }),
    ),
  );
  await settled(() =>
    expect(
      host.querySelector('th[data-column-id="findings"]')?.getAttribute("aria-sort"),
    ).toBe("descending"),
  );
  await act(async () => button("Finding instances").click());
  await settled(() =>
    expect(
      host
        .querySelector('th[data-column-id="findings"]')
        ?.getAttribute("aria-sort"),
    ).toBe("ascending"),
  );
  await act(async () => history!.back());
  await settled(() =>
    expect(
      host
        .querySelector('th[data-column-id="findings"]')
        ?.getAttribute("aria-sort"),
    ).toBe("descending"),
  );
});
it("does not collapse different association rows sharing a deployment", async () => {
  vi.mocked(cve.affectedInventory).mockImplementation(async (_id, view, p) => {
    const data = result(view, p, 2);
    data.items = data.items.map((item, index) => ({
      ...item,
      deployment_id: "same-deployment",
      workload_id: `prod/identity-${index}`,
    }));
    return data as never;
  });
  await render("?tab=workloads");
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(2),
  );
  expect(host.querySelectorAll('a[href*="same-deployment"]')).toHaveLength(2);
});
it("withholds rows, metrics and exports during pending refresh and exposes its failure", async () => {
  await render();
  await settled(() => expect(stats()[0]).toBe("610"));
  let reject!: (error: Error) => void;
  vi.mocked(cve.affectedInventory).mockImplementation(
    () =>
      new Promise((_, fail) => {
        reject = fail;
      }),
  );
  let fetch!: Promise<void>;
  await act(async () => {
    fetch = client.refetchQueries({ queryKey: ["cve-affected"] });
  });
  await settled(() => expect(host.querySelector("table")).toBeNull());
  expect(stats()).toEqual(["—", "—", "—", "—"]);
  expect(button("Export matching CSV").disabled).toBe(true);
  await act(async () => {
    reject(new Error("offline"));
    await fetch;
  });
  await settled(() => expect(host.textContent).toContain("offline"));
  expect(host.querySelector("table")).toBeNull();
});
it.each([
  "wrong-cve",
  "wrong-cluster",
  "wrong-view",
  "wrong-page",
  "duplicate",
  "null-row",
])("rejects malformed source %s", async (error) => {
  vi.mocked(cve.affectedInventory).mockImplementation(async (_id, view, p) => {
    const data = result(view, p, 2);
    if (error === "wrong-cve") data.cve_id = "CVE-other";
    if (error === "wrong-cluster") data.cluster_id = "other";
    if (error === "wrong-view") data.view = "packages";
    if (error === "wrong-page") data.offset = 100;
    if (error === "duplicate") data.items[1] = data.items[0];
    if (error === "null-row") data.items[0] = null as never;
    return data as never;
  });
  await render();
  await settled(() =>
    expect(host.textContent).toContain("Affected evidence is unavailable"),
  );
  expect(stats()).toEqual(["—", "—", "—", "—"]);
  expect(host.querySelector("table")).toBeNull();
  expect(button("Export matching CSV").disabled).toBe(true);
});
it.each([
  "images_page=-1",
  "images_sort=bad",
  "images_order=bad",
  "images_severity=bad",
  "tab=bad",
])("blocks invalid URL %s before a broader evidence read", async (query) => {
  await render(`?${query}`);
  await settled(() =>
    expect(host.textContent).toContain("Affected evidence is unavailable"),
  );
  expect(cve.affectedInventory).not.toHaveBeenCalled();
  expect(button("Export matching CSV").disabled).toBe(true);
});
it("recovers out-of-range pages without an invented range", async () => {
  await render("?images_page=999");
  await settled(() => expect(host.textContent).toContain("Showing 0–0 of 610"));
  expect(button("Next")).toBeUndefined();
  await act(async () => button("First page").click());
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(100),
  );
});
it("keeps digests disclosed and global scan navigation unbound", async () => {
  scope.cluster = undefined;
  scope.error = new Error("No selected cluster");
  await render("", true);
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  const cell = host.querySelector('td[data-column-id="image"]')!;
  expect(cell.querySelector("details")?.open).toBe(false);
  expect(cell.querySelector("[title]")?.getAttribute("title")).toBe(
    "team/app-0:v1",
  );
  expect(
    [...cell.querySelectorAll("[title]")].some((item) =>
      item.getAttribute("title")?.includes("sha256:"),
    ),
  ).toBe(false);
  expect(cell.querySelector("a")).toBeNull();
  expect(cell.querySelector("span")?.textContent).toBe("team/app-0:v1");
  expect(cve.affectedInventory).toHaveBeenLastCalledWith(
    key,
    "images",
    expect.objectContaining({ cluster_id: undefined }),
  );
});
it("uses fresh organization/user cache keys after context switches", async () => {
  await render();
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  await render("", false, "other:person");
  expect(
    client
      .getQueryCache()
      .getAll()
      .filter((query) => query.queryKey[0] === "cve-affected")
      .map((query) => query.queryKey[1]),
  ).toContain("other:person");
  expect(
    client
      .getQueryCache()
      .getAll()
      .filter((query) => query.queryKey[0] === "cve-affected")
      .map((query) => query.queryKey[1]),
  ).toContain("org:user");
});
it("reports matching export errors without inventing a successful export", async () => {
  vi.mocked(cve.affectedInventoryCSV).mockRejectedValue(new Error("offline"));
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

it("renders and exports exact image tuples instead of synthesized MAX fields", async () => {
  vi.mocked(cve.affectedInventory).mockImplementation(
    async (_id, view, request) => {
      const data = result(view, request, 1);
      if (view === "workloads") {
        const row = data.items[0] as CVEAffectedInventoryRows["workloads"];
        row.image_repository = "zzz/other";
        row.image_tag = "v1";
        row.image_evidence = [
          {
            image_ref: "aaa/app:v1",
            image_ref_normalized: "aaa/app:v1",
            image_repository: "aaa/app",
            image_tag: "v1",
            image_digest: "sha256:first",
          },
          {
            image_ref: "zzz/other:a",
            image_ref_normalized: "zzz/other:a",
            image_repository: "zzz/other",
            image_tag: "a",
            image_digest: "sha256:second",
          },
        ];
      }
      return data as never;
    },
  );
  await render("?tab=workloads");
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  expect(host.textContent).toContain("aaa/app:v1");
  expect(host.textContent).toContain("zzz/other:a");
  expect(host.textContent).not.toContain("zzz/other:v1");
  await act(async () => button("Export this page CSV").click());
  const row = vi.mocked(downloadCsv).mock.calls[0][2][0];
  const evidence = JSON.parse(String(row[3]));
  expect(
    evidence.map((tuple: { image_ref: string }) => tuple.image_ref),
  ).toEqual(["aaa/app:v1", "zzz/other:a"]);
});

it.each(["images", "workloads", "packages"] as const)(
  "discloses the hidden Last seen server sort in %s and exports the revealed timestamp",
  async (view) => {
    await render(`?tab=${view}&${view}_sort=last_seen&${view}_order=asc`);
    await settled(() =>
      expect(host.textContent).toContain(
        "Sorted by Last seen (ascending) · hidden column",
      ),
    );
    expect(host.querySelector('th[data-column-id="last_seen"]')).toBeNull();
    expect(cve.affectedInventory).toHaveBeenLastCalledWith(
      key,
      view,
      expect.objectContaining({ sort: "last_seen", order: "asc" }),
    );
    await act(async () => button("Export this page CSV").click());
    expect(vi.mocked(downloadCsv).mock.calls[0][1]).not.toContain("Last seen");
    await act(async () => button("Show sort column").click());
    await settled(() =>
      expect(
        host
          .querySelector('th[data-column-id="last_seen"]')
          ?.getAttribute("aria-sort"),
      ).toBe("ascending"),
    );
    expect(
      host.querySelector('td[data-column-id="last_seen"]')?.textContent,
    ).toBe(new Date(at).toLocaleString());
    expect(
      new URLSearchParams(history!.location.search).get(`${view}_sort`),
    ).toBe("last_seen");
    await act(async () => button("Export this page CSV").click());
    const [, headers, rows] = vi.mocked(downloadCsv).mock.calls[1];
    expect(rows[0][headers.indexOf("Last seen")]).toBe(at);
  },
);

it("uses a truthful header fallback when optional intelligence title is absent", async () => {
  vi.mocked(api.get).mockResolvedValue({
    data: { cve_id: key, kev_listed: false, aliases: [] },
  } as never);
  await render();
  await settled(() => expect(host.querySelector("table")).not.toBeNull());
  expect(host.textContent).toContain("Affected evidence for cluster Main.");
  expect(host.textContent).not.toContain("undefined");
});

it.each(["images", "workloads", "packages"] as const)(
  "keeps long %s image names compact with a complete readable tooltip and separate digest",
  async (view) => {
    const name =
      "registry.example.com/team/deep/path/very-long-application-name:v1";
    const digest = "sha256:" + "b".repeat(64);
    vi.mocked(cve.affectedInventory).mockImplementation(
      async (_id, currentView, request) => {
        const data = result(currentView, request, 1);
        if (currentView === "workloads") {
          const row = data.items[0] as CVEAffectedInventoryRows["workloads"];
          row.image_evidence = [
            {
              image_ref: `${name}@${digest}`,
              image_ref_normalized: `${name}@${digest}`,
              image_repository: "",
              image_tag: "",
              image_digest: digest,
            },
          ];
        } else if (currentView === "images" || currentView === "packages") {
          const row = data.items[0] as CVEAffectedInventoryRows["images"];
          row.image_ref = `${name}@${digest}`;
          row.image_repository = "";
          row.image_digest = digest;
        }
        return data as never;
      },
    );
    await render(`?tab=${view}`);
    await settled(() => expect(host.querySelector("table")).not.toBeNull());
    const cell = host.querySelector('td[data-column-id="image"]')!;
    const label = cell.querySelector(".line-clamp-2")!;
    expect(label.textContent).toBe(name);
    expect(label.getAttribute("title")).toBe(name);
    expect(cell.querySelector("details")?.open).toBe(false);
    expect(
      [...cell.querySelectorAll("[title]")].some((item) =>
        item.getAttribute("title")?.includes(digest),
      ),
    ).toBe(false);
  },
);
