import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { compliance, type BenchmarkExecutionRequest } from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import {
  benchCluster,
  benchOtherCluster,
  benchDetail,
  benchID,
  benchPage,
  benchRequest,
} from "@/test/benchmark-fixtures";
import { BenchmarksWorkspace } from "./BenchmarksWorkspace";
import { BenchmarkExecutionFormPage } from "./BenchmarkExecutionFormPage";

const scope = vi.hoisted(() => ({
  id: "",
  resolved: "",
  loading: false,
  error: null as Error | null,
}));
vi.mock("@/hooks/useCluster", () => ({
  useCluster: () => ({
    clusterId: scope.id,
    cluster: scope.resolved ? { id: scope.resolved } : null,
    isLoading: scope.loading,
    error: scope.error,
  }),
}));
vi.mock("@/api/client", () => ({
  compliance: {
    benchRequests: vi.fn(),
    benchRequest: vi.fn(),
    createBenchRequest: vi.fn(),
    retryBenchRequest: vi.fn(),
  },
}));
let root: Root;
let host: HTMLDivElement;
let client: QueryClient;
let history: RouterHistory;
let identity = { org_id: "org", user_id: "user" };
let mode: "list" | "create" | "retry" = "list";

beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  vi.unstubAllGlobals();
  vi.clearAllMocks();
  localStorage.clear();
  sessionStorage.clear();
  identity = { org_id: "org", user_id: "user" };
  Object.assign(scope, {
    id: benchCluster,
    resolved: benchCluster,
    loading: false,
    error: null,
  });
  vi.mocked(compliance.benchRequests).mockImplementation(async (params) =>
    benchPage([benchRequest()], params.offset),
  );
  vi.mocked(compliance.benchRequest).mockResolvedValue(benchDetail());
  vi.mocked(compliance.createBenchRequest).mockImplementation(
    async (clusterID, body) => ({
      request: {
        ...benchRequest(),
        cluster_id: clusterID,
        requested_cluster_id: clusterID,
        benchmark: body.benchmark,
        request_key: body.request_key,
      },
    }),
  );
  vi.mocked(compliance.retryBenchRequest).mockResolvedValue({
    request: { ...benchRequest(), revision: "2", attempt_count: 1 },
  });
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});
afterEach(() => {
  act(() => root.unmount());
  client.clear();
  host.remove();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
function Page() {
  return mode === "list" ? (
    <BenchmarksWorkspace active />
  ) : (
    <BenchmarkExecutionFormPage action={mode} />
  );
}
async function render(nextMode: typeof mode = "list", suffix = "") {
  mode = nextMode;
  const path =
    nextMode === "list"
      ? `/clusters/${benchCluster}/compliance?tab=benchmarks${suffix}`
      : nextMode === "create"
        ? `/clusters/${benchCluster}/compliance/benchmarks/new${suffix}`
        : `/clusters/${benchCluster}/compliance/benchmarks/${benchID()}/retry${suffix}`;
  history = createMemoryHistory({ initialEntries: [path] });
  await rerender();
}
async function rerender() {
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={{ ...identity }}>
          <TestRouter
            history={history}
            path={
              mode === "retry"
                ? "/clusters/$id/compliance/benchmarks/$requestId/retry"
                : "$"
            }
          >
            <Page />
          </TestRouter>
        </TablePreferencesProvider>
      </QueryClientProvider>,
    ),
  );
}
async function settle(check: () => void) {
  await vi.waitFor(async () => {
    await act(async () => {});
    check();
  });
}
function button(label: string) {
  return [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (node) => node.textContent?.trim() === label || node.getAttribute("aria-label") === label || node.getAttribute("data-export-label") === label,
  )!;
}
async function click(label: string) {
  await act(async () => button(label).click());
}
async function input(value: string) {
  await act(async () => {
    const node = host.querySelector<HTMLInputElement>("#bench-selector")!;
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(node, value);
    node.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => {
    resolve = yes;
    reject = no;
  });
  return { promise, resolve, reject };
}

it("loads complete server pages and restores URL page/selection on Back", async () => {
  const rows = Array.from({ length: 205 }, (_, i) => benchRequest(i + 1));
  vi.mocked(compliance.benchRequests).mockImplementation(async (params) =>
    benchPage(rows, params.offset),
  );
  await render(
    "list",
    `&bench_page=2&bench_request=${benchID()}&context=keep#attempts`,
  );
  await settle(() =>
    expect(host.textContent).toContain("205 durable requests"),
  );
  expect(compliance.benchRequests).toHaveBeenLastCalledWith({
    cluster_id: benchCluster,
    limit: 100,
    offset: 100,
  });
  expect(
    host.querySelector('[data-testid="benchmarks-table"]')!.textContent,
  ).toContain("benchmark-101");
  await settle(() => expect(host.textContent).toContain("Execution attempts"));
  await click("Next");
  await settle(() =>
    expect(
      host.querySelector('[data-testid="benchmarks-table"]')!.textContent,
    ).toContain("benchmark-201"),
  );
  expect(history.location.search).not.toContain("bench_request");
  expect(history.location.search).toContain("context=keep");
  expect(history.location.hash).toBe("#attempts");
  await act(async () => history.back());
  await settle(() => expect(host.textContent).toContain("benchmark-101"));
  expect(history.location.search).toContain("bench_request");
});
it("describes received reports with failed controls without claiming compliance success", async () => {
  vi.mocked(compliance.benchRequest).mockResolvedValue(
    benchDetail(benchRequest(1, "succeeded")),
  );
  await render("list", `&bench_request=${benchID()}`);
  await settle(() =>
    expect(host.textContent).toContain("5 evidence rows ingested"),
  );
  expect(host.textContent).toContain("1 fail");
  expect(host.textContent).toContain("5 evidence rows ingested");
  expect(button("Review retry")).toBeUndefined();
  expect(
    host.querySelector('[data-testid="benchmarks-table"]')!.textContent,
  ).not.toContain(benchID());
});
it("withholds stale rows and counts after failed refresh, recovers with Retry", async () => {
  await render();
  await settle(() => expect(host.textContent).toContain("1 durable requests"));
  const pending = deferred<ReturnType<typeof benchPage>>();
  vi.mocked(compliance.benchRequests).mockReturnValue(pending.promise);
  let refresh!: Promise<void>;
  await act(async () => {
    refresh = client.invalidateQueries({
      queryKey: ["compliance-bench-requests"],
    });
  });
  await settle(() =>
    expect(host.textContent).toContain("Refreshing executions"),
  );
  expect(button("Inspect").disabled).toBe(true);
  await act(async () => {
    pending.reject(new Error("private SQL details"));
    await refresh;
  });
  await settle(() =>
    expect(host.textContent).toContain("could not be loaded or refreshed"),
  );
  expect(host.querySelector('[data-testid="benchmarks-table"]')).toBeNull();
  expect(host.textContent).not.toContain("1 durable requests");
  expect(host.textContent).not.toContain("private SQL");
  vi.mocked(compliance.benchRequests).mockResolvedValue(benchPage());
  await click("Retry executions");
  await settle(() => expect(host.textContent).toContain("1 durable requests"));
});
it.each([
  "duplicate page",
  "invalid selection",
  "invalid page",
  "foreign row",
  "null row",
])("rejects %s instead of silently broadening", async (condition) => {
  if (condition === "foreign row")
    vi.mocked(compliance.benchRequests).mockResolvedValue({
      ...benchPage(),
      requests: [{ ...benchRequest(), cluster_id: benchOtherCluster }],
    });
  if (condition === "null row")
    vi.mocked(compliance.benchRequests).mockResolvedValue({
      ...benchPage(),
      requests: [null as unknown as BenchmarkExecutionRequest],
    });
  await render(
    "list",
    condition === "duplicate page"
      ? "&bench_page=1&bench_page=2"
      : condition === "invalid page"
        ? "&bench_page=foo"
        : condition === "invalid selection"
          ? "&bench_request=bad"
          : "",
  );
  await settle(() =>
    expect(host.textContent).toContain(
      condition.includes("page")
        ? "Choose a valid execution page"
        : condition === "invalid selection"
          ? "Choose one valid benchmark execution"
          : "could not be loaded or refreshed",
    ),
  );
  if (condition.includes("page"))
    expect(compliance.benchRequests).not.toHaveBeenCalled();
  if (condition === "invalid selection")
    expect(compliance.benchRequest).not.toHaveBeenCalled();
});
it.each(["wrong cluster", "error with stale cluster", "missing identity"])(
  "never reads or authors under %s",
  async (condition) => {
    if (condition === "wrong cluster") scope.resolved = benchOtherCluster;
    if (condition === "error with stale cluster")
      scope.error = new Error("offline");
    if (condition === "missing identity") identity.user_id = "";
    await render();
    expect(compliance.benchRequests).not.toHaveBeenCalled();
    expect(button("Queue kube-bench").disabled).toBe(true);
  },
);
it("retains a create draft across transient cluster errors and blocks invalidated scope before render", async () => {
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await input("cis-1.9");
  scope.error = new Error("offline");
  await rerender();
  expect(host.querySelector<HTMLInputElement>("#bench-selector")!.value).toBe(
    "cis-1.9",
  );
  expect(button("Save").disabled).toBe(true);
  scope.error = null;
  await rerender();
  expect(button("Save").disabled).toBe(false);
  await act(async () => {
    client.setQueryData(["clusters"], { clusters: [{ id: benchCluster }] });
    await client.invalidateQueries({ queryKey: ["clusters"] });
    button("Save").click();
  });
  expect(compliance.createBenchRequest).not.toHaveBeenCalled();
});
it("reuses the exact request key after unknown receipt and keeps selectors frozen", async () => {
  vi.mocked(compliance.createBenchRequest).mockRejectedValueOnce(
    new Error("connection lost"),
  );
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await input("  cis-1.9  ");
  await click("Save");
  await settle(() => expect(host.textContent).toContain("same request"));
  const first = vi.mocked(compliance.createBenchRequest).mock.calls[0];
  expect(first[1].benchmark).toBe("cis-1.9");
  expect(
    host.querySelector<HTMLInputElement>("#bench-selector")!.disabled,
  ).toBe(true);
  await click("Save");
  await settle(() =>
    expect(history.location.search).toContain("bench_request="),
  );
  expect(compliance.createBenchRequest).toHaveBeenLastCalledWith(...first);
});
it("retains unknown request identity across form remount and preserves Cancel context", async () => {
  vi.mocked(compliance.createBenchRequest).mockRejectedValue(
    new Error("unknown"),
  );
  const back = `/clusters/${benchCluster}/compliance?tab=benchmarks&bench_page=2&context=a&context=b#attempts`;
  await render("create", `?return_to=${encodeURIComponent(back)}`);
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(compliance.createBenchRequest).toHaveBeenCalledTimes(1),
  );
  const firstKey = vi.mocked(compliance.createBenchRequest).mock.calls[0][1]
    .request_key;
  await act(async () => root.unmount());
  root = createRoot(host);
  await render("create", `?return_to=${encodeURIComponent(back)}`);
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(compliance.createBenchRequest).toHaveBeenCalledTimes(2),
  );
  expect(
    vi.mocked(compliance.createBenchRequest).mock.calls[1][1].request_key,
  ).toBe(firstKey);
  await settle(() => expect(button("Cancel").disabled).toBe(false));
  await click("Cancel");
  expect(history.location.search).toContain("bench_page=2");
  expect(history.location.hash).toBe("#attempts");
});
it("does not send a request if pending key storage fails, or selectors are invalid", async () => {
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await input("bad/name");
  expect(button("Save").disabled).toBe(true);
  await input("");
  vi.stubGlobal("sessionStorage", {
    getItem: () => null,
    setItem: () => {
      throw new Error("denied");
    },
  });
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("No execution was requested"),
  );
  expect(compliance.createBenchRequest).not.toHaveBeenCalled();
});
it("does not navigate or confirm a late create after owner changes, including ABA", async () => {
  const pending = deferred<{ request: BenchmarkExecutionRequest }>();
  vi.mocked(compliance.createBenchRequest).mockReturnValue(pending.promise);
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  const submitted = vi.mocked(compliance.createBenchRequest).mock.calls[0][1];
  identity.user_id = "other";
  await rerender();
  identity.user_id = "user";
  await rerender();
  await act(async () =>
    pending.resolve({
      request: {
        ...benchRequest(),
        benchmark: "",
        request_key: submitted.request_key,
      },
    }),
  );
  expect(history.location.pathname).toContain("/benchmarks/new");
  expect(history.location.search).not.toContain("bench_request=");
});
it("requires a current reviewed revision after retry conflict and sends no automatic retries", async () => {
  vi.mocked(compliance.retryBenchRequest).mockRejectedValueOnce({
    response: { status: 409 },
  });
  await render("retry");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("Refresh and review its current state"),
  );
  expect(compliance.retryBenchRequest).toHaveBeenCalledExactlyOnceWith(
    benchID(),
    benchCluster,
    "1",
  );
  expect(button("Save").disabled).toBe(true);
  vi.mocked(compliance.benchRequest).mockResolvedValue(
    benchDetail({ ...benchRequest(1, "failed"), revision: "2" }),
  );
  await click("Refresh and review execution");
  await settle(() => expect(button("Save").disabled).toBe(false));
  vi.mocked(compliance.retryBenchRequest).mockResolvedValue({
    request: { ...benchRequest(), attempt_count: 1, revision: "3" },
  });
  await click("Save");
  await settle(() =>
    expect(history.location.search).toContain("bench_request="),
  );
  expect(compliance.retryBenchRequest).toHaveBeenLastCalledWith(
    benchID(),
    benchCluster,
    "2",
  );
});
it("blocks a second retry after an uncertain response until current execution is reviewed", async () => {
  vi.mocked(compliance.retryBenchRequest).mockRejectedValue(
    new Error("connection lost"),
  );
  await render("retry");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("it may already be queued"),
  );
  expect(button("Save").disabled).toBe(true);
  vi.mocked(compliance.benchRequest).mockResolvedValue(benchDetail());
  vi.mocked(compliance.benchRequest).mockResolvedValue(
    benchDetail({ ...benchRequest(), attempt_count: 0 }),
  );
  await click("Refresh and review execution");
  await settle(() =>
    expect(host.textContent).toContain("not eligible for retry"),
  );
  expect(compliance.retryBenchRequest).toHaveBeenCalledTimes(1);
  expect(button("Save").disabled).toBe(true);
});
it("never exposes an initially cached retry editor before the settled exact refresh", async () => {
  client.setQueryData(
    ["compliance-bench-request", "org:user", benchCluster, benchID()],
    benchDetail(),
  );
  const pending = deferred<ReturnType<typeof benchDetail>>();
  vi.mocked(compliance.benchRequest).mockReturnValue(pending.promise);
  await render("retry");
  expect(button("Save")).toBeUndefined();
  await act(async () => pending.reject(new Error("unavailable")));
  await settle(() =>
    expect(host.textContent).toContain("could not be resolved"),
  );
  expect(button("Save")).toBeUndefined();
});

it.each(["foreign receipt", "wrong request key", "changed selector"])(
  "withholds confirmation for %s",
  async (condition) => {
    vi.mocked(compliance.createBenchRequest).mockImplementation(
      async (_cluster, body) => ({
        request: {
          ...benchRequest(),
          benchmark:
            condition === "changed selector" ? "unexpected" : body.benchmark,
          cluster_id:
            condition === "foreign receipt" ? benchOtherCluster : benchCluster,
          request_key:
            condition === "wrong request key" ? benchID(999) : body.request_key,
        },
      }),
    );
    await render("create");
    await settle(() => expect(button("Save").disabled).toBe(false));
    await click("Save");
    await settle(() =>
      expect(host.textContent).toContain("could not be confirmed"),
    );
    expect(history.location.pathname).toContain("/benchmarks/new");
  },
);
it("blocks writes on a changed retry revision even before React updates, preserving the reviewed state", async () => {
  await render("retry");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await act(async () => {
    client.setQueryData(
      ["compliance-bench-request", "org:user", benchCluster, benchID()],
      benchDetail({ ...benchRequest(1, "failed"), revision: "2" }),
    );
    button("Save").click();
  });
  expect(compliance.retryBenchRequest).not.toHaveBeenCalled();
  await settle(() => expect(button("Save").disabled).toBe(true));
  expect(host.textContent).toContain("revision 1");
});
it("reports manage permission failures while preserving access to Cancel and the same request", async () => {
  vi.mocked(compliance.createBenchRequest).mockRejectedValue({
    response: { status: 403 },
  });
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("permissions do not allow"),
  );
  expect(button("Cancel").disabled).toBe(false);
});
it("requires history review on idempotency conflict rather than generating another key", async () => {
  vi.mocked(compliance.createBenchRequest).mockRejectedValue({
    response: { status: 409 },
  });
  await render("create");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("Review benchmark history"),
  );
  expect(button("Save").disabled).toBe(true);
  expect(compliance.createBenchRequest).toHaveBeenCalledTimes(1);
});

it("refreshes cached inventories on reopening even within the shared freshness window", async () => {
  client.setDefaultOptions({ queries: { retry: false, staleTime: 30000 } });
  client.setQueryData(
    ["compliance-bench-requests", "org:user", benchCluster, 0],
    benchPage(),
  );
  const pending = deferred<ReturnType<typeof benchPage>>();
  vi.mocked(compliance.benchRequests).mockReturnValue(pending.promise);
  await render();
  expect(compliance.benchRequests).toHaveBeenCalledOnce();
  expect(host.querySelector('[data-testid="benchmarks-table"]')).toBeNull();
  await act(async () => pending.resolve(benchPage()));
  await settle(() => expect(host.textContent).toContain("1 durable requests"));
});
it("checks freshness at page CSV dispatch before React updates", async () => {
  await render();
  await settle(() =>
    expect(
      host.querySelector('[data-testid="benchmarks-table"]'),
    ).not.toBeNull(),
  );
  const download = vi
    .spyOn(URL, "createObjectURL")
    .mockReturnValue("blob:should-not-download");
  const pending = deferred<ReturnType<typeof benchPage>>();
  vi.mocked(compliance.benchRequests).mockReturnValue(pending.promise);
  let refresh!: Promise<void>;
  await act(async () => {
    refresh = client.invalidateQueries({
      queryKey: ["compliance-bench-requests"],
    });
    button("Export page CSV").click();
  });
  expect(download).not.toHaveBeenCalled();
  await act(async () => {
    pending.resolve(benchPage());
    await refresh;
  });
});
it("does not repeat a non-idempotent retry even if a host config enables mutation retries", async () => {
  client.setDefaultOptions({
    queries: { retry: false },
    mutations: { retry: 3, retryDelay: 0 },
  });
  vi.mocked(compliance.retryBenchRequest).mockRejectedValue(
    new Error("unknown receipt"),
  );
  await render("retry");
  await settle(() => expect(button("Save").disabled).toBe(false));
  await click("Save");
  await settle(() =>
    expect(host.textContent).toContain("it may already be queued"),
  );
  expect(compliance.retryBenchRequest).toHaveBeenCalledTimes(1);
});
