import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  registries,
  scanJobs,
  type RegistryDTO,
  type ScanJobInventoryResponse,
} from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
import { RegistriesPage } from "./RegistriesPage";
vi.mock("@/api/client", () => ({
  registries: {
    list: vi.fn(),
    remove: vi.fn(),
    test: vi.fn(),
    syncNow: vi.fn(),
    cancelScans: vi.fn(),
  },
  scanJobs: { list: vi.fn() },
}));
vi.mock("@/hooks/useCluster", () => ({
  useCluster: () => ({ clusterId: "cluster" }),
}));
vi.mock("@/lib/csv", async (original) => ({
  ...(await original<typeof import("@/lib/csv")>()),
  downloadCsv: vi.fn(),
}));
let root: Root, host: HTMLDivElement, client: QueryClient;
const originalConfirm = Object.getOwnPropertyDescriptor(window, "confirm");
const registry = (id = "registry", org = "org"): RegistryDTO =>
  ({
    id,
    org_id: org,
    name: `Registry ${id}`,
    kind: "generic-v2",
    endpoint: "https://registry.test",
    auth_kind: "none",
    has_secret: false,
    scan_cadence: "daily",
    image_globs: [],
    scan_policy: {
      include_repos: [],
      exclude_repos: [],
      tag_selection: "all",
      block_promotion_threshold: "high",
    },
    images_seen: 9,
    last_sync_status: "ok",
    created_at: "",
    updated_at: "",
  }) as RegistryDTO;
const queue = (registryID?: string, org = "org"): ScanJobInventoryResponse => ({
  jobs: [
    {
      id: "job",
      org_id: org,
      registry_id: registryID,
      target_id: "target",
      target_ref: "registry/api:latest",
      attempt_count: 0,
      max_attempts: 3,
      requested_at: "2026-10-12T00:00:00Z",
      target_type: registryID ? "workload" : "image",
      status: registryID ? "pending" : "completed",
    },
  ],
  total: registryID ? 508 : 601,
  limit: 1,
  offset: 0,
  has_more: true,
  sort: "requested",
  order: "desc",
  summary: registryID
    ? {
        total: 508,
        pending: 500,
        running: 3,
        paused: 2,
        failed: 3,
        completed: 0,
        canceled: 0,
      }
    : {
        total: 601,
        pending: 400,
        running: 50,
        paused: 20,
        failed: 99,
        completed: 32,
        canceled: 0,
      },
});
beforeEach(() => {
  (
    globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean }
  ).IS_REACT_ACT_ENVIRONMENT = true;
  localStorage.clear();
  vi.mocked(registries.list).mockResolvedValue([registry()]);
  vi.mocked(scanJobs.list).mockImplementation(async (p) =>
    queue(p?.registry_id),
  );
  vi.mocked(registries.cancelScans).mockResolvedValue({
    registry_id: "registry",
    canceled: 505,
    active_remaining: 0,
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
  if (originalConfirm)
    Object.defineProperty(window, "confirm", originalConfirm);
  else Reflect.deleteProperty(window, "confirm");
  vi.restoreAllMocks();
  vi.resetAllMocks();
});
async function render(org = "org", user = "user") {
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={{ org_id: org, user_id: user }}>
          <TestRouter initialEntries={["/clusters/cluster/registries"]}>
            <RegistriesPage />
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
    (b) => b.textContent?.trim() === text,
  )!;
const jobCell = () => host.querySelector('td[data-column-id="scan-jobs"]')!;
async function openActions() {
  await act(async () =>
    host
      .querySelector('[aria-label="Actions for Registry registry"]')!
      .dispatchEvent(
        new MouseEvent("pointerdown", { bubbles: true, button: 0 }),
      ),
  );
  await settled(() =>
    expect(document.querySelector('[role="menu"]')).not.toBeNull(),
  );
}
const stop = () =>
  [...document.querySelectorAll<HTMLElement>('[role="menuitem"]')].find(
    (item) => item.textContent?.includes("Stop active scans"),
  )!;
it("uses full organization/registry summaries beyond200 and exports the exact row counts", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  expect(
    host.querySelector('[data-testid="registry-operator-summary"]')
      ?.textContent,
  ).toContain("470");
  expect(
    host.querySelector('[data-testid="registry-operator-summary"]')
      ?.textContent,
  ).toContain("99");
  expect(scanJobs.list).toHaveBeenCalledWith({
    target_type: "image",
    limit: 1,
  });
  expect(scanJobs.list).toHaveBeenCalledWith({
    registry_id: "registry",
    limit: 1,
  });
  expect(jobCell().textContent).toContain("3 failed");
  expect(host.textContent).not.toContain("latest 200");
  await act(async () => button("Export loaded registries CSV").click());
  expect(
    JSON.parse(String(vi.mocked(downloadCsv).mock.calls[0][2][0][5])),
  ).toMatchObject({
    active: 505,
    pending: 500,
    running: 3,
    paused: 2,
    failed: 3,
  });
});
it("uses registry-linked scope for Stop and invalidates all owner scan-job consumers", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  client.setQueryData(["scan-jobs", "org:user", "scanner"], "scanner-cache");
  client.setQueryData(["scan-jobs", "other:user", "scanner"], "foreign-cache");
  const confirm = vi.fn(() => true);
  Object.defineProperty(window, "confirm", {
    configurable: true,
    writable: true,
    value: confirm,
  });
  await openActions();
  await act(async () => stop().click());
  await settled(() =>
    expect(registries.cancelScans).toHaveBeenCalledWith("registry"),
  );
  expect(confirm).toHaveBeenCalledWith(
    "Stop 505 active scan jobs for Registry registry?",
  );
  expect(
    client.getQueryState(["scan-jobs", "org:user", "scanner"])?.isInvalidated,
  ).toBe(true);
  expect(
    client.getQueryState(["scan-jobs", "other:user", "scanner"])?.isInvalidated,
  ).toBe(false);
});
it("shows unavailable registry counters and disables Stop after a failed refresh", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  vi.mocked(scanJobs.list).mockImplementation(async (p) => {
    if (p?.registry_id) throw new Error("offline");
    return queue();
  });
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["scan-jobs", "registries", "org:user", "registry"],
    });
  });
  await settled(() => expect(jobCell().textContent).toContain("Unavailable"));
  expect(jobCell().textContent).not.toContain("idle");
  await act(async () => button("Export loaded registries CSV").click());
  expect(vi.mocked(downloadCsv).mock.calls[0][2][0][5]).toBe("Unavailable");
  await openActions();
  expect(stop().hasAttribute("data-disabled")).toBe(true);
  expect(registries.cancelScans).not.toHaveBeenCalled();
});
it("withholds organization KPIs after a failed image-queue refresh", async () => {
  await render();
  await settled(() =>
    expect(
      host.querySelector('[data-testid="registry-operator-summary"]')
        ?.textContent,
    ).toContain("470"),
  );
  vi.mocked(scanJobs.list).mockImplementation(async (p) => {
    if (p?.target_type) throw new Error("offline");
    return queue(p?.registry_id);
  });
  await act(async () => {
    await client.invalidateQueries({
      queryKey: ["scan-jobs", "registries", "org:user", "organization-image"],
    });
  });
  await settled(() =>
    expect(host.textContent).toContain(
      "Organization image jobs could not be loaded",
    ),
  );
  expect(
    host
      .querySelector('[data-testid="registry-operator-summary"]')
      ?.textContent?.match(/—/g),
  ).toHaveLength(2);
  expect(jobCell().textContent).toContain("505 active");
});
it.each([
  "missing-summary",
  "negative",
  "inconsistent-total",
  "wrong-org",
  "wrong-registry",
])("rejects malformed row queue %s", async (malformed) => {
  vi.mocked(scanJobs.list).mockImplementation(async (p) => {
    const result = queue(p?.registry_id);
    if (!p?.registry_id) return result;
    if (malformed === "missing-summary") delete result.summary;
    if (malformed === "negative") result.summary!.pending = -1;
    if (malformed === "inconsistent-total") result.summary!.running = 1000;
    if (malformed === "wrong-org") result.jobs[0].org_id = "foreign";
    if (malformed === "wrong-registry") result.jobs[0].registry_id = "foreign";
    return result;
  });
  await render();
  await settled(() => expect(jobCell().textContent).toContain("Unavailable"));
  expect(jobCell().textContent).not.toContain("idle");
  await openActions();
  expect(stop().hasAttribute("data-disabled")).toBe(true);
});
it("keeps cached counters unavailable while a row refresh is pending", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  let finish!: (value: ScanJobInventoryResponse) => void;
  vi.mocked(scanJobs.list).mockImplementation(async (p) =>
    p?.registry_id
      ? new Promise((resolve) => {
          finish = resolve;
        })
      : queue(),
  );
  await act(async () => {
    void client.invalidateQueries({
      queryKey: ["scan-jobs", "registries", "org:user", "registry"],
    });
  });
  await settled(() => expect(jobCell().textContent).toContain("Loading"));
  await openActions();
  expect(stop().hasAttribute("data-disabled")).toBe(true);
  await act(async () => finish(queue("registry")));
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
});
it("waits for fresh initial counts rather than showing a cached idle state", async () => {
  client.setQueryData(
    ["scan-jobs", "registries", "org:user", "registry", "registry"],
    {
      active: 0,
      pending: 0,
      running: 0,
      paused: 0,
      failed: 0,
      completed: 0,
      canceled: 0,
    },
  );
  let finish!: (value: ScanJobInventoryResponse) => void;
  vi.mocked(scanJobs.list).mockImplementation(async (p) =>
    p?.registry_id
      ? new Promise((resolve) => {
          finish = resolve;
        })
      : queue(),
  );
  await render();
  await settled(() => expect(jobCell().textContent).toContain("Loading"));
  expect(jobCell().textContent).not.toContain("idle");
  await act(async () => finish(queue("registry")));
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
});
it("switches org/user caches without exposing the prior inventory or queue", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  vi.mocked(registries.list).mockResolvedValue([
    registry("new-registry", "new-org"),
  ]);
  vi.mocked(scanJobs.list).mockImplementation(async (p) =>
    queue(p?.registry_id, "new-org"),
  );
  await render("new-org", "new-user");
  expect(host.textContent).not.toContain("Registry registry");
  await settled(() =>
    expect(host.textContent).toContain("Registry new-registry"),
  );
  expect(client.getQueryData(["registries", "org:user"])).toEqual([registry()]);
  expect(client.getQueryData(["registries", "new-org:new-user"])).toEqual([
    registry("new-registry", "new-org"),
  ]);
});
it("does not read off-page registry summaries and marks their CSV counters Not loaded", async () => {
  vi.mocked(registries.list).mockResolvedValue(
    Array.from({ length: 101 }, (_, i) => registry(String(i).padStart(3, "0"))),
  );
  await render();
  await settled(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(100),
  );
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  expect(scanJobs.list).not.toHaveBeenCalledWith({
    registry_id: "100",
    limit: 1,
  });
  await act(async () => button("Export loaded registries CSV").click());
  expect(
    vi
      .mocked(downloadCsv)
      .mock.calls[0][2].find((row) => row[0] === "Registry 100")?.[5],
  ).toBe("Not loaded");
});
it("withholds stale registry rows, CSV and inventory zeroes on list failure", async () => {
  await render();
  await settled(() => expect(jobCell().textContent).toContain("505 active"));
  vi.mocked(registries.list).mockRejectedValue(new Error("offline"));
  await act(async () => {
    await client.invalidateQueries({ queryKey: ["registries", "org:user"] });
  });
  await settled(() =>
    expect(host.textContent).toContain(
      "Registry inventory could not be loaded",
    ),
  );
  expect(host.textContent).not.toContain("Registry registry");
  expect(button("Export loaded registries CSV")).toBeUndefined();
  expect(
    host
      .querySelector('[data-testid="registry-operator-summary"]')
      ?.textContent?.match(/—/g),
  ).toHaveLength(3);
});
