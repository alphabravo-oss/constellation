import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import {
  createMemoryHistory,
  type RouterHistory,
} from "@tanstack/react-router";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  backupsApi,
  type BackupInventoryParams,
  type BackupInventoryResponse,
  type BackupInventoryRow,
} from "@/api/client";
import { TablePreferencesProvider } from "@/contexts/TablePreferencesContext";
import { TestRouter } from "@/test/router";
import { downloadCsv } from "@/lib/csv";
import { BackupPage } from "./BackupPage";
import { backupInventoryValid } from "./backup-inventory";
vi.mock("@/api/client", () => ({
  backupsApi: {
    inventory: vi.fn(),
    inventoryCSV: vi.fn(),
    getSchedule: vi.fn(),
    create: vi.fn(),
    get: vi.fn(),
    download: vi.fn(),
  },
}));
vi.mock("@/lib/csv", async (original) => ({
  ...(await original<typeof import("@/lib/csv")>()),
  downloadCsv: vi.fn(),
}));
let root: Root,
  host: HTMLDivElement,
  client: QueryClient,
  history: RouterHistory,
  identity = { org_id: "org", user_id: "user" };
const at = "2026-10-12T12:00:00.123456Z";
const backup = (
  id: string,
  status: BackupInventoryRow["status"] = "failed",
): BackupInventoryRow => ({
  id,
  org_id: identity.org_id,
  mode: "org-backup",
  status,
  started_at: at,
  size_bytes: 4096,
  signed: false,
  error: id,
});
const latest = () => ({
  ...backup("old-success", "succeeded"),
  started_at: "2020-01-01T00:00:00Z",
});
function inventory(
  request: BackupInventoryParams = {},
): BackupInventoryResponse {
  const all = Array.from({ length: 205 }, (_, i) =>
    backup(`run-${String(i + 1).padStart(4, "0")}`),
  );
  const matching = all.filter(
    (row) =>
      (!request.q || row.id.includes(request.q)) &&
      (!request.status || row.status === request.status) &&
      (!request.mode || row.mode === request.mode) &&
      (!request.signed || String(row.signed) === request.signed),
  );
  return {
    org_id: identity.org_id,
    backups: matching.slice(request.offset || 0, (request.offset || 0) + 100),
    filters: {
      q: request.q || "",
      status: request.status || "",
      mode: request.mode || "",
      signed: request.signed || "",
    },
    limit: 100,
    offset: request.offset || 0,
    sort: request.sort || "when",
    order: request.order || "desc",
    total: matching.length,
    has_more: (request.offset || 0) + 100 < matching.length,
    summary: {
      total: matching.length,
      running: 0,
      succeeded: 0,
      failed: matching.length,
      signed: 0,
      size_bytes: matching.length * 4096,
    },
    latest_success: latest(),
    source_complete: true,
    summary_scope: "matching_owned_backup_runs",
  };
}
function deferred<T>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => {
    resolve = r;
  });
  return { promise, resolve };
}
beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  identity = { org_id: "org", user_id: "user" };
  vi.mocked(backupsApi.inventory).mockImplementation(async (p) => inventory(p));
  vi.mocked(backupsApi.getSchedule).mockResolvedValue({
    enabled: false,
    cron_expr: "",
    sign_mode: "none",
  });
  vi.mocked(backupsApi.inventoryCSV).mockResolvedValue({
    total: 205,
    exported: 205,
    limit: 100000,
    truncated: false,
  });
  vi.mocked(backupsApi.download).mockResolvedValue(undefined);
  localStorage.clear();
});
afterEach(() => {
  act(() => root?.unmount());
  host?.remove();
  client?.clear();
  vi.restoreAllMocks();
  vi.resetAllMocks();
  vi.unstubAllGlobals();
});
async function settle(check: () => void) {
  await vi.waitFor(
    async () => {
      await act(async () => {});
      check();
    },
    { timeout: 3000 },
  );
}
async function render(url = "/settings/backup?page=2&context=keep#history") {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  history = createMemoryHistory({ initialEntries: [url] });
  await rerender();
}
async function rerender() {
  await act(async () =>
    root.render(
      <QueryClientProvider client={client}>
        <TablePreferencesProvider identity={{ ...identity }}>
          <TestRouter path="/settings/backup" history={history}>
            <BackupPage />
          </TestRouter>
        </TablePreferencesProvider>
      </QueryClientProvider>,
    ),
  );
}
const button = (label: string) =>
  [...host.querySelectorAll<HTMLButtonElement>("button")].find(
    (b) => b.textContent?.trim() === label,
  )!;
async function input(value: string) {
  await act(async () => {
    const field = host.querySelector<HTMLInputElement>(
      '[aria-label="Search backup history"]',
    )!;
    Object.getOwnPropertyDescriptor(
      HTMLInputElement.prototype,
      "value",
    )!.set!.call(field, value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
  });
}
it("pages all matching retained runs and shows full owned latest success outside the current failed page", async () => {
  await render();
  await settle(() =>
    expect(host.textContent).toContain("205 matching backup runs"),
  );
  expect(backupsApi.inventory).toHaveBeenCalledWith(
    expect.objectContaining({ limit: 100, offset: 100 }),
  );
  expect(host.querySelectorAll("tbody tr")).toHaveLength(100);
  expect(
    host.querySelector('[data-testid="backup-status"]')!.textContent,
  ).toContain("2020");
  expect(host.textContent).not.toContain("No backups yet");
  await act(async () => button("Next").click());
  await settle(() => expect(host.querySelectorAll("tbody tr")).toHaveLength(5));
  expect(history.location.search).toContain("page=3");
  await act(async () => history.back());
  await settle(() =>
    expect(backupsApi.inventory).toHaveBeenLastCalledWith(
      expect.objectContaining({ offset: 100 }),
    ),
  );
  expect(history.location.hash).toBe("#history");
});
it("literal tail search debounces and resets the page while retaining unrelated context", async () => {
  await render();
  await settle(() => expect(host.textContent).toContain("205 matching"));
  await input("run-0205");
  await settle(() =>
    expect(host.textContent).toContain("1 matching backup runs"),
  );
  expect(backupsApi.inventory).toHaveBeenLastCalledWith(
    expect.objectContaining({ q: "run-0205", offset: 0 }),
  );
  expect(history.location.search).toBe("?context=keep&q=run-0205");
  expect(
    host.querySelector('[data-testid="backup-status"]')!.textContent,
  ).toContain("2020");
});
it("exports matching metadata filters separately from scalar page CSV", async () => {
  await render(
    "/settings/backup?status=failed&mode=org-backup&signed=false&sort=size&order=asc&page=2",
  );
  await settle(() => expect(host.textContent).toContain("205 matching"));
  await act(async () => button("Export matching CSV").click());
  await settle(() =>
    expect(backupsApi.inventoryCSV).toHaveBeenCalledWith(
      expect.objectContaining({
        status: "failed",
        mode: "org-backup",
        signed: "false",
        sort: "size",
        order: "asc",
        offset: 100,
      }),
      "org",
      expect.any(Function),
    ),
  );
  await act(async () => button("Export this page metadata CSV").click());
  expect(vi.mocked(downloadCsv).mock.calls[0][2]).toHaveLength(100);
  expect(vi.mocked(downloadCsv).mock.calls[0][1]).not.toContain("Actions");
  expect(backupsApi.download).not.toHaveBeenCalled();
});
it("withholds failed cached history/latest KPIs and exports, recovers through Retry", async () => {
  await render();
  await settle(() => expect(host.textContent).toContain("205 matching"));
  vi.mocked(backupsApi.inventory).mockRejectedValue(new Error("failed"));
  await act(async () => client.refetchQueries({ queryKey: ["backups"] }));
  await settle(() =>
    expect(host.textContent).toContain("Backup history is unavailable"),
  );
  expect(host.querySelector("table")).toBeNull();
  expect(
    host.querySelector('[data-testid="backup-status"]')!.textContent,
  ).not.toContain("2020");
  expect(host.textContent).not.toContain("No backups yet");
  vi.mocked(backupsApi.inventory).mockImplementation(async (p) => inventory(p));
  await act(async () => button("Retry history").click());
  await settle(() => expect(host.textContent).toContain("205 matching"));
});
it("shows initial failure and unknown settings instead of an empty or local-storage claim", async () => {
  vi.mocked(backupsApi.inventory).mockRejectedValue(new Error("failed"));
  vi.mocked(backupsApi.getSchedule).mockRejectedValue(new Error("failed"));
  await render();
  await settle(() =>
    expect(host.textContent).toContain("Backup settings are unavailable"),
  );
  expect(host.textContent).toContain("Backup history is unavailable");
  expect(host.textContent).not.toContain("Local storage only");
  expect(button("Take backup now").disabled).toBe(true);
});
it.each(["page=no", "page=21474838", "status=bad", "sort=bad", "q=a&q=b"])(
  "rejects invalid URL%s without broadening inventory",
  async (query) => {
    await render(`/settings/backup?${query}`);
    await settle(() =>
      expect(host.textContent).toContain("Choose supported backup filters"),
    );
    expect(backupsApi.inventory).not.toHaveBeenCalled();
    await act(async () => button("Reset history filters").click());
    await settle(() => expect(host.textContent).toContain("205 matching"));
  },
);
it("preserves a confirmed table during refetch while blocking page CSV and artifact downloads", async () => {
  vi.mocked(backupsApi.inventory).mockImplementation(async (p) => {
    const data = inventory(p);
    data.backups[0].status = "succeeded";
    data.summary.succeeded = 1;
    data.summary.failed = 204;
    return data;
  });
  await render();
  await settle(() => expect(host.textContent).toContain("205 matching"));
  const read = deferred<BackupInventoryResponse>();
  vi.mocked(backupsApi.inventory).mockReturnValue(read.promise);
  let refresh!: Promise<unknown>;
  await act(async () => {
    refresh = client.refetchQueries({ queryKey: ["backups"] });
  });
  await settle(() => expect(host.textContent).toContain("Refreshing"));
  expect(host.querySelectorAll("tbody tr")).toHaveLength(100);
  expect(button("Export this page metadata CSV").disabled).toBe(true);
  expect(button("Download").disabled).toBe(true);
  await act(async () => {
    read.resolve(
      inventory({ limit: 100, offset: 100, sort: "when", order: "desc" }),
    );
    await refresh;
  });
});
it("isolates owner cache and rejects a retained export guard after the operator switches", async () => {
  await render();
  await settle(() => expect(host.textContent).toContain("205 matching"));
  let guard!: () => boolean;
  vi.mocked(backupsApi.inventoryCSV).mockImplementation(async (_p, _org, current) => {
    guard = current!;
    return new Promise(() => {});
  });
  await act(async () => button("Export matching CSV").click());
  expect(guard()).toBe(true);
  const pending = deferred<BackupInventoryResponse>();
  vi.mocked(backupsApi.inventory).mockReturnValue(pending.promise);
  identity = { org_id: "other-org", user_id: "other-user" };
  await rerender();
  expect(guard()).toBe(false);
  expect(host.querySelector("table")).toBeNull();
  expect(
    host.querySelector('[data-testid="backup-status"]')!.textContent,
  ).not.toContain("2020");
  expect(
    client
      .getQueryCache()
      .findAll({ queryKey: ["backups"] })
      .map((q) => q.queryKey[2]),
  ).toEqual(["org:user", "other-org:other-user"]);
});
it("recovers a deep empty page without a misleading pager range", async () => {
  await render("/settings/backup?page=21474837");
  await settle(() => expect(host.textContent).toContain("205 matching"));
  expect(host.textContent).toContain("No records were returned for this page");
  await act(async () => button("First page").click());
  await settle(() =>
    expect(host.querySelectorAll("tbody tr")).toHaveLength(100),
  );
});
it("validates every owned row and normalized filters, full summaries and latest-success receipt", () => {
  const req = { limit: 100, offset: 0, sort: "when", order: "desc" as const };
  const data = inventory(req);
  expect(backupInventoryValid(data, req, "org")).toBe(true);
  for (const alter of [
    (d: BackupInventoryResponse) => {
      d.latest_success!.org_id = "foreign";
    },
    (d: BackupInventoryResponse) => {
      d.filters.signed = "true";
    },
    (d: BackupInventoryResponse) => {
      d.backups[0].org_id = "foreign";
    },
    (d: BackupInventoryResponse) => {
      d.summary.failed--;
    },
    (d: BackupInventoryResponse) => {
      d.backups[0].signed = "false" as unknown as boolean;
    },
    (d: BackupInventoryResponse) => {
      d.latest_success!.status = "failed";
    },
    (d: BackupInventoryResponse) => {
      d.source_complete = false;
    },
  ]) {
    const bad = structuredClone(data);
    alter(bad);
    expect(backupInventoryValid(bad, req, "org")).toBe(false);
  }
});
it("polls the exact created receipt independently of filtered pages and preserves guarded automatic artifact download", async () => {
  vi.mocked(backupsApi.create).mockResolvedValue({
    id: "new-owned-backup",
    status: "running",
  });
  vi.mocked(backupsApi.get).mockResolvedValue({
    ...latest(),
    id: "new-owned-backup",
  });
  const download = deferred<void>();
  vi.mocked(backupsApi.download).mockReturnValue(download.promise);
  await render("/settings/backup?q=unmatched&status=failed");
  await settle(() => expect(host.textContent).toContain("0 matching"));
  await act(async () => button("Take backup now").click());
  await settle(() =>
    expect(backupsApi.download).toHaveBeenCalledWith(
      "new-owned-backup",
      expect.any(Function),
    ),
  );
  expect(backupsApi.get).toHaveBeenCalledWith("new-owned-backup");
  expect(history.location.search).toBe("?q=unmatched&status=failed");
  const guard = vi.mocked(backupsApi.download).mock.calls[0][1]!;
  expect(guard()).toBe(true);
  identity = { org_id: "another", user_id: "another" };
  await rerender();
  expect(guard()).toBe(false);
  await act(async () => download.resolve());
});
it("does not adopt a delayed create receipt after its submitted owner changes", async () => {
  const write = deferred<{ id: string; status: string }>();
  vi.mocked(backupsApi.create).mockReturnValue(write.promise);
  await render();
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  await act(async () => button("Take backup now").click());
  identity = { org_id: "another", user_id: "another" };
  await rerender();
  await act(async () =>
    write.resolve({ id: "old-owner-job", status: "running" }),
  );
  await settle(() => expect(host.textContent).not.toContain("Backing up…"));
  expect(backupsApi.get).not.toHaveBeenCalled();
  expect(backupsApi.download).not.toHaveBeenCalled();
});
it("rejects malformed rows without throwing during render", async () => {
  vi.mocked(backupsApi.inventory).mockImplementation(async (p) => {
    const data = inventory(p);
    data.backups[0] = null as unknown as BackupInventoryRow;
    return data;
  });
  await render();
  await settle(() =>
    expect(host.textContent).toContain("Backup history is unavailable"),
  );
  expect(host.querySelector("table")).toBeNull();
});
it("rechecks the exact schedule cache synchronously before a retained create button can dispatch", async () => {
  await render();
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  await act(async () => {
    void client.invalidateQueries({
      queryKey: ["backups-schedule"],
      refetchType: "none",
    });
    button("Take backup now").click();
  });
  expect(backupsApi.create).not.toHaveBeenCalled();
});
it("cannot revive an old create receipt after owner A-to-B-to-A", async () => {
  const write = deferred<{ id: string; status: string }>();
  vi.mocked(backupsApi.create).mockReturnValue(write.promise);
  await render();
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  await act(async () => button("Take backup now").click());
  identity = { org_id: "another", user_id: "another" };
  await rerender();
  identity = { org_id: "org", user_id: "user" };
  await rerender();
  await act(async () =>
    write.resolve({ id: "old-owner-job", status: "running" }),
  );
  await settle(() => expect(host.textContent).not.toContain("Backing up…"));
  expect(backupsApi.get).not.toHaveBeenCalled();
});
it("cannot revive an automatic artifact response after source invalidation or owner A-to-B-to-A", async () => {
  vi.mocked(backupsApi.create).mockResolvedValue({
    id: "new-owned-backup",
    status: "running",
  });
  vi.mocked(backupsApi.get).mockResolvedValue({
    ...latest(),
    id: "new-owned-backup",
  });
  const download = deferred<void>();
  vi.mocked(backupsApi.download).mockReturnValue(download.promise);
  await render();
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  await act(async () => button("Take backup now").click());
  await settle(() => expect(backupsApi.download).toHaveBeenCalled());
  const guard = vi.mocked(backupsApi.download).mock.calls[0][1]!;
  expect(guard()).toBe(true);
  await act(async () =>
    client.invalidateQueries({
      queryKey: ["backup-detail"],
      refetchType: "none",
    }),
  );
  expect(guard()).toBe(false);
  await act(async () => client.refetchQueries({ queryKey: ["backup-detail"] }));
  expect(guard()).toBe(false);
  identity = { org_id: "another", user_id: "another" };
  await rerender();
  identity = { org_id: "org", user_id: "user" };
  await rerender();
  expect(guard()).toBe(false);
  await act(async () => download.resolve());
});
it("rejects an unconfirmed create receipt instead of adopting an arbitrary pending job", async () => {
  vi.mocked(backupsApi.create).mockResolvedValue({
    id: "",
    status: "succeeded",
  });
  await render();
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  await act(async () => button("Take backup now").click());
  await settle(() => expect(button("Take backup now").disabled).toBe(false));
  expect(backupsApi.get).not.toHaveBeenCalled();
  expect(backupsApi.download).not.toHaveBeenCalled();
});
