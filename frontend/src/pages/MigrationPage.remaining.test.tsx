import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { toast } from "sonner";
import { clusters, enterprise, type MigrationImportListItem, type MigrationPreview, type MigrationRollbackBundle } from "@/api/client";
import { downloadJson } from "@/lib/download";
import { MigrationPage } from "./MigrationPage";
import remainingFixture from "./testdata/migration-remaining-preview.json";

vi.mock("@/api/client", () => ({
  clusters: { list: vi.fn() },
  enterprise: {
    migration: vi.fn(), migrationImportsPage: vi.fn(), migrationPreview: vi.fn(),
    migrationApply: vi.fn(), migrationRollback: vi.fn(), migrationRollbackBundle: vi.fn(),
  },
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn(), warning: vi.fn() } }));
vi.mock("@/lib/download", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/lib/download")>(), downloadJson: vi.fn(),
}));

let root: Root | undefined;
let host: HTMLDivElement;
let queryClient: QueryClient;
let imports: MigrationImportListItem[];
const exportText = JSON.stringify({
  vulnerability_profiles: [{ name: "reviewed-cves", entries: [{ name: "CVE-2026-1234" }] }],
  registries: [{ name: "internal-images", registry_type: "Docker Registry", registry: "https://registry.example.test" }],
});

function fixture(): MigrationPreview {
  return structuredClone(remainingFixture) as MigrationPreview;
}

function history(preview: MigrationPreview, status = "previewed"): MigrationImportListItem {
  return {
    id: preview.import_id!, source: "neuvector", status, summary: preview.summary,
    unsupported: preview.unsupported, created_at: "2026-09-26T00:00:00Z",
  };
}

beforeEach(() => {
  vi.stubGlobal("IS_REACT_ACT_ENVIRONMENT", true);
  imports = [];
  vi.mocked(clusters.list).mockResolvedValue({ clusters: [] });
  vi.mocked(enterprise.migration).mockResolvedValue({ sources: [], workflow: [] });
  vi.mocked(enterprise.migrationImportsPage).mockImplementation(async ({ limit = 25, cursor } = {}) => {
    const offset = cursor ? Number(cursor.slice("cursor-".length)) : 0;
    return {
      imports: imports.slice(offset, offset + limit),
      has_more: offset + limit < imports.length,
      next_cursor: offset + limit < imports.length ? `cursor-${offset + limit}` : undefined,
    };
  });
  vi.mocked(enterprise.migrationPreview).mockImplementation(async () => {
    const preview = fixture();
    imports = [history(preview)];
    return preview;
  });
});

afterEach(() => {
  act(() => root?.unmount());
  root = undefined;
  host?.remove();
  queryClient?.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.resetAllMocks();
});

async function settle() {
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 25)); });
}

async function render() {
  host = document.createElement("div");
  document.body.appendChild(host);
  root = createRoot(host);
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  await act(async () => root!.render(
    <QueryClientProvider client={queryClient}><MemoryRouter><MigrationPage /></MemoryRouter></QueryClientProvider>,
  ));
  await settle();
}

function element<ElementType extends HTMLElement = HTMLElement>(testId: string): ElementType {
  const found = host.querySelector<ElementType>(`[data-testid="${testId}"]`);
  expect(found, testId).not.toBeNull();
  return found!;
}

async function click(testId: string) {
  const button = element<HTMLButtonElement>(testId);
  expect(button.disabled, `${testId} must be enabled`).toBe(false);
  await act(async () => button.click());
  await settle();
}

async function previewExport() {
  const input = element<HTMLTextAreaElement>("migration-export-input");
  await act(async () => {
    Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, "value")!.set!.call(input, exportText);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await click("migration-preview-submit");
}

function statistic(label: string) {
  const labels = Array.from(element("migration-preview-result").querySelectorAll("div"));
  const labelElement = labels.find((candidate) => candidate.textContent === label);
  expect(labelElement, label).toBeDefined();
  return labelElement!.parentElement!.querySelector("span")?.textContent;
}

it("previews remaining families without a cluster and distinguishes create, update, and unchanged", async () => {
  await render();
  await previewExport();
  expect(enterprise.migrationPreview).toHaveBeenCalledWith({ source: "neuvector", export: exportText, cluster_id: undefined });
  const profiles = element("migration-preview-vulnerability-profiles");
  expect(profiles.querySelectorAll('[data-testid="migration-preview-vulnerability-profile"]')).toHaveLength(2);
  expect(profiles.textContent).toContain("reviewed-cves");
  expect(profiles.textContent).toContain("update");
  expect(profiles.textContent).toContain("existing-cves");
  expect(profiles.textContent).toContain("unchanged");
  const registries = element("migration-preview-registries");
  expect(registries.querySelectorAll('[data-testid="migration-preview-registry"]')).toHaveLength(1);
  expect(registries.textContent).toContain("internal-images");
  expect(registries.textContent).toContain("https://registry.example.test");
  expect(registries.textContent).toContain("create");
  expect(registries.textContent).toMatch(/reissue/i);
  expect(registries.textContent).toMatch(/manual scans/i);
  expect(registries.textContent).toContain("no credentials imported");
  expect(statistic("Vulnerability Profiles")).toBe("2");
  expect(statistic("Registries")).toBe("1");
  expect(statistic("Unchanged")).toBe("1");
});

it("loads an uploaded export into the editor and previews the same content", async () => {
  await render();
  const upload = element<HTMLInputElement>("migration-export-upload");
  await act(async () => {
    Object.defineProperty(upload, "files", { configurable: true, value: [new File([exportText], "remaining.json", { type: "application/json" })] });
    upload.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await settle();
  expect(element<HTMLTextAreaElement>("migration-export-input").value).toBe(exportText);
  await click("migration-preview-submit");
  expect(enterprise.migrationPreview).toHaveBeenCalledWith({ source: "neuvector", export: exportText, cluster_id: undefined });
  expect(element("migration-preview-vulnerability-profiles").textContent).toContain("reviewed-cves");
  expect(element("migration-preview-registries").textContent).toContain("internal-images");
});

it("loads older import history pages without silently truncating at 25", async () => {
  imports = Array.from({ length: 27 }, (_, index) => ({ ...history(fixture()), id: `history-${index}` }));
  imports[0].target_cluster_id = "00000000-0000-0000-0000-000000000001";
  await render();
  expect(enterprise.migrationImportsPage).toHaveBeenCalledWith({ limit: 25 });
  expect(element("migration-import-history").textContent).toContain("history-24");
  expect(element("migration-import-history").textContent).toContain("Target: 00000000-0000-0000-0000-000000000001");
  expect(element("migration-import-history").textContent).not.toContain("history-26");
  await click("migration-import-history-load-more");
  expect(enterprise.migrationImportsPage).toHaveBeenCalledWith({ limit: 25, cursor: "cursor-25" });
  expect(element("migration-import-history").textContent).toContain("history-26");
  expect(host.querySelector('[data-testid="migration-import-history-load-more"]')).toBeNull();
});

it("distinguishes loaded-row CSV from the full metadata history download", async () => {
  await render();
  const link = element<HTMLAnchorElement>("migration-import-history-export-all");
  expect(link.getAttribute("href")).toBe("/api/v1/migration/imports/export");
  expect(link.getAttribute("download")).toBe("migration-imports.ndjson");
  expect(host.textContent).toContain("The table’s CSV includes loaded rows only.");
  expect(host.textContent).toContain("Verify its final complete record and count");
});

it("keeps same-kind redacted diagnostics visible across previews without presenting rejected source as converted", async () => {
  const consoleErrors = vi.spyOn(console, "error").mockImplementation(() => {});
  await render();
  await previewExport();
  for (const iteration of [0, 1]) {
    if (iteration) await click("migration-preview-submit");
    const diagnostics = element("migration-preview-unsupported");
    expect(diagnostics.querySelectorAll("tbody tr")).toHaveLength(3);
    expect(diagnostics.textContent?.match(/REDACTED/g)).toHaveLength(3);
    expect(diagnostics.textContent).toContain("Registry credentials were omitted");
    expect(diagnostics.textContent).toContain("Identity tokens cannot be imported");
    expect(diagnostics.textContent).toContain("Scoped vulnerability rules cannot be represented exactly");
    expect(diagnostics.textContent).toContain('"redacted":true');
    expect(element("migration-preview-vulnerability-profiles").textContent).not.toContain("REDACTED");
    expect(diagnostics.parentElement?.textContent).not.toContain("These records were converted");
  }
  expect(consoleErrors.mock.calls.flat().join(" ")).not.toMatch(/same key/i);
});

it("refreshes partial apply and rollback history, downloads the bundle, and applies a later update", async () => {
  vi.mocked(enterprise.migrationApply).mockImplementation(async (id) => {
    imports = imports.map((item) => item.id === id ? {
      ...item, status: "partial_applied", applied_summary: {
        created: item.summary.create, updated: item.summary.update,
        vulnerability_profiles: 1, registries: item.summary.create, unchanged: item.summary.unchanged ?? 0,
      },
    } : item);
    return { id, status: "partial_applied" };
  });
  vi.mocked(enterprise.migrationRollback).mockImplementation(async (id) => {
    imports = imports.map((item) => item.id === id ? { ...item, status: "rolled_back" } : item);
    return { id, status: "rolled_back", restored: 1, deleted: 1 };
  });
  const bundle: MigrationRollbackBundle = {
    vulnerability_profiles: [{ action: "update", id: "profile-1", applied_at: "2026-09-26T00:01:00Z" }],
    registries: [{ action: "create", id: "registry-1", applied_at: "2026-09-26T00:01:00Z" }],
  };
  vi.mocked(enterprise.migrationRollbackBundle).mockResolvedValue(bundle);
  await render();
  await previewExport();
  await click("migration-import-apply-active");
  expect(enterprise.migrationApply).toHaveBeenCalledWith("remaining-import-1");
  expect(element<HTMLButtonElement>("migration-import-apply-active").disabled).toBe(true);
  expect(element("migration-import-history").textContent).toContain("partial applied");
  expect(element("migration-import-history").textContent).toContain("1 vulnerability profiles");
  expect(element("migration-import-history").textContent).toContain("1 registries");
  expect(element("migration-readiness-checklist").textContent).toContain("partially applied");
  await click("migration-import-rollback-bundle-remaining-import-1");
  expect(downloadJson).toHaveBeenCalledWith("constellation-migration-rollback-remaining-import-1.json", bundle);
  await click("migration-import-rollback-remaining-import-1");
  expect(enterprise.migrationRollback).toHaveBeenCalledWith("remaining-import-1");
  expect(element("migration-import-history").textContent).toContain("rolled back");
  expect(element<HTMLButtonElement>("migration-import-apply-active").disabled).toBe(false);
  expect(element<HTMLButtonElement>("migration-import-rollback-remaining-import-1").disabled).toBe(true);
  const updatedPreview = fixture();
  updatedPreview.import_id = "remaining-import-2";
  updatedPreview.summary.create = 0;
  updatedPreview.summary.update = 1;
  updatedPreview.summary.unchanged = 2;
  updatedPreview.registries![0].diff_action = "unchanged";
  vi.mocked(enterprise.migrationPreview).mockImplementationOnce(async () => {
    imports = [history(updatedPreview), ...imports];
    return updatedPreview;
  });
  await click("migration-preview-submit");
  await click("migration-import-apply-active");
  expect(enterprise.migrationApply).toHaveBeenLastCalledWith("remaining-import-2");
  expect(element("migration-import-history").textContent).toContain("0 created · 1 updated");
  expect(host.textContent).not.toMatch(/undefined|NaN/);
});

it.each([false, true])("handles rollback responses without counts (already rolled back: %s)", async (alreadyRolledBack) => {
  imports = [history(fixture(), "partial_applied")];
  vi.mocked(enterprise.migrationRollback).mockImplementation(async (id) => {
    imports = imports.map((item) => ({ ...item, status: "rolled_back" }));
    return { id, status: "rolled_back", already_rolled_back: alreadyRolledBack };
  });
  await render();
  await click("migration-import-rollback-remaining-import-1");
  expect(element("migration-import-history").textContent).toContain("rolled back");
  expect(toast.success).toHaveBeenCalledWith(alreadyRolledBack
    ? "Migration import already rolled back"
    : "Migration rollback complete (0 restored, 0 deleted)");
  expect(host.textContent).not.toMatch(/undefined|NaN/);
});

it("supports older previews and histories with omitted remaining arrays and counts", async () => {
  const legacy = fixture();
  Reflect.deleteProperty(legacy, "vulnerability_profiles");
  Reflect.deleteProperty(legacy, "registries");
  for (const key of ["vulnerability_profiles", "registries", "unchanged"]) Reflect.deleteProperty(legacy.summary, key);
  legacy.summary.total = 0;
  legacy.summary.create = 0;
  legacy.summary.update = 0;
  legacy.unsupported = [];
  legacy.summary.unsupported = 0;
  imports = [{ ...history(legacy, "applied"), applied_summary: {} }];
  vi.mocked(enterprise.migrationPreview).mockResolvedValue(legacy);
  await render();
  await previewExport();
  expect(statistic("Vulnerability Profiles")).toBe("0");
  expect(statistic("Registries")).toBe("0");
  expect(statistic("Unchanged")).toBe("0");
  expect(host.querySelector('[data-testid="migration-preview-vulnerability-profile"]')).toBeNull();
  expect(host.querySelector('[data-testid="migration-preview-registry"]')).toBeNull();
  expect(element("migration-import-history").textContent).toContain("0 created · 0 updated");
  expect(host.textContent).not.toMatch(/undefined|NaN/);
});
