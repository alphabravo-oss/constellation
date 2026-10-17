import { expect, type Page } from "@playwright/test";
import type {
  BackupInventoryResponse,
  BackupInventoryRow,
} from "../../src/api/client";
import { notificationThreats } from "./network-inventory";
export const backupOrg = "22222222-2222-4222-8222-222222222222";
const row = (
  index: number,
  patch: Partial<BackupInventoryRow> = {},
): BackupInventoryRow => ({
  id: `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`,
  org_id: backupOrg,
  mode: "org-backup",
  status: "failed",
  started_at: new Date(Date.UTC(2026, 9, 12, 0, 0, index)).toISOString(),
  size_bytes: index,
  signed: false,
  error: `Retained failure ${index}`,
  ...patch,
});
export function backupFixture() {
  const rows = Array.from({ length: 1205 }, (_, index) => row(index + 1));
  rows[1204].error = "needle%_literal";
  const latest = row(2001, {
    status: "succeeded",
    started_at: "2021-01-01T00:00:00Z",
    finished_at: "2021-01-01T00:00:01.123456Z",
    size_bytes: 8192,
    signed: true,
    sha256: "a".repeat(64),
    format_version: "constellation-orgbackup/v1",
    signer_identity: "Owned backup signer",
    s3_uri: "s3://owned/archive/latest.tar.gz",
    tables_included: ["assets", "findings"],
    error: "",
  });
  rows.push(
    latest,
    row(2000, {
      status: "succeeded",
      started_at: "2020-01-01T00:00:00Z",
      size_bytes: 4096,
      error: "",
    }),
  );
  const foreign = row(9001, {
    org_id: "foreign",
    status: "succeeded",
    started_at: "2030-01-01T00:00:00Z",
    signer_identity: "Foreign signer",
  });
  const unowned = {
    ...row(9002, {
      status: "succeeded",
      started_at: "2040-01-01T00:00:00Z",
      signer_identity: "Unowned legacy signer",
    }),
    org_id: null,
  };
  const source = [...rows, foreign, unowned],
    requests: URL[] = [];
  let failing = false;
  function inventory(url: URL, exportAll = false): BackupInventoryResponse {
    const filters = Object.fromEntries(
      ["q", "status", "mode", "signed"].map((key) => [
        key,
        (url.searchParams.get(key) || "") === "all"
          ? ""
          : (url.searchParams.get(key) || "").trim().toLowerCase(),
      ]),
    ) as BackupInventoryResponse["filters"];
    const owned = source.filter(
      (record) => record.org_id === backupOrg,
    ) as BackupInventoryRow[];
    const matching = owned.filter(
      (record) =>
        (!filters.q ||
          [
            record.id,
            record.mode,
            record.status,
            record.signer_identity,
            record.error,
            record.s3_uri,
          ]
            .join(" ")
            .toLowerCase()
            .includes(filters.q)) &&
        (!filters.status || record.status === filters.status) &&
        (!filters.mode || record.mode === filters.mode) &&
        (!filters.signed || record.signed === (filters.signed === "true")),
    );
    const sort = url.searchParams.get("sort") || "when",
      order = (url.searchParams.get("order") || "desc") as "asc" | "desc";
    const field = (record: BackupInventoryRow) =>
      sort === "when"
        ? record.started_at
        : sort === "size"
          ? record.size_bytes
          : sort === "signer"
            ? record.signer_identity || ""
            : record[sort as "mode" | "status"];
    const ordered = [...matching].sort((a, b) => {
      const av = field(a),
        bv = field(b);
      return (
        (typeof av === "number" && typeof bv === "number"
          ? av - bv
          : String(av).localeCompare(String(bv))) *
          (order === "desc" ? -1 : 1) || a.id.localeCompare(b.id)
      );
    });
    const limit = exportAll
        ? 100000
        : Number(url.searchParams.get("limit") || 100),
      offset = exportAll ? 0 : Number(url.searchParams.get("offset") || 0);
    return {
      backups: ordered.slice(offset, offset + limit),
      org_id: backupOrg,
      total: matching.length,
      has_more: offset + limit < matching.length,
      limit,
      offset,
      sort,
      order,
      filters,
      source_complete: true,
      summary_scope: "matching_owned_backup_runs",
      summary: {
        total: matching.length,
        running: matching.filter((record) => record.status === "running")
          .length,
        succeeded: matching.filter((record) => record.status === "succeeded")
          .length,
        failed: matching.filter((record) => record.status === "failed").length,
        signed: matching.filter((record) => record.signed).length,
        size_bytes: matching.reduce(
          (sum, record) => sum + record.size_bytes,
          0,
        ),
      },
      latest_success:
        [...owned]
          .filter((record) => record.status === "succeeded")
          .sort(
            (a, b) =>
              b.started_at.localeCompare(a.started_at) ||
              a.id.localeCompare(b.id),
          )[0] ?? null,
    };
  }
  async function install(page: Page) {
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request(),
        url = new URL(request.url()),
        path = url.pathname.replace(/^\/api\/v1/, "");
      expect(
        request.method(),
        "Backup inventory acceptance must remain read-only",
      ).toBe("GET");
      if (path === "/auth/me")
        return route.fulfill({
          json: {
            org_id: backupOrg,
            user_id: "operator",
            email: "operator@example.test",
            roles: ["GlobalAdmin"],
          },
        });
      if (path === "/clusters")
        return route.fulfill({ json: { clusters: [] } });
      if (path === "/runtime-threats")
        return route.fulfill({ json: notificationThreats(url) });
      if (path === "/findings")
        return route.fulfill({ json: { findings: [] } });
      if (path === "/backups/schedule")
        return route.fulfill({
          json: {
            enabled: false,
            cron_expr: "0 3 * * *",
            sign_mode: "static-key",
            s3_bucket: "configured-destination",
            s3_prefix: "backups",
          },
        });
      if (path === "/backups/inventory" || path === "/backups/inventory.csv") {
        requests.push(url);
        expect(url.searchParams.has("org_id")).toBe(false);
        if (failing)
          return route.fulfill({
            status: 500,
            json: { error: "Backup history is unavailable" },
          });
        const exporting = path.endsWith(".csv"),
          data = inventory(url, exporting);
        if (!exporting) return route.fulfill({ json: data });
        expect(url.searchParams.has("limit")).toBe(false);
        expect(url.searchParams.has("offset")).toBe(false);
        const headers = [
          "id",
          "org_id",
          "mode",
          "status",
          "started_at",
          "finished_at",
          "size_bytes",
          "sha256",
          "signed",
          "signer_identity",
          "format_version",
          "s3_uri",
          "tables_included",
          "error",
        ];
        const quote = (value: unknown) =>
          `"${String(value).replaceAll('"', '""')}"`;
        const body = [
          headers,
          ...data.backups.map((record) => [
            record.id,
            record.org_id,
            record.mode,
            record.status,
            record.started_at,
            record.finished_at ?? "",
            record.size_bytes,
            record.sha256 ?? "",
            record.signed,
            record.signer_identity ?? "",
            record.format_version ?? "",
            record.s3_uri ?? "",
            JSON.stringify(record.tables_included ?? []),
            record.error ?? "",
          ]),
        ]
          .map((record) => record.map(quote).join(","))
          .join("\n");
        return route.fulfill({
          contentType: "text/csv; charset=utf-8",
          headers: {
            "X-Export-Total": String(data.total),
            "X-Export-Limit": "100000",
            "X-Export-Truncated": "false",
            "X-Export-Org-ID": backupOrg,
            "X-Export-Scope": "matching_owned_backup_runs",
          },
          body,
        });
      }
      return route.fulfill({
        status: 404,
        json: { error: `Outside backup inventory fixture: ${path}` },
      });
    });
  }
  return {
    install,
    requests,
    rows,
    latest,
    foreign,
    unowned,
    fail: () => {
      failing = true;
    },
    recover: () => {
      failing = false;
    },
  };
}
