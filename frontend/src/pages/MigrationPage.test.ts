import { describe, expect, it } from "vitest";

import {
  buildMigrationReadiness,
  buildMigrationReport,
  MIGRATION_RECOMMENDED_ACTIONS,
  migrationAppliedSummaryLabel,
  type MigrationReadinessItem,
} from "@/lib/migration-readiness";
import type { MigrationImportListItem, MigrationPreview } from "@/api/client";
import remainingFixture from "./testdata/migration-remaining-preview.json";

const preview: MigrationPreview = {
  import_id: "import-1",
  summary: {
    source: "neuvector",
    total: 4,
    source_total: 5,
    source_counts: {
      policies: 1,
      admission_rules: 1,
      response_rules: 0,
      file_profiles: 1,
      process_profiles: 1,
      groups: 1,
      network_rules: 1,
      dpi_rules: 0,
      dpi_bindings: 0,
    },
    unaccounted_source: 0,
    create: 2,
    update: 1,
    enforce: 2,
    monitor: 1,
    enabled: 2,
    file_profiles: 1,
    process_profiles: 1,
    groups: 1,
    network_rules: 1,
    dpi_rules: 0,
    dpi_bindings: 0,
    unsupported: 1,
    engines: { "constellation-admission": 1, "constellation-builtin": 1 },
    categories: { admission: 1, runtime: 1 },
    read_only: true,
    rollback_hint: "Preview only.",
  },
  policies: [],
  file_profiles: [],
  process_profiles: [],
  groups: [],
  network_rules: [],
  dpi_rules: [],
  dpi_bindings: [],
  unsupported: [{
    kind: "file_profile",
    name: "nv.default.api",
    reason: "requires workload mapping",
    suggestion: "Map the NeuVector group to a workload.",
    source: { group: "nv.default.api" },
  }],
  rollback_bundle: "{\"policies\":[]}",
};

const activeImport: MigrationImportListItem = {
  id: "import-1",
  source: "neuvector",
  status: "partial_applied",
  summary: preview.summary,
  applied_summary: { policies: 2, created: 1, updated: 1 },
  unsupported: preview.unsupported,
  created_at: "2026-08-23T00:00:00Z",
  applied_at: "2026-08-23T00:01:00Z",
};

describe("migration readiness", () => {
  it("classifies empty migration state as a blocker", () => {
    const items = buildMigrationReadiness(undefined, undefined, []);
    expect(items).toContainEqual(expect.objectContaining({
      id: "preview-required",
      category: "blocker",
    }));
  });

  it("derives warnings and rollback evidence from partial NeuVector imports", () => {
    const items = buildMigrationReadiness(preview, activeImport, [activeImport]);
    expect(categoryFor(items, "manual-mapping")).toBe("warning");
    expect(categoryFor(items, "partial-apply")).toBe("warning");
    expect(categoryFor(items, "rollback-ready")).toBe("ready");
  });

  it("exports a report with counts, unsupported rows, history, and follow-up links", () => {
    const readiness = buildMigrationReadiness(preview, activeImport, [activeImport]);
    const report = buildMigrationReport({
      source: "neuvector",
      preview,
      activeImport,
      imports: [activeImport],
      readiness,
      actions: MIGRATION_RECOMMENDED_ACTIONS,
    });

    expect(report).toContain("# NeuVector Migration Report");
    expect(report).toContain("- Source objects: 5");
    expect(report).toContain("- Total items: 4");
    expect(report).toContain("- Process profiles: 1");
    expect(report).toContain("- Groups: 1");
    expect(report).toContain("- Network rules: 1");
    expect(report).toContain("## Source Counts");
    expect(report).toContain("- Admission rules: 1");
    expect(report).toContain("file_profile nv.default.api: requires workload mapping");
    expect(report).toContain("import-1 NeuVector partial_applied");
    expect(report).toContain("Enable attestation trust");
    expect(report).toContain("/settings/effective-config");
  });

  it("reports remaining-family changes separately from unchanged objects and omitted credentials", () => {
    const remaining = remainingFixture as MigrationPreview;
    const history: MigrationImportListItem = {
      id: remaining.import_id!, source: "neuvector", status: "partial_applied",
      summary: remaining.summary, unsupported: remaining.unsupported,
      applied_summary: { created: 1, updated: 1, vulnerability_profiles: 1, registries: 1, unchanged: 1 },
      created_at: "2026-09-26T00:00:00Z",
    };
    const readiness = buildMigrationReadiness(remaining, history, [history]);
    expect(readiness.find((item) => item.id === "manual-mapping")?.detail).toMatch(/not imported/i);
    expect(readiness.find((item) => item.id === "partial-apply")?.detail).not.toContain("queued records remain");
    const report = buildMigrationReport({
      source: "neuvector", preview: remaining, activeImport: history,
      imports: [history], readiness, actions: MIGRATION_RECOMMENDED_ACTIONS,
    });
    expect(report).toContain("Vulnerability profiles: 2");
    expect(report).toContain("Registries: 1");
    expect(report).toContain("Unchanged: 1");
    expect(report).toContain("must be reissued");
    expect(report).toContain("REDACTED");
    expect(report).not.toContain("Unsupported Or Queued Objects");
    expect(migrationAppliedSummaryLabel(history.applied_summary!)).toContain("2 object changes applied");
    expect(migrationAppliedSummaryLabel(history.applied_summary!)).toContain("1 unchanged");
  });
});

function categoryFor(items: MigrationReadinessItem[], id: string) {
  return items.find((item) => item.id === id)?.category;
}
