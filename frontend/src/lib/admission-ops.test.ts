import { describe, expect, it } from "vitest";

import type { AdmissionAssessResult, ComponentInstance } from "@/api/client";
import {
  admissionAppliedRevision,
  admissionDryRunHistoryKey,
  admissionDryRunHistoryEntryFromRow,
  admissionWebhookHealth,
  appendAdmissionDryRunHistory,
  makeAdmissionDryRunHistoryEntry,
  mergeAdmissionDryRunHistory,
  readAdmissionDryRunHistory,
  writeAdmissionDryRunHistory,
} from "./admission-ops";

const assessResult: AdmissionAssessResult = {
  image: "ghcr.io/acme/api:latest",
  namespace: "payments",
  decision: "deny",
  enforcement_mode: "monitor",
  matches: [{ policy_name: "block latest", action: "deny", reason: "latest tag" }],
};

const componentBase: ComponentInstance = {
  id: "admission-1",
  component: "admission",
  display_name: "Admission Controller",
  role: "controller",
  scope: "cluster",
  kind: "deployment",
  status: "healthy",
  cluster_id: "cluster-1",
  version: "1.0.0",
  commit: "abcdef",
  commit_short: "abcdef",
  hostname: "admission-1",
  uptime_seconds: 300,
  restart_count: 0,
  first_seen_at: "2026-08-23T20:00:00Z",
  last_seen_at: "2026-08-23T21:00:00Z",
};

describe("admission operations helpers", () => {
  it("creates, stores, and bounds dry-run history entries", () => {
    const key = admissionDryRunHistoryKey("cluster-1");
    const entry = makeAdmissionDryRunHistoryEntry({
      result: assessResult,
      image: " ghcr.io/acme/api:latest ",
      clusterId: "cluster-1",
      currentOutcome: "Admit + log",
      protectOutcome: "Block",
      now: new Date("2026-08-23T21:10:00Z"),
      id: "history-1",
    });

    expect(entry).toMatchObject({
      id: "history-1",
      image: "ghcr.io/acme/api:latest",
      namespace: "payments",
      matches: 1,
      current_outcome: "Admit + log",
      protect_outcome: "Block",
    });

    const entries = appendAdmissionDryRunHistory([{ ...entry, id: "old" }], entry, 1);
    writeAdmissionDryRunHistory(key, entries);
    expect(readAdmissionDryRunHistory(key)).toEqual([entry]);
  });

  it("uses retained server dry-run metadata and de-duplicates merged history", () => {
    const serverBacked = makeAdmissionDryRunHistoryEntry({
      result: {
        ...assessResult,
        dry_run_id: "server-history-1",
        assessed_at: "2026-08-23T21:15:00Z",
        current_outcome: "Admit + log",
        protect_outcome: "Block",
      },
      image: "ghcr.io/acme/api:latest",
      clusterId: "cluster-1",
      currentOutcome: "Admit",
      protectOutcome: "Admit",
      now: new Date("2026-08-23T21:10:00Z"),
    });

    expect(serverBacked).toMatchObject({
      id: "server-history-1",
      assessed_at: "2026-08-23T21:15:00Z",
      current_outcome: "Admit + log",
      protect_outcome: "Block",
    });

    const retained = admissionDryRunHistoryEntryFromRow({
      id: "server-history-1",
      assessed_at: "2026-08-23T21:15:01Z",
      cluster_id: "cluster-1",
      image: "ghcr.io/acme/api:latest",
      namespace: "payments",
      decision: "deny",
      enforcement_mode: "monitor",
      current_outcome: "Admit + log",
      protect_outcome: "Block",
      matches: 1,
    });
    const localOnly = { ...serverBacked, id: "local-history-1", assessed_at: "2026-08-23T21:14:00Z" };

    expect(mergeAdmissionDryRunHistory([retained], [serverBacked, localOnly]).map((entry) => entry.id)).toEqual([
      "server-history-1",
      "local-history-1",
    ]);
  });

  it("classifies admission webhook heartbeat health and applied revision", () => {
    const live = admissionWebhookHealth([{ ...componentBase, metadata: { applied_revision: 42 } }]);
    expect(live).toMatchObject({ label: "Live", tone: "success", instances: 1, healthy: 1, appliedRevision: "42" });
    expect(admissionAppliedRevision({ ...componentBase, metadata: { admission: { policy_revision: "rev-9" } } })).toBe("rev-9");

    const degraded = admissionWebhookHealth([
      componentBase,
      { ...componentBase, id: "admission-2", status: "stale", status_reason: "last heartbeat too old", last_seen_at: "2026-08-23T20:30:00Z" },
    ]);
    expect(degraded).toMatchObject({ label: "Degraded", tone: "warning", healthy: 1 });

    expect(admissionWebhookHealth([])).toMatchObject({ label: "Not observed", tone: "warning" });
  });
});
