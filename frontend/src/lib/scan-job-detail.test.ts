import { describe, expect, it } from "vitest";

import type { ScanJob } from "@/api/client";
import {
  scanJobBundleRows,
  scanJobMetadataRows,
  scanJobRetryState,
  scanJobTargetRows,
  scanJobTimingRows,
} from "./scan-job-detail";

const baseJob: ScanJob = {
  id: "job-1",
  target_id: "target-1",
  target_type: "image",
  target_ref: "registry.example.com/payments/api:1.2.3",
  status: "pending",
  attempt_count: 0,
  max_attempts: 3,
  requested_at: "2026-08-23T12:00:00Z",
};

describe("scan job detail helpers", () => {
  it("classifies retry state for queued, scheduled, failed, and completed jobs", () => {
    expect(scanJobRetryState(baseJob)).toMatchObject({ label: "Queued", tone: "pending" });
    expect(scanJobRetryState({ ...baseJob, next_attempt_at: "2026-08-23T12:05:00Z" })).toMatchObject({
      label: "Retry scheduled",
      tone: "warning",
      detail: "2026-08-23T12:05:00Z",
    });
    expect(scanJobRetryState({ ...baseJob, status: "failed", attempt_count: 3 })).toMatchObject({
      label: "Attempts exhausted",
      tone: "error",
      detail: "3/3 attempts used",
    });
    expect(scanJobRetryState({ ...baseJob, status: "completed", attempt_count: 1 })).toMatchObject({
      label: "Complete",
      tone: "success",
    });
  });

  it("keeps only populated timing rows in lifecycle order", () => {
    expect(scanJobTimingRows({
      ...baseJob,
      claimed_at: "2026-08-23T12:01:00Z",
      last_error_at: "2026-08-23T12:02:00Z",
      finished_at: "2026-08-23T12:03:00Z",
    }).map((row) => row.label)).toEqual(["Requested", "Claimed", "Last error", "Finished"]);
  });

  it("extracts target, bundle, and top-level metadata details", () => {
    const job: ScanJob = {
      ...baseJob,
      source_type: "registry",
      source_ref: "prod-registry",
      image_digest: "sha256:abc",
      metadata: { namespace: "payments", labels: { app: "api" }, replicas: 3 },
      bundle_metadata: { bundle_version: "2026.08.23", payload_hash: "sha256:def", record_count: 42 },
    };

    expect(scanJobTargetRows(job)).toEqual(expect.arrayContaining([
      { label: "Source ref", value: "prod-registry" },
      { label: "Image digest", value: "sha256:abc" },
      { label: "metadata.namespace", value: "payments" },
      { label: "metadata.labels", value: "{\"app\":\"api\"}" },
    ]));
    expect(scanJobBundleRows(job)).toEqual(expect.arrayContaining([
      { label: "Bundle version", value: "2026.08.23" },
      { label: "Records", value: "42" },
    ]));
    expect(scanJobMetadataRows(["not", "an", "object"])).toEqual([]);
  });
});
