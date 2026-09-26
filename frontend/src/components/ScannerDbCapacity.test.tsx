import { renderToStaticMarkup } from "react-dom/server";
import { expect, it } from "vitest";
import type { SystemHealthHeartbeat } from "@/api/client";
import { ScannerDbCapacity } from "./ScannerDbCapacity";

function scanner(hostname: string, status: string, metadata: SystemHealthHeartbeat["metadata"]): SystemHealthHeartbeat {
  return {
    component: "scanner",
    hostname,
    status,
    metadata,
    version: "1",
    commit: "test",
    commit_short: "test",
    uptime_seconds: 60,
    restart_count: 0,
    last_seen_at: "2026-09-26T00:00:00Z",
  };
}

it("shows live worker capacity and distinct applied host bundles without counting stale workers", () => {
  const html = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[
    scanner("a", "healthy", { max_concurrent: 4, active_jobs: 2, idle_capacity: 2, vulndb: { bundle_version: "host-v1" } }),
    scanner("b", "degraded", { max_concurrent: 3, active_jobs: 1, idle_capacity: 2, vulndb: { bundle_version: "host-v2" } }),
    scanner("stale", "stale", { max_concurrent: 8, active_jobs: 0, idle_capacity: 8, vulndb: { bundle_version: "old" } }),
    { ...scanner("controller", "healthy", { max_concurrent: 100 }), component: "controller" },
  ]} />);

  expect(html).toContain("4 idle / 7 slots · 3 active (2 workers)");
  expect(html).toContain("host-v1, host-v2");
  expect(html).not.toContain("old");
  expect(html).toContain("Engine DB download revision");
  expect(html).toContain("Engine DB applied revision");
  expect(html.match(/Not reported/g)).toHaveLength(2);
});

it("distinguishes missing, loading and unavailable reports from zero capacity", () => {
  const empty = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[]} />);
  const loading = renderToStaticMarkup(<ScannerDbCapacity loading />);
  const unavailable = renderToStaticMarkup(<ScannerDbCapacity unavailable />);
  const zero = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[scanner("idle", "healthy", { max_concurrent: 0, active_jobs: 0, idle_capacity: 0 })]} />);

  expect(empty).toContain("Not reported");
  expect(loading).toContain("Loading...");
  expect(unavailable).toContain("Unavailable");
  expect(zero).toContain("0 idle / 0 slots · 0 active (1 worker)");
});
