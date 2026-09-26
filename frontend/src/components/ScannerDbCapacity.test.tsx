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

function statusValue(html: string, label: string): string | undefined {
  const labelAt = html.indexOf(`>${label}</dt>`);
  return labelAt < 0 ? undefined : html.slice(labelAt).match(/<dd[^>]*>(.*?)<\/dd>/)?.[1];
}

it("shows each engine's download and applied revisions separately from the host bundle", () => {
  const html = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[
    scanner("a", "healthy", {
      max_concurrent: 4,
      active_jobs: 2,
      idle_capacity: 2,
      vulndb: { bundle_version: "host-only-bundle" },
      engine_db: {
        trivy: { download_revision: "trivy-down-1", applied_revision: "trivy-applied-1", status: "ready" },
        grype: { download_revision: "grype-down-1", applied_revision: "grype-applied-1", status: "updating" },
      },
    }),
  ]} />);

  expect(statusValue(html, "Worker capacity")).toContain("2 idle / 4 slots");
  expect(statusValue(html, "Host VulnDB applied bundle")).toBe("host-only-bundle");
  expect(statusValue(html, "Trivy DB download revision")).toBe("trivy-down-1");
  expect(statusValue(html, "Trivy DB applied revision")).toBe("trivy-applied-1");
  expect(statusValue(html, "Trivy DB status")).toBe("ready");
  expect(statusValue(html, "Grype DB download revision")).toBe("grype-down-1");
  expect(statusValue(html, "Grype DB applied revision")).toBe("grype-applied-1");
  expect(statusValue(html, "Grype DB status")).toBe("updating");
  expect(html.match(/host-only-bundle/g)).toHaveLength(1);
});

it("shows partial reporting across live scanners without counting stale or crashlooping reports", () => {
  const html = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[
    scanner("a", "healthy", { max_concurrent: 4, active_jobs: 2, idle_capacity: 2, vulndb: { bundle_version: "host-v1" }, engine_db: { trivy: { download_revision: "trivy-d1", applied_revision: "trivy-a1", status: "ready" } } }),
    scanner("b", "degraded", { max_concurrent: 3, active_jobs: 1, idle_capacity: 2, vulndb: { bundle_version: "host-v2" }, engine_db: { trivy: { download_revision: "trivy-d2" }, grype: { applied_revision: "grype-a2", status: "unknown" } } }),
    scanner("c", "healthy", undefined),
    scanner("stale", "stale", { max_concurrent: 8, active_jobs: 0, idle_capacity: 8, vulndb: { bundle_version: "stale-host" }, engine_db: { trivy: { download_revision: "stale-revision" } } }),
    scanner("crashlooping", "crashlooping", { engine_db: { grype: { applied_revision: "crashloop-revision" } } }),
    { ...scanner("controller", "healthy", { engine_db: { trivy: { download_revision: "controller-revision" } } }), component: "controller" },
  ]} />);

  expect(html).toContain("4 idle / 7 slots · 3 active (2 workers)");
  expect(statusValue(html, "Host VulnDB applied bundle")).toBe("host-v1, host-v2");
  expect(statusValue(html, "Trivy DB download revision")).toBe("trivy-d1, trivy-d2 (2/3 reporting)");
  expect(statusValue(html, "Trivy DB applied revision")).toBe("trivy-a1 (1/3 reporting)");
  expect(statusValue(html, "Trivy DB status")).toBe("ready (1/3 reporting)");
  expect(statusValue(html, "Grype DB download revision")).toBe("Not reported");
  expect(statusValue(html, "Grype DB applied revision")).toBe("grype-a2 (1/3 reporting)");
  expect(statusValue(html, "Grype DB status")).toBe("unknown (1/3 reporting)");
  expect(html).not.toMatch(/stale-host|stale-revision|crashloop-revision|controller-revision/);
});

it("distinguishes no live scanner, missing fields, loading, and unavailable reports from zero capacity", () => {
  const empty = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[]} />);
  const stale = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[scanner("old", "stale", { engine_db: { trivy: { download_revision: "old" } } })]} />);
  const loading = renderToStaticMarkup(<ScannerDbCapacity loading />);
  const unavailable = renderToStaticMarkup(<ScannerDbCapacity unavailable />);
  const zero = renderToStaticMarkup(<ScannerDbCapacity heartbeats={[scanner("idle", "healthy", { max_concurrent: 0, active_jobs: 0, idle_capacity: 0, engine_db: { trivy: { download_revision: "downloaded" } } })]} />);

  expect(statusValue(empty, "Trivy DB download revision")).toBe("No active scanner report");
  expect(statusValue(stale, "Trivy DB download revision")).toBe("No active scanner report");
  expect(stale).not.toContain("old");
  expect(statusValue(loading, "Trivy DB download revision")).toBe("Loading...");
  expect(statusValue(unavailable, "Trivy DB download revision")).toBe("Unavailable");
  expect(zero).toContain("0 idle / 0 slots · 0 active (1 worker)");
  expect(statusValue(zero, "Trivy DB download revision")).toBe("downloaded");
  expect(statusValue(zero, "Trivy DB applied revision")).toBe("Not reported");
  expect(statusValue(zero, "Grype DB download revision")).toBe("Not reported");
  expect(statusValue(zero, "Grype DB applied revision")).toBe("Not reported");
});
