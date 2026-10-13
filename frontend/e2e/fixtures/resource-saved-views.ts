import { expect, type Page } from "@playwright/test";
import { notificationThreats } from "./network-inventory";

export const savedViewCluster = "11111111-1111-4111-8111-111111111111";
export const savedViewSibling = "22222222-2222-4222-8222-222222222222";
export const savedViewRegistry = "33333333-3333-4333-8333-333333333333";
export const savedViewNode = "44444444-4444-4444-8444-444444444444";
export type SavedViewAdopter = "assets" | "deployments" | "runtime" | "scanner";
const uuid = (index: number) =>
  `00000000-0000-4000-8000-${String(index).padStart(12, "0")}`;

export const savedViewCases = [
  {
    kind: "assets",
    label: "asset",
    table: "assets-table",
    filters: {
      q: "needle",
      kind: "image",
      criticality: "high",
      ai_workload: "true",
      sort: "asset",
      order: "asc",
    },
  },
  {
    kind: "deployments",
    label: "deployment",
    table: "deployments-page",
    filters: {
      q: "needle",
      namespace: "prod",
      group_mode: "protect",
      risk_fact: "host_network",
      platform_role: "none",
      hide_platform: "false",
    },
  },
  {
    kind: "runtime",
    label: "runtime event",
    table: "runtime-live-table",
    filters: {
      tab: "live",
      q: "needle",
      kind: "exec",
      source: "runtime-agent",
      severity: "high",
      verdict: "alert",
      workload: "prod/needle",
      namespace: "prod",
      node: savedViewNode,
      after: "2026-01-01T00:00:00.123456789Z",
      before: "2030-01-01T02:00:00.987654321+02:00",
      sort: "at",
      order: "asc",
    },
  },
  {
    kind: "scanner",
    label: "scan job",
    table: "scanner-recent-jobs",
    filters: {
      tab: "jobs",
      q: "needle",
      status: "failed",
      target_type: "image",
      cluster_id: savedViewCluster,
      registry_id: savedViewRegistry,
      sort: "target",
      order: "asc",
    },
  },
] as const;

export function resourceSavedViewFixture(kind: SavedViewAdopter) {
  const definition = savedViewCases.find((item) => item.kind === kind)!;
  const at = new Date().toISOString();
  let owner = { org_id: "org-resource", user_id: "user-resource" };
  const requests: URL[] = [];
  const rows = ["needle", "other"].flatMap((query, queryIndex) =>
    Array.from({ length: 205 }, (_, index) => ({
      id: uuid(queryIndex * 1000 + index + 1),
      org_id: "org-resource",
      cluster_id: savedViewCluster,
      name: `${query}-${String(index + 1).padStart(4, "0")}`,
      query,
      namespace: "prod",
      platform_role: "",
      asset_kind: "image",
      criticality: "high",
      ai_workload: true,
      group_mode: "protect",
      risk_factors: { host_network: 0 } as Record<string, number>,
      event_kind: "exec",
      source: "runtime-agent",
      severity: "high",
      verdict: "alert",
      node_id: savedViewNode,
      registry_id: savedViewRegistry,
      status: "failed",
      target_type: "image",
      at,
    })),
  );
  // Negative cohorts exercise the predicates, rather than returning metadata that
  // simply mirrors any request. They must never enter the matching 205-row page.
  const negative = (name: string, change: Partial<(typeof rows)[number]>) =>
    rows.push({
      ...rows[0],
      id: uuid(9000 + rows.length),
      name: `needle-${name}`,
      ...change,
    });
  negative("sibling", { cluster_id: savedViewSibling });
  negative("foreign", { org_id: "org-foreign" });
  if (kind === "assets") {
    negative("workload", { asset_kind: "workload" });
    negative("low-criticality", { criticality: "low" });
    negative("not-ai", { ai_workload: false });
  } else if (kind === "deployments") {
    negative("namespace", { namespace: "other" });
    negative("platform", { platform_role: "core" });
    negative("unmatched-mode", { group_mode: "monitor" });
    negative("missing-fact", { risk_factors: { privileged: 1 } });
  } else if (kind === "runtime") {
    negative("namespace", { namespace: "other" });
    negative("node", { node_id: savedViewSibling });
    negative("severity", { severity: "low" });
    negative("verdict", { verdict: "observed" });
    negative("kind", { event_kind: "network" });
    negative("source", { source: "another-agent" });
    negative("old", { at: "2020-01-01T00:00:00Z" });
  } else {
    negative("registry", { registry_id: savedViewSibling });
    negative("status", { status: "completed" });
    negative("type", { target_type: "repository" });
  }

  const base =
    kind === "scanner"
      ? "/settings/scanner"
      : `/clusters/${savedViewCluster}/${kind}`;
  const params = new URLSearchParams(definition.filters);
  params.set("page", "2");
  params.set("selected", uuid(101));
  params.append("context", "return-proof");
  params.append("context", "second-value");
  if (kind === "runtime") {
    params.set("event", uuid(101));
    params.set("event_at", at);
  }
  const initial = `${base}?${params}#retained-context`;

  function inventory(url: URL) {
    const p = url.searchParams;
    const q = p.get(kind === "assets" ? "search" : "q");
    expect(["needle", "other"]).toContain(q);
    expect(p.get("cluster_id")).toBe(savedViewCluster);
    expect(p.get("limit")).toBe("100");
    const offset = Number(p.get("offset"));
    expect([0, 100, 200]).toContain(offset);
    // Assert every backend-owned filter; omitted filters cannot receive a valid
    // response even if the browser would otherwise accept its canned metadata.
    const expected: Record<string, string> =
      kind === "assets"
        ? {
            kind: "image",
            criticality: "high",
            ai_workload: "true",
            sort: "asset",
            order: "asc",
          }
        : kind === "deployments"
          ? {
              namespace: "prod",
              group_mode: "protect",
              risk_fact: "host_network",
              platform_role: "none",
              hide_platform: "false",
            }
          : kind === "runtime"
            ? {
                kind: "exec",
                source: "runtime-agent",
                severity: "high",
                verdict: "alert",
                workload: "prod/needle",
                namespace: "prod",
                node: savedViewNode,
                after: params.get("after")!,
                before: params.get("before")!,
                sort: "at",
                order: "asc",
              }
            : {
                status: "failed",
                target_type: "image",
                registry_id: savedViewRegistry,
                sort: "target",
                order: "asc",
              };
    for (const [key, value] of Object.entries(expected))
      expect(p.get(key), `${kind} filter ${key}`).toBe(value);
    const matching = rows
      .filter((row) => {
        if (
          row.org_id !== owner.org_id ||
          row.cluster_id !== p.get("cluster_id") ||
          !row.name.toLowerCase().includes(q!)
        )
          return false;
        if (kind === "assets")
          return (
            row.asset_kind === p.get("kind") &&
            row.criticality === p.get("criticality") &&
            String(row.ai_workload) === p.get("ai_workload")
          );
        if (kind === "deployments")
          return (
            row.namespace === p.get("namespace") &&
            row.group_mode === p.get("group_mode") &&
            Object.hasOwn(row.risk_factors, p.get("risk_fact")!) &&
            row.platform_role !== "core"
          );
        if (kind === "runtime")
          return (
            row.namespace === p.get("namespace") &&
            row.node_id === p.get("node") &&
            row.event_kind === p.get("kind") &&
            row.source === p.get("source") &&
            row.severity === p.get("severity") &&
            row.verdict === p.get("verdict") &&
            Date.parse(row.at) >= Date.parse(p.get("after")!) &&
            Date.parse(row.at) < Date.parse(p.get("before")!)
          );
        return (
          row.registry_id === p.get("registry_id") &&
          row.status === p.get("status") &&
          row.target_type === p.get("target_type")
        );
      })
      .sort((a, b) => a.name.localeCompare(b.name));
    expect(matching).toHaveLength(owner.org_id === "org-resource" ? 205 : 0);
    const page = matching.slice(offset, offset + 100),
      total = matching.length;
    const metadata = {
      limit: 100,
      offset,
      total,
      has_more: offset + page.length < total,
      sort: p.get("sort"),
      order: p.get("order"),
    };
    if (kind === "assets")
      return {
        ...metadata,
        assets: page.map((row) => ({
          ...row,
          display_name: `registry.test/${row.name}:stable`,
          kind: "image",
          criticality: "high",
          ai_workload: true,
          labels: {},
          first_seen_at: at,
          last_seen_at: at,
          risk_score: 70,
          open_findings: 1,
          critical_findings: 0,
          high_findings: 1,
          image_signed: false,
          sbom_count: 1,
        })),
        summary: {
          total,
          images: total,
          workloads: 0,
          critical_high: total,
          open_findings: total,
          unsigned_images: total,
          signed_images: 0,
          signature_unknown: 0,
          missing_sbom: 0,
          with_sbom: total,
          ai: total,
        },
      };
    if (kind === "deployments")
      return {
        ...metadata,
        deployments: page.map((row) => ({
          ...row,
          kind: "Deployment",
          labels: {},
          risk_score: 70,
          risk_factors: { host_network: 0 },
          finding_count: 1,
          critical_count: 0,
          high_count: 1,
          first_seen_at: at,
          last_seen_at: at,
        })),
        platform_count: 0,
        summary: {
          total,
          at_risk: total,
          finding_count: total,
          critical_count: 0,
          high_count: total,
        },
      };
    if (kind === "runtime")
      return {
        ...metadata,
        ...Object.fromEntries(p),
        cluster_id: savedViewCluster,
        limit: 100,
        offset,
        total,
        events: page.map((row) => ({
          id: row.id,
          row_id: `${row.id}@${at}`,
          cluster_id: savedViewCluster,
          at,
          kind: "exec",
          source: "runtime-agent",
          severity: "high",
          verdict: "alert",
          node_id: savedViewNode,
          namespace: "prod",
          workload_id: `prod/needle/${row.name}`,
          attack_techniques: [],
          payload: { message: row.name },
        })),
        summary: {
          total,
          alerting: total,
          blocks: 0,
          quarantines: 0,
          affected_workloads: total,
          observed: 0,
        },
      };
    return {
      ...metadata,
      jobs: page.map((row) => ({
        id: row.id,
        org_id: "org-resource",
        target_id: row.id,
        target_type: "image",
        target_ref: `registry.test/${row.name}:stable`,
        target_cluster_id: savedViewCluster,
        registry_id: savedViewRegistry,
        status: "failed",
        attempt_count: 1,
        max_attempts: 3,
        requested_at: at,
        error: "Metadata source unavailable",
      })),
      queue_metrics: [],
      summary: {
        total,
        pending: 0,
        running: 0,
        paused: 0,
        failed: total,
        completed: 0,
        canceled: 0,
      },
    };
  }

  async function install(page: Page) {
    await page.route("**/api/v1/**", async (route) => {
      expect(
        route.request().method(),
        "Saved-view acceptance only uses read-only APIs",
      ).toBe("GET");
      const url = new URL(route.request().url()),
        path = url.pathname.replace(/^\/api\/v1/, "");
      requests.push(url);
      if (path === "/auth/me")
        return route.fulfill({
          json: {
            ...owner,
            email: "resource@example.test",
            roles: ["GlobalAdmin"],
          },
        });
      if (path === "/clusters")
        return route.fulfill({
          json: {
            clusters: [
              {
                id: savedViewCluster,
                name: "Saved view cluster",
                state: "connected",
              },
              { id: savedViewSibling, name: "Sibling", state: "connected" },
            ],
          },
        });
      if (path === "/runtime-threats")
        return route.fulfill({ json: notificationThreats(url) });
      if (path === "/findings")
        return route.fulfill({
          json: {
            findings: [],
            total: 0,
            limit: Number(url.searchParams.get("limit") ?? 50),
            offset: 0,
            has_more: false,
            lifecycle_counts: {
              open: 0,
              accepted: 0,
              suppressed: 0,
              triaged: 0,
              in_progress: 0,
              resolved: 0,
            },
          },
        });
      const endpoint = {
        assets: "/assets",
        deployments: "/deployments",
        runtime: "/events",
        scanner: "/scan-jobs",
      }[kind];
      if (path === endpoint) return route.fulfill({ json: inventory(url) });
      if (path === "/runtime/overview") {
        expect(url.searchParams.get("cluster_id")).toBe(savedViewCluster);
        return route.fulfill({
          json: {
            summary: {
              window_hours: 24,
              events: 0,
              alerts: 0,
              blocks: 0,
              quarantines: 0,
              affected_workloads: 0,
              techniques: 0,
            },
            subsystems: [],
            modes: [],
            rules: [],
            recent_events: [],
            workloads: [],
          },
        });
      }
      if (path === "/system/config")
        return route.fulfill({
          json: {
            revision: 1,
            config: {
              scanner_db_refresh_minutes: 360,
              scanner_offline_db: false,
              nvd_enabled: true,
            },
          },
        });
      if (path === "/scan/status")
        return route.fulfill({
          json: { scanned: 0, scheduled: 0, scanning: 0, failed: 0, paused: 0 },
        });
      if (path === "/scan/scanner")
        return route.fulfill({ json: { scanners: [] } });
      if (path === "/system-health")
        return route.fulfill({
          json: { heartbeats: [], source_status: [], enforcement_overview: {} },
        });
      if (/^\/scan-jobs\/[\da-f-]+\/attempts$/.test(path))
        return route.fulfill({ json: { attempts: [] } });
      return route.fulfill({
        status: 404,
        json: { error: `No saved-view fixture for ${path}` },
      });
    });
  }
  return {
    definition,
    initial,
    base,
    params,
    requests,
    install,
    changeOwner: (org_id: string, user_id: string) => {
      owner = { org_id, user_id };
    },
  };
}
