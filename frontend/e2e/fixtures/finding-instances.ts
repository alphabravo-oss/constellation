import { expect, type Page } from "@playwright/test";
import type { Finding } from "../../src/api/client";
import { notificationThreats } from "./network-inventory";

export const instanceCluster = "11111111-1111-4111-8111-111111111111";
export const instanceID = "33333333-3333-4333-8333-333333333333";
export const instanceRoot = `/clusters/${instanceCluster}/findings`;
export const instanceTimes = ["2026-10-10T00:00:00.123456Z", "2026-10-10T00:00:00.123457Z"];
const seconds = Date.parse("2026-10-10T00:00:00Z") / 1000;
const comment = (id: string, body: string) => ({ id, body, author_id: "operator", created_at: "2026-10-11T00:00:00Z" });

// The backend suite proves persistence/tenant scope. This independent browser
// fixture catches URL, selection, draft and cache conflation at microseconds.
export function findingInstances() {
  const rows: Finding[] = instanceTimes.map((first_seen_at, i) => ({
    id: instanceID, row_id: `${instanceID}:${seconds}.${123456 + i}`, revision: "1",
    first_seen_at, last_seen_at: first_seen_at, cluster_id: instanceCluster,
    source_cluster_id: instanceCluster, target_cluster_id: null,
    kind: "vulnerability", external_id: "CVE-2099-1234", title: `Retained observation ${i + 1}`,
    severity: "high", lifecycle: "open", risk_score: 75, attack_techniques: [], asset_id: "",
  }));
  const comments = rows.map((_, i) => [comment(`comment-${i}`, `Discussion for observation ${i + 1}`)]);
  const writes: Array<{ firstSeen: string; action: string; body: Record<string, string>; status: number }> = [];
  const href = (index: number, action = "") => `${instanceRoot}/${instanceID}${action ? `/${action}` : ""}?${new URLSearchParams({ first_seen_at: instanceTimes[index] })}`;
  async function install(page: Page) {
    await page.route("**/api/v1/**", async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname.replace(/^\/api\/v1/, "");
      const method = request.method();
      if (path === "/auth/me") return route.fulfill({ json: { user_id: "operator", org_id: "org", email: "operator@example.test", roles: ["GlobalAdmin"] } });
      if (path === "/clusters") return route.fulfill({ json: { clusters: [{ id: instanceCluster, name: "Observation fixture", state: "connected" }] } });
      if (path === "/runtime-threats") return route.fulfill({ json: notificationThreats(url) });
      if (path === "/findings") {
        const lifecycle = url.searchParams.get("lifecycle");
        const selected = rows.filter(row => !lifecycle || lifecycle === "all" || row.lifecycle === lifecycle);
        const offset = Number(url.searchParams.get("offset") ?? 0), limit = Number(url.searchParams.get("limit") ?? 100);
        if (url.searchParams.has("cluster_id")) expect(url.searchParams.get("cluster_id")).toBe(instanceCluster);
        if (url.searchParams.has("q")) expect(url.searchParams.get("q")).toBe(`id:${instanceID}`);
        return route.fulfill({ json: { findings: selected.slice(offset, offset + limit), total: selected.length, limit, offset, has_more: offset + limit < selected.length, lifecycle_counts: Object.fromEntries(["open", "triaged", "in_progress", "resolved", "accepted", "suppressed"].map(state => [state, rows.filter(row => row.lifecycle === state).length])) } });
      }
      if (path === `/findings/${instanceID}`) {
        expect(method, "Legacy ambiguity must never dispatch a write").toBe("GET");
        return route.fulfill({ status: 409, json: { code: "ambiguous_finding_id", error: "Multiple retained observations" } });
      }
      const match = path.match(new RegExp(`^/finding-instances/${instanceID}(?:/(comments|triage|suppress|accept-risk))?$`));
      if (match) {
        expect(url.searchParams.getAll("first_seen_at")).toHaveLength(1);
        expect(url.searchParams.get("cluster_id")).toBe(instanceCluster);
        const index = instanceTimes.indexOf(url.searchParams.get("first_seen_at")!);
        expect(index, "Raw microsecond selector must identify exactly one observation").toBeGreaterThanOrEqual(0);
        const row = rows[index], action = match[1] ?? "detail";
        if (method === "GET") {
          if (action === "comments") return route.fulfill({ json: { ...row, comments: comments[index], legacy_comments: [comment("legacy", "Earlier unqualified discussion")], legacy_history_scope: "uuid" } });
          expect(action).toBe("detail");
          return route.fulfill({ json: row });
        }
        expect(method).toBe("POST");
        const body = request.postDataJSON() as Record<string, string>;
        const status = body.reviewed_revision === row.revision ? 200 : 409;
        writes.push({ firstSeen: row.first_seen_at, action, body, status });
        if (status === 409) return route.fulfill({ status, json: { code: "finding_revision_conflict", error: "Observation changed" } });
        if (action === "comments") {
          const added = comment(`added-${index}-${comments[index].length}`, body.body);
          comments[index].push(added);
          return route.fulfill({ json: { ...row, ...added, finding_id: row.id, status: "ok" } });
        }
        row.lifecycle = action === "triage" ? "triaged" : action === "suppress" ? "suppressed" : "accepted";
        row.revision = String(BigInt(row.revision!) + 1n);
        return route.fulfill({ json: { ...row, status: "ok" } });
      }
      return route.fulfill({ status: 404, json: { error: `Outside finding observation fixture: ${path}` } });
    });
  }
  return { install, rows, comments, writes, href };
}
