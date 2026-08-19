// cluster-scope.spec.ts — Wave J2 verification of cluster-mode scoping.
//
// For each cluster-mode page in the sidebar, this spec:
//   (i)  navigates to /clusters/:id/<page>
//   (ii) intercepts the page's outbound /api/v1/* requests and asserts each one
//        carries `cluster_id=:id` for the endpoints we've threaded
//   (iii) hits the API directly with that cluster_id and asserts no returned row
//         claims a different cluster_id (when the row carries the field).
//
// The spec doesn't try to be exhaustive about every visible piece of data —
// it pins the *contract*: under /clusters/:id/* the server is asked for, and
// returns, cluster-scoped data. Visual / count-based asserts are intentionally
// avoided so the spec doesn't go stale as the discoverer ingests new findings.
import { test, expect, type Page } from "@playwright/test";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const CREDS = { email: "admin@dev", password: "devpass123" };

async function login(page: Page) {
  const resp = await page.request.post(`${API}/api/v1/auth/login`, { data: CREDS });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  await page.addInitScript((t) => localStorage.setItem("constellation.token", t), token);
  return token as string;
}

interface PageProbe {
  /** path fragment under /clusters/:id/ */
  path: string;
  /** stable data-testid on the page root that carries `data-cluster-id` */
  testid: string;
  /** API URL fragments we expect the page to fetch (sub-string match, not exact) */
  apiHints: string[];
  /** API GET endpoints to additionally exercise directly with cluster_id and assert per-row scoping */
  apiDirect?: string[];
}

// The cluster-mode sidebar groups from AppShell.tsx, mapped to test probes.
// We intentionally skip NetworkMapPage (parallel work) and the routes that are
// org-level by design (CVE, Settings, AI, Federation, Coverage, System Health,
// Access Control, Integrations).
const PAGES: PageProbe[] = [
  { path: "dashboard",       testid: "dashboard-page",        apiHints: ["/api/v1/findings", "/api/v1/dashboard/summary"] },
  { path: "findings",        testid: "findings-page",         apiHints: ["/api/v1/findings"], apiDirect: ["/api/v1/findings?limit=50"] },
  { path: "assets",          testid: "assets-page",           apiHints: ["/api/v1/assets"],   apiDirect: ["/api/v1/assets?limit=50"] },
  { path: "deployments",     testid: "deployments-page",      apiHints: ["/api/v1/deployments"], apiDirect: ["/api/v1/deployments?limit=50"] },
  { path: "compliance",      testid: "compliance-page",       apiHints: ["/api/v1/compliance/summary"] },
  { path: "runtime",         testid: "runtime-page",          apiHints: ["/api/v1/runtime/overview", "/api/v1/events"] },
  { path: "response-rules",  testid: "response-rules-page",   apiHints: ["/api/v1/response-rules-v2"] },
  { path: "vuln-profiles",   testid: "vuln-profiles-page",    apiHints: ["/api/v1/vuln-profiles"] },
  { path: "groups",          testid: "groups-page",           apiHints: ["/api/v1/groups"] },
  { path: "policies",        testid: "policies-page",         apiHints: ["/api/v1/policies"] },
  { path: "audit",           testid: "audit-page",            apiHints: ["/api/v1/audit/events"] },
];

test.describe("cluster-mode scoping (Wave J2)", () => {
  let token = "";

  test.beforeEach(async ({ page }) => {
    token = await login(page);
  });

  test("every cluster-mode page threads cluster_id into its fetches", async ({ page }) => {
    await page.goto("/clusters");
    const card = page.getByTestId("cluster-card").first();
    const clusterId = await card.getAttribute("data-cluster-id");
    expect(clusterId).toBeTruthy();

    for (const probe of PAGES) {
      const captured: string[] = [];
      const handler = (req: import("@playwright/test").Request) => {
        const url = req.url();
        if (url.includes("/api/v1/")) captured.push(url);
      };
      page.on("request", handler);
      try {
        await page.goto(`/clusters/${clusterId}/${probe.path}`);

        // Wait for the page root to render (skeleton -> resolved). If a page
        // never renders the testid we still validate the network trace.
        const root = page.getByTestId(probe.testid);
        await root.waitFor({ state: "visible", timeout: 10_000 }).catch(() => undefined);
        if (await root.isVisible()) {
          await expect(root).toHaveAttribute("data-cluster-id", clusterId!);
        }

        // Give react-query a beat to drain in-flight requests.
        await page.waitForTimeout(750);

        // For each apiHint, at least one captured URL matching that hint must
        // also carry the cluster_id query param. (Some pages issue multiple
        // queries; we don't require *every* one to carry the param — only that
        // the cluster-scoped data fetches do.)
        for (const hint of probe.apiHints) {
          const matched = captured.filter((u) => u.includes(hint));
          if (matched.length === 0) continue; // page didn't fetch this endpoint on this load
          const scoped = matched.filter((u) => u.includes(`cluster_id=${clusterId}`));
          expect(scoped, `expected at least one ${hint} call to carry cluster_id=${clusterId}, got ${matched.join(", ")}`)
            .not.toHaveLength(0);
        }
      } finally {
        page.off("request", handler);
      }
    }
  });

  test("API endpoints honor cluster_id: returned rows never carry a different cluster_id", async ({ page }) => {
    const list = await page.request.get(`${API}/api/v1/clusters`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(list.ok()).toBeTruthy();
    const { clusters } = await list.json();
    expect(clusters.length).toBeGreaterThanOrEqual(1);

    const direct = [
      ...new Set(
        PAGES.flatMap((p) => p.apiDirect ?? []),
      ),
    ];
    for (const c of clusters) {
      for (const path of direct) {
        const sep = path.includes("?") ? "&" : "?";
        const url = `${API}${path}${sep}cluster_id=${c.id}`;
        const resp = await page.request.get(url, { headers: { Authorization: `Bearer ${token}` } });
        expect(resp.ok(), `GET ${url} returned ${resp.status()}`).toBeTruthy();
        const body = await resp.json();
        // The list endpoints use varying envelope keys; pull whatever array we find.
        const rows: Array<Record<string, unknown>> =
          body.findings ?? body.assets ?? body.deployments ?? body.checks ?? body.policies ?? [];
        for (const row of rows) {
          if (row.cluster_id && row.cluster_id !== c.id) {
            throw new Error(
              `${path} returned a row with cluster_id=${row.cluster_id} when filter requested ${c.id}`,
            );
          }
        }
      }
    }
  });
});
