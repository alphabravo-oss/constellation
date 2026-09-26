import { expect, test, type Page } from "@playwright/test";

const clusterId = "precedence-cluster";
const base = `/clusters/${clusterId}`;

type Rule = {
  id: number;
  from: string;
  to: string;
  ports: string;
  applications: string[];
  action: "allow" | "deny";
  comment: string;
  learned: boolean;
  disable: boolean;
  cfg_type: string;
  priority: number;
  match_counter: number;
  last_match_timestamp: number;
};

const fixtureRules: Rule[] = [
  { id: 20, from: "alpha", to: "external", ports: "tcp/443", applications: [], action: "allow", comment: "", learned: false, disable: false, cfg_type: "user_created", priority: 100, match_counter: 1, last_match_timestamp: 0 },
  { id: 5, from: "beta", to: "external", ports: "tcp/8443", applications: [], action: "deny", comment: "", learned: false, disable: false, cfg_type: "user_created", priority: 200, match_counter: 900, last_match_timestamp: 0 },
  { id: 11, from: "gamma", to: "external", ports: "tcp/9443", applications: [], action: "allow", comment: "", learned: false, disable: false, cfg_type: "user_created", priority: 300, match_counter: 20, last_match_timestamp: 0 },
];

async function installFixture(page: Page) {
  let rules = fixtureRules.map((rule) => ({ ...rule }));
  const moves: Array<{ from: string; to: string }> = [];
  let listRequests = 0;

  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
    const method = request.method();
    let response: unknown;

    if (path === "/auth/me" && method === "GET") {
      response = { user_id: "precedence-user", org_id: "precedence-org", email: "precedence@example.test", roles: ["GlobalAdmin"] };
    } else if (path === "/clusters" && method === "GET") {
      response = { clusters: [{ id: clusterId, name: "Precedence Fixture", state: "connected" }] };
    } else if (path === `/clusters/${clusterId}/network-rules` && method === "GET") {
      listRequests += 1;
      response = { cluster_id: clusterId, rules, summary: { total: rules.length, allow: 2, deny: 1, learned: 0, disabled: 0 } };
    } else if (path === `/clusters/${clusterId}/network-rules:move-top` && method === "POST") {
      const body = request.postDataJSON() as { from: string; to: string };
      const index = rules.findIndex((rule) => rule.from === body.from && rule.to === body.to);
      expect(index).toBeGreaterThan(0);
      moves.push(body);
      const moved = { ...rules[index], priority: rules[0].priority - 10 };
      rules = [moved, ...rules.filter((_, ruleIndex) => ruleIndex !== index)];
      response = { ok: true, priority: moved.priority };
    } else if (path === "/migration/imports" && method === "GET") {
      response = { imports: [], has_more: false };
    } else if (path === "/runtime-dlp-rules" && method === "GET") {
      response = { rules: [] };
    } else if (path === "/runtime-signatures" && method === "GET") {
      response = { signatures: [] };
    } else if (path === "/groups" && method === "GET") {
      response = { groups: [] };
    } else if (path === "/vuln-profiles" && method === "GET") {
      response = { profiles: [] };
    } else if (path === "/response-rules-v2" && method === "GET") {
      response = { rules: [] };
    } else if (path === "/findings" && method === "GET") {
      response = { findings: [] };
    } else if (path === "/runtime-threats" && method === "GET") {
      response = { threats: [] };
    } else {
      await route.fulfill({ status: 404, json: { error: `Unexpected fixture request: ${method} ${path}` } });
      return;
    }
    await route.fulfill({ status: 200, json: response });
  });

  return { moves, listRequests: () => listRequests };
}

test("Policy Center precedence links open the correct cluster rule pages", async ({ page }) => {
  await installFixture(page);
  await page.goto(`${base}/policy`);
  await expect(page.getByTestId("policy-center-page")).toBeVisible();

  const network = page.getByTestId("policy-family-network-rules-reorder");
  const response = page.getByTestId("policy-family-response-rules-reorder");
  await expect(network).toContainText("arbitrary positions are not supported");
  await expect(network).toContainText("initially follows evaluation order");
  await expect(response).toContainText("Move response rules up or down");
  await expect(page.getByTestId("policy-family-admission-reorder")).toHaveCount(0);
  await expect(network.getByRole("link", { name: "Manage Network Rules precedence" })).toHaveAttribute("href", `${base}/network-rules`);
  await expect(response.getByRole("link", { name: "Manage Response Rules precedence" })).toHaveAttribute("href", `${base}/response-rules`);

  await network.getByRole("link", { name: "Manage Network Rules precedence" }).click();
  await expect(page).toHaveURL(new RegExp(`${base}/network-rules$`));
  await expect(page.getByRole("heading", { name: "Network Rules", exact: true })).toBeVisible();
  await page.goBack();
  await expect(page.getByTestId("policy-center-page")).toBeVisible();
  await page.getByRole("link", { name: "Manage Response Rules precedence" }).click();
  await expect(page).toHaveURL(new RegExp(`${base}/response-rules$`));
  await expect(page.getByRole("heading", { name: "Response Rules", exact: true })).toBeVisible();
});

test("Network Rules initially follows API evaluation order and move-to-top refetches it", async ({ page }) => {
  const fixture = await installFixture(page);
  await page.goto(`${base}/network-rules`);
  const rows = page.locator("table tbody tr");
  await expect(rows).toHaveCount(3);
  await expect(rows).toContainText(["alpha", "beta", "gamma"]);
  await expect(rows.first().getByRole("button", { name: "Already highest precedence" })).toBeDisabled();
  await expect(page.getByText("Initially shown in server evaluation order.", { exact: false })).toBeVisible();

  await page.getByRole("button", { name: "Matches", exact: true }).click();
  await expect(rows).toContainText(["beta", "gamma", "alpha"]);
  expect(fixture.moves).toHaveLength(0);

  await page.getByPlaceholder("Search from, to, application, port…").fill("gamma");
  await expect(rows).toHaveCount(1);
  await expect(rows.first().getByRole("button", { name: "Move to top (evaluate first)" })).toBeEnabled();
  await rows.first().getByRole("button", { name: "Move to top (evaluate first)" }).click();
  await expect.poll(() => fixture.moves).toEqual([{ from: "gamma", to: "external" }]);
  await expect.poll(() => fixture.listRequests()).toBeGreaterThanOrEqual(2);

  await page.getByPlaceholder("Search from, to, application, port…").fill("");
  await page.getByRole("button", { name: "Matches", exact: true }).click();
  await page.getByRole("button", { name: "Matches", exact: true }).click();
  await expect(rows).toContainText(["gamma", "alpha", "beta"]);
  await expect(rows.first()).toContainText("90");
  await expect(rows.first().getByRole("button", { name: "Already highest precedence" })).toBeDisabled();
});
