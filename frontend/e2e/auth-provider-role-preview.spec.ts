import { expect, test } from "@playwright/test";

for (const type of ["ldap", "saml", "oidc"]) {
  test(`${type} saved role preview is redacted and distinguishes org and namespace grants`, async ({ page }) => {
    const calls: { path: string; body: unknown }[] = [];
    const provider = {
      id: type, type, name: `${type.toUpperCase()} provider`, enabled: true, auth_order: 0,
      config: type === "ldap" ? { url: "ldaps://directory.example.test", bind_password: "***REDACTED***" }
        : type === "saml" ? { entity_id: "urn:example:provider", sp_key_pem: "***REDACTED***" }
          : { issuer_url: "https://id.example.test", client_secret: "***REDACTED***" },
      role_mapping: { rules: { "sec-team": "SecurityAdmin" }, default: "Auditor" }, revision: 1,
    };
    await page.route("**/api/v1/**", async (route) => {
      const request = route.request();
      const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
      if (path === "/auth/me") {
        await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
      } else if (path === "/clusters") {
        await route.fulfill({ json: { clusters: [] } });
      } else if (path === "/auth-servers" && request.method() === "GET") {
        await route.fulfill({ json: { auth_servers: [provider] } });
      } else if (path === `/auth-servers/${type}/scoped-mappings` && request.method() === "GET") {
        await route.fulfill({ json: { scoped_mappings: [{ id: "mapping", group: "sec-team", role: "Analyst", cluster_id: "cluster-id", namespace: "prod" }] } });
      } else if (path === `/auth-servers/${type}/role-preview`) {
        calls.push({ path, body: request.postDataJSON() });
        await route.fulfill({ json: {
          provider_type: type, input_kind: `${type}_group`, group_count: 2, matched_group_count: 1,
          default_applied: false, grants: [
            { role: "SecurityAdmin", scope: "organization" },
            { role: "Analyst", scope: "namespace", cluster_id: "cluster-id", namespace: "prod" },
          ],
        } });
      } else {
        await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
      }
    });

    await page.goto(`/settings/access/sso/${type}`);
    await expect(page.getByRole("heading", { name: "Mapped access preview" })).toBeVisible();
    await expect(page.getByText("No directory search, assertion verification, token validation, or sign-in occurs.")).toBeVisible();
    await page.getByRole("textbox", { name: type === "ldap" ? "Resolved LDAP group CNs" : type === "saml" ? "SAML group attribute values" : "OIDC groups claim values" }).fill("Sec-Team\nprivate-group");
    await page.getByRole("button", { name: "Preview saved mapping" }).click();
    await expect(page.getByRole("status")).toContainText("1 of 2 group values matched.");
    await expect(page.getByRole("status")).toContainText("SecurityAdmin · organization");
    await expect(page.getByRole("status")).toContainText("Analyst · namespace cluster-id / prod");
    expect(calls).toEqual([{ path: `/auth-servers/${type}/role-preview`, body: { groups: ["Sec-Team", "private-group"] } }]);
    await expect(page.getByRole("status")).not.toContainText("private-group");
  });
}

test("provider editor saves normalized rules and manages scoped grants", async ({ page }) => {
  const provider = {
    id: "oidc", type: "oidc", name: "OIDC provider", enabled: true, auth_order: 0,
    config: { issuer_url: "https://id.example.test", client_id: "client", client_secret: "***REDACTED***" },
    role_mapping: { rules: {}, default: "Auditor" }, revision: 1,
  };
  const saved: unknown[] = [];
  let mappings: { id: string; group: string; role: string; cluster_id: string; namespace: string }[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    else if (path === "/clusters") await route.fulfill({ json: { clusters: [] } });
    else if (path === "/auth-servers" && request.method() === "GET") await route.fulfill({ json: { auth_servers: [provider] } });
    else if (path === "/auth-servers/oidc/scoped-mappings" && request.method() === "GET") await route.fulfill({ json: { scoped_mappings: mappings } });
    else if (path === "/auth-servers/oidc/scoped-mappings" && request.method() === "POST") {
      mappings = [{ id: "new-map", ...request.postDataJSON(), group: request.postDataJSON().group.toLowerCase() }];
      await route.fulfill({ status: 201, json: mappings[0] });
    } else if (path === "/auth-servers/oidc/scoped-mappings/new-map" && request.method() === "DELETE") {
      mappings = [];
      await route.fulfill({ json: { status: "deleted" } });
    } else if (path === "/auth-servers/oidc" && request.method() === "PUT") {
      saved.push(request.postDataJSON());
      await route.fulfill({ json: provider });
    } else await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
  });

  await page.goto("/settings/access/sso/oidc");
  await page.getByRole("textbox", { name: "Group value" }).fill("Ops-Team");
  await page.getByRole("textbox", { name: "Cluster ID" }).fill("123e4567-e89b-12d3-a456-426614174000");
  await page.getByRole("textbox", { name: "Namespace" }).fill("prod");
  await page.getByRole("button", { name: "Add scoped mapping" }).click();
  await expect(page.getByText(/ops-team → Analyst/)).toBeVisible();
  await page.getByRole("button", { name: "Remove" }).click();
  await expect(page.getByText(/ops-team → Analyst/)).toHaveCount(0);
  await page.getByRole("textbox", { name: "Organization role rules" }).fill("Ops-Team = SecurityAdmin");
  await page.getByRole("button", { name: "Save changes" }).click();
  await expect.poll(() => saved.length).toBe(1);
  expect(saved[0]).toMatchObject({ role_mapping: { rules: { "ops-team": "SecurityAdmin" }, default: "Auditor" } });
  expect(saved[0]).not.toMatchObject({ config: { client_secret: "***REDACTED***" } });
});
