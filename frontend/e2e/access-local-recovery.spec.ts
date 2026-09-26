import { expect, test } from "@playwright/test";

test("local-user recovery controls call the scoped routes and exclude SSO users", async ({ page }) => {
  const userId = "11111111-1111-4111-8111-111111111111";
  const calls: string[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname.replace(/^\/api\/v1/, "");
    if (path === "/auth/me") {
      await route.fulfill({ json: { user_id: "admin", org_id: "org", email: "admin@example.test", roles: ["GlobalAdmin"] } });
    } else if (path === "/clusters") {
      await route.fulfill({ json: { clusters: [] } });
    } else if (path === "/auth-servers") {
      await route.fulfill({ json: { auth_servers: [] } });
    } else if (path === "/access-control") {
      await route.fulfill({ json: {
        summary: { users_total: 2, roles_total: 0, role_bindings_total: 0, api_tokens_total: 0 },
        users: [
          { id: userId, name: "Local User", email: "local@example.test", status: "active", auth_provider_id: "local", roles: [], last_login_at: "", mfa_enabled: false, local_password: true, locked: calls.length === 0, password_reset_required: calls.includes(`/users/${userId}/force-password-reset`) },
          { id: "sso", name: "SSO User", email: "sso@example.test", status: "active", auth_provider_id: "oidc:issuer", roles: [], last_login_at: "", mfa_enabled: true, local_password: false, locked: false, password_reset_required: false },
        ],
        roles: [], role_bindings: [], service_accounts: [], api_tokens: [], permission_matrix: [], guardrails: [],
      } });
    } else if (path === `/users/${userId}/unlock` || path === `/users/${userId}/force-password-reset`) {
      expect(request.method()).toBe("POST");
      calls.push(path);
      await route.fulfill({ json: { status: path.endsWith("unlock") ? "unlocked" : "reset_required" } });
    } else {
      await route.fulfill({ status: 404, json: { error: "Unexpected fixture request" } });
    }
  });

  await page.goto("/settings/access?tab=users");
  const users = page.getByTestId("access-users");
  await expect(users).toContainText("Local User");
  await expect(users.getByRole("button", { name: "Unlock" })).toHaveCount(1);
  await expect(users.getByRole("button", { name: "Require reset" })).toHaveCount(1);
  await expect(users).toContainText("No local password");

  page.on("dialog", (dialog) => dialog.accept());
  await users.getByRole("button", { name: "Unlock" }).click();
  await expect.poll(() => calls).toContain(`/users/${userId}/unlock`);
  await users.getByRole("button", { name: "Require reset" }).click();
  await expect.poll(() => calls).toContain(`/users/${userId}/force-password-reset`);
});
