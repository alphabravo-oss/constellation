import { test, expect, type Page } from "@playwright/test";

const accessCookie = "__Host-constellation-session";
const refreshCookie = "__Host-constellation-refresh";

async function signIn(page: Page) {
  await page.goto("/auth/login");
  await page.getByLabel("Email").fill("admin@demo.test");
  await page.getByLabel("Password", { exact: true }).fill("Constellation!1");
  const responsePromise = page.waitForResponse((response) => response.url().endsWith("/api/v1/auth/login") && response.request().method() === "POST");
  await page.getByRole("button", { name: /^Sign in$/ }).click();
  const response = await responsePromise;
  expect(response.status()).toBe(200);
  expect(await response.json()).not.toHaveProperty("token");
  await expect(page).toHaveURL(/\/clusters$/);
}

test("browser credentials remain HttpOnly and absent from JavaScript storage", async ({ page, context }) => {
  await signIn(page);
  const cookies = (await context.cookies()).filter((cookie) => [accessCookie, refreshCookie].includes(cookie.name));
  expect(cookies).toHaveLength(2);
  for (const cookie of cookies) {
    expect(cookie.httpOnly).toBe(true);
    expect(cookie.secure).toBe(true);
    expect(cookie.sameSite).toBe("Strict");
    expect(cookie.path).toBe("/");
  }
  const access = cookies.find((cookie) => cookie.name === accessCookie)!;
  expect(access.expires - Date.now() / 1000).toBeLessThanOrEqual(900);
  expect(await page.evaluate(() => document.cookie)).not.toContain("constellation-session");
  expect(await page.evaluate(() => document.cookie)).not.toContain("constellation-refresh");
  expect(await page.evaluate(() => localStorage.getItem("constellation.token"))).toBeNull();
  expect(await page.evaluate(() => sessionStorage.getItem("constellation.token"))).toBeNull();
});

test("expired access recovers across two tabs without replaying the refresh token", async ({ page, context }) => {
  await signIn(page);
  const before = (await context.cookies()).find((cookie) => cookie.name === refreshCookie)!;
  await context.clearCookies({ name: accessCookie });
  const sibling = await context.newPage();
  await Promise.all([page.reload(), sibling.goto("/clusters")]);
  await expect(page.getByRole("heading", { name: /^Clusters$/ })).toBeVisible();
  await expect(sibling.getByRole("heading", { name: /^Clusters$/ })).toBeVisible();
  const after = (await context.cookies()).find((cookie) => cookie.name === refreshCookie)!;
  expect(after.value).not.toBe(before.value);
  expect(Math.abs(after.expires - before.expires)).toBeLessThan(1);
  await context.clearCookies({ name: accessCookie });
  await page.reload();
  await expect(page.getByRole("heading", { name: /^Clusters$/ })).toBeVisible();
  const later = (await context.cookies()).find((cookie) => cookie.name === refreshCookie)!;
  expect(later.value).not.toBe(after.value);
  await page.getByLabel("User menu").click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/auth\/login(?:\?|$)/);
  await expect(sibling).toHaveURL(/\/auth\/login(?:\?|$)/);
});

test("cookie mutations require CSRF protection and configuration reports live provenance", async ({ page, context, baseURL }) => {
  await signIn(page);
  const denied = await context.request.post(`${baseURL}/api/v1/auth/logout`, {
    headers: { Origin: "https://untrusted.example", "X-Constellation-Client": "browser" },
  });
  expect(denied.status()).toBe(403);
  const result = await page.evaluate(async () => {
    const headers = { "Content-Type": "application/json", "X-Constellation-Client": "browser" };
    const invalid = await fetch("/api/v1/system/config", {
      method: "PATCH", headers, body: JSON.stringify({ egress_proxy: { https_proxy: "malformed-credential-secret" } }),
    });
    const changed = await fetch("/api/v1/system/config", {
      method: "PATCH", headers, body: JSON.stringify({ tls_verify: false }),
    });
    return { invalidStatus: invalid.status, invalidBody: await invalid.text(), changedStatus: changed.status, config: await changed.json() };
  });
  expect(result.invalidStatus).toBe(400);
  expect(result.invalidBody).not.toContain("malformed-credential-secret");
  expect(JSON.parse(result.invalidBody).field_errors[0].field).toBe("egress_proxy.https_proxy");
  expect(result.changedStatus).toBe(200);
  expect(result.config.config.tls_verify).toBe(false);
  expect(result.config.provenance.tls_verify.source).toBe("database");
  expect(result.config.applied.provider.revision).toBe(result.config.revision);
  expect(result.config.applied.provider.scope).toBe("serving_replica");
  const restored = await page.evaluate(async () => (await fetch("/api/v1/system/config", {
    method: "PATCH", headers: { "Content-Type": "application/json", "X-Constellation-Client": "browser" },
    body: JSON.stringify({ tls_verify: true }),
  })).status);
  expect(restored).toBe(200);
  await page.goto("/settings/effective-config");
  await expect(page.getByTestId("effective-config-provider-applied")).toBeVisible();
});

test("refresh reuse revokes the session and does not allow browser recovery", async ({ page, context, baseURL }) => {
  await signIn(page);
  const before = (await context.cookies()).find((cookie) => cookie.name === refreshCookie)!;
  const headers = { Origin: baseURL!, "X-Constellation-Client": "browser" };
  const rotated = await context.request.post(`${baseURL}/api/v1/auth/refresh`, { headers });
  expect(rotated.status()).toBe(200);
  expect(await rotated.json()).not.toHaveProperty("token");
  const replay = await context.request.post(`${baseURL}/api/v1/auth/refresh`, {
    headers: { ...headers, Cookie: `${refreshCookie}=${before.value}` },
  });
  expect(replay.status()).toBe(401);
  await page.reload();
  await expect(page).toHaveURL(/\/auth\/login$/);
});
