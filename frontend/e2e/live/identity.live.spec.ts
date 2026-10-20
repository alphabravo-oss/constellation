import { expect, test, type APIRequestContext, type Page } from "@playwright/test";
import { execFileSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { LIVE_EMAIL, LIVE_PASSWORD } from "./env";

test("OIDC session is secure, bounded and mapped from the configured claim", async ({ page }) => {
  const res = await page.request.get("/api/v1/auth/me");
  expect(res.ok()).toBeTruthy();
  expect((await res.json()).roles).toContain("GlobalAdmin");
  const cookies = await page.context().cookies();
  const session = cookies.find(c => c.name === "__Host-constellation-session")!;
  expect(session.httpOnly).toBeTruthy(); expect(session.secure).toBeTruthy();
  expect(session.path).toBe("/"); expect(session.sameSite).toBe("Lax");
  expect(session.expires - Date.now() / 1000).toBeLessThanOrEqual(600);
  expect(cookies.some(c => c.name.includes("refresh"))).toBeFalsy();
  expect(session.value.startsWith("csi_")).toBeTruthy();
});

test("settings show one generic OIDC provider, its role map and break-glass status", async ({ page }) => {
  await page.goto("/settings/identity");
  await expect(page.getByRole("heading", { name: "Single sign-on provider (OIDC)", exact: true }).first()).toBeVisible();
  await expect(page.getByText("alphabravo_roles", { exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "platform-admins", exact: true })).toBeVisible();
  await expect(page.getByText("TOTP required", { exact: true })).toBeVisible();
  const response = await page.request.get("/api/v1/settings/identity");
  const settings = await response.json();
  expect(settings.oidc.roles_claim).toBe("alphabravo_roles");
  expect(settings.oidc.role_mapping["platform-admins"]).toBe("GlobalAdmin");
  expect(settings.break_glass.totp_required).toBeTruthy();
  for (const secret of ["client_secret", "password_hash", "totp_secret"]) expect(JSON.stringify(settings)).not.toContain(secret);
  await expect(page.getByRole("button", { name: "Add provider", exact: true })).toHaveCount(0);
  await page.screenshot({path:test.info().outputPath("identity-settings.png"),fullPage:true});
});

async function oidcLogin(page: Page) {
  await page.goto("/auth/login"); await page.getByRole("button", { name: "Continue with SSO" }).click();
  await page.locator("#username").fill(LIVE_EMAIL); await page.locator("#password").fill(LIVE_PASSWORD); await page.locator("#kc-login").click();
}

async function issuerAdmin(request: APIRequestContext) {
  const root = process.env.IDENTITY_PROOF_ROOT!;
  const response = await request.post(`${root}/realms/master/protocol/openid-connect/token`, { form: { grant_type: "password", client_id: "admin-cli", username: process.env.IDENTITY_PROOF_ADMIN_USER!, password: process.env.IDENTITY_PROOF_ADMIN_PASSWORD! } });
  expect(response.ok()).toBeTruthy();
  return { root: `${root}/admin/realms/constellation-proof`, headers: { Authorization: `Bearer ${(await response.json()).access_token}` } };
}

test("removing the upstream group removes access on the next OIDC token", async ({ browser, request, baseURL }) => {
  test.skip(!process.env.IDENTITY_PROOF_ROOT, "requires the throwaway issuer control credentials");
  const admin = await issuerAdmin(request);
  const users = await request.get(`${admin.root}/users?username=${encodeURIComponent(LIVE_EMAIL)}&exact=true`, { headers: admin.headers });
  const user = (await users.json())[0]; expect(user).toBeTruthy();
  const groups = await request.get(`${admin.root}/users/${user.id}/groups`, { headers: admin.headers });
  const group = (await groups.json()).find((g: { name: string }) => g.name === "platform-admins"); expect(group).toBeTruthy();
  const context = await browser.newContext({ baseURL, storageState: { cookies: [], origins: [] } });
  try {
    expect((await request.delete(`${admin.root}/users/${user.id}/groups/${group.id}`, { headers: admin.headers })).ok()).toBeTruthy();
    const page = await context.newPage(); await oidcLogin(page);
    await expect(page.locator("body")).toContainText("no mapped roles");
    expect((await context.request.get("/api/v1/auth/me")).status()).toBe(401);
  } finally {
    expect((await request.put(`${admin.root}/users/${user.id}/groups/${group.id}`, { headers: admin.headers })).ok()).toBeTruthy();
    await context.close();
  }
});

function totp(secret: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "";
  for (const c of secret.replace(/=/g, "").toUpperCase()) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const bytes = Buffer.from(bits.match(/.{8}/g)!.map(b => parseInt(b, 2)));
  const step = Buffer.alloc(8); step.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", bytes).update(step).digest(); const offset = h[h.length - 1] & 15;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1000000).padStart(6, "0");
}

test("break-glass signs in with the issuer down and emits an operator alert", async ({ browser, request, baseURL }) => {
  test.skip(!process.env.BREAK_GLASS_PASSWORD || !process.env.IDENTITY_PROOF_KUBE_NAMESPACE, "requires live emergency proof credentials");
  test.setTimeout(180_000);
  const namespace = process.env.IDENTITY_PROOF_KUBE_NAMESPACE!;
  const deployment = process.env.IDENTITY_PROOF_KUBE_DEPLOYMENT ?? "issuer";
  const context = await browser.newContext({ baseURL, storageState: { cookies: [], origins: [] } });
  try {
    const tokenResponse=await request.post(`${process.env.IDENTITY_PROOF_ROOT}/realms/constellation-proof/protocol/openid-connect/token`,{form:{grant_type:"password",client_id:"constellation",client_secret:process.env.IDENTITY_PROOF_CLIENT_SECRET!,username:LIVE_EMAIL,password:LIVE_PASSWORD,scope:"openid email profile"}});
    expect(tokenResponse.ok()).toBeTruthy();
    const bearer=(await tokenResponse.json()).access_token;
    // First sighting after the issuer is down still uses the last-good JWKS.
    execFileSync("kubectl", ["-n", namespace, "scale", `deployment/${deployment}`, "--replicas=0"]);
    await expect.poll(async () => (await request.get(`${process.env.IDENTITY_PROOF_ROOT}/realms/constellation-proof/.well-known/openid-configuration`)).status(), { timeout: 30_000 }).toBe(503);
    expect((await request.get("/api/v1/auth/me",{headers:{Authorization:`Bearer ${bearer}`}})).status()).toBe(200);
    const page = await context.newPage(); await page.goto("/auth/login");
    await page.getByRole("button", { name: "Emergency access", exact: true }).click();
    await page.screenshot({path:test.info().outputPath("break-glass-login.png"),fullPage:true});
    await page.locator("#login-password").fill(process.env.BREAK_GLASS_PASSWORD!);
    const emergencyCode=totp(process.env.BREAK_GLASS_TOTP_SECRET!);
    await page.locator("#login-totp").fill(emergencyCode);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page).toHaveURL(/\/clusters(?:[/?#]|$)/, { timeout: 30_000 });
    expect((await (await context.request.get("/api/v1/auth/me")).json()).email).toBe("break-glass@constellation.local");
    const session = (await context.cookies()).find(c => c.name === "__Host-constellation-session")!;
    expect(session.expires - Date.now() / 1000).toBeLessThanOrEqual(300);
    const prometheus = process.env.IDENTITY_PROOF_PROMETHEUS!;
    await expect.poll(async () => {
      const response = await request.get(`${prometheus}/api/v1/query`, { params: { query: 'ALERTS{alertname="ConstellationBreakGlassUsed",alertstate="firing"}' } });
      return (await response.json()).data.result.length;
    }, { timeout: 90_000, intervals: [1000, 2000, 5000] }).toBeGreaterThan(0);
    await page.goto("/settings/identity"); await expect(page.getByText("TOTP required", { exact: true })).toBeVisible();
    const emergencyHeaders={Origin:baseURL!,"X-Constellation-Client":"browser"};
    const attempt=(password:string,totp:string)=>context.request.post("/api/v1/auth/break-glass",{headers:emergencyHeaders,data:{password,totp}});
    expect((await attempt(process.env.BREAK_GLASS_PASSWORD!,emergencyCode)).status()).toBe(401); // one-use TOTP
    expect((await attempt(process.env.BREAK_GLASS_PASSWORD!,"")).status()).toBe(401); // mandatory TOTP
    expect((await attempt("incorrect-password",emergencyCode)).status()).toBe(401);
    expect((await attempt("incorrect-password",emergencyCode)).status()).toBe(401);
    const limited=await attempt("incorrect-password",emergencyCode);
    expect(limited.status()).toBe(429);expect(limited.headers()["retry-after"]).toBe("300");
    expect((await context.request.post("/api/v1/auth/logout",{headers:emergencyHeaders})).status()).toBe(200);
    expect((await context.request.get("/api/v1/auth/me")).status()).toBe(401);

  } finally {
    execFileSync("kubectl", ["-n", namespace, "scale", `deployment/${deployment}`, "--replicas=1"]);
    await context.close();
  }
});
