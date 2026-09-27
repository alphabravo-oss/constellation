import { expect, test, type BrowserContext } from "@playwright/test";
import { login } from "./utils";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";

test("programmatic login reuses a valid browser session and replaces a revoked one", async ({ browser }) => {
  const contexts: BrowserContext[] = [];
  const signIn = async () => {
    const context = await browser.newContext();
    contexts.push(context);
    const page = await context.newPage();
    const token = await login(page);
    const access = (await context.cookies(API)).find((cookie) => cookie.name === "__Host-constellation-session");
    expect(access).toBeDefined();
    return { page, token, access: access!.value };
  };

  try {
    const first = await signIn();
    const second = await signIn();
    expect(second.access).toBe(first.access);
    expect(second.token).toBe(first.token);

    const logout = await second.page.request.post(`${API}/api/v1/auth/logout`, {
      headers: { "X-Constellation-Client": "browser", Origin: new URL(API).origin },
    });
    expect(logout.ok()).toBe(true);

    const third = await signIn();
    expect(third.access).not.toBe(first.access);
    const me = await third.page.request.get(`${API}/api/v1/auth/me`);
    expect(me.ok()).toBe(true);
    const bearerMe = await third.page.request.get(`${API}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${third.token}` },
    });
    expect(bearerMe.ok()).toBe(true);
  } finally {
    await Promise.all(contexts.map((context) => context.close()));
  }
});
