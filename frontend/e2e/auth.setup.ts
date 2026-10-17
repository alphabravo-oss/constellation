import { expect, test } from "@playwright/test";
import { authStatePath, writeAuthState } from "./auth-state";
import { CREDS, loginRequest } from "./utils";

const API = process.env.VITE_API_URL ?? "http://localhost:18080";

test("prepare browser and CLI authentication", async ({ request }) => {
  test.setTimeout(150_000);
  const bearer = await loginRequest(request, CREDS);
  expect(bearer.ok()).toBe(true);
  const { token } = await bearer.json() as { token: string };
  expect(token).toBeTruthy();

  const browser = await loginRequest(request, CREDS, true);
  expect(browser.ok()).toBe(true);
  const cookies = (await request.storageState()).cookies.filter((cookie) =>
    ["__Host-constellation-session", "__Host-constellation-refresh"].includes(cookie.name));
  expect(cookies).toHaveLength(2);
  writeAuthState({ api: API, email: CREDS.email, token, cookies });
  test.info().annotations.push({ type: "auth-state", description: authStatePath });
});
