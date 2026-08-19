import type { Page } from "@playwright/test";

export const CREDS = {
  email: "admin@demo.test",
  password: "Constellation!1",
};

const API = process.env.VITE_API_URL ?? "http://localhost:18080";

/** Programmatic login (faster than UI flow for setup steps in other specs). */
export async function login(page: Page) {
  // Hit the API directly and stash the token in localStorage; matches how the SPA stores it.
  const resp = await page.request.post(`${API}/api/v1/auth/login`, {
    data: CREDS,
  });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  await page.addInitScript((t) => {
    localStorage.setItem("constellation.token", t);
  }, token);
}
