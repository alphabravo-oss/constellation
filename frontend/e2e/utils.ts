import type { Page } from "@playwright/test";

export const CREDS = {
  email: "admin@demo.test",
  password: "Constellation!1",
};

const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const tokenCache = new Map<string, string>();

type Credentials = typeof CREDS;

async function cachedTokenIsValid(page: Page, token: string) {
  const resp = await page.request.get(`${API}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  }).catch(() => null);
  return Boolean(resp?.ok());
}

export async function getAuthToken(page: Page, creds: Credentials = CREDS) {
  const key = `${API}:${creds.email}`;
  const cached = tokenCache.get(key);
  if (cached && await cachedTokenIsValid(page, cached)) {
    return cached;
  }
  tokenCache.delete(key);

  const resp = await page.request.post(`${API}/api/v1/auth/login`, {
    data: creds,
  });
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  tokenCache.set(key, token);
  return token as string;
}

/** Programmatic login (faster than UI flow for setup steps in other specs). */
export async function login(
  page: Page,
  options: { creds?: Credentials; fallbackToDemo?: boolean; theme?: "dark" | "light" } = {},
) {
  let credentials = options.creds ?? CREDS;
  let token: string;
  try {
    token = await getAuthToken(page, credentials);
  } catch (err) {
    if (!options.fallbackToDemo || !options.creds || options.creds.email === CREDS.email) {
      throw err;
    }
    credentials = CREDS;
    token = await getAuthToken(page, credentials);
  }
  const response = await page.request.post(`${API}/api/v1/auth/login`, {
    data: credentials,
    headers: { "X-Constellation-Client": "browser", Origin: new URL(API).origin },
  });
  if (!response.ok()) throw new Error(`browser login failed: ${response.status()}`);
  await page.addInitScript(({ theme }) => {
    localStorage.removeItem("constellation.token");
    if (theme) localStorage.setItem("constellation.theme", theme);
  }, { theme: options.theme });
  return token;
}
