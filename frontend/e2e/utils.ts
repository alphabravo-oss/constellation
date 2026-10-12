import { test, type APIRequestContext, type Page } from "@playwright/test";
import { setTimeout as delay } from "node:timers/promises";
import { readAuthState, writeAuthState, type BrowserCookie } from "./auth-state";

export const CREDS = {
  email: "admin@demo.test",
  password: "Constellation!1",
};

const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const tokenCache = new Map<string, string>();
const browserSessionCache = new Map<string, BrowserCookie[]>();
const browserCookieNames = ["__Host-constellation-session", "__Host-constellation-refresh"];

type Credentials = typeof CREDS;

// Setup runs against the production limiter. Auth/security specs deliberately
// create and revoke sessions; respect its cooldown instead of disabling it or
// forging client IPs. Invalid credentials and other errors still fail promptly.
export async function loginRequest(request: APIRequestContext, creds: Credentials, browser = false) {
  const deadline = Date.now() + 65_000;
  while (true) {
    const response = await request.post(`${API}/api/v1/auth/login`, {
      data: creds,
      ...(browser ? { headers: { "X-Constellation-Client": "browser", Origin: new URL(API).origin } } : {}),
    });
    if (response.status() !== 429) return response;
    const value = response.headers()["retry-after"];
    const seconds = Number(value);
    const wait = value && Number.isFinite(seconds)
      ? seconds * 1000
      : value ? Date.parse(value) - Date.now() : 6000;
    const milliseconds = Math.max(1000, Number.isFinite(wait) ? wait : 6000);
    if (Date.now() + milliseconds > deadline) return response;
    await response.dispose();
    // Preserve the workflow's timeout budget when production throttling delays
    // setup. This extends only the actual cooldown, not assertion timeouts or
    // the login retry deadline, and never retries a failed workflow.
    const info = test.info();
    info.setTimeout(info.timeout + milliseconds);
    await delay(milliseconds);
  }
}
function credentialsKey(creds: Credentials) {
  return JSON.stringify([API, creds.email, creds.password]);
}

function sharedAuthState(creds: Credentials) {
  if (creds.email !== CREDS.email || creds.password !== CREDS.password) return null;
  const state = readAuthState();
  return state?.api === API && state.email === creds.email ? state : null;
}

function updateSharedAuthState(creds: Credentials, update: { token?: string; cookies?: BrowserCookie[] }) {
  const state = sharedAuthState(creds);
  if (state) writeAuthState({ ...state, ...update });
}

async function cachedTokenIsValid(page: Page, token: string) {
  const resp = await page.request.get(`${API}/api/v1/auth/me`, {
    headers: { Authorization: `Bearer ${token}` },
  }).catch(() => null);
  return Boolean(resp?.ok());
}

export async function getAuthToken(page: Page, creds: Credentials = CREDS) {
  const key = credentialsKey(creds);
  const cached = tokenCache.get(key) ?? sharedAuthState(creds)?.token;
  if (cached && await cachedTokenIsValid(page, cached)) {
    tokenCache.set(key, cached);
    return cached;
  }
  tokenCache.delete(key);

  const resp = await loginRequest(page.request, creds);
  if (!resp.ok()) throw new Error(`login failed: ${resp.status()}`);
  const { token } = await resp.json();
  tokenCache.set(key, token);
  updateSharedAuthState(creds, { token });
  return token as string;
}

async function ensureBrowserSession(page: Page, creds: Credentials) {
  const key = credentialsKey(creds);
  const cached = browserSessionCache.get(key) ?? sharedAuthState(creds)?.cookies;
  if (cached && cached.every((cookie) => cookie.expires > Date.now() / 1000 + 30)) {
    await page.context().addCookies(cached);
    const response = await page.request.get(`${API}/api/v1/auth/me`).catch(() => null);
    if (response?.ok()) {
      browserSessionCache.set(key, cached);
      return;
    }
  }
  browserSessionCache.delete(key);
  await page.context().clearCookies({ name: /^__Host-constellation-(session|refresh)$/ });
  const response = await loginRequest(page.request, creds, true);
  if (!response.ok()) throw new Error(`browser login failed: ${response.status()}`);
  const cookies = (await page.context().cookies(API)).filter((cookie) => browserCookieNames.includes(cookie.name));
  if (cookies.length !== browserCookieNames.length) throw new Error("browser login did not set session cookies");
  browserSessionCache.set(key, cookies);
  updateSharedAuthState(creds, { cookies });
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
  await ensureBrowserSession(page, credentials);
  await page.addInitScript(({ theme }) => {
    localStorage.removeItem("constellation.token");
    if (theme) localStorage.setItem("constellation.theme", theme);
  }, { theme: options.theme });
  return token;
}
