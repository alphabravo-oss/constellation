import { readFileSync, writeFileSync, mkdirSync, renameSync } from "node:fs";
import path from "node:path";
import type { BrowserContext } from "@playwright/test";

export type BrowserCookie = Awaited<ReturnType<BrowserContext["cookies"]>>[number];

export type AuthState = {
  api: string;
  email: string;
  token: string;
  cookies: BrowserCookie[];
};

// Parallel local acceptance runs keep their short-lived sessions separate.
const authStateDir = path.resolve(process.env.PLAYWRIGHT_AUTH_STATE_DIR ?? ".playwright-auth");
export const authStatePath = path.join(authStateDir, "state.json");
// Real Playwright storageState (cookies for the API host), consumed by playwright.config.ts
// `use.storageState` so every chromium spec starts with a browser session already attached.
export const storageStatePath = path.join(authStateDir, "storage-state.json");

// The `setup` project always runs before `chromium` (playwright.config.ts dependencies), so the
// file is expected to exist; a missing file is a misconfiguration worth failing loudly on.
export function readAuthState(): AuthState | null {
  try {
    return JSON.parse(readFileSync(authStatePath, "utf8")) as AuthState;
  } catch (error) {
    throw new Error(`Playwright auth state is unavailable at ${authStatePath}`, { cause: error });
  }
}

export function writeAuthState(state: AuthState) {
  mkdirSync(path.dirname(authStatePath), { recursive: true, mode: 0o700 });
  const nextPath = `${authStatePath}.${process.pid}`;
  writeFileSync(nextPath, JSON.stringify(state), { mode: 0o600 });
  renameSync(nextPath, authStatePath);
}
