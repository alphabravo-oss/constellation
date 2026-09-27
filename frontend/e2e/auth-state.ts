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

export const authStatePath = path.resolve(".playwright-auth/state.json");

export function readAuthState(): AuthState | null {
  if (process.env.PLAYWRIGHT_AUTH_SETUP !== "1") return null;
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
