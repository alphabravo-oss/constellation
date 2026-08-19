// Standalone Playwright config for the L2 Network Map screenshots.
// Uses the already-running dev server on :5173 / :18080 instead of the test
// rig (which runs go-seed against a separate Postgres). Set this config with
// `npx playwright test --config e2e/netmap-screens.config.ts`.
import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /network_resolve\.spec\.ts/,
  fullyParallel: false,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "off",
    screenshot: "off",
    video: "off",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } } },
  ],
});
