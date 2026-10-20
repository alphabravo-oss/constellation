import { defineConfig, devices } from "@playwright/test";

// Live tier for the C1 UI: real browser login against a running dev stack
// (Vite + Go API + Postgres with real data). Nothing is seeded or mocked.
//   PLAYWRIGHT_BASE_URL=http://127.0.0.1:5273 LIVE_EMAIL=… LIVE_PASSWORD=… \
//     npx playwright test --config=playwright.live.config.ts
export const LIVE_STORAGE = "e2e/live/.auth/state.json";

export default defineConfig({
  testDir: "./e2e/live",
  outputDir: "test-results/live",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [["list"]],
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5273",
    viewport: { width: 1440, height: 900 },
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "live-auth", testMatch: /auth\.live\.setup\.ts/ },
    {
      name: "live",
      testMatch: /\.live\.spec\.ts/,
      dependencies: ["live-auth"],
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 }, storageState: LIVE_STORAGE },
    },
  ],
});
