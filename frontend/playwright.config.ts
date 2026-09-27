import { defineConfig, devices } from "@playwright/test";

const PORT = 5179;
const API = process.env.VITE_API_URL ?? "http://localhost:18080";
const chromiumExecutablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;
const recordVideo = process.env.CI || process.env.PLAYWRIGHT_RECORD_VIDEO === "1";
const externalBaseURL = process.env.PLAYWRIGHT_BASE_URL;
const authSetup = process.env.PLAYWRIGHT_AUTH_SETUP === "1";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  globalSetup: "./e2e/global-setup.ts",
  globalTeardown: "./e2e/global-teardown.ts",
  reporter: [["list"], ["html", { open: "never" }]],
  use: {
    baseURL: externalBaseURL ?? `http://localhost:${PORT}`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: recordVideo ? "retain-on-failure" : "off",
  },
  projects: [
    ...(authSetup ? [{ name: "setup", testMatch: /auth\.setup\.ts/ }] : []),
    {
      name: "chromium",
      testIgnore: /auth\.setup\.ts/,
      dependencies: authSetup ? ["setup"] : [],
      use: {
        ...devices["Desktop Chrome"],
        ...(chromiumExecutablePath ? { launchOptions: { executablePath: chromiumExecutablePath } } : {}),
      },
    },
  ],
  webServer: externalBaseURL ? undefined : {
    command: `npm run build && npm run preview -- --port ${PORT} --strictPort`,
    url: `http://localhost:${PORT}`,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      VITE_API_URL: API,
    },
  },
});
