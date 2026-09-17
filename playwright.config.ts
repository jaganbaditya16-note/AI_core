import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end configuration.
 *
 * Runs both services itself:
 *   - API  (uvicorn on :8000, pointed at a deliberately unreachable database)
 *   - Web  (next dev on :3000)
 *
 * The unreachable database is intentional: it makes the health page's
 * "reachable, dependency degraded" path deterministic, which is the most
 * interesting end-to-end assertion available in Phase 0.
 */
const API_URL = "http://127.0.0.1:8000";
const WEB_URL = "http://127.0.0.1:3000";

const apiCommand = [
  "PYTHONPATH=apps/api/src",
  "AICORE_ENVIRONMENT=test",
  "AICORE_LOG_LEVEL=warning",
  "AICORE_DATABASE_URL=postgresql+psycopg://aicore:aicore@127.0.0.1:1/aicore",
  "AICORE_DATABASE_CONNECT_TIMEOUT_SECONDS=1",
  "apps/api/.venv/bin/python -m uvicorn aicore_api.main:app --host 127.0.0.1 --port 8000",
].join(" ");

/**
 * Escape hatch for environments where Playwright cannot download a browser
 * (restricted networks) but a Chromium build is available locally:
 *
 *   PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium npx playwright test
 */
const executablePath = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH;

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : [["list"]],

  use: {
    baseURL: WEB_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    ...(executablePath ? { launchOptions: { executablePath } } : {}),
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: [
    {
      command: apiCommand,
      url: `${API_URL}/health`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      stdout: "pipe",
    },
    {
      command: "npm run dev --workspace @aicore/web -- --hostname 127.0.0.1 --port 3000",
      url: `${WEB_URL}/`,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "pipe",
    },
  ],
});
