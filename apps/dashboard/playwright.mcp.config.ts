import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "dashboard-mcp.spec.ts",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  workers: 1,
  retries: 0,
  reporter: "list",
  outputDir: "../../build/mcp-browser-results",
  use: { baseURL: "http://127.0.0.1:43181", screenshot: "only-on-failure" },
  projects: [
    ...(["chromium", "webkit"] as const).flatMap((browserName) => [
      { name: `${browserName}-desktop`, use: { browserName, viewport: { width: 1440, height: 1000 } } },
      { name: `${browserName}-narrow`, use: { browserName, viewport: { width: 390, height: 700 } } },
    ]),
  ],
  webServer: {
    command: "node scripts/sync-brand.mjs && node node_modules/next/dist/bin/next dev --hostname 127.0.0.1 --port 43181",
    url: "http://127.0.0.1:43181/healthz",
    reuseExistingServer: false,
  },
});
