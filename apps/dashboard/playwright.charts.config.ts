import { defineConfig } from "@playwright/test";
import type { ChartOptions } from "./tests/chart-layout.spec";

export default defineConfig<ChartOptions>({
  testDir: "./tests",
  testMatch: "chart-layout.spec.ts",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  workers: 1,
  retries: 0,
  reporter: [["list"], ["html", { outputFolder: "../../.demo/chart-report", open: "never" }]],
  outputDir: "../../.demo/chart-results",
  use: { baseURL: "http://127.0.0.1:43174", screenshot: "only-on-failure" },
  projects: [
    ...["chromium", "webkit"].flatMap((browserName) => [0, 15].map((scrollbar) => ({
      name: `${browserName}-${scrollbar}px-scrollbars`,
      use: { browserName: browserName as "chromium" | "webkit", zoom: 1.5, scrollbar },
    }))),
    ...[1, 1.25, 1.5, 1.75, 2].map((zoom) => ({
      name: `chromium-browser-zoom-${zoom * 100}%`,
      use: { browserName: "chromium" as const, zoom, zoomMode: "browser" as const, scrollbar: 15 },
    })),
  ],
  webServer: {
    command: "node .next/standalone/apps/dashboard/server.js",
    env: { HOSTNAME: "127.0.0.1", PORT: "43174" },
    url: "http://127.0.0.1:43174",
    reuseExistingServer: false,
  },
});
