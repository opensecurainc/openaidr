import { test, expect, type Page } from "@playwright/test";

const sources = ["osquery-npm-packages", "osquery-python-packages", "openaidr-mcp-servers", "openaidr-plugins"];
const stamp = "2026-10-01T11:55:00Z";
function history() {
  return { timezone: "UTC", scope: "tenant", checks_enabled: true, interval_seconds: 300,
    days: Array.from({ length: 30 }, (_, i) => {
      const date = new Date(Date.UTC(2026, 8, i + 2)).toISOString().slice(0, 10);
      return { date, captured_at: `${date}T11:55:00Z` as string | null, categories: Object.fromEntries(sources.map((source, n) => [source,
        { components: i === 29 ? [1, 5, 0, 0][n] : [2, 4, 1, 1][n], device_weighted: i === 29 ? [1, 10, 0, 0][n] : [4, 8, 2, 2][n] }])) as Record<string, { components: number; device_weighted: number }> | null };
    }) };
}
const specs = [["certifi", 3], ["pillow", 2], ["pip", 2], ["acorn", 1], ["idna", 1], ["paramiko", 2]] as const;
const components = specs.flatMap(([name, devices], index) => Array.from({ length: devices }, (_, d) => ({
  id: `${name}-${d}`, root_id: `root-${index}`, sensor_id: `device-${(index + d) % 6}`, hostname: `workstation-${(index + d) % 6}`,
  source: name === "acorn" ? sources[0] : sources[1], name, identifier: name, version: "1.0.0", path: `/test/${name}`,
  root: "/test", root_status: "ok", root_collected_at: stamp, last_seen_at: stamp, evidence: "installed", metadata: {},
  vulnerability: { provider: "OSV", status: "complete", reason: "", checked_at: stamp, findings: [{
    id: `GHSA-${name}`, aliases: [], source_ids: [`GHSA-${name}`], summary: "Synthetic advisory", severity: "high", fixed_versions: [],
    severity_vectors: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  }] },
})));
const roots = Array.from({ length: 36 }, (_, i) => ({ id: `root-${i}`, sensor_id: `device-${i % 6}`, hostname: `workstation-${i % 6}`,
  source: sources[i % 4], root: `/test/environment-${i}`, status: i < 2 ? "error" : i < 8 ? "partial" : "ok",
  collected_at: stamp, last_success_at: i < 2 ? null : stamp, message: i < 2 ? "Permission denied" : "", component_count: 2,
}));

async function mock(page: Page, response: () => { status?: number; json: unknown }) {
  await page.clock.setFixedTime(new Date("2026-10-01T12:00:00Z"));
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("/auth/me")) return route.fulfill({ json: { user: { id: "reviewer", name: "Reviewer", email: "reviewer@example.invalid", roles: ["security_leadership"], tenant: { id: "tenant", name: "Synthetic inventory", slug: "test" } } } });
    if (url.pathname === "/api/v1/inventory/attention-history") return route.fulfill(response());
    if (url.pathname.endsWith("/components")) return route.fulfill({ json: { items: components.filter((row) => row.source === url.searchParams.get("source") && (!url.searchParams.get("sensor_id") || row.sensor_id === url.searchParams.get("sensor_id"))), next_cursor: "" } });
    if (url.pathname.endsWith("/roots")) return route.fulfill({ json: { items: roots.filter((row) => row.source === url.searchParams.get("source")), next_cursor: "" } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

test("compact supply chain uses live weighted history and keeps review and coverage usable", async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1366, height: 768 });
  await mock(page, () => ({ json: history() }));
  const historyRequest = page.waitForRequest((request) => new URL(request.url()).pathname.endsWith("/attention-history"));
  await page.goto("/ai-supply-chain");
  expect(new URL((await historyRequest).url()).pathname).toBe("/api/v1/inventory/attention-history");
  await expect(page.getByRole("radio", { name: "Device-weighted", exact: true })).toBeChecked();
  await expect(page.locator("[data-day]")).toHaveCount(30);
  await expect(page.getByTestId("attention-history-latest")).toContainText("11 component-device pairs");
  await expect(page.getByTestId("attention-history-latest")).toContainText("6 components");
  const coverage = page.getByRole("region", { name: "Loaded scan coverage", exact: true });
  const queue = page.getByRole("region", { name: "Components needing attention", exact: true });
  await expect(queue.locator("tbody tr")).toHaveCount(6);
  await expect(coverage).toContainText("28 successful");
  await expect(coverage).toContainText("6 partial");
  await expect(coverage).toContainText("2 failed");
  await expect(page.getByRole("region", { name: "Component categories", exact: true })).toHaveCount(0);
  await expect(page.getByRole("searchbox", { name: "Search inventory" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  const layout = await page.evaluate(() => {
    const queue = document.querySelector('section[aria-label="Components needing attention"]')!.getBoundingClientRect();
    const coverage = document.querySelector('section[aria-label="Loaded scan coverage"]')!.getBoundingClientRect();
    return { queueBottom: queue.bottom, coverageTop: coverage.top, coverageBottom: coverage.bottom, overflow: document.documentElement.scrollWidth > innerWidth };
  });
  expect(layout.coverageTop).toBeGreaterThanOrEqual(layout.queueBottom);
  expect(layout.coverageBottom).toBeLessThanOrEqual(768);
  expect(layout.overflow).toBe(false);
  await page.screenshot({ path: testInfo.outputPath("supply-chain-trend-desktop.png"), fullPage: true, animations: "disabled" });
  const day = page.locator("[data-day]").first();
  await day.hover();
  await expect(page.getByRole("tooltip")).toContainText("Weighted");
  await expect(page.getByRole("tooltip")).toContainText("Plugins");
  await day.focus();
  await day.press("End");
  await expect(page.locator("[data-day]").last()).toBeFocused();
  await expect(page.getByRole("tooltip")).toContainText("Recorded Oct 1");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("tooltip")).toHaveCount(0);
  await page.locator("label").filter({ hasText: /^Unweighted$/ }).click();
  await expect(page.getByTestId("attention-history-latest")).toContainText("6 components");
  await page.getByRole("button", { name: "View daily data", exact: true }).click();
  const daily = page.getByRole("region", { name: "Daily attention data" });
  await expect(daily.locator("tbody tr")).toHaveCount(30);
  await expect(daily.locator("tbody tr").last().getByRole("cell").nth(5)).toHaveText("6");
  await page.locator("label").filter({ hasText: /^Device-weighted$/ }).click();
  await expect(daily.locator("tbody tr").last().getByRole("cell").nth(5)).toHaveText("11");
  await page.getByRole("button", { name: "View daily data", exact: true }).click();
  await page.getByRole("button", { name: "How counts are calculated" }).click();
  await expect(page.getByText(/CVSS does not change the weight/)).toBeVisible();
  await page.getByRole("button", { name: "How counts are calculated" }).click();
  await queue.getByRole("button", { name: "Show 3 affected devices for certifi" }).hover();
  await expect(page.getByRole("dialog", { name: "Affected devices for certifi" })).toBeVisible();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "View scan locations" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.locator("tbody tr")).toHaveCount(36);
  await expect(dialog.locator("tbody tr").first()).toContainText("Permission denied");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("button", { name: "View scan locations" })).toBeFocused();
  await page.getByRole("button", { name: "All components", exact: true }).click();
  await expect(page.getByRole("button", { name: "All components", exact: true })).toHaveAttribute("aria-expanded", "false");
  await expect(page.getByRole("searchbox", { name: "Search inventory" })).toBeHidden();
  await page.getByRole("button", { name: "All components", exact: true }).click();
  await expect(page.getByRole("button", { name: "All components", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByRole("searchbox", { name: "Search inventory" })).toBeVisible();
  await page.getByRole("button", { name: "Show npm packages" }).click();
  await expect(page.getByRole("region", { name: "All components", exact: true }).locator("tbody tr")).toHaveCount(1);
  await expect(page.getByText(/Review is filtered/)).toHaveCount(0);
  await expect(page.getByTestId("attention-history-latest")).toContainText("11 component-device pairs");
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await page.setViewportSize({ width: 390, height: 740 });
  await expect(page.getByRole("searchbox", { name: "Search inventory" })).toBeVisible();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const reviewToggle = await page.getByRole("button", { name: "All components", exact: true }).boundingBox();
  expect(reviewToggle!.x + reviewToggle!.width).toBeLessThanOrEqual(390);
  await page.locator("[data-day]").last().click();
  const tooltip = await page.getByRole("tooltip").boundingBox();
  expect(tooltip!.x).toBeGreaterThanOrEqual(0);
  expect(tooltip!.x + tooltip!.width).toBeLessThanOrEqual(390);
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "View scan locations" }).click();
  await expect(dialog).toBeVisible();
  await page.keyboard.press("Escape");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: testInfo.outputPath("supply-chain-trend-mobile.png"), fullPage: true, animations: "disabled" });
});

test("missing history stays blank and distinct from zero while failed refreshes retain explicit prior data", async ({ page }) => {
  const data = history();
  data.days[0].categories = null; data.days[0].captured_at = null;
  data.days[1].categories = Object.fromEntries(sources.map((source) => [source, { components: 0, device_weighted: 0 }]));
  let failed = false;
  await mock(page, () => failed ? { status: 503, json: { error: { message: "History offline" } } } : { json: data });
  await page.goto("/ai-supply-chain");
  const missingDay = page.locator("[data-day]").first();
  await missingDay.focus();
  await expect(page.getByRole("tooltip")).toContainText("No snapshot recorded");
  await expect(missingDay.locator("text, circle, [data-category]")).toHaveCount(0);
  await page.locator("[data-day]").nth(1).focus();
  await expect(page.getByRole("tooltip")).not.toContainText("No snapshot recorded");
  await expect(page.getByRole("tooltip")).toContainText("Total00");
  await expect(page.locator("[data-day]").nth(1).locator("circle")).toHaveCount(1);
  await expect(page.locator("[data-day]").nth(1).locator("[data-category]")).toHaveCount(0);
  failed = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("Showing the last loaded history");
  await expect(page.getByTestId("attention-history-latest")).toContainText("11 component-device pairs");
  failed = false;
  data.checks_enabled = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByText(/Vulnerability checks are disabled/)).toBeVisible();
  data.days.forEach((day) => { day.categories = null; day.captured_at = null; });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText("No attention history recorded yet", { exact: true })).toBeVisible();
  await expect(page.locator("[data-day]")).toHaveCount(0);
  failed = true;
  await page.reload();
  await expect(page.locator("main").getByRole("alert")).toContainText("History offline");
  await expect(page.getByText("No attention history recorded yet", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Components needing attention", exact: true }).locator("tbody tr")).toHaveCount(6);
});
