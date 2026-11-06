import { test, expect } from "@playwright/test";

test("database observations, unavailable statistics, refresh failures, and access", async ({ page }, info) => {
  const now = Date.now();
  const stamp = new Date(now).toISOString();
  let role = "it_admin", state = "disabled", queryState = "warming", fail = false, stale = false, requests = 0, sourcesAvailable = true;
  let extraSources = 0, omittedGroups = 3;
  const sourceHeaders = new Map<string, Record<string, string>>();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/system/")) sourceHeaders.set(path, route.request().headers());
    if (path.endsWith("auth/me")) return route.fulfill({ json: { user: { id: "u", name: "Operator", email: "test@example.invalid", roles: [role], tenant: { id: "t", name: "Test tenant", slug: "test" } } } });
    if (path.endsWith("system/database"))
      return route.fulfill({ json: { ok: false, checked_at: new Date().toISOString(), latency_ms: null, pools: [], activity: null } });
    if (path.endsWith("system/status")) return route.fulfill({ json: { version: "2026.10.7+e6156fc", services: ["ingest", "api", "detect", "admin"].map((name) => ({ name, status: name === "admin" ? "unknown" : "ok", last_seen_at: name === "admin" ? null : stamp, lag_events: name === "detect" ? 0 : null })), database: { ok: true, latency_ms: 1 }, ingest: { sensors_online: 2 } } });
    if (path.endsWith("system/metrics")) return route.fulfill({ json: { status: "ok", hostname: "test-host", disk_path: "/", interval_seconds: 60, last_sample_at: stamp,
      samples: Array.from({ length: 5 }, (_, i) => ({ time: new Date(now - (4 - i) * 60000).toISOString(), cpu_percent: 66 + i, memory_percent: 13, disk_percent: 35, cpu_count: 2,
        memory_used_bytes: 1024 ** 3, memory_total_bytes: 8 * 1024 ** 3, disk_used_bytes: 35 * 1024 ** 3, disk_total_bytes: 100 * 1024 ** 3,
        disk_read_bytes_per_second: 10 * 1024, disk_write_bytes_per_second: 30 * 1024, service_cpu_percent: { postgres: 46 + i, server: 15, dashboard: 1.3 } })) } });
    if (path.endsWith("system/diagnostics")) {
      requests++;
      if (fail) return route.fulfill({ status: 503, json: { error: { message: "Diagnostics temporarily unavailable" } } });
      return route.fulfill({ json: { status: state, stale, message: state === "warming" ? "Waiting for the first background sample." : "Database diagnostics have not been enabled for this dedicated tenant database.", checked_at: stamp, window_start: new Date(now - 240000).toISOString(), window_seconds: 240,
        ...(sourcesAvailable ? { sources: { status: "limited", window_seconds: 30, collection_started_at: stamp, omitted_groups: omittedGroups, dropped_observations: 2,
          items: queryState === "ok" ? [
            { query_id: "app:1234567890abcdef", label: "Read query", source: { page: "Server Health", card: "Database health", endpoint: "GET /api/v1/system/database", job: "" }, calls: 20, failures: 1, total_time_ms: 200 },
            { query_id: "app:1234567890abcdef", label: "Read query", source: { page: "Overview", card: "Risk summary", endpoint: "GET /api/v1/overview", job: "" }, calls: 7, failures: 0, total_time_ms: 70 },
            { query_id: "app:2234567890abcdef", label: "Claim risk assessment work", source: { page: "", card: "", endpoint: "", job: "Risk assessment" }, calls: 10, failures: 0, total_time_ms: 500 },
            { query_id: "app:3234567890abcdef", label: "Read query", source: { page: "", card: "", endpoint: "", job: "" }, calls: 1, failures: 0, total_time_ms: 10 },
            ...Array.from({ length: extraSources }, (_, i) => ({ query_id: `app:extra${i + 1}`, label: "Read query", source: { page: "", card: "", endpoint: "", job: `Additional job ${i + 1}` }, calls: 1, failures: 0, total_time_ms: 9 / (i + 1) })),
          ] : [] } } : {}),
        queries: { status: queryState, without_baseline: 2, items: queryState === "ok" ? [
          { query_id: "-9185746353102059456", label: "Update agent statistics", calls: 804, total_exec_time: 54270, shared_blks_hit: 9408200, shared_blks_read: 136 },
          { query_id: "6210389441145567039", label: "Claim risk assessment work", calls: 148, total_exec_time: 6820, shared_blks_hit: 592041, shared_blks_read: 28 },
        ] : [] },
        scans: { status: "ok", without_baseline: 0, items: [{ relid: 11, relname: "events_1234567890abcdef1234567890abcdef_20261006", seq_scan: 66, seq_tup_read: 18100000, idx_scan: 1234 }] },
        active_total: 1, active: [{ pid: 1024, query_id: "-9185746353102059456", label: "Update agent statistics", seconds: 0.4, wait_event_type: "Lock", wait_event: "transactionid" }],
      } });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/server");
  const panel = page.getByRole("region", { name: "PostgreSQL diagnostics", exact: true });
  await expect(panel.getByText("Database diagnostics not enabled", { exact: true })).toBeVisible();
  state = "warming";
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByText("Starting database diagnostics", { exact: true })).toBeVisible();
  state = "ok";
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByText("Collecting a baseline", { exact: true })).toBeVisible();
  await expect(panel.getByText(/The server collects samples in the background/)).toBeVisible();
  await expect(panel.getByText(/Keep this page open/)).toHaveCount(0);
  await expect(panel.getByText("Lock: transactionid", { exact: true })).toBeVisible();
  await expect(panel.getByText("No application queries observed in this sample. Collection continues in the background.", { exact: true })).toBeVisible();
  queryState = "ok";
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByRole("row").filter({ hasText: "804" })).toContainText("54.27 s");
  await expect(panel.getByRole("row").filter({ hasText: "804" })).toContainText("67.5 ms");
  await expect(panel.getByText("18,100,000", { exact: true })).toBeVisible();
  const sources = panel.getByRole("region", { name: "Queries by source", exact: true });
  await expect(sources.getByRole("columnheader", { name: "Source", exact: true })).toBeVisible();
  await expect(sources.getByRole("row").filter({ hasText: "Server Health" })).toContainText("Database health");
  await expect(sources.getByRole("row").filter({ hasText: "Server Health" })).toContainText("10.0 ms");
  await expect(sources.getByText("app:1234567890abcdef", { exact: true })).toHaveCount(2);
  await expect(sources.getByText("Background job: Risk assessment", { exact: true })).toBeVisible();
  await expect(sources.getByText("Unknown source", { exact: true })).toBeVisible();
  await expect(sources.getByText("Partial observations:", { exact: false })).toBeVisible();
  await expect(sources.locator("tbody tr")).toHaveCount(4);
  await expect(sources.getByText("Showing the 4 source groups with the most elapsed time; 3 more groups are not shown.", { exact: true })).toBeVisible();
  extraSources = 16;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(sources.locator("tbody tr")).toHaveCount(10);
  await expect(sources.locator("tbody tr").first()).toContainText("Server Health");
  await expect(sources.locator("tbody tr").last()).toContainText("app:extra6");
  await expect(sources.getByText("app:extra7", { exact: true })).toHaveCount(0);
  await expect(sources.getByText("Showing the 10 source groups with the most elapsed time; 13 more groups are not shown.", { exact: true })).toBeVisible();
  omittedGroups = 0;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(sources.getByText("Showing the 10 source groups with the most elapsed time; 10 more groups are not shown.", { exact: true })).toBeVisible();
  expect(sourceHeaders.get("/api/v1/system/diagnostics")).toMatchObject({ "x-openaidr-page": "/administration/server", "x-openaidr-card": "database-diagnostics" });
  expect(sourceHeaders.get("/api/v1/system/database")).toMatchObject({ "x-openaidr-page": "/administration/server", "x-openaidr-card": "database-health" });
  expect(sourceHeaders.get("/api/v1/system/status")).toMatchObject({ "x-openaidr-page": "/administration/server", "x-openaidr-card": "server-status" });
  expect(sourceHeaders.get("/api/v1/system/metrics")).toMatchObject({ "x-openaidr-page": "/administration/server", "x-openaidr-card": "host-metrics" });
  await expect(panel.locator(".bg-chart-1").first()).toHaveCSS("background-color", "rgb(3, 112, 124)");
  const host = page.getByRole("region", { name: "Host resource usage", exact: true });
  await expect(host.locator(".recharts-surface")).toHaveCount(4);
  await host.getByRole("combobox", { name: "Host metrics time range" }).click();
  await page.getByRole("option", { name: "Last 5 minutes", exact: true }).click();
  await expect(page.getByRole("region", { name: "CPU by service", exact: true }).locator(".recharts-line-curve")).toHaveCount(3);
  await page.setViewportSize({ width: 1440, height: 1600 });
  await panel.screenshot({ path: info.outputPath("query-source-attribution.png"), animations: "disabled" });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.screenshot({ path: info.outputPath("server-diagnostics-desktop.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const tables = panel.getByRole("region", { name: "Scrollable data table", exact: true });
  await tables.first().evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  await sources.getByRole("columnheader", { name: "Mean time", exact: true }).scrollIntoViewIfNeeded();
  await expect(sources.getByRole("columnheader", { name: "Mean time", exact: true })).toBeInViewport();
  await tables.first().evaluate((element) => { element.scrollLeft = 0; });
  await tables.nth(1).evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  await panel.getByRole("columnheader", { name: "Buffer reads", exact: true }).scrollIntoViewIfNeeded();
  await expect(panel.getByRole("columnheader", { name: "Buffer reads", exact: true })).toBeInViewport();
  await tables.nth(1).evaluate((element) => { element.scrollLeft = 0; });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("server-diagnostics-mobile.png"), fullPage: true, animations: "disabled" });
  stale = true;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByText("Database diagnostics are delayed", { exact: true })).toBeVisible();
  await expect(panel.getByRole("heading", { name: "Last observed active queries", exact: true })).toBeVisible();
  await expect(panel.getByText(/Historical readings/)).toBeVisible();
  await expect(panel.getByText("18,100,000", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 1440, height: 1080 });
  await panel.screenshot({ path: info.outputPath("server-diagnostics-background.png"), animations: "disabled" });
  stale = false;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByText("Database diagnostics are delayed", { exact: true })).toHaveCount(0);
  await expect(panel.getByRole("heading", { name: "Active queries and waits", exact: true })).toBeVisible();
  sourcesAvailable = false;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(sources.getByText("Source attribution is unavailable on this backend.", { exact: true })).toBeVisible();
  fail = true;
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByRole("alert")).toContainText("current activity is unknown");
  await expect(panel.getByRole("heading", { name: "Last observed active queries", exact: true })).toBeVisible();
  fail = false;
  queryState = "disabled";
  await panel.getByRole("button", { name: "Retry" }).click();
  await expect(panel.getByText("Query statistics unavailable", { exact: true })).toBeVisible();
  await expect(panel.getByText("Lock: transactionid", { exact: true })).toBeVisible();
  state = "unavailable";
  await panel.getByRole("button", { name: "Refresh database diagnostics" }).click();
  await expect(panel.getByText("Database diagnostics unavailable", { exact: true })).toBeVisible();
  await expect(panel.getByRole("table")).toHaveCount(0);
  const before = requests;
  role = "security_leadership";
  await page.reload();
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(panel).toHaveCount(0);
  expect(requests).toBe(before);
  expect(errors).toEqual([]);
});
