import { test, expect } from "@playwright/test";
import { appVersionAge } from "../src/lib/app-version-age";

test.use({ timezoneId: "America/Los_Angeles", hasTouch: true });

test("sensor usage, inventory order, history ranges, gaps, missing readings, refresh errors, and mobile layout", async ({
  page,
}, info) => {
  const now = Date.parse("2026-10-03T05:00:00Z");
  await page.clock.setFixedTime(now);
  const devices = [
    {
      id: "sensor-a",
      hostname: "Test sensor A",
      status: "online",
      cpu_percent: 125.5,
      memory_rss_bytes: 48 * 1024 ** 2,
      max_memory_rss_bytes_24h: 2_680_000_000,
      log_records: 10,
      metric_points: 1,
      spans: 1,
    },
    {
      id: "sensor-b",
      hostname: "Older sensor",
      status: "offline",
      cpu_percent: null,
      memory_rss_bytes: null,
      log_records: 95,
      metric_points: 3,
      spans: 2,
    },
    {
      id: "sensor-c",
      hostname: "Test sensor C",
      status: "online",
      memory_rss_bytes: 0,
      max_memory_rss_bytes_24h: 0,
      log_records: 5,
      metric_points: 35,
      spans: 10,
    },
    {
      id: "sensor-d",
      hostname: "Offline sensor",
      status: "offline",
      log_records: 20,
      metric_points: 0,
      spans: 0,
    },
    {
      id: "sensor-e",
      hostname: "Disabled sensor",
      status: "disabled",
      log_records: 110,
      metric_points: 9,
      spans: 11,
    },
  ].map((device) => ({
    label: "",
    os: "macos",
    arch: "arm64",
    sensor_version: "0.1.0",
    host_kind: "workstation",
    last_heartbeat_at: new Date(
      now - (device.status === "offline" ? 600000 : 0),
    ).toISOString(),
    telemetry_queue_depth: 0,
    queue_depth: 0,
    latest_export_at: null,
    exports: 0,
    ...device,
  }));
  let fail = false;
  let failOverview = true;
  let failHealth = false;
  let zero = false;
  let offline = false;
  let reverseDevices = false;
  let releaseOverview!: () => void;
  let overviewDelay: Promise<void> | undefined = new Promise<void>((resolve) => {
    releaseOverview = resolve;
  });
  let metricsRequests = 0;
  const requests: string[] = [];
  const commandRequests: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("request", (request) => {
    if (/\/sensors\/[^/]+\/commands$/.test(new URL(request.url()).pathname))
      commandRequests.push(request.url());
  });
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({
        json: {
          user: {
            id: "u",
            name: "Operator",
            email: "test@example.invalid",
            roles: ["it_admin"],
            tenant: { id: "t", name: "Test tenant", slug: "test" },
          },
        },
      });
    if (url.pathname.endsWith("telemetry/overview")) {
      await overviewDelay;
      if (failOverview)
        return route.fulfill({ status: 503, json: { error: { message: "Telemetry overview timed out" } } });
      return route.fulfill({
        json: {
          range: "24h",
          service: null,
          bucket_seconds: 3600,
          generated_at: new Date(now).toISOString(),
          window_start: new Date(now - 86400000).toISOString(),
          summary: {
            exports: 24,
            records: 312,
            log_records: 240,
            metric_points: 48,
            spans: 24,
            devices: 5,
            online_devices: 2,
            offline_devices: 2,
            disabled_devices: 1,
            last_export_at: new Date(now).toISOString(),
          },
          activity: Array.from({ length: 24 }, (_, index) => ({
            start: new Date(now - (24 - index) * 3600000).toISOString(),
            exports: 1,
            log_records: 10,
            metric_points: 2,
            spans: 1,
          })),
          available_services: ["claude-code"],
          services: [{ name: "claude-code", exports: 24, log_records: 240, metric_points: 48, spans: 24, last_export_at: new Date(now).toISOString() }],
          devices: reverseDevices ? [...devices].reverse() : devices,
          recent_exports: [],
        },
      });
    }
    if (url.pathname.endsWith("sensors/health")) {
      if (failHealth)
        return route.fulfill({ status: 503, json: { error: { message: "Sensor health temporarily unavailable" } } });
      const rows = reverseDevices ? [...devices].reverse() : devices;
      return route.fulfill({ json: { items: rows.map(({ exports, log_records, metric_points, spans, latest_export_at, sensor_version, ...device }) => ({ ...device, version: sensor_version })) } });
    }
    if (url.pathname.endsWith("/metrics")) {
      metricsRequests++;
      requests.push(url.searchParams.get("range") || "");
      if (fail)
        return route.fulfill({
          status: 503,
          json: { error: { message: "Metrics temporarily unavailable" } },
        });
      const device = devices.find((item) => url.pathname.includes(item.id))!;
      const range = url.searchParams.get("range") || "24h";
      const seconds = {
        "1h": 3600,
        "6h": 21600,
        "24h": 86400,
        "7d": 604800,
        "30d": 2592000,
      }[range]!;
      const bucket = {
        "1h": 60,
        "6h": 60,
        "24h": 300,
        "7d": 1800,
        "30d": 7200,
      }[range]!;
      const count = range === "6h" ? 360 : 48;
      return route.fulfill({
        json: {
          sensor_id: device.id,
          range,
          generated_at: new Date(now).toISOString(),
          window_start: new Date(now - seconds * 1000).toISOString(),
          bucket_seconds: bucket,
          latest: {
            last_heartbeat_at: offline
              ? new Date(now - 600000).toISOString()
              : device.last_heartbeat_at,
            status: offline ? "offline" : device.status,
            cpu_percent: zero ? 0 : device.cpu_percent,
            memory_rss_bytes: zero ? 0 : device.memory_rss_bytes,
          },
          samples:
            device.id === "sensor-b"
              ? []
              : Array.from({ length: zero ? 1 : count }, (_, index) => ({
                  time: new Date(
                    now - (count - index) * bucket * 1000,
                  ).toISOString(),
                  cpu_percent: zero ? 0 : (index % 20) * 8,
                  memory_rss_bytes: zero ? 0 : (32 + (index % 24)) * 1024 ** 2,
                })).filter((_, index) => index < 20 || index > 25),
        },
      });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/app");
  await expect(page.getByRole("heading", { name: "App Health", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "App Health", exact: true })).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("App Health");
  const panel = page.getByRole("region", {
    name: "App resource usage",
    exact: true,
  });
  await expect(panel.getByText("125.5%", { exact: true })).toBeVisible();
  await expect(panel.getByText("View resource samples", { exact: true })).toHaveCount(0);
  await expect(panel.getByRole("table")).toHaveCount(0);
  await expect(panel.locator("summary")).toHaveCount(0);
  const heading = panel.getByRole("heading", { name: "App resource usage", exact: true });
  const measurementHelp = panel.getByRole("button", { name: "How sensor usage is measured", exact: true });
  const measurementDetails = page.getByRole("dialog", { name: "How sensor usage is measured", exact: true });
  await measurementHelp.scrollIntoViewIfNeeded();
  const headingBounds = (await heading.boundingBox())!;
  const helpBounds = (await measurementHelp.boundingBox())!;
  expect(helpBounds.x - (headingBounds.x + headingBounds.width)).toBeGreaterThanOrEqual(0);
  expect(helpBounds.x - (headingBounds.x + headingBounds.width)).toBeLessThanOrEqual(16);
  expect(Math.abs(helpBounds.y + helpBounds.height / 2 - headingBounds.y - headingBounds.height / 2)).toBeLessThan(2);
  await measurementHelp.focus();
  await page.keyboard.press("Enter");
  await expect(measurementDetails).toContainText("Desktop UI, coding agents, and helper processes are excluded.");
  await expect(measurementDetails).toContainText("5-minute averages in Local time");
  await page.keyboard.press("Escape");
  await expect(measurementDetails).toBeHidden();
  await expect(measurementHelp).toBeFocused();
  await expect(page.getByRole("region", { name: "Guardrail hooks", exact: true })).toHaveCount(0);
  for (const name of ["Install hooks", "Remove hooks", "Refresh policy", "Refresh sensor commands"]) {
    await expect(page.getByRole("button", { name, exact: true })).toHaveCount(0);
  }
  await expect(page.getByText("Device maintenance", { exact: true })).toHaveCount(0);
  await expect(page.getByTestId("stat-records")).toHaveText("N/A");
  await expect(page.getByTestId("stat-exports")).toHaveText("N/A");
  await expect(page.getByTestId("stat-devices")).toHaveText("5");
  await expect(page.getByTestId("stat-online-devices")).toHaveText("2");
  const inventory = page.getByRole("table").filter({
    has: page.getByRole("columnheader", { name: "App CPU", exact: true }),
  });
  const inventoryNames = inventory.locator("tbody tr td:first-child p:first-child");
  const memoryCell = (name: string) => inventory.getByRole("row").filter({ hasText: name }).locator("td").nth(5);
  await expect(memoryCell("Test sensor A")).toHaveText("50MB (2.68G)");
  await expect(memoryCell("Test sensor C")).toHaveText("0MB (0MB)");
  await expect(memoryCell("Older sensor")).toHaveText("Not reported (N/A)");
  await expect(inventory.getByRole("columnheader", { name: "App memory", exact: true })).toHaveAttribute(
    "title", "Current memory (maximum recorded in the past 24 hours)",
  );
  await expect(inventoryNames).toHaveText([
    "Test sensor A", "Test sensor C", "Older sensor", "Offline sensor", "Disabled sensor",
  ]);
  await expect(inventory.locator("tbody tr td:nth-child(7)")).toHaveText(Array(5).fill("N/A"));
  const activity = page.locator('[data-slot="card"]').filter({
    has: page.getByRole("heading", { name: "Telemetry activity", exact: true }),
  });
  const services = page.locator('[data-slot="card"]').filter({
    has: page.getByRole("heading", { name: "Source services", exact: true }),
  });
  for (const [width, height, layout] of [[1440, 1080, "desktop"], [390, 844, "mobile"]] as const) {
    await page.setViewportSize({ width, height });
    await expect(activity.getByRole("status")).toHaveText("Loading telemetry activity…");
    await expect(services.getByRole("status")).toHaveText("Loading source services…");
    for (const card of [activity, services]) {
      await card.scrollIntoViewIfNeeded();
      await expect(card.getByRole("heading")).toBeInViewport();
      await expect(card.getByRole("status")).toBeInViewport();
      const bounds = (await card.boundingBox())!;
      expect(bounds.height).toBeGreaterThanOrEqual(360);
      expect(bounds.x).toBeGreaterThanOrEqual(0);
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await activity.locator("..").screenshot({ path: info.outputPath(`sensor-health-loading-${layout}.png`), animations: "disabled" });
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  releaseOverview();
  overviewDelay = undefined;
  await expect(page.locator("main").getByRole("alert")).toContainText("Telemetry overview timed out");
  await expect(activity.getByText("Telemetry activity unavailable", { exact: true })).toBeVisible();
  await expect(services.getByText("Source services unavailable", { exact: true })).toBeVisible();
  await expect(activity.getByRole("status")).toHaveCount(0);
  await expect(services.getByRole("status")).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("sensor-health-overview-unavailable.png"), fullPage: true, animations: "disabled" });
  failOverview = false;
  overviewDelay = new Promise<void>((resolve) => {
    releaseOverview = resolve;
  });
  await page.locator("main").getByRole("button", { name: "Retry", exact: true }).click();
  await expect(activity.getByRole("status")).toHaveText("Loading telemetry activity…");
  await expect(services.getByRole("status")).toHaveText("Loading source services…");
  releaseOverview();
  overviewDelay = undefined;
  await expect(page.getByTestId("stat-records")).toHaveText("312");
  const rankedNames = [
    "Test sensor C", "Test sensor A", "Older sensor", "Offline sensor", "Disabled sensor",
  ];
  await expect(inventoryNames).toHaveText(rankedNames);
  await expect(inventory.locator("tbody tr td:nth-child(7)")).toHaveText(["50", "12", "100", "20", "130"]);
  await page.setViewportSize({ width: 1920, height: 1080 });
  await inventory.locator('xpath=ancestor::*[@data-slot="card"]').screenshot({
    path: info.outputPath("sensor-inventory-online-first.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("combobox", { name: "Device status", exact: true }).click();
  await page.getByRole("option", { name: "Online", exact: true }).click();
  await expect(inventoryNames).toHaveText(["Test sensor C", "Test sensor A"]);
  await page.getByRole("combobox", { name: "Device status", exact: true }).click();
  await page.getByRole("option", { name: "All statuses", exact: true }).click();
  await expect(inventoryNames).toHaveText(rankedNames);
  await expect(activity.locator(".recharts-area-curve")).toHaveCount(3);
  await expect(services.getByRole("img", { name: "claude-code: 312 records, 100% of total", exact: true })).toBeVisible();
  overviewDelay = new Promise<void>((resolve) => {
    releaseOverview = resolve;
  });
  failOverview = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: "Refreshing", exact: true })).toBeDisabled();
  await expect(activity.locator(".recharts-area-curve")).toHaveCount(3);
  await expect(services.getByRole("img", { name: "claude-code: 312 records, 100% of total", exact: true })).toBeVisible();
  await expect(activity.getByRole("status")).toHaveCount(0);
  await expect(services.getByRole("status")).toHaveCount(0);
  releaseOverview();
  overviewDelay = undefined;
  await expect(page.locator("main").getByRole("alert")).toContainText("Showing the last successful response");
  await expect(activity.locator(".recharts-area-curve")).toHaveCount(3);
  await expect(services.getByRole("img", { name: "claude-code: 312 records, 100% of total", exact: true })).toBeVisible();
  failOverview = false;
  await page.locator("main").getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  failHealth = true;
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("Unable to refresh app health");
  await expect(panel.getByText("125.5%", { exact: true })).toBeVisible();
  failHealth = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  await expect(
    panel.locator("p.figure").filter({ hasText: /^48.0 MiB$/ }),
  ).toBeVisible();
  for (const name of ["App CPU", "App memory"]) {
    await expect(
      page.getByRole("columnheader", { name, exact: true }),
    ).toBeVisible();
  }
  await expect(
    page
      .getByRole("row")
      .filter({ hasText: "Older sensor" })
      .getByText("Not reported", { exact: true }),
  ).toHaveCount(3); // queues plus unreported hardware identity
  reverseDevices = true;
  await Promise.all([
    page.waitForResponse((response) => new URL(response.url()).pathname.endsWith("sensors/health")),
    page.getByRole("button", { name: "Refresh apps", exact: true }).click(),
  ]);
  await expect(page.getByRole("button", { name: "Refresh apps", exact: true })).toBeEnabled();
  await expect(inventoryNames).toHaveText(rankedNames);
  await expect(
    panel.getByRole("combobox", { name: "Sensor for resource usage" }),
  ).toHaveText("Test sensor A");
  await expect(panel.locator(".recharts-area-curve")).toHaveCount(2);
  const curve = panel.locator(".recharts-area-curve").first();
  expect((await curve.getAttribute("d"))!.match(/M/g)!.length).toBe(2);

  for (const [name, value] of [
    ["Last 30 days", "30d"],
    ["Last 7 days", "7d"],
    ["Last 6 hours", "6h"],
    ["Last hour", "1h"],
  ]) {
    await panel
      .getByRole("combobox", { name: "Sensor metrics time range" })
      .click();
    await page.getByRole("option", { name, exact: true }).click();
    await expect.poll(() => requests.at(-1)).toBe(value);
    await expect(panel.locator(".recharts-area-curve")).toHaveCount(2);
    await expect(memoryCell("Test sensor A")).toHaveText("50MB (2.68G)");
  }
  const cpuChart = panel.getByLabel("Sensor cpu usage over time", {
    exact: true,
  });
  await expect(panel.getByText(/Choose a shorter range/)).toHaveCount(0);
  await cpuChart.getByRole("application").focus();
  await page.keyboard.press("ArrowRight");
  await expect(cpuChart.locator(".recharts-tooltip-wrapper")).toContainText(
    "PDT",
  );
  await expect(cpuChart.locator(".recharts-tooltip-wrapper")).toContainText(
    "1-minute average",
  );
  await measurementHelp.click();
  await expect(measurementDetails).toContainText("1-minute averages in Local time");
  await page.keyboard.press("Escape");
  const beforeTimeZoneChange = metricsRequests;
  await page.getByRole("radio", { name: "UTC", exact: true }).check();
  await measurementHelp.click();
  await expect(measurementDetails).toContainText("1-minute averages in UTC");
  expect(metricsRequests).toBe(beforeTimeZoneChange);
  await page.keyboard.press("Escape");
  await page.getByRole("radio", { name: "Local", exact: true }).check();
  await page.mouse.click(1000, 100);
  await panel.screenshot({ path: info.outputPath("sensor-resource-header-desktop.png"), animations: "disabled" });
  await page.screenshot({
    path: info.outputPath("sensor-usage-desktop.png"),
    fullPage: true,
    animations: "disabled",
  });

  fail = true;
  await panel.getByRole("button", { name: "Refresh sensor metrics" }).click();
  await expect(panel.getByRole("alert")).toContainText(
    "Showing the last successful response",
  );
  await expect(panel.getByText("125.5%", { exact: true })).toBeVisible();
  fail = false;
  offline = true;
  await panel.getByRole("button", { name: "Retry" }).click();
  await expect(panel.getByText(/Readings may be stale/)).toBeVisible();
  zero = true;
  await panel.getByRole("button", { name: "Refresh sensor metrics" }).click();
  await expect(
    panel.locator("p.figure").filter({ hasText: /^0.0%$/ }),
  ).toBeVisible();
  await expect(
    panel.locator("p.figure").filter({ hasText: /^0.0 MiB$/ }),
  ).toBeVisible();
  await expect(panel.locator(".recharts-area-dots circle")).toHaveCount(2);

  zero = false;
  await panel
    .getByRole("combobox", { name: "Sensor for resource usage" })
    .click();
  await page.getByRole("option", { name: "Older sensor", exact: true }).click();
  await expect(panel.getByText("Not reported", { exact: true })).toHaveCount(2);
  await expect(
    panel.getByText("No measurements in this range", { exact: true }),
  ).toHaveCount(2);
  await expect(panel.getByText("125.5%", { exact: true })).toHaveCount(0);

  for (const [control, option] of [
    ["Time range", "Last 7 days"],
    ["Service filter", "claude-code"],
  ]) {
    let releaseOverview!: () => void;
    overviewDelay = new Promise<void>((resolve) => {
      releaseOverview = resolve;
    });
    await page.getByRole("combobox", { name: control, exact: true }).click();
    await page.getByRole("option", { name: option, exact: true }).click();
    await expect(page.getByTestId("stat-records")).toHaveText("N/A");
    await expect(activity.getByRole("status")).toHaveText("Loading telemetry activity…");
    await expect(services.getByRole("status")).toHaveText("Loading source services…");
    await expect(activity.locator(".recharts-area-curve")).toHaveCount(0);
    await expect(services.getByRole("img")).toHaveCount(0);
    await expect(panel.getByRole("combobox", { name: "Sensor for resource usage" })).toHaveText("Older sensor");
    releaseOverview();
    overviewDelay = undefined;
    await expect(page.getByTestId("stat-records")).toHaveText("312");
    await expect(activity.locator(".recharts-area-curve")).toHaveCount(3);
    await expect(services.getByRole("img", { name: "claude-code: 312 records, 100% of total", exact: true })).toBeVisible();
    await expect(
      panel.getByRole("combobox", { name: "Sensor for resource usage" }),
    ).toHaveText("Older sensor");
    await expect(
      panel.getByRole("combobox", { name: "Sensor metrics time range" }),
    ).toHaveText("Last hour");
  }

  offline = false;
  await page
    .getByRole("textbox", { name: "Search devices" })
    .fill("Test sensor A");
  await expect(panel.getByText("125.5%", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  const drawer = page.getByRole("dialog", { name: "Workspace navigation" });
  await drawer.getByRole("link", { name: "App Health", exact: true }).click();
  await expect(drawer).toBeHidden();
  await expect(page.getByRole("heading", { name: "App Health", exact: true })).toBeVisible();
  await memoryCell("Test sensor A").scrollIntoViewIfNeeded();
  await expect(memoryCell("Test sensor A")).toBeInViewport();
  await expect(memoryCell("Test sensor A")).toHaveText("50MB (2.68G)");
  expect(await memoryCell("Test sensor A").evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await measurementHelp.scrollIntoViewIfNeeded();
  const mobileHeadingBounds = (await heading.boundingBox())!;
  const mobileHelpBounds = (await measurementHelp.boundingBox())!;
  expect(mobileHelpBounds.x - (mobileHeadingBounds.x + mobileHeadingBounds.width)).toBeGreaterThanOrEqual(0);
  expect(mobileHelpBounds.x - (mobileHeadingBounds.x + mobileHeadingBounds.width)).toBeLessThanOrEqual(16);
  expect(Math.abs(mobileHelpBounds.y + mobileHelpBounds.height / 2 - mobileHeadingBounds.y - mobileHeadingBounds.height / 2)).toBeLessThan(2);
  await measurementHelp.tap();
  await expect(measurementDetails).toBeVisible();
  await expect(measurementDetails).toContainText("1-minute averages in Local time");
  const detailsBounds = (await measurementDetails.boundingBox())!;
  expect(detailsBounds.x).toBeGreaterThanOrEqual(0);
  expect(detailsBounds.x + detailsBounds.width).toBeLessThanOrEqual(390);
  expect(await measurementDetails.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.screenshot({ path: info.outputPath("sensor-resource-help-mobile.png"), animations: "disabled" });
  await measurementHelp.tap();
  await expect(measurementDetails).toBeHidden();
  await page.screenshot({ path: info.outputPath("sensor-resource-header-mobile.png"), animations: "disabled" });
  await cpuChart.scrollIntoViewIfNeeded();
  const chartBounds = (await cpuChart.boundingBox())!;
  await page.touchscreen.tap(
    chartBounds.x + chartBounds.width * 0.8,
    chartBounds.y + 80,
  );
  const mobileReadout = cpuChart.locator(".recharts-tooltip-wrapper");
  await expect(mobileReadout).toBeVisible();
  await expect(mobileReadout).toContainText("PDT");
  const readoutBounds = (await mobileReadout.boundingBox())!;
  expect(readoutBounds.x).toBeGreaterThanOrEqual(0);
  expect(readoutBounds.x + readoutBounds.width).toBeLessThanOrEqual(390);
  await panel.getByRole("heading", { name: "App resource usage", exact: true }).tap();
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    window.scrollTo(0, 0);
  });
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath("sensor-usage-mobile.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("textbox", { name: "Search devices" }).fill("");
  await expect(inventoryNames).toHaveText(rankedNames);
  devices.find((device) => device.id === "sensor-c")!.status = "offline";
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(inventoryNames).toHaveText([
    "Test sensor A", "Older sensor", "Test sensor C", "Offline sensor", "Disabled sensor",
  ]);
  await expect(
    panel.getByRole("combobox", { name: "Sensor for resource usage" }),
  ).toHaveText("Test sensor A");
  await page
    .getByRole("textbox", { name: "Search devices" })
    .fill("no matching sensor");
  await expect(
    panel.getByText("No sensors in view", { exact: true }),
  ).toBeVisible();
  const before = metricsRequests;
  await page.waitForTimeout(100);
  expect(metricsRequests).toBe(before);
  expect(commandRequests).toEqual([]);
  expect(errors).toEqual([]);
});

test("fleet health finds online upload failures, separates queues, and clears recovered faults", async ({ page }, info) => {
  const now = "2026-10-12T07:00:00Z";
  await page.clock.setFixedTime(new Date(now));
  const report = {
    version: 1,
    activity: { upload_failed: false, stalled_for_s: 0, last_success_at: now, dropped: 0 },
    telemetry: { enabled: true, listening: true, upload_failed: false, stalled_for_s: 0, last_success_at: now },
    collectors_failed: 0,
  };
  let recovered = false;
  let failHealth = false;
  let offlineHealth: "current" | "legacy" | "missing" = "current";
  const devices = () => [
    { id: "healthy", hostname: "Healthy customer laptop", status: "online", queue_depth: 0,
      health: { status: "healthy", reasons: [], reported_at: now, stale: false, report } },
    { id: "broken", hostname: "Customer upload failure", status: "online", queue_depth: recovered ? 0 : 1234,
      health: { status: recovered ? "healthy" : "needs_attention", reported_at: now, stale: false,
        reasons: recovered ? [] : [{ code: "activity_upload_failed", message: "Activity uploads are failing" }],
        report: { ...report, activity: { ...report.activity, upload_failed: !recovered } } } },
    { id: "older", hostname: "Older customer sensor", status: "online", queue_depth: 17,
      health: { status: "unknown", reasons: [], reported_at: null, stale: false, report: null } },
    { id: "offline", hostname: "Offline customer sensor", status: "offline", queue_depth: 5,
      health: offlineHealth === "missing" ? undefined : { status: offlineHealth === "legacy" ? "needs_attention" : "unknown",
        reasons: offlineHealth === "legacy" ? [{ code: "heartbeat_missing", message: "No heartbeat in the last 90 seconds" }] : [],
        reported_at: null, stale: true, report: null } },
    { id: "disabled", hostname: "Disabled customer sensor", status: "disabled", queue_depth: 3,
      health: { status: "disabled", reasons: [], reported_at: null, stale: true, report: null } },
  ].map(device => ({ label: "", os: "darwin", arch: "arm64", version: "2026.10.11+62f96d8",
    host_kind: "workstation", last_heartbeat_at: device.status === "offline" ? "2026-10-12T06:50:00Z" : now, telemetry_queue_depth: 0,
    cpu_percent: 2.4, memory_rss_bytes: 60817408, ...device }));
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("auth/me")) return route.fulfill({ json: { user: {
      id: "u", name: "Operator", email: "operator@example.invalid", roles: ["it_admin"],
      tenant: { id: "t", name: "Customer", slug: "customer" },
    } } });
    if (path.endsWith("sensors/health")) return failHealth
      ? route.fulfill({ status: 503, json: { error: { message: "Health refresh failed" } } })
      : route.fulfill({ json: { items: devices() } });
    if (path.endsWith("telemetry/overview")) return route.fulfill({ json: {
      range: "24h", service: null, generated_at: now, window_start: now, bucket_seconds: 3600,
      summary: { exports: 1, records: 1, log_records: 1, metric_points: 0, spans: 0,
        devices: 5, online_devices: 3, offline_devices: 1, disabled_devices: 1, last_export_at: now },
      activity: [], available_services: [], services: [], recent_exports: [],
      devices: devices().map(({ version, ...device }) => ({ ...device, sensor_version: version,
        exports: 1, log_records: 1, metric_points: 0, spans: 0, latest_export_at: now })),
    } });
    if (path.endsWith("/metrics")) return route.fulfill({ json: {
      sensor_id: "healthy", range: "24h", generated_at: now, window_start: now, bucket_seconds: 300,
      latest: { last_heartbeat_at: now, status: "online", cpu_percent: 2.4, memory_rss_bytes: 60817408 }, samples: [],
    } });
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/app");
  const fleet = page.getByRole("status", { name: "Fleet health", exact: true });
  await expect(fleet).toContainText("1 device needs attention · 2 health unknown");
  const table = page.getByRole("region", { name: "Scrollable device inventory" });
  const inventoryCard = table.locator('xpath=ancestor::*[@data-slot="card"]');
  const resourceUsage = page.getByRole("region", { name: "App resource usage", exact: true });
  const names = table.locator("tbody tr td:first-child p:first-child");
  await expect(names).toHaveText(["Customer upload failure", "Healthy customer laptop", "Older customer sensor", "Offline customer sensor", "Disabled customer sensor"]);
  const broken = table.getByRole("row").filter({ hasText: "Customer upload failure" });
  await expect(broken.getByText("Online", { exact: true })).toBeVisible();
  await expect(broken.getByText("Needs attention", { exact: true })).toBeVisible();
  await expect(broken.getByText("1,234", { exact: true })).toBeVisible();
  const offline = table.getByRole("row").filter({ hasText: "Offline customer sensor" });
  await expect(offline.getByText("Offline", { exact: true })).toBeVisible();
  await expect(offline.getByText("Health unknown", { exact: true })).toBeVisible();
  await expect(offline).not.toContainText("Needs attention");
  await expect(table).not.toContainText("No heartbeat in the last 90 seconds");
  for (const [width, height] of [[1440, 1080], [390, 844]]) {
    await page.setViewportSize({ width, height });
    const inventoryBounds = (await inventoryCard.boundingBox())!;
    const usageBounds = (await resourceUsage.boundingBox())!;
    expect(usageBounds.y).toBeGreaterThan(inventoryBounds.y + inventoryBounds.height);
    for (const control of [
      page.getByRole("textbox", { name: "Search devices" }),
      page.getByRole("combobox", { name: "Device status", exact: true }),
      page.getByRole("combobox", { name: "Device health", exact: true }),
    ]) {
      const bounds = (await control.boundingBox())!;
      expect(bounds.y + bounds.height).toBeLessThanOrEqual(inventoryBounds.y);
    }
    await resourceUsage.getByRole("heading", { name: "App resource usage", exact: true }).scrollIntoViewIfNeeded();
    await expect(resourceUsage.getByRole("heading", { name: "App resource usage", exact: true })).toBeInViewport();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath(`device-inventory-first-${width}.png`), fullPage: true, animations: "disabled" });
    await page.getByRole("button", { name: "View health for Customer upload failure", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Activity uploads are failing");
    await expect(dialog.locator("dt").filter({ hasText: /^Pending activity$/ }).locator("+ dd")).toHaveText("1,234");
    await expect(dialog.locator("dt").filter({ hasText: /^Pending exports$/ }).locator("+ dd")).toHaveText("0");
    expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await dialog.screenshot({ path: info.outputPath(`sensor-attention-details-${width}.png`) });
    await page.keyboard.press("Escape");
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole("textbox", { name: "Search devices" }).fill("Healthy customer laptop");
    await page.getByRole("combobox", { name: "Device status", exact: true }).click();
    await page.getByRole("option", { name: "Online", exact: true }).click();
    await expect(names).toHaveText(["Healthy customer laptop"]);
    await fleet.getByRole("button", { name: "Show devices needing attention", exact: true }).click();
    await expect(names).toHaveText(["Customer upload failure"]);
    await expect(page.getByRole("textbox", { name: "Search devices" })).toHaveValue("");
    await expect(page.getByRole("combobox", { name: "Device status", exact: true })).toHaveText("All statuses");
    await expect(page.getByRole("combobox", { name: "Device health", exact: true })).toHaveText("Needs attention");
    const showAll = fleet.getByRole("button", { name: "Show all devices", exact: true });
    await expect(showAll).toBeVisible();
    await page.screenshot({ path: info.outputPath(`attention-filter-${width}.png`), fullPage: true, animations: "disabled" });
    await showAll.click();
    await expect(page.getByRole("combobox", { name: "Device health", exact: true })).toHaveText("All health states");
    await expect(names).toHaveText(["Customer upload failure", "Healthy customer laptop", "Older customer sensor", "Offline customer sensor", "Disabled customer sensor"]);
    await expect(fleet.getByRole("button", { name: "Show devices needing attention", exact: true })).toBeVisible();
  }
  await page.setViewportSize({ width: 2048, height: 1230 });
  await table.evaluate(element => { element.scrollLeft = 0; });
  await table.screenshot({ path: info.outputPath("sensor-attention-fleet.png") });
  await page.getByRole("button", { name: "Show devices needing attention" }).click();
  await expect(names).toHaveText(["Customer upload failure"]);
  await page.getByRole("combobox", { name: "Device health", exact: true }).click();
  await page.getByRole("option", { name: "All health states", exact: true }).click();
  await expect(names).toHaveCount(5);
  await expect(fleet.getByRole("button", { name: "Show devices needing attention", exact: true })).toBeVisible();
  await page.getByRole("combobox", { name: "Device health", exact: true }).click();
  await page.getByRole("option", { name: "Needs attention", exact: true }).click();
  await expect(fleet.getByRole("button", { name: "Show all devices", exact: true })).toBeVisible();
  await expect(names).toHaveText(["Customer upload failure"]);
  recovered = true;
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(page.getByText("No devices in view", { exact: true })).toBeVisible();
  await expect(fleet).toContainText("0 devices need attention · 2 health unknown");
  await page.getByRole("combobox", { name: "Device health", exact: true }).click();
  await page.getByRole("option", { name: "Health unknown", exact: true }).click();
  await expect(names).toHaveText(["Older customer sensor", "Offline customer sensor"]);
  await page.getByRole("button", { name: "View health for Older customer sensor" }).click();
  await expect(page.getByRole("dialog")).toContainText("Update the sensor");
  await page.keyboard.press("Escape");
  for (const source of ["current", "legacy", "missing"] as const) {
    offlineHealth = source;
    await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
    await expect(page.getByRole("button", { name: "Refresh apps", exact: true })).toBeEnabled();
    await expect(names).toHaveText(["Older customer sensor", "Offline customer sensor"]);
    await expect(fleet).toContainText("0 devices need attention · 2 health unknown");
    await expect(offline.getByText("Health unknown", { exact: true })).toBeVisible();
    await expect(offline).not.toContainText("No heartbeat in the last 90 seconds");
    await page.getByRole("button", { name: "View health for Offline customer sensor", exact: true }).click();
    const dialog = page.getByRole("dialog");
    await expect(dialog).toContainText("Current sensor health is unknown while this device is offline");
    await expect(dialog).toContainText("Measurements below are from the last heartbeat");
    await expect(dialog).not.toContainText("Update the sensor");
    await expect(dialog).not.toContainText("No heartbeat in the last 90 seconds");
    await expect(dialog.locator("dt").filter({ hasText: /^Last heartbeat$/ }).locator("+ dd")).not.toHaveText("Never");
    await page.keyboard.press("Escape");
  }
  failHealth = true;
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Health refresh failed" })).toBeVisible();
});

test("relative version ages use valid build dates across gaps, leap days, and year boundaries", () => {
  const sensor = (sensor_version: string, status: "online" | "offline" | "disabled" = "online") => ({ sensor_version, status });
  const age = appVersionAge([
    sensor("2026.1.2+fffffff"),
    sensor("2026.1.2+0000000", "disabled"),
    sensor("v2026.1.1+abcdef0", "offline"),
    sensor("2025.12.31+abcdef0"),
    sensor("2025.12.26+abcdef0"),
    sensor("2025.12.25+abcdef0", "offline"),
    sensor("2025.12.24+abcdef0"),
    sensor("2025.12.23+abcdef0", "offline"),
    sensor("2024.1.1+abcdef0"),
    ...["", "0.1.0", "2026.2.30+abcdef0", "2026.13.1+abcdef0", "2026.1.0+abcdef0", "2026.1.3", "2026.1.3+invalid", "2026.1.3+abcdef0junk"].map(value => sensor(value)),
  ]);
  expect(age.referenceDate).toBe("2026.1.2");
  expect(age.referenceVersions).toEqual(["2026.1.2+0000000", "2026.1.2+fffffff"]);
  expect(age.disabled).toBe(1);
  expect(age.unknown).toBe(8);
  expect(age.buckets.map(({ online, offline }) => [online, offline])).toEqual([
    [1, 0], [0, 1], [1, 0], [0, 0], [0, 0], [0, 0], [0, 0], [1, 0], [0, 1], [1, 0], [1, 1],
  ]);
  expect(appVersionAge([sensor("2024.3.1+abcdef0"), sensor("2024.2.29+abcdef0")]).buckets[1].online).toBe(1);
  expect(appVersionAge([sensor("2025.3.1+abcdef0"), sensor("2025.2.29+abcdef0")]).unknown).toBe(1);
  expect(appVersionAge([sensor("2026.11.2+abcdef0"), sensor("2026.10.31+abcdef0")]).buckets[2].online).toBe(1);
  expect(appVersionAge([sensor("2026.10.14+abcdef0", "disabled"), sensor("2026.10.13+abcdef0")]).buckets[1].online).toBe(1);
  expect(appVersionAge([
    sensor("v2026.10.14+abcdef0123456789", "offline"),
    sensor("2026.10.13+fffffff"),
    sensor("v2026.10.14+abcdef0123456789", "disabled"),
  ]).referenceVersions).toEqual(["v2026.10.14+abcdef0123456789"]);
  expect(appVersionAge([]).referenceDate).toBeNull();
  expect(appVersionAge([]).referenceVersions).toEqual([]);
  expect(appVersionAge([sensor("0.1.0")]).referenceDate).toBeNull();
  expect(appVersionAge([sensor("0.1.0")]).referenceVersions).toEqual([]);
});

test("relative app version age shows eleven fleet buckets, offline stacks, accessible readouts, and honest data states", async ({ page, browserName }, info) => {
  const now = "2026-11-03T05:00:00Z";
  await page.clock.setFixedTime(new Date(now));
  let failHealth = false;
  let releaseHealth!: () => void;
  const pendingHealth = new Promise<void>(resolve => { releaseHealth = resolve; });
  let sensors = [
    { version: "2026.10.13+abcdef0", status: "online" },
    { version: "2026.10.13+abcdef1", status: "online" },
    { version: "2026.10.12+abcdef0", status: "online" },
    { version: "2026.10.10+abcdef0", status: "online" },
    { version: "2026.10.9+abcdef0", status: "offline" },
    { version: "2026.10.7+abcdef0", status: "offline" },
    { version: "2026.9.1+abcdef0", status: "online" },
    { version: "2026.10.5+abcdef0", status: "offline" },
    { version: "2026.10.4+abcdef0", status: "online" },
    { version: "2026.10.3+abcdef0", status: "offline" },
  ].map((sensor, index) => ({
    id: `sensor-${index}`, hostname: `Fleet sensor ${index}`, label: "", os: "darwin", arch: "arm64",
    host_kind: "workstation", last_heartbeat_at: now, telemetry_queue_depth: 0, queue_depth: 0, ...sensor,
  }));
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await page.route("**/api/v1/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("auth/me")) return route.fulfill({ json: { user: {
      id: "u", name: "Operator", email: "operator@example.invalid", roles: ["it_admin"],
      tenant: { id: "t", name: "Test workspace", slug: "test" },
    } } });
    if (path.endsWith("sensors/health")) {
      await pendingHealth;
      return failHealth
        ? route.fulfill({ status: 503, json: { error: { message: "Health refresh failed" } } })
        : route.fulfill({ json: { items: sensors } });
    }
    if (path.endsWith("telemetry/overview")) return route.fulfill({ json: {
      range: "24h", service: null, generated_at: now, window_start: now, bucket_seconds: 3600,
      summary: { exports: 61272, records: 2912274, log_records: 2912274, metric_points: 0, spans: 0,
        devices: 1, online_devices: 1, offline_devices: 0, disabled_devices: 0, last_export_at: now },
      activity: [2, 1, 3, 1, 4].map((value, i) => ({ start: new Date(Date.parse(now) - (5 - i) * 3600000).toISOString(), exports: 1, log_records: value, metric_points: 0, spans: 0 })),
      available_services: ["claude-code"], services: [], recent_exports: [],
      devices: sensors.slice(0, 1).map(({ version, ...device }) => ({ ...device, sensor_version: version,
        exports: 1, log_records: 1, metric_points: 0, spans: 0, latest_export_at: now })),
    } });
    if (path.endsWith("/metrics")) return route.fulfill({ json: {
      sensor_id: "sensor-0", range: "24h", generated_at: now, window_start: now, bucket_seconds: 300,
      latest: { last_heartbeat_at: now, status: "online", cpu_percent: null, memory_rss_bytes: null }, samples: [],
    } });
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/app");
  const chart = page.getByRole("region", { name: "Relative App version age", exact: true });
  const caption = chart.getByText(/^Days behind newest reported version \(/);
  await expect(chart).toContainText("Loading app versions");
  await expect(caption).toHaveCount(0);
  await expect(chart.getByRole("button")).toHaveCount(0);
  releaseHealth();
  const labels = ["0d", "1d", "2d", "3d", "4d", "5d", "6d", "7d", "8d", "9d", ">9d"];
  const counts = [[2, 0], [1, 0], [0, 0], [1, 0], [0, 1], [0, 0], [0, 1], [0, 0], [0, 1], [1, 0], [1, 1]];
  const bucketNames = labels.map((label, i) => `${label}: ${counts[i][0]} online, ${counts[i][1]} offline`);
  const buckets = chart.getByRole("button");
  await expect(buckets).toHaveCount(11);
  for (let i = 0; i < labels.length; i++) await expect(buckets.nth(i)).toHaveAccessibleName(bucketNames[i]);
  await expect(chart.getByRole("list", { name: "Version age series" })).toHaveText("Online 6Offline 4");
  await expect(chart).toContainText("10 plotted");
  await expect(caption).toHaveText("Days behind newest reported version (2026.10.13+abcdef0, 2026.10.13+abcdef1)");
  await expect(chart.getByText(/^Latest reported versions?:/)).toHaveCount(0);
  await expect(chart.getByRole("table")).toContainText("Newest enrolled build date: 2026.10.13");
  await expect(chart.getByRole("table").locator("tbody tr")).toHaveCount(11);

  // Fleet scope stays intact even when the inventory and telemetry are filtered.
  await page.getByRole("textbox", { name: "Search devices" }).fill("Fleet sensor 0");
  const service = page.getByRole("combobox", { name: "Service filter", exact: true });
  await service.click();
  await page.getByRole("option", { name: "claude-code", exact: true }).click();
  await expect(chart).toContainText("10 plotted");
  await expect(buckets.last()).toHaveAccessibleName(">9d: 1 online, 1 offline");
  await page.getByRole("textbox", { name: "Search devices" }).fill("");

  for (const width of [2048, 1536, 1440, 768, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await chart.scrollIntoViewIfNeeded();
    await expect(caption).toBeVisible();
    const captionBounds = (await caption.boundingBox())!;
    const bucketBounds = (await chart.getByRole("group").boundingBox())!;
    expect(captionBounds.y).toBeGreaterThanOrEqual(bucketBounds.y + bucketBounds.height);
    expect(await chart.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    await expect.poll(() => page.evaluate(() => ({ width: innerWidth, content: document.documentElement.scrollWidth })), {
      message: `Responsive charts settle without page overflow at ${width}px`,
    }).toEqual({ width, content: width });
    const bounds = (await chart.boundingBox())!;
    for (const button of await buckets.all()) {
      const box = (await button.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(bounds.x);
      expect(box.x + box.width).toBeLessThanOrEqual(bounds.x + bounds.width);
    }
    const firstBar = (await buckets.first().locator(".bg-chart-1").boundingBox())!;
    const nextBar = (await buckets.nth(1).locator(".bg-chart-1").boundingBox())!;
    expect(nextBar.x - (firstBar.x + firstBar.width)).toBeCloseTo(2, 1);
    if (width === 2048) {
      const stat = (await page.getByTestId("stat-records").boundingBox())!;
      expect(bounds.x).toBeGreaterThan(stat.x + stat.width);
      await page.getByRole("region", { name: "Telemetry summary", exact: true }).screenshot({ path: info.outputPath("relative-app-age-desktop.png") });
    }
    if (width === 390) await chart.screenshot({ path: info.outputPath("relative-app-age-mobile.png") });
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  await buckets.last().hover();
  let readout = page.getByRole("dialog");
  await expect(readout).toContainText(">9d behind newest reported version");
  await expect(readout).toContainText("Reference build date: 2026.10.13");
  await expect(readout).toContainText("Online1 deviceOffline1 device");
  const grey = await buckets.last().locator(".bg-input").evaluate(element => getComputedStyle(element).backgroundColor);
  const teal = await buckets.last().locator(".bg-chart-1").evaluate(element => getComputedStyle(element).backgroundColor);
  expect(grey).not.toBe(teal);
  const offline = (await buckets.last().locator(".bg-input").boundingBox())!;
  const online = (await buckets.last().locator(".bg-chart-1").boundingBox())!;
  expect(offline.y).toBeLessThan(online.y);
  expect(offline.height).toBeCloseTo(online.height, 1);
  await page.mouse.move(0, 0);
  await buckets.first().focus();
  await expect(page.getByRole("dialog")).toContainText("0d behind newest reported version");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  // Safari on macOS uses Option-Tab to include buttons in keyboard navigation.
  await page.keyboard.press(browserName === "webkit" && process.platform === "darwin" ? "Alt+Tab" : "Tab");
  await expect(buckets.nth(1)).toBeFocused();
  await expect(page.getByRole("dialog")).toContainText("1d behind newest reported version");
  await page.keyboard.press("Escape");
  await page.setViewportSize({ width: 390, height: 844 });
  await buckets.last().tap();
  readout = page.getByRole("dialog");
  await expect(readout).toBeVisible();
  const tooltipBounds = (await readout.boundingBox())!;
  expect(tooltipBounds.x).toBeGreaterThanOrEqual(0);
  expect(tooltipBounds.x + tooltipBounds.width).toBeLessThanOrEqual(390);
  await page.keyboard.press("Escape");

  // Wall-clock time alone does not move any sensor to an older bucket.
  await page.clock.setFixedTime(new Date("2027-02-03T05:00:00Z"));
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(buckets.first()).toHaveAccessibleName(bucketNames[0]);
  failHealth = true;
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(chart).toContainText("Stale app version data");
  await expect(caption).toHaveText("Days behind newest reported version (2026.10.13+abcdef0, 2026.10.13+abcdef1)");
  await expect(buckets.last()).toHaveAccessibleName(bucketNames[10]);
  failHealth = false;
  sensors = [
    { ...sensors[0], version: "2026.10.14+abcdef0" },
    { ...sensors[1], version: "2026.10.13+abcdef1", status: "offline" },
    { ...sensors[2], version: "0.1.0" },
    { ...sensors[3], status: "disabled" },
  ];
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(chart).toContainText("2 plotted");
  await expect(caption).toHaveText("Days behind newest reported version (2026.10.14+abcdef0)");
  await expect(chart).toContainText("Excluded: 1 unknown version · 1 disabled");
  await expect(chart).not.toContainText("Stale app version data");
  await expect(buckets.nth(1)).toHaveAccessibleName("1d: 0 online, 1 offline");
  sensors = [{ ...sensors[0], version: "2026.10.15+0123456789abcdef0123456789abcdef01234567", status: "disabled" }];
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(caption).toHaveText(`Days behind newest reported version (${sensors[0].version})`);
  await expect(chart).toContainText("No online or offline devices with version dates");
  expect(await chart.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
  await expect(caption).toBeVisible();
  sensors = [{ ...sensors[0], version: "0.1.0", status: "online" }];
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(chart).toContainText("No online or offline devices with version dates");
  await expect(caption).toHaveCount(0);
  await expect(chart.getByRole("button")).toHaveCount(0);
  sensors = [];
  await page.getByRole("button", { name: "Refresh apps", exact: true }).click();
  await expect(chart).toContainText("No enrolled devices");
  await expect(caption).toHaveCount(0);
  failHealth = true;
  await page.reload();
  await expect(chart).toContainText("App versions unavailable");
  await expect(caption).toHaveCount(0);
  await expect(chart.getByRole("button")).toHaveCount(0);
  expect(errors).toEqual([]);
});
