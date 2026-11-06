import { test, expect } from "@playwright/test";

test("host charts appear by default with responsive layout, time ranges, readouts, and refresh failures", async ({
  page,
}, info) => {
  const now = Date.now();
  const samples = Array.from({ length: 12 }, (_, index) => ({
    time: new Date(now - (12 - index) * 60000).toISOString(),
    cpu_percent: 15 + index * 2,
    memory_percent: ((4 + index) / 32) * 100,
    disk_percent: 18,
    disk_read_bytes_per_second: index === 8 ? 16 * 1024 ** 2 : index * 2048,
    disk_write_bytes_per_second: index === 8 ? 32 * 1024 ** 2 : index * 1024,
    cpu_count: 8,
    memory_used_bytes: (4 + index) * 1024 ** 3,
    memory_total_bytes: 32 * 1024 ** 3,
    disk_used_bytes: 36 * 1024 ** 3,
    disk_total_bytes: 200 * 1024 ** 3,
    disk_available_bytes: 160 * 1024 ** 3,
    disk_is_root: false,
    root_disk_percent: 97,
    root_disk_used_bytes: Math.round(29.1 * 1024 ** 3),
    root_disk_total_bytes: 30 * 1024 ** 3,
    root_disk_available_bytes: Math.round(0.8 * 1024 ** 3),
    service_cpu_percent: { postgres: 18 + index, server: 0, dashboard: null },
  }));
  let fail = false;
  let status = "ok";
  const requests: string[] = [];
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({
        json: {
          user: {
            id: "u",
            name: "Operator",
            email: "test@example.invalid",
            roles: ["it_admin", "security_analyst", "security_leadership"],
            tenant: { id: "t", name: "Test tenant", slug: "test" },
          },
        },
      });
    if (url.pathname.endsWith("system/database"))
      return route.fulfill({ json: { ok: false, checked_at: new Date().toISOString(), latency_ms: null, pools: [], activity: null } });
    if (url.pathname.endsWith("system/status"))
      return route.fulfill({
        json: {
          version: "test",
          services: [],
          database: { ok: true, latency_ms: 2 },
          ingest: { sensors_online: 1, events_last_hour: 0 },
        },
      });
    if (url.pathname.endsWith("system/metrics")) {
      const range = url.searchParams.get("range") || "";
      requests.push(range);
      const interval = range === "7d" ? 600 : range === "30d" ? 1800 : 60;
      const longSamples = interval === 60 ? null : Array.from({ length: range === "7d" ? 1008 : 1440 }, (_, index) => ({
        ...samples[0],
        time: new Date(now - ((range === "7d" ? 1008 : 1440) - index) * interval * 1000).toISOString(),
        cpu_percent: 20 + index % 50,
        root_disk_percent: index < 500 ? null : 97,
        gap_before: index === 500,
      }));
      if (fail)
        return route.fulfill({
          status: 503,
          json: { error: { message: "Metrics temporarily unavailable" } },
        });
      return route.fulfill({
        json: {
          status,
          message:
            status === "stale"
              ? "Host metrics are delayed. Showing the last collected samples."
              : "",
          hostname: "openaidr-prod-canary",
          disk_path: "/srv/openaidr",
          interval_seconds: interval,
          last_sample_at: samples.at(-1)!.time,
          ...(longSamples ? {
            latest_sample: samples.at(-1),
            service_cpu_summary: { total_samples: 43200, services: {
              postgres: { count: 43000, percent: 23.5, cores: 1.88 },
              server: { count: 43200, percent: 0, cores: 0 },
              dashboard: { count: 0, percent: null, cores: null },
            } },
          } : {}),
          samples: longSamples || (range === "5m"
            ? samples.filter((sample) => new Date(sample.time).getTime() >= now - 5 * 60000)
            : samples),
        },
      });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/server");
  const section = page.getByRole("region", { name: "Host resource usage" });
  for (const title of ["CPU usage", "Memory usage", "Disk space", "Disk I/O"]) {
    await expect(
      section.getByRole("heading", { name: title, exact: true }),
    ).toBeVisible();
    await expect(section.getByLabel(`${title} over time`, { exact: true })).toBeVisible();
  }
  await expect(section.locator(".recharts-surface")).toHaveCount(4);
  await expect(section.getByRole("button", { name: /host history/ })).toHaveCount(0);
  async function expectChartLayout(columns: number) {
    const diskSummary = section.getByRole("heading", { name: "Disk space", exact: true }).locator("..");
    await expect.poll(async () => (await diskSummary.boundingBox())?.height ?? Infinity).toBeLessThanOrEqual(168);
    await expect.poll(() => diskSummary.evaluate((summary) => {
      const bounds = summary.getBoundingClientRect();
      return Array.from(summary.querySelectorAll("p, span")).every((element) => {
        const box = element.getBoundingClientRect();
        return box.left >= bounds.left && box.right <= bounds.right;
      });
    })).toBe(true);
    await expect.poll(() => section.locator(".recharts-surface").evaluateAll((charts) => {
      const bounds = charts.map((chart) => chart.getBoundingClientRect());
      return {
        columns: new Set(bounds.map((box) => Math.round(box.x))).size,
        rows: new Set(bounds.map((box) => Math.round(box.y))).size,
        fits: bounds.every((box) => box.left >= 0 && box.right <= innerWidth && box.width > 200 && box.height >= 256),
      };
    })).toEqual({ columns, rows: 4 / columns, fits: true });
    await expect.poll(() => section.locator(".recharts-surface").evaluateAll((charts) =>
      charts.flatMap((chart, index) => {
        const bounds = chart.getBoundingClientRect();
        const labels = Array.from(chart.querySelectorAll(".recharts-cartesian-axis-tick-value"));
        const times = Array.from(chart.querySelectorAll(".recharts-xAxis-tick-labels .recharts-cartesian-axis-tick-value"))
          .map((label) => label.getBoundingClientRect());
        const clipped = labels.filter((label) => {
          const box = label.getBoundingClientRect();
          return box.left < bounds.left || box.right > bounds.right || box.bottom > bounds.bottom;
        }).map((label) => `Chart ${index}: clipped ${label.textContent}`);
        const overlaps = times.some((box, index) => index > 0 && box.left < times[index - 1].right + 4);
        return [
          ...clipped,
          ...(times.length < 2 ? [`Chart ${index}: missing time labels`] : []),
          ...(overlaps ? [`Chart ${index}: overlapping time labels`] : []),
        ];
      }),
    )).toEqual([]);
  }
  await expect(section.getByRole("tab")).toHaveCount(0);
  await expect(section.getByRole("table")).toHaveCount(0);
  const services = page.getByRole("region", { name: "CPU by service", exact: true });
  await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("23.5%");
  await expect(services.getByRole("row").filter({ hasText: "API server" })).toContainText("0.0%");
  await expect(services.getByRole("row").filter({ hasText: "Dashboard" })).toContainText("Not recorded");
  await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("12 of 12 samples");
  const serviceLines = services.locator(".recharts-line-curve");
  await expect(serviceLines.nth(0)).toHaveCSS("stroke", "rgb(3, 112, 124)");
  await expect(serviceLines.nth(1)).toHaveCSS("stroke", "rgb(166, 127, 169)");
  await expect(serviceLines.nth(1)).toHaveCSS("stroke-dasharray", "6px, 4px");
  await expect(services.locator(".bg-chart-1").first()).toHaveCSS("background-color", "rgb(3, 112, 124)");
  const io = section.locator(".recharts-surface").nth(3);
  await expect(io.locator(".recharts-line-curve").nth(0)).toHaveCSS("stroke", "rgb(3, 112, 124)");
  await expect(io.locator(".recharts-line-curve").nth(1)).toHaveCSS("stroke", "rgb(166, 127, 169)");
  const ioLegend = section.getByRole("heading", { name: "Disk I/O", exact: true }).locator("..").locator("p svg line");
  for (let index = 0; index < 2; index++) {
    await expect(ioLegend.nth(index)).toHaveCSS("stroke-dasharray", "none");
    await expect(io.locator(".recharts-line-curve").nth(index)).toHaveCSS("stroke-dasharray", "none");
  }
  await expect(section.getByText("37.0%", { exact: true })).toBeVisible();
  const disks = section.getByRole("heading", { name: "Disk space", exact: true }).locator("..");
  await expect(disks.getByText("Boot disk (/):", { exact: false })).toContainText("97.0%");
  await expect(disks.getByText("Data disk (/srv/openaidr):", { exact: false })).toContainText("18.0%");
  await expect(disks.getByText("0.8 GiB available", { exact: true })).toBeVisible();
  await expect(disks.getByText("160 GiB available", { exact: true })).toBeVisible();
  for (const total of [
    "2.96 of 8 logical cores in use",
    "15.0 GiB used / 32.0 GiB total",
    "29.1 GiB used / 30.0 GiB total",
    "36.0 GiB used / 200 GiB total",
  ]) {
    await expect(section.getByText(total, { exact: true })).toBeVisible();
  }
  await expect(section.getByText("11.0 KiB/s", { exact: true })).toBeVisible();
  await section
    .getByRole("combobox", { name: "Host metrics time range" })
    .click();
  await page.getByRole("option", { name: "Last hour", exact: true }).click();
  await expect.poll(() => requests.at(-1)).toBe("1h");
  await expect(
    section.getByRole("heading", { name: "CPU usage", exact: true }),
  ).toBeVisible();
  await expect(page.getByRole("listbox")).toBeHidden();
  await section.getByRole("combobox", { name: "Host metrics time range" }).click();
  await page.getByRole("option", { name: "Last 5 minutes", exact: true }).click();
  await expect.poll(() => requests.at(-1)).toBe("5m");
  await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("27.0%");
  await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("5 of 5 samples");
  await page.getByRole("radio", { name: "UTC", exact: true }).check();
  for (const [range, days, interval] of [["7d", 7, 10], ["30d", 30, 30]] as const) {
    await section.getByRole("combobox", { name: "Host metrics time range" }).click();
    await page.getByRole("option", { name: `Last ${days} days`, exact: true }).click();
    await expect.poll(() => requests.at(-1)).toBe(range);
    await expect(section.getByText(`${interval}-minute averages; summary values show the latest reading.`)).toBeVisible();
    await expect(section.getByText("37.0%", { exact: true })).toBeVisible();
    await expect(disks.getByText("97.0%", { exact: true })).toBeVisible();
    await expect(disks.getByText("0.8 GiB available", { exact: true })).toBeVisible();
    await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("43000 of 43200 samples");
    await expect(services.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("23.5%");
    const startDate = new Intl.DateTimeFormat("en-US", { month: "short", day: "numeric", timeZone: "UTC" }).format(now - days * 86400000);
    await expect(section.locator(".recharts-xAxis-tick-labels").first()).toContainText(startDate);
    await expect(services.locator(".recharts-xAxis-tick-labels")).toContainText(startDate);
    // A missing minute inside an aggregate must still break the plotted line.
    await expect.poll(async () => (await section.locator(".recharts-line-curve").first().getAttribute("d"))?.match(/M/g)?.length).toBe(2);
    await expectChartLayout(4);
    await section.screenshot({ path: info.outputPath(`host-resources-${range}.png`), animations: "disabled" });
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await expectChartLayout(1);
  await section.screenshot({ path: info.outputPath("host-resources-30d-mobile.png"), animations: "disabled" });
  await section.getByRole("combobox", { name: "Host metrics time range" }).click();
  await page.getByRole("option", { name: "Last 5 minutes", exact: true }).click();
  await expect.poll(() => requests.at(-1)).toBe("5m");
  await page.setViewportSize({ width: 1920, height: 1080 });
  await expectChartLayout(4);
  await section.screenshot({
    path: info.outputPath("host-resource-plots-wide.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 1100, height: 1080 });
  await expectChartLayout(2);
  await page.setViewportSize({ width: 1280, height: 900 });
  await expectChartLayout(4);
  await section.evaluate((element) => element.scrollIntoView({ block: "center" }));
  await section.screenshot({
    path: info.outputPath("host-resource-plots-laptop.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await expectChartLayout(4);
  await page.screenshot({
    path: info.outputPath("server-health-desktop.png"),
    fullPage: true,
    animations: "disabled",
  });
  const ioChart = section.getByLabel("Disk I/O over time", { exact: true });
  await page.getByRole("radio", { name: "UTC", exact: true }).check();
  await ioChart.getByRole("application").focus();
  await page.keyboard.press("ArrowRight");
  const readout = ioChart.locator(".recharts-tooltip-wrapper");
  await expect(readout).toBeVisible();
  await expect(readout).toContainText("UTC");
  const tooltips = section.locator(".recharts-tooltip-wrapper");
  async function expectSyncedReadouts(source: number) {
    await expect(tooltips.nth(source)).toBeVisible();
    const timestamp = await tooltips.nth(source).locator("p").first().textContent();
    expect(timestamp).toBeTruthy();
    for (const tooltip of await tooltips.all()) {
      await expect(tooltip).toBeVisible();
      await expect(tooltip.locator("p").first()).toHaveText(timestamp!);
    }
    await expect(section.locator(".recharts-tooltip-cursor")).toHaveCount(4);
    await expect(services.locator(".recharts-tooltip-cursor")).toHaveCount(0);
  }
  await expectSyncedReadouts(3);
  for (const label of ["Read", "Write"]) {
    const row = readout.getByRole("listitem").filter({ hasText: label });
    await expect(row).toContainText("KiB/s");
    await expect(row.locator("svg line")).toHaveCSS("stroke-dasharray", "none");
  }
  for (const [index, plot] of (await section.getByRole("application").all()).entries()) {
    await page.mouse.move(0, 0);
    await plot.focus();
    await page.keyboard.press("ArrowRight");
    await expectSyncedReadouts(index);
    const bounds = (await plot.locator(".recharts-cartesian-grid").boundingBox())!;
    await page.mouse.move(bounds.x + bounds.width * 0.25, bounds.y + bounds.height / 2);
    await expectSyncedReadouts(index);
    const previous = await tooltips.nth(index).locator("p").first().textContent();
    await page.mouse.move(bounds.x + bounds.width * 0.75, bounds.y + bounds.height / 2);
    await expect(tooltips.nth(index).locator("p").first()).not.toHaveText(previous!);
    await expectSyncedReadouts(index);
  }
  await section.screenshot({
    path: info.outputPath("host-resource-plots-synchronized.png"),
    animations: "disabled",
  });
  await page.mouse.move(0, 0);
  for (const tooltip of await tooltips.all()) await expect(tooltip).toBeHidden();
  await expect(section.locator(".recharts-tooltip-cursor")).toHaveCount(0);
  fail = true;
  await section.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(section.getByRole("alert")).toContainText(
    "Showing the last successful response",
  );
  await expect(section.locator(".recharts-surface")).toHaveCount(4);
  await expect(section.getByText("37.0%", { exact: true })).toBeVisible();
  await expect(services.getByText("Historical CPU readings", { exact: true })).toBeVisible();
  fail = false;
  status = "stale";
  await section.getByRole("button", { name: "Retry" }).click();
  await expect(
    section.getByText("Host metrics delayed", { exact: true }),
  ).toBeVisible();
  await expect(
    section.getByText("Host metrics are delayed. Showing the last collected samples.", { exact: true }),
  ).toBeVisible();
  await expect(section.getByRole("alert")).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(
    section.getByRole("heading", { name: "Disk I/O", exact: true }),
  ).toBeVisible();
  await expectChartLayout(1);
  await section.getByRole("combobox", { name: "Host metrics time range" }).click();
  await page.getByRole("option", { name: "Last 6 hours", exact: true }).click();
  await expect.poll(() => requests.at(-1)).toBe("6h");
  await section.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(section.locator(".recharts-surface")).toHaveCount(4);
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
  await section.screenshot({
    path: info.outputPath("host-resource-plots-mobile.png"),
    animations: "disabled",
  });
  await page.screenshot({
    path: info.outputPath("server-health-mobile.png"),
    fullPage: true,
    animations: "disabled",
  });
  expect(errors).toEqual([]);
});

test("missing metrics stay distinct from zero readings and viewers make no metrics request", async ({
  page,
}) => {
  let role = "it_admin";
  let requested = 0;
  let collecting = false;
  let capacityAvailable = false;
  let diskPath = "/";
  let sameFilesystem = false;
  let diskCapacity = {};
  const sampledAt = new Date().toISOString();
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("auth/me"))
      return route.fulfill({
        json: {
          user: {
            id: "u",
            name: "Operator",
            email: "test@example.invalid",
            roles: [role],
            tenant: { id: "t", name: "Test tenant", slug: "test" },
          },
        },
      });
    if (path.endsWith("system/database"))
      return route.fulfill({ json: { ok: false, checked_at: new Date().toISOString(), latency_ms: null, pools: [], activity: null } });
    if (path.endsWith("system/status"))
      return route.fulfill({
        json: {
          version: "test",
          services: [],
          database: { ok: true, latency_ms: 2 },
          ingest: { sensors_online: 1, events_last_hour: 0 },
        },
      });
    if (path.endsWith("system/metrics")) {
      requested++;
      return route.fulfill({
        json: {
          status: collecting ? "ok" : "waiting",
          message: collecting ? "" : "Waiting for the first host sample.",
          hostname: null,
          disk_path: diskPath,
          interval_seconds: 60,
          last_sample_at: collecting ? sampledAt : null,
          samples: collecting
            ? [
                ...(sameFilesystem ? [{
                  time: new Date(new Date(sampledAt).getTime() - 60000).toISOString(),
                  cpu_percent: 0, memory_percent: 0,
                  disk_percent: 99, root_disk_percent: 20, disk_is_root: false,
                  disk_read_bytes_per_second: 0, disk_write_bytes_per_second: 0,
                }] : []),
                {
                  time: sampledAt,
                  cpu_percent: 0,
                  memory_percent: 0,
                  disk_percent: 0,
                  disk_read_bytes_per_second: 0,
                  disk_write_bytes_per_second: 0,
                  ...(sameFilesystem ? { disk_is_root: true } : {}),
                  ...(capacityAvailable
                    ? {
                        cpu_count: 8,
                        memory_used_bytes: 0,
                        memory_total_bytes: 32 * 1024 ** 3,
                        disk_used_bytes: 0,
                        disk_total_bytes: 500 * 1024 ** 3,
                        ...diskCapacity,
                        service_cpu_percent: { postgres: 0, server: null, dashboard: null },
                      }
                    : {}),
                },
              ]
            : [],
        },
      });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/administration/server");
  await expect(
    page.getByText("Waiting for the first host sample.", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".recharts-surface")).toHaveCount(0);
  collecting = true;
  await page.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(page.locator(".recharts-surface")).toHaveCount(4);
  await expect(page.getByText("0.0%", { exact: true })).toHaveCount(3);
  await expect(page.locator(".recharts-line-dots circle")).toHaveCount(5);
  const missingCapacity = page.getByText("Capacity not recorded", {
    exact: true,
  });
  await expect(missingCapacity).toHaveCount(3);
  capacityAvailable = true;
  await page.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(missingCapacity).toHaveCount(0);
  const serviceCpu = page.getByRole("region", { name: "CPU by service", exact: true });
  await expect(serviceCpu.getByRole("row").filter({ hasText: "PostgreSQL" })).toContainText("0.0%");
  await expect(serviceCpu.locator(".recharts-line-dots circle")).toHaveCount(1);
  for (const total of [
    "0.00 of 8 logical cores in use",
    "0 B used / 32.0 GiB total",
    "0 B used / 500 GiB total",
  ]) {
    await expect(page.getByText(total, { exact: true })).toBeVisible();
  }
  const disks = page.getByRole("heading", { name: "Disk space", exact: true }).locator("..");
  await expect(disks.getByText("Boot disk (/):", { exact: false })).toContainText("0.0%");
  await expect(disks.getByText("Data disk", { exact: false })).toHaveCount(0);
  // An older collector measuring a data path must not invent a boot reading.
  diskPath = "/srv/openaidr";
  await page.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(disks.getByText("Boot disk (/):", { exact: false })).toContainText("Not recorded");
  await expect(disks.getByText("Data disk (/srv/openaidr):", { exact: false })).toContainText("0.0%");
  await expect(disks.getByText("Available space not recorded", { exact: true })).toHaveCount(2);
  sameFilesystem = true;
  await page.getByRole("button", { name: "Refresh host metrics" }).click();
  await expect(disks.getByText("Data disk", { exact: false })).toHaveCount(0);
  await expect(disks.getByText("Boot disk (/):", { exact: false })).toContainText("0.0%");
  await expect(disks.getByText("Data path /srv/openaidr shares the boot filesystem.", { exact: true })).toBeVisible();
  // A remounted data path must not relabel its previous readings as boot usage.
  const diskChart = page.getByLabel("Disk space over time", { exact: true });
  await diskChart.getByRole("application").focus();
  await page.keyboard.press("ArrowRight");
  await page.keyboard.press("ArrowLeft");
  await expect(diskChart.locator(".recharts-tooltip-wrapper")).toContainText("20.0%");
  await expect(diskChart.locator(".recharts-tooltip-wrapper")).not.toContainText("99.0%");
  for (const [used, total, available, capacity, availability] of [
    [99.94, 999.4, 99.94, "99.9 GiB used / 999 GiB total", "99.9 GiB available"],
    [99.95, 999.9, 99.95, "100 GiB used / 1000 GiB total", "100 GiB available"],
    [1280, 2048, 0.01, "1.3 TiB used / 2.0 TiB total", "<0.1 GiB available"],
    [0, 500, 0, "0 B used / 500 GiB total", "0.0 GiB available"],
  ] as const) {
    diskCapacity = {
      disk_used_bytes: Math.round(used * 1024 ** 3),
      disk_total_bytes: Math.round(total * 1024 ** 3),
      disk_available_bytes: Math.round(available * 1024 ** 3),
    };
    await page.getByRole("button", { name: "Refresh host metrics" }).click();
    await expect(disks.getByText(capacity, { exact: true })).toBeVisible();
    await expect(disks.getByText(availability, { exact: true })).toBeVisible();
  }
  const before = requested;
  role = "security_leadership";
  await page.reload();
  await expect(
    page.getByText("Access restricted", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Host resource usage" }),
  ).toHaveCount(0);
  await expect(page.getByRole("region", { name: "CPU by service", exact: true })).toHaveCount(0);
  expect(requested).toBe(before);
});
