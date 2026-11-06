import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const credentialsPath =
  process.env.OPENAIDR_DEMO_CREDENTIALS || resolve("../../.demo/login.json");
const credentials: { email: string; password: string } = JSON.parse(
  readFileSync(credentialsPath, "utf8"),
);
const formatted = (value: number) =>
  new Intl.NumberFormat("en-US").format(value);

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email address").fill(credentials.email);
  await page.getByLabel("Password", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Open findings", exact: true }),
  ).toBeVisible();
}

test("real login, stored telemetry, filters, devices, export details, and logout", async ({
  page,
  context,
}, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  const anonymous = await page.evaluate(
    async () => (await fetch("/api/v1/telemetry/overview")).status,
  );
  expect(anonymous).toBe(401);
  await page.getByLabel("Email address").fill(credentials.email);
  await page
    .getByLabel("Password", { exact: true })
    .fill("incorrect-demo-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "invalid email or password" }),
  ).toContainText("invalid email or password");
  await expect(page.getByLabel("Password", { exact: true })).toHaveValue("");
  await signIn(page);
  // Telemetry volume and services live on App Health.
  await page.goto("/administration/app");
  await expect(page.getByTestId("stat-records")).toBeVisible();
  const overview = await page.evaluate(async () =>
    (await fetch("/api/v1/telemetry/overview")).json(),
  );
  expect(overview.summary.records).toBeGreaterThanOrEqual(60);
  expect(overview.summary.log_records).toBeGreaterThanOrEqual(30);
  expect(overview.summary.metric_points).toBeGreaterThanOrEqual(20);
  expect(overview.summary.spans).toBeGreaterThanOrEqual(10);
  expect(overview.summary.online_devices).toBeGreaterThanOrEqual(1);
  await expect(page.getByTestId("stat-records")).toHaveText(
    formatted(overview.summary.records),
  );
  await expect(page.getByTestId("stat-exports")).toHaveText(
    formatted(overview.summary.exports),
  );
  await expect(page.locator(".recharts-surface").first()).toBeVisible();
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  const session = (await context.cookies()).find((cookie) => cookie.httpOnly);
  expect(session?.secure).toBe(true);
  await page.screenshot({
    path: info.outputPath("overview.png"),
    fullPage: true,
  });

  await page.getByRole("combobox", { name: "Service filter" }).click();
  const filteredRequest = page.waitForResponse(
    (response) =>
      response.url().includes("telemetry/overview?") &&
      response.url().includes("service=claude-code") &&
      response.ok(),
  );
  await page.getByRole("option", { name: "claude-code", exact: true }).click();
  const filtered = await (await filteredRequest).json();
  expect(filtered.summary.records).toBeLessThan(overview.summary.records);
  await expect(page.getByTestId("stat-records")).toHaveText(
    formatted(filtered.summary.records),
  );
  await page.getByRole("combobox", { name: "Time range", exact: true }).click();
  const rangedRequest = page.waitForResponse(
    (response) =>
      response.url().includes("telemetry/overview?") &&
      response.url().includes("range=7d") &&
      response.ok(),
  );
  await page.getByRole("option", { name: "Last 7 days", exact: true }).click();
  expect((await (await rangedRequest).json()).range).toBe("7d");
  await page.getByRole("button", { name: "Clear filter", exact: true }).click();
  await expect(page.getByTestId("stat-records")).toHaveText(
    formatted(overview.summary.records),
  );
  await expect(page.getByRole("tab", { name: /^(Chart|Table)$/ })).toHaveCount(0);
  const activityChart = page.getByLabel("Stacked chart of log records, metric points, and spans by received time", { exact: true });
  await activityChart.getByRole("application").focus();
  await page.keyboard.press("ArrowRight");
  await expect(activityChart.locator(".recharts-tooltip-wrapper")).toContainText("Log records");

  await page.getByRole("link", { name: "App Health", exact: true }).click();
  await expect(
    page.getByText("Linux demo sensor", { exact: true }),
  ).toBeVisible();
  const device = overview.devices.find(
    (item: { label: string }) => item.label === "Linux demo sensor",
  );
  expect(device?.status).toBe("online");
  expect(device?.telemetry_queue_depth).toBe(0);
  await page.getByLabel("Search devices").fill("no-such-demo-device");
  await expect(
    page.getByText("No devices in view", { exact: true }),
  ).toBeVisible();
  await page.getByLabel("Search devices").clear();
  await expect(
    page.getByText("Linux demo sensor", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("devices.png"),
    fullPage: true,
  });

  await page
    .getByRole("link", { name: "Evidence Search", exact: true })
    .click();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  const evidenceSessions = page.getByRole("navigation", { name: "Matching sessions" }).getByRole("button");
  await expect(evidenceSessions.first()).toBeVisible();
  const nativeActivity = page.getByRole("region", { name: "Session activity" }).getByRole("button", { name: /^Open event/ }).filter({ has: page.getByText("Native telemetry", { exact: true }) });
  for (const session of await evidenceSessions.all()) {
    await session.click();
    if (await nativeActivity.count()) break;
  }
  await nativeActivity.first().click();
  await page.getByRole("button", { name: /Open telemetry record/ }).click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Export evidence" }),
  ).toBeVisible();
  await expect(
    page.getByText("Yes · demo resource label", { exact: true }),
  ).toBeVisible();
  // The owner sees flattened records and the stored payload itself.
  const dialog = page.getByRole("dialog");
  await expect(
    dialog.getByRole("columnheader", { name: "Attributes" }),
  ).toBeVisible();
  await expect(dialog.getByText("openaidr.demo=true").first()).toBeVisible();
  await dialog.getByRole("tab", { name: "Raw payload" }).click();
  await expect(dialog.getByText("Canonical OTLP JSON")).toBeVisible();
  await expect(dialog.getByText('"openaidr.demo"').first()).toBeVisible();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  await page.screenshot({
    path: info.outputPath("telemetry.png"),
    fullPage: true,
  });
  await expect(page.getByRole("combobox", { name: "Activity type" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  expect(
    await page.evaluate(
      async () => (await fetch("/api/v1/telemetry/overview")).status,
    ),
  ).toBe(401);
  expect(errors).toEqual([]);
});

test("dashboard fits a mobile viewport with functional navigation", async ({
  page,
}, info) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  const dimensions = await page.evaluate(() => ({
    viewport: innerWidth,
    content: document.documentElement.scrollWidth,
  }));
  expect(dimensions.content).toBeLessThanOrEqual(dimensions.viewport);
  await page
    .getByRole("button", { name: "Open navigation", exact: true })
    .click();
  await page
    .getByRole("dialog")
    .getByRole("link", { name: "App Health", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toBeHidden();
  await expect(page.getByLabel("Search devices")).toBeVisible();
  await page.screenshot({
    path: info.outputPath("mobile.png"),
    fullPage: true,
  });
});
