import { test, expect } from "@playwright/test";
import { creditAmount, validCreditSnapshot } from "../src/lib/credits";
import { mockChartData } from "./fixtures/chart-layout";
import { creditFixture, inactiveCredits } from "./fixtures/credits";

test.use({ locale: "en-US", timezoneId: "UTC", hasTouch: true });

test("credits preserve fractional amounts and reject unverified accounting", () => {
  expect(creditAmount("35945.125400")).toBe("35,945.1254");
  expect(creditAmount("0.000001")).toBe("0.000001");
  expect(creditAmount("0.000000")).toBe("0");
  expect(creditAmount("0")).toBe("0");
  expect(creditAmount("0.025")).toBe("0.025");
  expect(creditAmount(null)).toBe("Unavailable");
  expect(creditAmount("-1.000000")).toBe("Unavailable");
  for (const invalid of ["1e2", "01", "0.0000001"]) expect(creditAmount(invalid)).toBe("Unavailable");
  expect(validCreditSnapshot(creditFixture())).toBe(true);
  expect(validCreditSnapshot(inactiveCredits("disabled"))).toBe(true);
  expect(validCreditSnapshot({ ...creditFixture(), status: "disabled" })).toBe(false);
  expect(validCreditSnapshot({ ...creditFixture(), status: "disabled", balance: { available: null, reserved: null } })).toBe(true);
  expect(validCreditSnapshot({ ...creditFixture(), credits_per_usd: "1" } as never)).toBe(false);
});

test("credit balance and feature usage remain readable with keyboard and touch", async ({ page }, info) => {
  await mockChartData(page);
  const requests: string[] = [];
  page.on("request", request => requests.push(new URL(request.url()).pathname));
  await page.route("**/api/v1/credits?**", route => route.fulfill({ json: creditFixture(new URL(route.request().url()).searchParams.get("range")!) }));
  await page.goto("/costs/openaidr");
  await expect(page.locator("main h1")).toHaveText("Credits & Usage");
  const balance = page.getByRole("region", { name: "Credit balance", exact: true });
  await expect(balance).toContainText("$1 = 100 credits");
  await expect(balance).toContainText("35,945.1254");
  await expect(balance).toContainText("10.000001");
  await expect(balance).toContainText("12.66");
  const chart = page.getByLabel("Credit usage chart", { exact: true });
  await expect(chart.locator(".recharts-bar")).toHaveCount(6);
  await chart.getByRole("application").focus();
  for (let index = 0; index < 24; index++) await page.keyboard.press("ArrowRight");
  await expect(chart.locator(".recharts-tooltip-wrapper")).toContainText("20 operations");
  await expect(chart.locator(".recharts-tooltip-wrapper")).toContainText("0.02 credits");
  const table = page.getByRole("table", { name: "Credit usage by feature" });
  await expect(table.getByRole("columnheader")).toHaveText(["Feature", "Operations", "Credits used"]);
  await expect(table.locator("tbody tr")).toHaveCount(10);
  await expect(table.getByRole("row").filter({ hasText: "Live Guardrail" })).toContainText("0.02");
  await expect(page.getByRole("button", { name: /Add more|Automatic reload/ })).toHaveCount(0);
  await expect(page.locator("main")).not.toContainText(/gpt-|claude-|provider|input tokens|output tokens/i);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole("heading", { name: "Credit balance", exact: true }).scrollIntoViewIfNeeded();
    await page.screenshot({ path: info.outputPath(`credits-${width}.png`), fullPage: true, animations: "disabled" });
  }
  await chart.scrollIntoViewIfNeeded();
  const bounds = (await chart.boundingBox())!;
  await page.touchscreen.tap(bounds.x + bounds.width * 0.8, bounds.y + 80);
  await expect(chart.locator(".recharts-tooltip-wrapper")).toContainText("credits");
  const readout = (await chart.locator(".recharts-tooltip-wrapper").boundingBox())!;
  expect(readout.x).toBeGreaterThanOrEqual(0);
  expect(readout.x + readout.width).toBeLessThanOrEqual(320);
  const tableScroll = page.getByRole("region", { name: "Scrollable data table" });
  await tableScroll.scrollIntoViewIfNeeded();
  await tableScroll.focus();
  await expect(tableScroll).toBeFocused();
  // WebKit cancels native scrolling when keyup occurs before the next frame.
  for (let index = 0; index < 20; index++) await page.keyboard.press("ArrowRight", { delay: 50 });
  await expect.poll(() => tableScroll.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
  await expect(table.getByRole("columnheader", { name: "Credits used", exact: true })).toBeInViewport();
  for (let index = 0; index < 20; index++) await page.keyboard.press("ArrowLeft", { delay: 50 });
  await expect.poll(() => tableScroll.evaluate(element => element.scrollLeft)).toBeLessThanOrEqual(1);
  await expect(table.getByRole("columnheader", { name: "Feature", exact: true })).toBeInViewport();
  await tableScroll.hover();
  await page.mouse.wheel(1000, 0);
  await expect.poll(() => tableScroll.evaluate(element => element.scrollLeft)).toBeGreaterThan(0);
  await expect(table.getByRole("columnheader", { name: "Credits used", exact: true })).toBeInViewport();
  await page.getByRole("button", { name: "30d", exact: true }).click();
  await expect(page.getByRole("region", { name: "Credit usage", exact: true })).toContainText("Daily credit usage · UTC");
  await page.getByRole("button", { name: "90d", exact: true }).click();
  await expect(page.getByRole("button", { name: "90d", exact: true })).toHaveAttribute("aria-pressed", "true");
  expect(requests).toContain("/api/v1/credits");
  expect(requests).not.toContain("/api/v1/costs/detections");
});

test("feature usage defaults to highest credits and sorts both numeric columns", async ({ page }) => {
  await mockChartData(page);
  await page.route("**/api/v1/credits?**", route => {
    const data = creditFixture(new URL(route.request().url()).searchParams.get("range")!);
    data.by_service.find(row => row.service === "guardrail")!.operations = 1234;
    data.by_service.find(row => row.service === "url_reputation")!.credits_charged = "2.000000";
    Object.assign(data.by_service.find(row => row.service === "rule_generation")!, { credits_charged: "0.000000", operations: 0 });
    data.by_service.find(row => row.service === "package_vulnerabilities")!.credits_charged = null;
    return route.fulfill({ json: data });
  });
  await page.goto("/costs/openaidr");
  const table = page.getByRole("table", { name: "Credit usage by feature" });
  const creditsHeader = table.getByRole("columnheader", { name: "Credits used", exact: true });
  const operationsHeader = table.getByRole("columnheader", { name: "Operations", exact: true });
  const features = table.locator("tbody tr td:first-child");
  const credits = table.locator("tbody tr td:nth-child(3)");
  const operations = table.locator("tbody tr td:nth-child(2)");
  await expect(creditsHeader).toHaveAttribute("aria-sort", "descending");
  await expect(operationsHeader).toHaveAttribute("aria-sort", "none");
  await expect(features).toHaveText(["Investigations", "URL reputation", "Application research", "Skill analysis", "Assistant", "Overview summaries", "Session summaries", "Live Guardrail", "Rule generation", "Package vulnerabilities"]);
  await expect(credits).toHaveText(["10", "2", "1", "0.5", "0.4", "0.1", "0.1", "0.02", "0", "Unavailable"]);

  await creditsHeader.getByRole("button").focus();
  await page.keyboard.press("Enter");
  await expect(creditsHeader).toHaveAttribute("aria-sort", "ascending");
  await expect(credits).toHaveText(["0", "0.02", "0.1", "0.1", "0.4", "0.5", "1", "2", "10", "Unavailable"]);
  await page.keyboard.press("Space");
  await expect(creditsHeader).toHaveAttribute("aria-sort", "descending");
  await expect(credits).toHaveText(["10", "2", "1", "0.5", "0.4", "0.1", "0.1", "0.02", "0", "Unavailable"]);

  await operationsHeader.getByRole("button").click();
  await expect(operationsHeader).toHaveAttribute("aria-sort", "descending");
  await expect(creditsHeader).toHaveAttribute("aria-sort", "none");
  await expect(operations).toHaveText(["1,234", "20", "20", "4", "2", "2", "2", "1", "1", "0"]);
  await expect(features.first()).toHaveText("Live Guardrail");
  await operationsHeader.getByRole("button").click();
  await expect(operationsHeader).toHaveAttribute("aria-sort", "ascending");
  await expect(operations).toHaveText(["0", "1", "1", "2", "2", "2", "4", "20", "20", "1,234"]);

  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(operationsHeader).toHaveAttribute("aria-sort", "ascending");
  await expect(operations).toHaveText(["0", "1", "1", "2", "2", "2", "4", "20", "20", "1,234"]);
  await page.getByRole("button", { name: "30d", exact: true }).click();
  await expect(page.getByText("Daily credit usage · UTC", { exact: true })).toBeVisible();
  await expect(operationsHeader).toHaveAttribute("aria-sort", "ascending");
  await expect(operations).toHaveText(["0", "1", "1", "2", "2", "2", "4", "20", "20", "1,234"]);
  await creditsHeader.getByRole("button").click();
  await expect(creditsHeader).toHaveAttribute("aria-sort", "descending");
  await expect(credits).toHaveText(["10", "2", "1", "0.5", "0.4", "0.1", "0.1", "0.02", "0", "Unavailable"]);
});

test("disabled, missing rates, unavailable balances and empty history stay distinct", async ({ page }, info) => {
  await mockChartData(page);
  let data = inactiveCredits("disabled");
  await page.route("**/api/v1/credits?**", route => route.fulfill({ json: data }));
  await page.goto("/costs/openaidr");
  await expect(page.getByText("Credit charging is off", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Credit balance" })).toContainText("Unavailable");
  await expect(page.getByLabel("Credit usage chart", { exact: true })).toHaveCount(0);
  for (const width of [1440, 320]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`credits-disabled-${width}.png`), fullPage: true, animations: "disabled" });
  }
  for (const [status, title] of [["unconfigured", "Credits are not configured"], ["unavailable", "Credit information is unavailable"]] as const) {
    data = inactiveCredits(status);
    await page.getByRole("button", { name: "Refresh credits" }).click();
    await expect(page.getByText(title, { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Credit balance" }).locator("dd")).toHaveText(["Unavailable", "Unavailable", "Unavailable"]);
  }
  data = { ...creditFixture(), balance: { available: "0.000000", reserved: "0.000000" },
    summary: { credits_charged: "0.000000", operations: 0, pending_operations: 0, unrated_operations: 0 }, by_service: [], series: [] };
  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(page.getByText("No operations in this period", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Credit balance" }).locator("dd")).toHaveText(["0", "0", "0"]);
  data = { ...data, status: "exhausted", balance: { available: "0.000000", reserved: "10.000000" } };
  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(page.getByText("No credits available", { exact: true })).toBeVisible();
  data = { ...creditFixture(), status: "disabled", balance: { available: null, reserved: null } };
  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(page.getByText("Credit charging is off", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Credit balance" }).locator("dd")).toHaveText(["Unavailable", "Unavailable", "12.66"]);
  await expect(page.getByLabel("Credit usage chart", { exact: true })).toBeVisible();
  await expect(page.getByRole("table", { name: "Credit usage by feature" })).toBeVisible();
});

test("confirmed usage hides historical rate annotations and preserves values across stale refreshes", async ({ page }, info) => {
  await mockChartData(page);
  let data = creditFixture();
  data.summary.pending_operations = 2;
  data.summary.unrated_operations = 2;
  data.by_service[0].pending_operations = 2;
  data.by_service[0].unrated_operations = 1;
  const bucket = data.series.find(row => row.by_service.some(service => service.service === "guardrail"))!;
  bucket.pending_operations = 2;
  bucket.unrated_operations = 1;
  data.series.at(-1)!.unrated_operations = 1;
  data.series.at(-1)!.by_service[0].unrated_operations = 1;
  let failed = false;
  await page.route("**/api/v1/credits?**", route => failed
    ? route.fulfill({ status: 503, json: { error: { message: "Unavailable" } } })
    : route.fulfill({ json: data }));
  await page.goto("/costs/openaidr");
  await expect(page.getByRole("region", { name: "Credit balance" }).locator("dd")).toHaveText(["35,945.1254", "10.000001", "12.66"]);
  await expect(page.getByText(/2 operations are pending/)).toBeVisible();
  const table = page.getByRole("table", { name: "Credit usage by feature" });
  await expect(table.getByRole("columnheader")).toHaveText(["Feature", "Operations", "Credits used"]);
  await expect(table.getByRole("row").filter({ hasText: "Live Guardrail" }).getByRole("cell")).toHaveText(["Live Guardrail", "20", "0.02"]);
  const chart = page.getByLabel("Credit usage chart", { exact: true });
  await chart.getByRole("application").focus();
  for (let index = 0; index < 24; index++) await page.keyboard.press("ArrowRight");
  await expect(chart.locator(".recharts-tooltip-wrapper")).toContainText("0.02 credits");
  await expect(page.locator("main")).not.toContainText(/partial|settlement|without a (credit )?rate|no recorded credit rate/i);
  await page.screenshot({ path: info.outputPath("credits-confirmed-usage.png"), fullPage: true, animations: "disabled" });
  failed = true;
  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("Showing the last loaded information");
  await expect(page.getByRole("region", { name: "Credit balance" })).toContainText("35,945.1254");
  await page.getByRole("button", { name: "90d", exact: true }).click();
  await expect(page.getByRole("region", { name: "Credit balance" })).toHaveCount(0);
  failed = false;
  data = { ...creditFixture("90d"), tenant_id: "another-tenant" };
  await page.getByRole("button", { name: "Refresh credits" }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("could not be verified");
  await expect(page.getByRole("region", { name: "Credit balance" })).toHaveCount(0);
});
