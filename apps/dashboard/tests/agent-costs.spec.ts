import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { once } from "node:events";
import { expectPublicNames } from "./public-names";
import { money } from "../src/lib/cost";

let backend: ChildProcess;
let output = "";
test.beforeAll(async () => {
  // Allow database creation and fixture seeding on a busy development host.
  // Individual browser flows retain the normal test timeout.
  test.setTimeout(120_000);
  if (!process.env.OPENAIDR_TEST_DATABASE_URL)
    throw new Error(
      "Set OPENAIDR_TEST_DATABASE_URL to a disposable PostgreSQL database. See docs/telemetry.md#agent-costs.",
    );
  backend = spawn(
    process.env.OPENAIDR_TEST_PYTHON || "python3",
    ["tests/fixtures/agent-costs-server.py"],
    { stdio: ["ignore", "pipe", "pipe"] },
  );
  backend.stdout!.on("data", (chunk) => {
    output += chunk.toString();
  });
  backend.stderr!.on("data", (chunk) => {
    output += chunk.toString();
  });
  const port = process.env.OPENAIDR_COST_TEST_API_PORT || "8769";
  await expect
    .poll(
      async () => {
        if (backend.exitCode !== null || backend.signalCode !== null)
          throw new Error(output);
        try {
          return (await fetch(`http://127.0.0.1:${port}/api/v1/auth/me`))
            .status;
        } catch {
          return 0;
        }
      },
      { timeout: 90_000 },
    )
    .toBe(401);
});
test.afterAll(async () => {
  if (backend && backend.exitCode === null) {
    const closed = once(backend, "close");
    backend.kill("SIGTERM");
    const [code] = await closed;
    expect(code, output).toBe(0);
  }
});

async function signIn(
  page: Page,
  path = "/costs/agents",
  email = "costs@example.invalid",
) {
  await page.goto("/login");
  await page.getByLabel("Email address").fill(email);
  await page.getByLabel("Password", { exact: true }).fill("cost-test-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).not.toHaveURL(/\/login$/);
  if ((page.viewportSize()?.width ?? 1440) < 1024)
    await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  await page.getByRole("navigation", { name: "Workspace navigation", exact: true })
    .locator(`a[href="${path}"]`).click();
  await page.getByRole("radio", { name: "UTC", exact: true }).check();
  await expect(
    path === "/costs/agents"
      ? page.getByRole("table", { name: "Cost by model" })
      : page
          .getByRole("heading", { name: "Credit balance", exact: true }),
  ).toBeVisible();
}

test("hook estimates show partial costs separately with honest range and filter limits", async ({page}, info) => {
  await signIn(page);
  const section = page.getByRole("region", {name:"Hook estimates", exact:true});
  const table = section.getByRole("table");
  await expect(table).toContainText("GitHub Copilot");
  await expect(table).toContainText("Assumed model: claude-sonnet-4-6");
  await expect(table).toContainText("~$0.0003");
  await expect(table.getByText("Cost unknown", {exact:true})).toHaveCount(2);
  await expect(table).toContainText("Guardrail");
  await expect(section).toContainText("not billed spend");
  await page.screenshot({path:info.outputPath("hook-estimates.png")});
  await page.getByRole("button", {name:"90d",exact:true}).click();
  await expect(section).toContainText("retained for 30 days");
  await expect(table).toHaveCount(0);
  await page.getByRole("button", {name:"24h",exact:true}).click();
  await expect(table).toContainText("~$0.0003");
  await page.getByRole("combobox", {name:"User filter",exact:true}).click();
  await page.getByRole("option", {name:"Alice",exact:true}).click();
  await expect(section).toContainText("Clear filters");
  await expect(table).toHaveCount(0);
  await page.getByRole("button", {name:"Clear filters",exact:true}).click();
  await expect(table).toContainText("~$0.0003");
  await page.setViewportSize({width:580,height:720});
  await section.scrollIntoViewIfNeeded();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  const scroll = section.getByRole("region", {name:"Scrollable data table"});
  await scroll.evaluate(node => { node.scrollLeft = node.scrollWidth; });
  await expect(table.getByText("~$0.0003", {exact:true})).toBeInViewport();
});

test("usage processing warning waits one minute and clears after processing", async ({ page }, info) => {
  // Poll fresh server snapshots even when the browser clock is far behind.
  await page.clock.install({ time: new Date("2000-01-01T00:00:00Z") });
  await page.clock.pauseAt(new Date("2000-01-01T00:00:01Z"));
  let age = 59_999;
  let pending = 1;
  await page.route("**/api/v1/costs/agents/summary?**", async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    await route.fulfill({ response, json: { ...data,
      processing: {
        ...data.processing,
        pending_exports: pending,
        pending_since: new Date(Date.parse(data.until) - age).toISOString(),
      },
    } });
  });
  await signIn(page);
  const warning = page.getByRole("status").filter({ hasText: "Usage is still being processed" });
  await expect(warning).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("usage-within-grace-period.png") });

  age = 60_000;
  await page.clock.fastForward(30_000);
  await expect(warning).toBeVisible();
  await page.screenshot({ path: info.outputPath("usage-processing-delayed.png") });

  pending = 0;
  await page.clock.fastForward(30_000);
  await expect(warning).toHaveCount(0);
});

test("usage processing warning remains when pending timing is unavailable", async ({ page }) => {
  let pendingSince: string | null = null;
  await page.route("**/api/v1/costs/agents/summary?**", async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    await route.fulfill({ response, json: { ...data,
      processing: { ...data.processing, pending_exports: 1, pending_since: pendingSince },
    } });
  });
  await signIn(page);
  const warning = page.getByRole("status").filter({ hasText: "Usage is still being processed" });
  await expect(warning).toBeVisible();
  pendingSince = "invalid";
  const refreshed = page.waitForResponse("**/api/v1/costs/agents/summary?**");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await refreshed;
  await expect(page.getByText("Updating results.", { exact: false })).toHaveCount(0);
  await expect(warning).toBeVisible();
});

test("project attribution progress is separate from usage processing", async ({ page }, info) => {
  await page.route("**/api/v1/costs/agents/summary?**", async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    await route.fulfill({ response, json: { ...data,
      processing: { ...data.processing, pending_exports: 0, pending_project_sessions: 2 },
    } });
  });
  await signIn(page);
  await expect(page.getByRole("status").filter({ hasText: "Project attribution is updating" })).toBeVisible();
  await expect(page.getByText("Usage is still being processed", { exact: false })).toHaveCount(0);
  await expect(page.getByRole("table", { name: "Cost by project", exact: true })).toBeVisible();
  await page.getByRole("status").filter({ hasText: "Project attribution is updating" })
    .screenshot({ path: info.outputPath("project-attribution-progress.png") });
});

test("real costs reconcile across ranges, row filters, sorting, and the cost chart", async ({
  page,
}, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await signIn(page);
  const ranges = page.getByRole("group", { name: "Cost time range", exact: true });
  await expect(ranges.getByRole("button")).toHaveText(["24h", "30d", "90d"]);
  await expect(ranges.getByRole("button", { name: "30d", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByText("38 of 50 calls priced", { exact: true })).toBeVisible();
  await ranges.getByRole("button", { name: "24h", exact: true }).click();
  await expect(
    page.getByText("36 of 48 calls priced", { exact: true }),
  ).toBeVisible();
  await expect(page.locator(".recharts-surface")).toHaveCount(1);
  for (const dimension of ["model", "project", "activity", "reasoning effort"]) {
    const table = page.getByRole("table", { name: `Cost by ${dimension}`, exact: true });
    await expect(table).toBeVisible();
    await expect(table.getByRole("columnheader")).toHaveCount(3);
    await expect(table.getByRole("columnheader", { name: "Calls", exact: true })).toHaveCount(0);
  }
  const models = page.getByRole("table", { name: "Cost by model" });
  await models.getByRole("button", { name: "Cost", exact: true }).click();
  await expect(
    models.getByRole("columnheader", { name: "Cost" }),
  ).toHaveAttribute("aria-sort", "ascending");
  await expect(models.getByRole("row").nth(1)).toContainText("gpt-6-luna");
  await models.getByRole("button", { name: "Cost", exact: true }).click();
  await expect(
    models.getByRole("columnheader", { name: "Cost" }),
  ).toHaveAttribute("aria-sort", "descending");
  await expect(models.getByRole("row").nth(1)).toContainText("gpt-6-astra");
  await page.getByRole("combobox", { name: "User filter", exact: true }).click();
  await page.getByRole("option", { name: "Alice", exact: true }).click();
  await expect(
    page.getByText("12 of 12 calls priced", { exact: true }),
  ).toBeVisible();
  await expect(
    models.getByRole("button", {
      name: "Filter by model: gpt-6-astra",
      exact: true,
    }),
  ).toBeVisible();
  await expect(models.getByRole("row")).toHaveCount(2);
  await page
    .getByRole("button", { name: "Clear filters", exact: true })
    .click();
  await expect(
    page.getByText("36 of 48 calls priced", { exact: true }),
  ).toBeVisible();
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.getByRole("button", { name: "30d", exact: true }).click();
  await expect(
    page.getByText("38 of 50 calls priced", { exact: true }),
  ).toBeVisible();
  const chart = page.getByRole("region", { name: "Cost over time by user", exact: true });
  await expect(chart.getByText("Daily estimated spend in USD · UTC", { exact: true })).toBeVisible();
  const grid = chart.locator(".recharts-cartesian-grid-horizontal line").first();
  const plotWidth = Number(await grid.getAttribute("x2")) - Number(await grid.getAttribute("x1"));
  const firstBar = chart.locator(".recharts-bar-rectangle path").first();
  const barWidth = Number(await firstBar.getAttribute("width"));
  expect(barWidth).toBeGreaterThan(plotWidth / 31 * 0.85);
  expect(barWidth).toBeLessThanOrEqual(plotWidth / 31);
  await page.screenshot({ path: info.outputPath("agent-costs-30d.png"), fullPage: true });
  await page.getByRole("button", { name: "90d", exact: true }).click();
  await expect(page.getByText("39 of 51 calls priced", { exact: true })).toBeVisible();
  await expect(ranges.getByRole("button", { name: "90d", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(chart.getByText("Daily estimated spend in USD · UTC", { exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("agent-costs-90d.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  for (const button of await ranges.getByRole("button").all()) await expect(button).toBeInViewport();
  await page.screenshot({ path: info.outputPath("agent-costs-90d-mobile.png"), fullPage: true });
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.getByRole("combobox", { name: "Project filter", exact: true }).click();
  await page.getByRole("option", { name: "Archive", exact: true }).click();
  await expect(page.getByText("1 of 1 calls priced", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(page.getByText("39 of 51 calls priced", { exact: true })).toBeVisible();
  await expect(
    page.getByRole("tablist", { name: "Cost display", exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByLabel("Estimated cost over time", { exact: true }),
  ).toBeVisible();
  await page.getByRole("button", { name: "24h", exact: true }).click();
  await expect(
    page.getByText("36 of 48 calls priced", { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("agent-costs-desktop.png"),
    fullPage: true,
  });
  expect(errors).toEqual([]);
});


test("compact stacked user costs preserve totals, isolation, and keyboard and touch readouts", async ({
  browser,
}, info) => {
  const context = await browser.newContext({
    baseURL: test.info().project.use.baseURL,
    hasTouch: true,
    viewport: { width: 1920, height: 900 },
  });
  const page = await context.newPage();
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  try {
    await signIn(page);
    const chart = page.getByRole("region", {
      name: "Cost over time by user",
      exact: true,
    });
    const users = chart.getByRole("group", {
      name: "Users in cost chart",
      exact: true,
    });
    await expect(users.getByRole("button")).toHaveCount(4);
    const userButtons = await users.getByRole("button").all();
    for (const button of userButtons) await expect(button).toBeInViewport();
    const userRows = await users.getByRole("button").evaluateAll((buttons) =>
      buttons.map((button) => button.getBoundingClientRect().top),
    );
    expect(new Set(userRows).size).toBe(1);
    for (const title of ["Models", "Projects", "Activity", "Reasoning effort"]) {
      const section = page.getByRole("region", { name: title, exact: true });
      await expect(section.getByRole("heading", { name: title, exact: true })).toBeInViewport();
      const scroll = section.getByRole("region", { name: "Scrollable data table" });
      expect(await scroll.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    }
    const breakdownTops = await page.getByRole("region", {
      name: /^(Models|Projects|Activity|Reasoning effort)$/,
    }).evaluateAll((sections) => sections.map((section) => section.getBoundingClientRect().top));
    expect(new Set(breakdownTops).size).toBe(1);
    const toolbarTops = await page.getByRole("group", { name: "Cost time range" })
      .or(page.getByRole("button", { name: "Refresh", exact: true }))
      .or(page.getByRole("combobox"))
      .evaluateAll((controls) => controls.map((control) => control.getBoundingClientRect().top));
    expect(new Set(toolbarTops).size).toBe(1);
    await expect(
      page.getByRole("table", { name: "Cost by user", exact: true }),
    ).toHaveCount(0);
    await expect(chart.locator(".recharts-bar")).toHaveCount(4);
    const data = await (
      await page.request.get("/api/v1/costs/agents/summary?range=30d")
    ).json();
    const aliceIndex = data.user_series.findIndex(
      (user: { name: string }) => user.name === "Alice",
    );
    const alice = data.user_series[aliceIndex];
    const cost = new Intl.NumberFormat("en-US", {
      style: "currency",
      currency: "USD",
    });
    await expect(chart.getByLabel("Displayed chart cost")).toContainText(
      cost.format(data.summary.cost_usd),
    );
    const aliceBar = chart
      .locator(".recharts-bar")
      .nth(aliceIndex)
      .locator(".recharts-bar-rectangle path")
      .first();
    const color = await aliceBar.getAttribute("fill");
    expect(color).toContain("var(--chart-1)");
    const palette = await users
      .locator("[aria-hidden=true]")
      .evaluateAll((nodes) =>
        nodes.map((node) => (node as HTMLElement).style.background),
      );
    expect(new Set(palette).size).toBe(4);
    expect(palette.every((value) => value.includes("var(--chart-1)"))).toBe(
      true,
    );
    await users
      .getByRole("button", { name: "Show Alice only", exact: true })
      .click();
    await expect(chart.locator(".recharts-bar")).toHaveCount(1);
    await expect(
      chart.locator(".recharts-bar-rectangle path").first(),
    ).toHaveAttribute("fill", color!);
    await expect(chart.getByLabel("Displayed chart cost")).toContainText(
      cost.format(alice.cost_usd),
    );
    await expect(
      page.getByRole("table", { name: "Cost by model" }).getByRole("row"),
    ).toHaveCount(5);
    await chart.getByRole("application").focus();
    await page.keyboard.press("ArrowRight");
    const tooltip = chart.locator(".recharts-tooltip-wrapper");
    await expect(tooltip).toBeVisible();
    await expect(tooltip).toContainText("Alice");
    await expect(tooltip).toContainText("UTC");
    await expect(tooltip).not.toContainText("Bob");
    await users
      .getByRole("button", { name: "Show Dana only", exact: true })
      .click();
    await expect(
      chart.getByText("Cost estimates are unavailable", { exact: true }),
    ).toBeVisible();
    await expect(chart.getByLabel("Displayed chart cost")).toContainText(
      "Unavailable",
    );
    await chart.getByRole("button", { name: "All users", exact: true }).click();
    await expect(chart.locator(".recharts-bar")).toHaveCount(4);
    await page.screenshot({
      path: info.outputPath("agent-costs-users-desktop.png"),
      fullPage: true,
    });
    for (const width of [1280, 1024, 768, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(() => page.evaluate(() =>
        document.documentElement.scrollWidth <= innerWidth,
      )).toBe(true);
      for (const scroll of await page.getByRole("region", { name: "Scrollable data table" }).all()) {
        expect(await scroll.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
      }
      for (const filter of await page.getByRole("combobox").all()) {
        const bounds = await filter.boundingBox();
        expect(bounds!.x).toBeGreaterThanOrEqual(0);
        expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
        expect(bounds!.height).toBeGreaterThanOrEqual(32);
      }
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await expect
      .poll(() =>
        page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      )
      .toBe(true);
    const plot = chart.getByLabel("Estimated cost over time", { exact: true });
    await plot.scrollIntoViewIfNeeded();
    const box = await plot.boundingBox();
    await page.touchscreen.tap(box!.x + box!.width * 0.7, box!.y + 80);
    await expect(tooltip).toBeVisible();
    await expect(tooltip).toContainText("Dana");
    const readout = await tooltip.boundingBox();
    expect(readout!.x).toBeGreaterThanOrEqual(0);
    expect(readout!.x + readout!.width).toBeLessThanOrEqual(390);
    await users
      .getByRole("button", { name: "Show Charlie only", exact: true })
      .click();
    await expect(chart.locator(".recharts-bar")).toHaveCount(1);
    await chart.getByRole("button", { name: "All users", exact: true }).click();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({
      path: info.outputPath("agent-costs-users-mobile.png"),
      fullPage: true,
    });
    expect(errors).toEqual([]);
  } finally {
    await context.close();
  }
});

test("cost chart supports a backend without per-user series during rollout", async ({
  page,
}) => {
  await page.route("**/api/v1/costs/agents/summary?*", async (route) => {
    const response = await route.fetch();
    const data = await response.json();
    delete data.user_series;
    await route.fulfill({ response, json: data });
  });
  await signIn(page);
  await expect(
    page.getByRole("heading", { name: "Cost over time", exact: true }),
  ).toBeVisible();
  await expect(page.locator(".recharts-bar")).toHaveCount(1);
  const users = page.getByRole("table", { name: "Cost by user", exact: true });
  await expect(users.getByRole("row")).toHaveCount(5);
  await users
    .getByRole("button", { name: "Filter by user: Alice", exact: true })
    .click();
  await expect(
    page.getByText("13 of 13 calls priced", { exact: true }),
  ).toBeVisible();
  await expect(users.getByRole("row")).toHaveCount(2);
});

test("reasoning effort costs sort by level and filter by the recorded level", async ({ page }, info) => {
  await signIn(page);
  await page.getByRole("button", { name: "24h", exact: true }).click();
  const table = page.getByRole("table", { name: "Cost by reasoning effort", exact: true });
  const data = await (await page.request.get("/api/v1/costs/agents/summary")).json();
  expect(data.by_reasoning_effort.reduce((calls: number, row: { calls: number }) => calls + row.calls, 0)).toBe(data.summary.calls);
  const levels = ["None", "Minimal", "Low", "Medium", "High", "Extra high", "Max", "Ultra"];
  for (const level of [...levels, "Auto", "Unknown"]) {
    await expect(table.getByRole("button", { name: `Filter by reasoning effort: ${level}`, exact: true })).toBeVisible();
  }
  await table.getByRole("button", { name: "Cost", exact: true }).click();
  await expect(table.getByRole("columnheader", { name: "Cost", exact: true })).toHaveAttribute("aria-sort", "ascending");
  const effortHeader = table.getByRole("columnheader", { name: "Reasoning effort", exact: true });
  const effortRows = table.locator("tbody").getByRole("button");
  const sortEffort = table.getByRole("button", { name: "Reasoning effort", exact: true });
  await sortEffort.focus();
  await page.keyboard.press("Enter");
  await expect(effortHeader).toHaveAttribute("aria-sort", "ascending");
  await expect(table.getByRole("columnheader", { name: "Cost", exact: true })).toHaveAttribute("aria-sort", "none");
  await expect(effortRows).toHaveText([...levels, "Auto", "Unknown"]);
  await sortEffort.click();
  await expect(effortHeader).toHaveAttribute("aria-sort", "descending");
  await expect(effortRows).toHaveText([...levels].reverse().concat("Auto", "Unknown"));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText("Updating results.", { exact: false })).toHaveCount(0);
  await expect(effortRows).toHaveText([...levels].reverse().concat("Auto", "Unknown"));
  await table.getByRole("button", { name: "Filter by reasoning effort: Extra high", exact: true }).click();
  const filter = page.getByRole("combobox", { name: "Reasoning effort filter", exact: true });
  await expect(filter).toHaveText("Extra high");
  await expect(table.getByRole("row")).toHaveCount(2);
  const expected = data.by_reasoning_effort.find((row: { name: string }) => row.name === "xhigh");
  await expect(page.getByText(`${expected.priced_calls} of ${expected.calls} calls priced`, { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "90d", exact: true }).click();
  await expect(filter).toHaveText("Extra high");
  await filter.click();
  await page.getByRole("option", { name: "Unknown", exact: true }).click();
  await expect(table.getByRole("button", { name: "Filter by reasoning effort: Unknown", exact: true })).toBeVisible();
  await expect(table.getByRole("row")).toHaveCount(2);
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await page.getByRole("button", { name: "24h", exact: true }).click();
  await expect(effortRows).toHaveText([...levels].reverse().concat("Auto", "Unknown"));
  await table.getByRole("button", { name: "Cost", exact: true }).click();
  await expect(effortHeader).toHaveAttribute("aria-sort", "none");
  await expect(table.getByRole("columnheader", { name: "Cost", exact: true })).toHaveAttribute("aria-sort", "descending");
  const effortNames: Record<string, string> = {
    none: "None", minimal: "Minimal", low: "Low", medium: "Medium", high: "High", xhigh: "Extra high",
    max: "Max", ultra: "Ultra", auto: "Auto", unknown: "Unknown",
  };
  await expect(effortRows).toHaveText(data.by_reasoning_effort.map((row: { name: string }) => effortNames[row.name]));
  const explanation = page.getByText("How cost estimates are calculated", { exact: true });
  await explanation.click();
  await expect(page.getByText("Reasoning effort uses reported request settings.", { exact: false })).toBeVisible();
  await explanation.click();
  await page.screenshot({ path: info.outputPath("reasoning-effort-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await sortEffort.click();
  await expect(effortRows).toHaveText([...levels, "Auto", "Unknown"]);
  await table.getByRole("button", { name: "Filter by reasoning effort: High", exact: true }).click();
  await expect(filter).toHaveText("High");
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: info.outputPath("reasoning-effort-mobile.png"), fullPage: true });
});

test("model provider logos preserve labels, filtering, and responsive layout", async ({ page }, info) => {
  await signIn(page, "/costs/agents", "providers@example.invalid");
  const models = page.getByRole("table", { name: "Cost by model", exact: true });
  for (const [model, provider] of [
    ["gpt-6-astra", "OpenAI"], ["claude-opus-5-5", "Anthropic"],
    ["gemini-3-pro", "Google Gemini"], ["openai/o3", "OpenAI"],
  ]) {
    await expect(models.getByRole("button", { name: `Filter by model: ${model}`, exact: true })
      .getByRole("img", { name: provider, exact: true })).toBeVisible();
  }
  for (const model of ["custom-model", "Guardrail"]) {
    const row = models.getByRole("button", { name: `Filter by model: ${model}`, exact: true });
    await expect(row).toBeVisible();
    await expect(row.getByRole("img")).toHaveCount(0);
  }
  await expectPublicNames(page);
  for (const icon of ["openai", "anthropic", "googlegemini"]) {
    const asset = await page.request.get(`/app-icons/${icon}.svg`);
    expect(asset.ok()).toBe(true);
    expect(asset.headers()["content-type"]).toContain("image/svg+xml");
  }
  for (const width of [1920, 1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    // WebKit can return from resizing before container queries update the grid.
    await expect.poll(async () => {
      const tops = await page.getByRole("region", { name: /^(Models|Projects|Activity|Reasoning effort)$/ })
        .evaluateAll(sections => sections.map(section => section.getBoundingClientRect().top));
      return new Set(tops).size;
    }).toBe(width === 1920 ? 1 : width === 1440 ? 2 : 4);
    const label = models.getByText("claude-opus-5-5", { exact: true });
    expect(await label.evaluate(element => element.getBoundingClientRect().height <=
      parseFloat(getComputedStyle(element).lineHeight))).toBe(true);
    const scroll = page.getByRole("region", { name: "Models", exact: true })
      .getByRole("region", { name: "Scrollable data table", exact: true });
    expect(await scroll.evaluate(element => element.scrollWidth <= element.clientWidth)).toBe(true);
    expect(await models.locator("td button").evaluateAll(buttons => buttons.every(button =>
      button.scrollWidth <= button.clientWidth))).toBe(true);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`model-providers-${width}.png`), fullPage: true });
  }
  await models.getByRole("button", { name: "Filter by model: gemini-3-pro", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Model filter", exact: true })).toHaveText("gemini-3-pro");
  await expect(models.getByRole("row")).toHaveCount(2);
  await expect(models.getByRole("img", { name: "Google Gemini", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(models.getByRole("row")).toHaveCount(7);
});

test("unknown prices, empty filters, network retry, and mobile layout stay explicit", async ({
  page,
  context,
}, info) => {
  await signIn(page);
  await page
    .getByRole("button", { name: "Filter by model: custom-model", exact: true })
    .click();
  await expect(
    page.getByText("Cost estimates are unavailable", { exact: true }),
  ).toBeVisible();
  await expect(page.locator("main")).not.toContainText("$0.00");
  await page
    .getByRole("combobox", { name: "User filter", exact: true })
    .click();
  await page.getByRole("option", { name: "Alice", exact: true }).click();
  await expect(
    page.getByText("No usage matches these filters", { exact: true }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Clear filters", exact: true })
    .first()
    .click();
  await expect(
    page.getByText("38 of 50 calls priced", { exact: true }),
  ).toBeVisible();
  await context.setOffline(true);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "Unable to load data" }),
  ).toBeVisible();
  await context.setOffline(false);
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "Unable to load data" }),
  ).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect
    .poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    )
    .toBe(true);
  await page
    .getByRole("combobox", { name: "Project filter", exact: true })
    .click();
  await page.getByRole("option", { name: "Console", exact: true }).click();
  await expect(
    page.getByRole("table", { name: "Cost by project" }).getByRole("row"),
  ).toHaveCount(2);
  await page.screenshot({
    path: info.outputPath("agent-costs-mobile.png"),
    fullPage: true,
  });
});

test("large cost teams group users, paginate models, search, and keep results visible during refresh", async ({
  page,
}, info) => {
  await signIn(page, "/costs/agents", "scale@example.invalid");
  const users = page.getByRole("group", { name: "Users in cost chart", exact: true });
  const models = page.getByRole("table", { name: "Cost by model", exact: true });
  await expect(users.getByRole("button")).toHaveCount(6);
  const otherUsers = users.getByRole("button", { name: "Show Other users (125) only", exact: true });
  await expect(otherUsers).toContainText("$7,875.00");
  await otherUsers.click();
  await expect(page.getByLabel("Displayed chart cost")).toContainText("$7,875.00");
  await expect(page.locator(".recharts-bar")).toHaveCount(1);
  await page.getByRole("button", { name: "All users", exact: true }).click();
  await expect(models.getByRole("row")).toHaveCount(26);
  const paging = page.getByLabel("Models pagination", { exact: true });
  await expect(paging).toContainText("1–25 of 130");
  await page.route("**/api/v1/costs/agents/summary?*", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: { message: "Temporary cost failure" } }),
    }),
  );
  await paging.getByRole("button", { name: "Next", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "Stale data" }),
  ).toBeVisible();
  await expect(paging).toContainText("1–25 of 130");
  await expect(
    users.getByRole("button", { name: "Show jev-operator only", exact: true }),
  ).toBeVisible();
  await expect(
    paging.getByRole("button", { name: "Previous", exact: true }),
  ).toBeDisabled();
  await expect(
    paging.getByRole("button", { name: "Next", exact: true }),
  ).toBeDisabled();
  await page.unroute("**/api/v1/costs/agents/summary?*");
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(paging).toContainText("26–50 of 130");
  await expect(
    models.getByRole("button", {
      name: "Filter by model: model-104",
      exact: true,
    }),
  ).toBeVisible();
  await page.getByLabel("Search users", { exact: true }).fill("007");
  await expect(page.getByText("1 matches", { exact: true })).toBeVisible();
  await page
    .getByRole("combobox", { name: "User filter", exact: true })
    .click();
  await page.getByRole("option", { name: "Person 007", exact: true }).click();
  await expect(
    page.getByText("1 of 1 calls priced", { exact: true }),
  ).toBeVisible();
  await expect(models.getByRole("row")).toHaveCount(2);
  await page
    .getByRole("button", { name: "Clear filters", exact: true })
    .click();
  await expect(
    page.getByText("130 of 130 calls priced", { exact: true }),
  ).toBeVisible();
  await expect(paging).toContainText("1–25 of 130");
  await page.getByLabel("Search users", { exact: true }).fill("");
  await page.getByLabel("Search models", { exact: true }).fill("Guar");
  await expect(page.getByText("2 matches", { exact: true })).toBeVisible();
  for (const [model, cost, index] of [
    ["JeV-1.13.0", 130, 1],
    ["Guardrail-1.13.0", 129, 0],
  ] as const) {
    const label = "Guardrail";
    await page.getByRole("combobox", { name: "Model filter", exact: true }).click();
    const options = page.getByRole("option", { name: "Guardrail", exact: true });
    await expect(options).toHaveCount(2);
    const selectedModel = page.waitForResponse((response) => {
      const url = new URL(response.url());
      return url.pathname.endsWith("/costs/agents/summary") && url.searchParams.get("model") === model;
    });
    await options.nth(index).click();
    const filtered = await (await selectedModel).json();
    expect(filtered.summary.cost_usd).toBe(cost);
    expect(filtered.by_model.map((row: { name: string }) => row.name)).toEqual([model]);
    await expect(page.getByText("1 of 1 calls priced", { exact: true })).toBeVisible();
    if (model === "JeV-1.13.0") {
      await expect(page.getByRole("button", { name: "Show jev-operator only", exact: true })).toHaveAttribute("title", "jev-operator");
      await expect(page.getByRole("button", { name: "Filter by project: /workspace/jev", exact: true })).toHaveAttribute("title", "/workspace/jev");
    }
    await expect(page.getByRole("combobox", { name: "Model filter", exact: true })).toHaveText(label);
    await expect(page.getByRole("button", { name: `Filter by model: ${label}`, exact: true })).toHaveAttribute("title", label);
    await expectPublicNames(page, page.getByRole("table", { name: "Cost by model", exact: true }));
    await page.getByRole("button", { name: "Clear filters", exact: true }).click();
    await expect(page.getByText("130 of 130 calls priced", { exact: true })).toBeVisible();
  }
  await page.getByLabel("Search models", { exact: true }).fill("Guardrail");
  await expect(page.getByText("2 matches", { exact: true })).toBeVisible();
  await page.getByLabel("Search models", { exact: true }).fill("");
  const refresh = page.getByRole("button", { name: "Refresh", exact: true });
  for (const action of ["Refresh", "90d"]) {
    let release!: () => void;
    const waiting = new Promise<void>((resolve) => {
      release = resolve;
    });
    const endpoint = "**/api/v1/costs/agents/summary?*";
    await page.route(endpoint, async (route) => {
      await waiting;
      await route.continue();
    });
    try {
      const requested = page.waitForRequest(endpoint);
      await page.getByRole("button", { name: action, exact: true }).click();
      await requested;
      await expect(refresh).toBeDisabled();
      await expect(page.getByText("Updating results.", { exact: false })).toHaveCount(0);
      await expect(users).toBeVisible();
      await expect(page.getByText("130 of 130 calls priced", { exact: true })).toBeVisible();
      await page.screenshot({ path: info.outputPath(`agent-costs-${action.toLowerCase()}-pending.png`) });
    } finally {
      release();
    }
    await expect(refresh).toBeEnabled();
    await expect(models.getByRole("row")).toHaveCount(26);
    await page.unroute(endpoint);
  }
  const unrelated: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/telemetry/overview"))
      unrelated.push(request.url());
  });
  await page.reload();
  await expect(users).toBeVisible();
  expect(unrelated).toEqual([]);
  await page.screenshot({
    path: info.outputPath("agent-costs-scale-desktop.png"),
    fullPage: true,
  });
  await page.goto("/administration/app");
  await expect.poll(() => unrelated.length).toBeGreaterThan(0);
  await expect(
    page.getByRole("heading", { name: "App Health", exact: true }),
  ).toBeVisible();
});
