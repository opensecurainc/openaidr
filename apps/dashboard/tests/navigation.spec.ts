import { test, expect, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const credentials = JSON.parse(
  readFileSync(
    process.env.OPENAIDR_DEMO_CREDENTIALS || resolve("../../.demo/login.json"),
    "utf8",
  ),
);
const pages = [
  ["Overview", "Overview", "/"],
  ["Detection and Response", "Risky Sessions/Users", "/user-risk"],
  ["AI Asset Management", "AI Apps", "/ai-inventory"],
  ["AI Asset Management", "AI Supply Chain", "/ai-supply-chain"],
  ["AI Asset Management", "AI Skills", "/ai-skills"],
  ["Detection and Response", "Detection Queue", "/detections"],
  ["Detection and Response", "Evidence Search", "/evidence"],
  ["Detection and Response", "Detection Rules", "/detection-rules"],
  ["Real-time Guardrail", "Live Guardrail", "/guardrail/live"],
  ["Real-time Guardrail", "Guardrail Configuration", "/guardrail/configuration"],
  ["Real-time Guardrail", "Guardrail History", "/guardrail/history"],
  ["Real-time Guardrail", "Company Policy and Knowledge", "/company-knowledge"],
  ["Cost Management", "AI Agent Costs", "/costs/agents"],
  ["Cost Management", "Credits & Usage", "/costs/openaidr"],
  ["Administration", "App Health", "/administration/app"],
  ["Administration", "Server Health", "/administration/server"],
  ["Administration", "App Enrollment", "/administration/enrollment"],
  ["Administration", "Integrations", "/administration/integrations"],
  ["Administration", "Audit Logs", "/audit-logs"],
  ["Administration", "Users and Roles", "/administration/users"],
  ["Administration", "Settings", "/administration/settings"],
] as const;

async function signIn(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Email address").fill(credentials.email);
  await page.getByLabel("Password", { exact: true }).fill(credentials.password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "AI summary", exact: true }),
  ).toBeVisible();
}

async function noPageOverflow(page: Page) {
  const size = await page.evaluate(() => ({
    content: document.documentElement.scrollWidth,
    viewport: innerWidth,
  }));
  expect(size.content).toBeLessThanOrEqual(size.viewport);
}

test("all requested categories and pages share navigation, headings, and Geist", async ({
  page,
}, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await signIn(page);
  // The header names the build so a screenshot identifies what it shows.
  await expect(page.locator("header [data-slot=build-info]")).toHaveText(
    /^OpenAIDR \d{4}\.\d{1,2}\.\d{1,2}\+[0-9a-f]{7,40} · Built .+$/,
  );
  const nav = page.getByRole("navigation", { name: "Workspace navigation" });
  await expect(nav.getByRole("link")).toHaveCount(pages.length);
  for (const group of new Set(pages.map(([group]) => group))) {
    await expect(
      nav.locator("p").filter({ hasText: new RegExp(`^${group}$`) }),
    ).toBeVisible();
  }
  await expect(
    page.getByText("Your environment. Your data.", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText("Telemetry stays in your organization’s infrastructure.", {
      exact: true,
    }),
  ).toHaveCount(0);
  for (const [group, title, path, navTitle = title] of pages) {
    const link = nav.getByRole("link", { name: navTitle, exact: true });
    await expect(link).toHaveAttribute("href", path);
    await link.click();
    await expect(page).toHaveURL((url) => url.pathname === path);
    await expect(page.locator("main h1")).toHaveText(title);
    await expect(page.locator('main [role="status"]').filter({ hasText: /Loading|Checking access/ })).toHaveCount(0);
    await expect(link).toHaveAttribute("aria-current", "page");
    await expect(
      page.getByRole("navigation", { name: "Breadcrumb" }),
    ).toContainText(group);
    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
    await expect(
      page.getByRole("alert").filter({ hasText: "Unable to load data" }),
    ).toHaveCount(0);
    expect(
      await page
        .locator("main")
        .evaluate((node) => getComputedStyle(node).fontFamily),
    ).toMatch(/^GeistSans,/);
    // The type scale resets the font-family namespace; weight utilities must survive it.
    expect(
      await page
        .locator("main h1")
        .evaluate((node) => getComputedStyle(node).fontWeight),
    ).toBe("600");
    await noPageOverflow(page);
    if (path === "/administration/app") {
      const chart = page.getByLabel("Stacked chart of log records, metric points, and spans by received time");
      const areas = chart.locator(".recharts-area-area");
      await expect(areas).toHaveCount(3);
      const keys = page.getByRole("list", { name: "Series", exact: true }).locator("svg line");
      for (const [index, color] of ["rgb(3, 112, 124)", "rgb(166, 127, 169)", "rgb(59, 67, 81)"].entries()) {
        await expect(areas.nth(index)).toHaveCSS("fill", color);
        await expect(areas.nth(index)).toHaveAttribute("fill-opacity", "0.08");
        await expect(keys.nth(index)).toHaveCSS("stroke", color);
      }
      for (const [index, pattern] of [[1, "5 3"], [2, "2 3"]] as const) {
        await expect(chart.locator(".recharts-area-curve").nth(index)).toHaveAttribute("stroke-dasharray", pattern);
        await expect(keys.nth(index)).toHaveAttribute("stroke-dasharray", pattern);
      }
    }
  }
  await expect(
    page.getByRole("heading", { name: "Tenant", exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("settings-desktop.png"),
    fullPage: true,
  });
  await page.goto("/devices");
  await expect(page).toHaveURL(/\/administration\/app$/);
  await page.goto("/telemetry");
  await expect(page).toHaveURL(/\/evidence$/);
  await expect(
    page.getByRole("button", { name: /^View export / }).first(),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("evidence-desktop.png"),
    fullPage: true,
  });
  expect(errors).toEqual([]);
});

test("mobile navigation reaches every page and keeps content within the viewport", async ({
  page,
}, info) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await signIn(page);
  for (const [, title, , navTitle = title] of pages) {
    await page.getByRole("button", { name: "Open navigation" }).click();
    const drawer = page.getByRole("dialog", { name: "Workspace navigation" });
    await expect(
      drawer.getByRole("link").filter({ hasText: /^OpenAIDR$/ }),
    ).toHaveCount(1);
    await drawer.getByRole("link", { name: navTitle, exact: true }).click();
    await expect(drawer).toBeHidden();
    await expect(page.locator("main h1")).toHaveText(title);
    await expect(page.locator('main [role="status"]').filter({ hasText: /Loading|Checking access/ })).toHaveCount(0);
    await noPageOverflow(page);
  }
  await page.screenshot({
    path: info.outputPath("settings-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page
    .getByRole("dialog")
    .getByRole("link", { name: "Settings", exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("navigation-mobile.png") });
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toBeHidden();
  await expect(
    page.getByRole("button", { name: "Open navigation" }),
  ).toBeFocused();
});

test("section actions wrap below the title on narrow screens", async ({
  page,
}) => {
  await page.setViewportSize({ width: 360, height: 800 });
  await signIn(page);
  await page.goto("/administration/enrollment");
  const heading = page.getByRole("heading", {
    name: "Enrollment tokens",
    exact: true,
  });
  const action = page.getByRole("button", { name: "Create enrollment link" }).first();
  await expect(action).toBeVisible();
  const title = await heading.boundingBox();
  const button = await action.boundingBox();
  expect(title && button).toBeTruthy();
  // The title keeps its own line width instead of being squeezed beside the actions.
  expect(title!.width).toBeGreaterThanOrEqual(200);
  const overlaps =
    title!.x < button!.x + button!.width &&
    button!.x < title!.x + title!.width &&
    title!.y < button!.y + button!.height &&
    button!.y < title!.y + title!.height;
  expect(overlaps).toBe(false);
  await noPageOverflow(page);
});

test("data failures can be retried and cost views load", async ({
  page,
}) => {
  await signIn(page);
  let fail = true;
  await page.route("**/api/v1/users", async (route) => {
    if (fail)
      await route.fulfill({
        status: 503,
        json: { error: { message: "Temporary users outage" } },
      });
    else await route.continue();
  });
  await page.goto("/administration/users");
  await expect(
    page.getByRole("alert").filter({ hasText: "Unable to load data" }),
  ).toContainText("Temporary users outage");
  await expect(
    page.getByText("No users returned", { exact: true }),
  ).toHaveCount(0);
  fail = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(
    page.getByRole("cell").filter({ hasText: credentials.email }),
  ).toBeVisible();
  await expect(
    page.getByRole("alert").filter({ hasText: "Unable to load data" }),
  ).toHaveCount(0);
  for (const [path, text, count] of [
    ["/costs/agents", "Cost over time by user", 1],
    ["/costs/openaidr", "Credit balance", 1],
  ] as const) {
    await page.goto(path);
    const headings = page.getByRole("heading", { name: text, exact: true });
    await expect(headings).toHaveCount(count);
    for (const heading of await headings.all()) await expect(heading).toBeVisible();
    await expect(
      page.getByRole("combobox", { name: "Service filter" }),
    ).toHaveCount(0);
  }
});

test("restricted roles do not request audit or enrollment credentials", async ({
  page,
}) => {
  await signIn(page);
  await page.route("**/api/v1/auth/me", async (route) => {
    const response = await route.fetch();
    const value = await response.json();
    value.user.roles = ["security_leadership"];
    await route.fulfill({ response, json: value });
  });
  const protectedRequests: string[] = [];
  page.on("request", (request) => {
    if (/\/api\/v1\/(audit|sensors\/enrollment-(tokens|links))/.test(request.url()))
      protectedRequests.push(request.url());
  });
  await page.goto("/administration/enrollment");
  await expect(
    page.getByText("Access restricted", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Create enrollment link", exact: true }),
  ).toHaveCount(0);
  await page.goto("/audit-logs");
  await expect(page.locator("main")).toContainText(/administrator|owner/i);
  expect(protectedRequests).toEqual([]);
});

test.describe("enrollment link defaults", () => {
  test.use({ timezoneId: "America/Los_Angeles" });
test("enrollment controls require explicit actions and clear one-time secrets", async ({
  page,
  context,
}, info) => {
  await signIn(page);
  const id = "00000000-0000-4000-8000-000000000001";
  const secret = "https://tenant.example/enroll#token=oaet_" + "a".repeat(43);
  let tokens: Record<string, unknown>[] = [];
  let expectedLabel = "Browser test";
  let expectedHours = 1;
  let creates = 0,
    revokes = 0;
  // Only enrollment responses are simulated. No credential mutations reach the live API.
  await page.route("**/api/v1/sensors/enrollment-**", async (route) => {
    const request = route.request();
    if (request.method() === "POST") {
      expect(request.url()).toContain("/sensors/enrollment-links");
      const payload = request.postDataJSON();
      expect(payload).toEqual({
        label: expectedLabel,
        expires_in_hours: expectedHours,
        max_uses: 100,
      });
      creates++;
      const item = {
        id,
        label: payload.label,
        uses: 0,
        max_uses: payload.max_uses,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + expectedHours * 3600000).toISOString(),
        revoked_at: null,
      };
      tokens = [item];
      await route.fulfill({ status: 201, json: { ...item, enrollment_url: secret } });
    } else if (request.method() === "DELETE") {
      expect(request.url()).toContain(id);
      revokes++;
      tokens = tokens.map((item) => ({
        ...item,
        revoked_at: new Date().toISOString(),
      }));
      await route.fulfill({ status: 204 });
    } else {
      expect(request.method()).toBe("GET");
      await route.fulfill({ json: { items: tokens } });
    }
  });
  await page.goto("/administration/enrollment");
  await page
    .getByRole("button", { name: "Create enrollment link", exact: true })
    .first()
    .click();
  const dialog = page.getByRole("dialog");
  const label = dialog.getByLabel("Label (optional)", { exact: true });
  await expect(label).toHaveValue("");
  await expect(dialog.getByRole("spinbutton", { name: "Max uses", exact: true })).toHaveValue("100");
  const expiry = dialog.getByRole("combobox", { name: "Expires after" });
  await expect(expiry).toHaveText("1 hour");
  await expiry.click();
  await expect(page.getByRole("option")).toHaveText(["1 hour", "24 hours", "7 days"]);
  await page.getByRole("listbox").screenshot({ path: info.outputPath("enrollment-expiry-options.png") });
  await page.getByRole("option", { name: "1 hour", exact: true }).click();
  await dialog.screenshot({ path: info.outputPath("enrollment-link-defaults-desktop.png") });
  await label.fill("  Browser test  ");
  expect(creates).toBe(0);
  await dialog
    .getByRole("button", { name: "Create enrollment link", exact: true })
    .click();
  await expect(page.getByLabel("Enrollment link", { exact: true })).toHaveValue(
    secret,
  );
  expect(creates).toBe(1);
  expect(await page.evaluate(() => localStorage.length)).toBe(0);
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await dialog.getByRole("button", { name: "Copy link", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secret);
  await dialog.screenshot({ path: info.outputPath("enrollment-link-created.png") });
  await page.setViewportSize({ width: 390, height: 844 });
  await noPageOverflow(page);
  await expect(dialog.getByRole("button", { name: "Done", exact: true })).toBeInViewport();
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByLabel("Enrollment link", { exact: true })).toHaveCount(0);
  await page
    .getByRole("button", { name: "Revoke Browser test", exact: true })
    .click();
  expect(revokes).toBe(0);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(revokes).toBe(0);
  await page
    .getByRole("button", { name: "Revoke Browser test", exact: true })
    .click();
  await dialog
    .getByRole("button", { name: "Revoke token", exact: true })
    .click();
  await expect(dialog).toBeHidden();
  expect(revokes).toBe(1);
  await expect(
    page.getByRole("button", { name: "Revoke Browser test", exact: true }),
  ).toBeDisabled();
  for (const [input, time, generated, option, hours] of [
    ["", "2026-10-02T19:34:00Z", "202610021234_rollout", "24 hours", 24],
    ["   ", "2026-01-02T11:04:00Z", "202601020304_rollout", "7 days", 168],
  ] as const) {
    await page.clock.setFixedTime(new Date(time));
    expectedLabel = generated;
    expectedHours = hours;
    const before = creates;
    await page.getByRole("button", { name: "Create enrollment link", exact: true }).first().click();
    await expect(label).toHaveValue("");
    await expect(expiry).toHaveText("1 hour");
    await label.fill(input);
    await expiry.click();
    await page.getByRole("option", { name: option, exact: true }).click();
    await noPageOverflow(page);
    if (!input) {
      await dialog.screenshot({ path: info.outputPath("enrollment-link-defaults-mobile.png") });
    }
    expect(creates).toBe(before);
    await dialog.getByRole("button", { name: "Create enrollment link", exact: true }).click();
    await expect(page.getByLabel("Enrollment link", { exact: true })).toHaveValue(secret);
    expect(creates).toBe(before + 1);
    await dialog.getByRole("button", { name: "Done", exact: true }).click();
    await expect(page.getByRole("cell").filter({ hasText: generated })).toBeVisible();
  }
});
});
