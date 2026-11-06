import { expect, test, type Page } from "@playwright/test";
import { mockChartData } from "./fixtures/chart-layout";

const channel = "https://app.slack.com/client/T0123456789/C0123456789";
const otherChannel = "https://acme.slack.com/archives/C9876543210";

async function setup(page: Page, role = "it_admin", url = "") {
  await mockChartData(page);
  const state = { role, tenant: "tenant-a", failure: false, settings: { slack_channel_url: url, version: 0, updated_at: null as string | null } };
  const writes: Record<string, unknown>[] = [];
  const responses: Record<string, unknown> = {
    "settings/session-detection": { enabled: true, version: 1, max_cost_usd_per_attempt: "2", hourly_cost_usd: "10", availability: { reason: "ready" } },
    "settings/model-keys": { guardrail: { configured: false, masked: "", updated_at: null }, detection: { configured: false, masked: "", updated_at: null } },
    "settings/telemetry-retention": { mode: null, cleanup_threshold_percent: null, version: 0, message: "", status: "unconfigured", automatic_available: false, last_cleanup_at: null },
    "settings/summary-reports": { automatic: false, available: false, version: 0, destination: null, next_report_at: null, delivery: { pending: 0, failed: 0, last_sent_at: null } },
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Test operator", email: "operator@example.test", roles: [state.role], tenant: { id: state.tenant, slug: state.tenant, name: "OpenSecura test" } } } });
    if (path === "settings/support") {
      if (state.failure) return route.fulfill({ status: 503, json: { error: { message: "Unavailable" } } });
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON();
        writes.push(body);
        if (body.version !== state.settings.version) return route.fulfill({ status: 409, json: { error: { message: "Support settings changed. Refresh and try again." } } });
        state.settings = { slack_channel_url: body.slack_channel_url, version: state.settings.version + 1, updated_at: "2026-10-23T18:00:00Z" };
      }
      return route.fulfill({ json: state.settings });
    }
    if (path in responses) return route.fulfill({ json: responses[path] });
    return route.fallback();
  });
  return { state, writes };
}

test("admins save and remove a persistent support link that opens in a separate tab", async ({ page, context }, info) => {
  const { writes } = await setup(page);
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Support", exact: true });
  const input = card.getByLabel("Slack channel link");
  await expect(input).toHaveValue("");
  await input.fill(channel);
  await card.getByRole("button", { name: "Save support channel" }).click();
  await expect(card.getByRole("status")).toHaveText("Support channel saved.");
  expect(writes).toEqual([{ slack_channel_url: channel, version: 0 }]);
  await page.getByRole("button", { name: "Contact support", exact: true }).click();
  const panel = page.getByRole("dialog", { name: "Contact support" });
  const link = panel.getByRole("link", { name: "Open Slack" });
  await expect(link).toHaveAttribute("href", channel);
  await expect(link).toHaveAttribute("rel", "noopener noreferrer");
  await context.route("https://app.slack.com/**", route => route.fulfill({ body: "Test Slack channel" }));
  const popupPromise = context.waitForEvent("page");
  await link.click();
  const popup = await popupPromise;
  await expect(popup).toHaveURL(channel);
  expect(await popup.evaluate(() => window.opener)).toBeNull();
  await popup.close();
  await page.keyboard.press("Escape");
  await page.reload();
  await expect(input).toHaveValue(channel);
  await page.setViewportSize({ width: 1600, height: 1000 });
  await page.getByRole("button", { name: "Contact support", exact: true }).click();
  await expect(panel.getByRole("link", { name: "Open Slack" })).toBeVisible();
  await page.screenshot({ path: info.outputPath("support-settings.png"), animations: "disabled" });
  await page.keyboard.press("Escape");
  await input.fill("");
  await card.getByRole("button", { name: "Save support channel" }).click();
  await expect(card.getByRole("status")).toHaveText("Support channel removed.");
  await page.getByRole("button", { name: "Contact support", exact: true }).click();
  await expect(panel.getByRole("link", { name: "Open Slack" })).toHaveCount(0);
  await panel.getByRole("link", { name: "Set up support" }).click();
  await expect(page).toHaveURL(/\/administration\/settings#support$/);
  await expect(panel).toHaveCount(0);
  await page.reload();
  await expect(input).toHaveValue("");
});

for (const role of ["security_analyst", "security_leadership"]) {
  test(`${role} can use support but cannot configure it`, async ({ page }) => {
    const { state, writes } = await setup(page, role, channel);
    for (const path of ["/", "/administration/settings"]) {
      await page.goto(path);
      await page.getByRole("button", { name: "Contact support", exact: true }).click();
      const panel = page.getByRole("dialog", { name: "Contact support" });
      await expect(panel.getByRole("link", { name: "Open Slack" })).toHaveAttribute("href", channel);
      await expect(page.getByLabel("Slack channel link")).toHaveCount(0);
    }
    await page.keyboard.press("Escape");
    state.settings.slack_channel_url = "";
    await page.getByRole("button", { name: "Contact support", exact: true }).click();
    const panel = page.getByRole("dialog", { name: "Contact support" });
    await expect(panel).toContainText("Contact your IT admin for help.");
    await expect(panel.getByRole("link")).toHaveCount(0);
    expect(writes).toEqual([]);
  });
}

test("conflicts and read failures retain the draft and block an unverified save", async ({ page }) => {
  const { state, writes } = await setup(page, "it_admin", channel);
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Support", exact: true });
  const input = card.getByLabel("Slack channel link");
  await expect(input).toHaveValue(channel);
  await input.fill(otherChannel);
  state.settings = { ...state.settings, version: 1, slack_channel_url: "" };
  await card.getByRole("button", { name: "Save support channel" }).click();
  await expect(card.getByRole("alert")).toContainText("changed while you were editing");
  await expect(input).toHaveValue(otherChannel);
  await expect(card.getByRole("button", { name: "Save support channel" })).toBeDisabled();
  await card.getByRole("button", { name: "Discard changes" }).click();
  await expect(input).toHaveValue("");
  await input.fill(otherChannel);
  state.failure = true;
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByRole("alert")).toContainText("Unable to load");
  await expect(input).toHaveValue(otherChannel);
  await expect(card.getByRole("button", { name: "Save support channel" })).toBeDisabled();
  state.failure = false;
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByRole("button", { name: "Save support channel" })).toBeEnabled();
  await card.getByRole("button", { name: "Save support channel" }).click();
  await expect(card.getByRole("status")).toHaveText("Support channel saved.");
  expect(writes).toEqual([{ slack_channel_url: otherChannel, version: 0 }, { slack_channel_url: otherChannel, version: 1 }]);
});

test("support suppresses stale or unsafe links and clears the panel when tenants change", async ({ page }) => {
  const { state } = await setup(page, "it_admin", channel);
  await page.goto("/costs/agents");
  const trigger = page.getByRole("button", { name: "Contact support", exact: true });
  const panel = page.getByRole("dialog", { name: "Contact support" });
  await trigger.click();
  await expect(panel.getByRole("link", { name: "Open Slack" })).toHaveAttribute("href", channel);
  await page.keyboard.press("Escape");
  state.failure = true;
  await trigger.click();
  await expect(panel.getByRole("alert")).toContainText("Support is unavailable");
  await expect(panel.getByRole("link")).toHaveCount(0);
  state.failure = false;
  state.settings.slack_channel_url = "javascript:alert(1)";
  await panel.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(panel.getByRole("alert")).toContainText("Support is unavailable");
  await expect(panel.getByRole("link")).toHaveCount(0);
  state.settings.slack_channel_url = channel;
  await panel.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(panel.getByRole("link", { name: "Open Slack" })).toHaveAttribute("href", channel);
  state.tenant = "tenant-b";
  state.settings = { slack_channel_url: "", version: 0, updated_at: null };
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(panel).toHaveCount(0);
  await trigger.click();
  await expect(panel.getByRole("link", { name: "Set up support" })).toBeVisible();
  await expect(panel.getByRole("link", { name: "Open Slack" })).toHaveCount(0);
});

test("support remains reachable and keyboard accessible at desktop and mobile widths", async ({ page }, info) => {
  await setup(page, "it_admin", channel);
  await page.goto("/administration/settings");
  const trigger = page.getByRole("button", { name: "Contact support", exact: true });
  const panel = page.getByRole("dialog", { name: "Contact support" });
  for (const [width, height] of [[1600, 1000], [1280, 800], [1024, 768], [390, 844], [320, 568], [390, 280]]) {
    await page.setViewportSize({ width, height });
    await trigger.focus();
    await page.keyboard.press("Enter");
    await expect(panel.getByRole("link", { name: "Open Slack" })).toBeVisible();
    await panel.getByRole("link", { name: "Open Slack" }).scrollIntoViewIfNeeded();
    await expect(panel.getByRole("link", { name: "Open Slack" })).toBeInViewport();
    const bounds = await panel.boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(width);
    expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(height);
    expect(await page.locator("header").evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    const breadcrumb = await page.locator('header [aria-current="page"]').boundingBox();
    const timeZone = await page.getByRole("group", { name: "Time zone", exact: true }).boundingBox();
    expect(breadcrumb!.x + breadcrumb!.width).toBeLessThanOrEqual(timeZone!.x);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    if (width === 390 && height === 844) await page.screenshot({ path: info.outputPath("support-mobile.png"), animations: "disabled" });
    await page.keyboard.press("Escape");
    await expect(panel).toHaveCount(0);
    await expect(trigger).toBeFocused();
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await trigger.click();
  await page.getByRole("heading", { name: "Settings", exact: true }).click();
  await expect(panel).toHaveCount(0);
});
