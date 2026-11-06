import { expect, test, type Page } from "@playwright/test";

async function setup(page: Page, role = "it_admin", available = true) {
  let settings = { enabled: false, configured: false, available, version: 0,
    delivery: { pending: 0, failed: 0, last_sent_at: null as string | null } };
  let readFailure = false;
  let reads = 0;
  const writes: Record<string, unknown>[] = [];
  let tests = 0;
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Operator",
      email: "operator@example.test", roles: [role], tenant: { id: "tenant", slug: "tenant", name: "Tenant" } } } });
    if (path === "settings/slack") {
      if (route.request().method() === "GET") {
        reads++;
        if (readFailure) return route.fulfill({ status: 503, json: { error: { message: "Service unavailable" } } });
      }
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON();
        writes.push(body);
        if (body.version !== settings.version) return route.fulfill({ status: 409, json: { error: { message: "Slack settings changed. Refresh and try again" } } });
        settings = { ...settings, enabled: body.enabled, version: settings.version + 1,
          configured: "webhook_url" in body ? Boolean(body.webhook_url) : settings.configured };
      }
      return route.fulfill({ json: settings });
    }
    if (path === "settings/slack/test") {
      tests++;
      settings.delivery.pending++;
      return route.fulfill({ status: 202, json: { queued: true } });
    }
    if (path === "settings/model-keys") return route.fulfill({ json: {
      guardrail: { configured: false, masked: "", updated_at: null }, detection: { configured: false, masked: "", updated_at: null },
    } });
    if (path === "settings/summary-reports") return route.fulfill({ json: {
      automatic: false, available: false, version: 0, destination: null, next_report_at: null,
      delivery: { pending: 0, failed: 0, last_sent_at: null },
    } });
    if (path === "settings/session-detection") return route.fulfill({ json: {
      enabled: true, version: 0, max_cost_usd_per_attempt: "2", hourly_cost_usd: "10", availability: { reason: "ready" },
    } });
    if (path === "settings/telemetry-retention") return route.fulfill({ json: {
      mode: null, version: 0, cleanup_threshold_percent: null, automatic_available: false,
      message: "No retention policy has been saved.", status: "unconfigured", last_cleanup_at: null,
    } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  await page.goto("/administration/integrations");
  return { writes, tests: () => tests, reads: () => reads,
    readFailure: (value: boolean) => { readFailure = value; },
    available: (value: boolean) => { settings.available = value; },
    changed: () => { settings = { ...settings, configured: true, enabled: true, version: settings.version + 1 }; },
    delivered: () => { settings.delivery = { pending: 0, failed: 0, last_sent_at: "2026-10-19T08:05:40Z" }; },
  };
}

async function connect(page: Page) {
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  await card.getByLabel("Webhook URL", { exact: true }).fill("https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET");
  await card.getByRole("checkbox", { name: "Enable Slack notifications" }).check();
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toHaveValue("");
  return card;
}

test("saved webhook survives unavailable server setup and failed status refresh", async ({ page }, info) => {
  const state = await setup(page);
  const card = await connect(page);
  await expect(card).toContainText("Send incident and low disk space alerts to one shared channel.");
  await expect(card).toContainText("Sends one alert when a completed investigation detects an incident");
  await expect(card).toContainText("warns when server disk usage reaches 95%");
  await expect(card).toContainText("Policy findings and routine investigation summaries stay in the dashboard.");
  state.delivered();
  state.available(false);
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByText("Webhook saved. Delivery unavailable.", { exact: true })).toBeVisible();
  await expect(card.getByText("Server setup is incomplete. Your saved webhook is retained. Contact an operator to restore delivery.")).toBeVisible();
  await expect(card.getByRole("checkbox")).toBeChecked();
  await expect(card.getByRole("button", { name: "Send test message" })).toBeDisabled();
  await expect(card.getByText("Last successful delivery:", { exact: false })).toBeVisible();
  await card.screenshot({ path: info.outputPath("slack-delivery-unavailable.png"), animations: "disabled" });

  state.readFailure(true);
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByRole("alert")).toContainText("Unable to verify Slack status");
  await expect(card.getByText("Last known status: Webhook saved. Delivery unavailable.", { exact: true })).toBeVisible();
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toBeVisible();
  await expect(card.getByRole("button", { name: "Disconnect Slack" })).toBeDisabled();
  expect(state.writes).toHaveLength(1);

  state.readFailure(false);
  state.available(true);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(card.getByText("Webhook saved. Notifications enabled.", { exact: true })).toBeVisible();
  await expect(card.getByRole("alert")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Send test message" })).toBeEnabled();
});

test("status refreshes after save and delivery without overwriting an unsaved webhook", async ({ page }) => {
  await page.clock.install();
  const state = await setup(page);
  const readsBeforeSave = state.reads();
  const card = await connect(page);
  await expect.poll(state.reads).toBeGreaterThan(readsBeforeSave);
  await card.getByRole("button", { name: "Send test message" }).click();
  await expect(card.getByText("Pending deliveries: 1. Failed deliveries: 0.")).toBeVisible();
  state.delivered();
  await page.clock.runFor(15_000);
  await expect(card.getByText("Last successful delivery:", { exact: false })).toBeVisible();
  await expect(card.getByText("Pending deliveries: 0. Failed deliveries: 0.")).toBeVisible();
  await expect(card.getByText("Webhook saved. Notifications enabled.", { exact: true })).toBeVisible();

  const replacement = "https://hooks.slack.com/services/TTEST/BTEST/REPLACEMENT_SECRET";
  await card.getByLabel("Replace webhook URL", { exact: true }).fill(replacement);
  const readsBeforeEdit = state.reads();
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.clock.runFor(15_000);
  expect(state.reads()).toBe(readsBeforeEdit);
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toHaveValue(replacement);
  expect(state.writes).toHaveLength(1);
  expect(state.tests()).toBe(1);
});

test("a newer background response preserves the draft and requires explicit conflict recovery", async ({ page }, info) => {
  await page.clock.install();
  const state = await setup(page);
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  const input = card.getByLabel("Webhook URL", { exact: true });
  await input.focus();
  let releaseRead!: () => void;
  const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
  await page.route("**/api/v1/settings/slack", async (route) => {
    await readGate;
    await route.fallback();
  });
  state.changed();
  await page.clock.runFor(15_000);
  await expect(card.getByRole("button", { name: "Refresh", exact: true })).toBeDisabled();
  await expect(input).toBeFocused();
  await expect(input).toBeEnabled();
  const webhook = "https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET";
  await page.keyboard.insertText(webhook);
  releaseRead();
  await expect(card.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  const replacement = card.getByLabel("Replace webhook URL", { exact: true });
  await expect(replacement).toBeFocused();
  await expect(replacement).toHaveValue(webhook);
  await expect(card.getByRole("checkbox")).not.toBeChecked();
  await expect(card.getByRole("alert")).toContainText("Slack settings changed while you were editing");
  await expect(card.getByRole("button", { name: "Save Slack settings" })).toBeDisabled();
  await expect(card.getByRole("button", { name: "Disconnect Slack" })).toBeDisabled();
  await card.screenshot({ path: info.outputPath("slack-draft-conflict.png"), animations: "disabled" });
  await replacement.press("Enter");
  expect(state.writes).toHaveLength(0);
  await card.getByRole("button", { name: "Discard changes" }).click();
  await expect(replacement).toHaveValue("");
  await expect(card.getByRole("checkbox")).toBeChecked();
  await expect(card.getByRole("alert")).toHaveCount(0);
  await expect(card.getByRole("button", { name: "Send test message" })).toBeEnabled();
  await replacement.fill(webhook);
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await expect(replacement).toHaveValue("");
  expect(state.writes).toEqual([{ version: 1, enabled: true, webhook_url: webhook }]);
});

test("a read started before saving cannot replace the saved connection", async ({ page }) => {
  await setup(page);
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  await card.getByLabel("Webhook URL", { exact: true }).fill("https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET");
  await card.getByRole("checkbox", { name: "Enable Slack notifications" }).check();
  let saveStarted!: () => void;
  let releaseSave!: () => void;
  let readStarted!: () => void;
  let releaseRead!: () => void;
  const saving = new Promise<void>((resolve) => { saveStarted = resolve; });
  const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
  const reading = new Promise<void>((resolve) => { readStarted = resolve; });
  const readGate = new Promise<void>((resolve) => { releaseRead = resolve; });
  let holdRead = true;
  await page.route("**/api/v1/settings/slack", async (route) => {
    if (route.request().method() === "PUT") {
      saveStarted();
      await saveGate;
    } else if (holdRead) {
      holdRead = false;
      readStarted();
      await readGate;
      return route.fulfill({ json: { enabled: false, configured: false, available: true, version: 0,
        delivery: { pending: 0, failed: 0, last_sent_at: null } } });
    }
    return route.fallback();
  });
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await saving;
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await reading;
  const abortedRead = page.waitForEvent("requestfailed", { predicate: (request) =>
    request.method() === "GET" && request.url().endsWith("/api/v1/settings/slack"), timeout: 15_000 });
  releaseSave();
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toBeVisible();
  releaseRead();
  await abortedRead;
  await expect(card.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  await expect(card.getByText("Webhook saved. Notifications enabled.", { exact: true })).toBeVisible();
  await expect(card.getByRole("button", { name: "Send test message" })).toBeEnabled();
});

test("shared channel setup keeps the secret private and tests only saved destinations", async ({ page }, info) => {
  const state = await setup(page);
  await expect(page.getByRole("heading", { name: "Integrations", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Workspace navigation" }).getByRole("link", { name: "Integrations", exact: true })).toHaveAttribute("aria-current", "page");
  for (const name of ["Codex CLI", "Claude Code", "Device setup"]) {
    await expect(page.getByRole("region", { name, exact: true })).toHaveCount(0);
  }
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  await expect(card.getByText("No webhook saved.", { exact: true })).toBeVisible();
  await expect(card.getByRole("button", { name: "Send test message" })).toBeDisabled();
  const webhook = "https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET";
  await card.getByLabel("Webhook URL", { exact: true }).fill(webhook);
  await expect(card.getByLabel("Webhook URL", { exact: true })).toHaveAttribute("type", "password");
  await card.getByRole("checkbox", { name: "Enable Slack notifications" }).check();
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toHaveValue("");
  expect(state.writes).toEqual([{ version: 0, enabled: true, webhook_url: webhook }]);
  expect(state.tests()).toBe(0);
  await card.getByRole("button", { name: "Send test message" }).click();
  await expect(card.getByText("Test message queued. Delivery status updates automatically.")).toBeVisible();
  await expect(card.getByText("Pending deliveries: 1. Failed deliveries: 0.")).toBeVisible();
  await expect(card.getByText("No messages delivered yet.")).toBeVisible();
  expect(state.tests()).toBe(1);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 640 : 1000 });
    await card.getByRole("button", { name: "Disconnect Slack" }).scrollIntoViewIfNeeded();
    await expect(card.getByRole("button", { name: "Disconnect Slack" })).toBeInViewport();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath(`slack-integrations-${width}.png`), fullPage: true,
      animations: "disabled", style: "nextjs-portal { visibility: hidden; }" });
  }
  await card.getByRole("checkbox", { name: "Enable Slack notifications" }).uncheck();
  await expect(card.getByRole("button", { name: "Send test message" })).toBeDisabled();
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await expect(card.getByText("Webhook saved. Notifications disabled.")).toBeVisible();
  expect(state.writes[1]).toEqual({ version: 1, enabled: false });
  await card.getByRole("button", { name: "Disconnect Slack" }).click();
  await expect(card.getByText("No webhook saved.", { exact: true })).toBeVisible();
  expect(state.writes[2]).toEqual({ version: 2, enabled: false, webhook_url: "" });
  await page.goto("/administration/settings");
  await expect(page.getByRole("heading", { name: "Settings", exact: true, level: 1 })).toBeVisible();
  await expect(page.getByRole("region", { name: "Share reports with OpenSecura", exact: true })).toHaveCount(0);
  await expect(card).toHaveCount(0);
});

test("setup errors preserve input and do not report success", async ({ page }) => {
  const state = await setup(page);
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  await expect(card.getByLabel("Webhook URL", { exact: true })).toBeVisible();
  state.changed();
  const webhook = "https://hooks.slack.com/services/TTEST/BTEST/SYNTHETIC_SECRET";
  await card.getByLabel("Webhook URL", { exact: true }).fill(webhook);
  await card.getByRole("checkbox", { name: "Enable Slack notifications" }).check();
  await card.getByRole("button", { name: "Save Slack settings" }).click();
  await expect(card.getByRole("alert")).toContainText("Slack settings changed");
  await expect(card.getByLabel("Webhook URL", { exact: true })).toHaveValue(webhook);
  await expect(card.getByRole("button", { name: "Send test message" })).toBeDisabled();
  await expect(card.getByText("No webhook saved.", { exact: true })).toBeVisible();
  expect(state.writes).toEqual([{ version: 0, enabled: true, webhook_url: webhook }]);
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByRole("alert")).toContainText("Slack settings changed while you were editing");
  await expect(card.getByLabel("Replace webhook URL", { exact: true })).toHaveValue(webhook);
  await expect(card.getByRole("checkbox")).toBeChecked();
  await expect(card.getByRole("button", { name: "Save Slack settings" })).toBeDisabled();
});

test("server setup is required and non-admin roles cannot configure Slack", async ({ page }) => {
  await setup(page, "it_admin", false);
  const card = page.getByRole("region", { name: "Slack notifications", exact: true });
  await expect(card.getByText("An operator must complete server setup before Slack can be enabled.")).toBeVisible();
  await expect(card.getByRole("checkbox")).toBeDisabled();
  await expect(card.getByRole("button", { name: "Save Slack settings" })).toBeDisabled();
  await page.unrouteAll();
  await setup(page, "security_analyst");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(card).toHaveCount(0);
});
