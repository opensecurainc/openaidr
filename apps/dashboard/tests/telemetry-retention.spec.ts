import { test, expect, type Page } from "@playwright/test";

type Settings = {
  mode: string | null;
  cleanup_threshold_percent: number | null;
  version: number;
  message: string;
  status: string;
  automatic_available: boolean;
  last_cleanup_at: string | null;
};

async function retentionPage(page: Page, { role = "it_admin", available = true, mode = null, threshold = null }: {
  role?: string; available?: boolean; mode?: string | null; threshold?: number | null;
} = {}) {
  let settings: Settings = {
    mode, cleanup_threshold_percent: threshold, version: mode ? 1 : 0,
    message: mode ? "Waiting for the next retention check." : "No retention policy has been saved. Telemetry is retained.",
    status: mode ? "waiting" : "unconfigured", automatic_available: available, last_cleanup_at: null,
  };
  const writes: { mode: string; cleanup_threshold_percent: number | null; version: number }[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/v1/auth/me") return route.fulfill({ json: { user: {
      id: "00000000-0000-7000-8000-000000000001", name: "Test operator", email: "operator@example.invalid", roles: [role],
      tenant: { id: "00000000-0000-7000-8000-000000000002", name: "Test workspace", slug: "test" },
    } } });
    if (path === "/api/v1/settings/telemetry-retention") {
      if (route.request().method() === "PUT") {
        const payload = route.request().postDataJSON();
        writes.push(payload);
        settings = { ...settings, ...payload, version: settings.version + 1, status: "waiting", message: "Waiting for the next retention check." };
      }
      return route.fulfill({ json: settings });
    }
    if (path === "/api/v1/settings/model-keys") return route.fulfill({ json: {
      guardrail: { configured: false, masked: "", updated_at: null },
      detection: { configured: false, masked: "", updated_at: null },
    } });
    if (path === "/api/v1/response/policy") return route.fulfill({ json: { version: 0, rules: [], updated_at: null } });
    return route.fulfill({ status: 404, json: {} });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Telemetry retention", exact: true });
  await expect(card.getByRole("group", { name: "Retention period", exact: true })).toBeVisible();
  return { card, writes };
}

test("administrator saves both limits independently and cancellation preserves the policy", async ({ page }) => {
  const { card, writes } = await retentionPage(page);
  const period = card.getByRole("group", { name: "Retention period", exact: true });
  const cleanup = card.getByRole("group", { name: "Auto-clean when disk usage reaches", exact: true });
  await expect(card.getByRole("button", { name: "Save retention", exact: true })).toBeDisabled();
  await period.getByRole("radio", { name: "7 days", exact: true }).check();
  await cleanup.getByRole("radio", { name: "70%", exact: true }).check();
  expect(writes).toEqual([]);
  await card.getByRole("button", { name: "Save retention", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("younger telemetry when disk usage reaches 70%");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(writes).toEqual([]);
  await page.reload();
  await expect(period.getByRole("radio", { checked: true })).toHaveCount(0);
  await expect(cleanup.getByRole("radio", { name: "Turn off", exact: true })).toBeChecked();

  for (const [index, [label, mode, threshold]] of [
    ["7 days", "7", 70], ["30 days", "30", 80], ["90 days", "90", 90], ["Unlimited", "unlimited", 80],
  ].entries()) {
    await period.getByRole("radio", { name: String(label), exact: true }).check();
    if (index > 0) await expect(cleanup.getByRole("radio", { checked: true })).toHaveValue(String(writes[index - 1].cleanup_threshold_percent));
    await cleanup.getByRole("radio", { name: `${threshold}%`, exact: true }).check();
    await expect(period.getByRole("radio", { name: String(label), exact: true })).toBeChecked();
    await card.getByRole("button", { name: "Save retention", exact: true }).click();
    if (mode === "unlimited") await expect(page.getByRole("dialog")).toContainText("Telemetry will have no age limit.");
    await page.getByRole("button", { name: "Confirm retention", exact: true }).click();
    await expect(page.getByRole("dialog")).toBeHidden();
    expect(writes[index]).toEqual({ mode, cleanup_threshold_percent: threshold, version: index });
    await page.reload();
    await expect(period.getByRole("radio", { name: String(label), exact: true })).toBeChecked();
    await expect(cleanup.getByRole("radio", { name: `${threshold}%`, exact: true })).toBeChecked();
  }
  await cleanup.getByRole("radio", { name: "Turn off", exact: true }).check();
  await expect(cleanup.getByRole("radio", { name: "Turn off", exact: true })).toBeChecked();
  await expect(period.getByRole("radio", { name: "Unlimited", exact: true })).toBeChecked();
  expect(writes).toHaveLength(4);
  await card.getByRole("button", { name: "Save retention", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Automatic disk cleanup will be disabled.");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  await page.reload();
  await expect(cleanup.getByRole("radio", { name: "80%", exact: true })).toBeChecked();
  await period.getByRole("radio", { name: "Unlimited", exact: true }).focus();
  await page.keyboard.press("ArrowLeft");
  await expect(period.getByRole("radio", { name: "90 days", exact: true })).toBeFocused();
  await expect(period.getByRole("radio", { name: "90 days", exact: true })).toBeChecked();
  await expect(period.getByRole("radio", { name: "90 days", exact: true }).locator("..")).toHaveCSS("outline-style", "none");
  await expect(period.getByRole("radio", { name: "90 days", exact: true }).locator("..")).toHaveCSS("text-decoration-line", "underline");
  await cleanup.getByRole("radio", { name: "80%", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(cleanup.getByRole("radio", { name: "90%", exact: true })).toBeChecked();
  const focusedThreshold = cleanup.getByRole("radio", { name: "90%", exact: true }).locator("..");
  await expect(focusedThreshold).toHaveCSS("outline-style", "none");
  await expect(focusedThreshold).toHaveCSS("text-decoration-line", "underline");
  await page.keyboard.press("ArrowRight");
  await expect(cleanup.getByRole("radio", { name: "Turn off", exact: true })).toBeChecked();
  await expect(cleanup.getByRole("radio", { name: "Turn off", exact: true })).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(cleanup.getByRole("radio", { name: "90%", exact: true })).toBeChecked();
  await cleanup.getByRole("radio", { name: "70%", exact: true }).click();
  await expect(cleanup.getByRole("radio", { name: "70%", exact: true }).locator("..")).toHaveCSS("outline-style", "none");
  await cleanup.getByRole("radio", { name: "90%", exact: true }).click();
  expect(writes).toHaveLength(4);

  await page.emulateMedia({ reducedMotion: "reduce" });
  const selection = period.locator('[aria-hidden="true"] > span');
  await expect(selection).toHaveCSS("transition-property", "none");
  const navy = await page.getByRole("group", { name: "Time zone" }).locator('[aria-hidden="true"] > span').evaluate((node) => getComputedStyle(node).backgroundColor);
  await expect(selection).toHaveCSS("background-color", navy);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await card.scrollIntoViewIfNeeded();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    for (const radio of await card.getByRole("radio").all()) {
      await expect(radio).toBeVisible();
      const box = (await radio.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0);
      expect(box.x + box.width).toBeLessThanOrEqual(width);
    }
    const periodBox = (await period.boundingBox())!;
    const cleanupBox = (await cleanup.boundingBox())!;
    const lastThresholdBox = (await cleanup.getByRole("radio", { name: "90%", exact: true }).boundingBox())!;
    const offBox = (await cleanup.getByRole("radio", { name: "Turn off", exact: true }).boundingBox())!;
    expect(offBox.y).toBe(lastThresholdBox.y);
    expect(offBox.x).toBeCloseTo(lastThresholdBox.x + lastThresholdBox.width, 1);
    if (width === 1440) expect(cleanupBox.y).toBe(periodBox.y);
    else expect(cleanupBox.y).toBeGreaterThanOrEqual(periodBox.y + periodBox.height);
  }
  if (process.env.OPENAIDR_RETENTION_SCREENSHOT) {
    await page.setViewportSize({ width: 1440, height: 1080 });
    await card.screenshot({ path: process.env.OPENAIDR_RETENTION_SCREENSHOT });
  }
});

test("legacy Automatic displays Unlimited and its saved threshold", async ({ page }) => {
  const { card, writes } = await retentionPage(page, { mode: "automatic", threshold: 80 });
  await expect(card.getByRole("radio", { name: "Unlimited", exact: true })).toBeChecked();
  await expect(card.getByRole("radio", { name: "80%", exact: true })).toBeChecked();
  for (const radio of await card.getByRole("radio").all()) await expect(radio).toBeEnabled();
  await expect(card.getByRole("button", { name: "Save retention", exact: true })).toBeEnabled();
  await expect(card.getByRole("radio", { name: "Turn off", exact: true })).toBeEnabled();
  expect(writes).toEqual([]);
});

for (const mode of ["30", "automatic"]) test(`disk cleanup can be turned off from ${mode} even when disk measurements are unavailable`, async ({ page }) => {
  const { card, writes } = await retentionPage(page, { available: false, mode, threshold: 80 });
  const savedMode = mode === "automatic" ? "unlimited" : mode;
  for (const label of ["70%", "80%", "90%"])
    await expect(card.getByRole("radio", { name: label, exact: true })).toBeDisabled();
  await expect(card.getByRole("button", { name: "Save retention", exact: true })).toBeDisabled();
  await card.getByRole("radio", { name: "Turn off", exact: true }).check();
  expect(writes).toEqual([]);
  await card.getByRole("button", { name: "Save retention", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText(mode === "automatic" ? "Telemetry will have no age limit." : "Telemetry older than 30 days");
  await expect(page.getByRole("dialog")).toContainText("Automatic disk cleanup will be disabled.");
  await page.getByRole("button", { name: "Confirm retention", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(writes).toEqual([{ mode: savedMode, cleanup_threshold_percent: null, version: 1 }]);
  await page.reload();
  await expect(card.getByRole("radio", { name: mode === "automatic" ? "Unlimited" : "30 days", exact: true })).toBeChecked();
  await expect(card.getByRole("radio", { name: "Turn off", exact: true })).toBeChecked();
  await card.getByRole("radio", { name: "Unlimited", exact: true }).check();
  await card.getByRole("button", { name: "Save retention", exact: true }).click();
  await expect(page.getByRole("dialog")).not.toContainText("younger telemetry");
  await page.getByRole("button", { name: "Confirm retention", exact: true }).click();
  await expect(page.getByRole("dialog")).toBeHidden();
  expect(writes[1]).toEqual({ mode: "unlimited", cleanup_threshold_percent: null, version: 2 });
});
