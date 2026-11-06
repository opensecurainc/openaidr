import { expect, test, type Page } from "@playwright/test";

async function setup(page: Page, role = "it_admin") {
  const state = { name: "Original organization", failure: false };
  const writes: unknown[] = [];
  const tenant = () => ({ id: "tenant-a", slug: "original-organization", name: state.name });
  const responses: Record<string, unknown> = {
    "settings/support": { slack_channel_url: "", version: 0, updated_at: null },
    "settings/session-detection": { enabled: true, version: 1, availability: { reason: "ready" } },
    "settings/model-keys": { guardrail: { configured: false, masked: "", updated_at: null }, detection: { configured: false, masked: "", updated_at: null } },
    "settings/telemetry-retention": { mode: null, cleanup_threshold_percent: null, version: 0, message: "", status: "unconfigured", automatic_available: false, last_cleanup_at: null },
    "settings/summary-reports": { automatic: false, available: false, version: 0, destination: null, next_report_at: null, delivery: { pending: 0, failed: 0, last_sent_at: null } },
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: {
      id: "operator", name: "Operator", email: "operator@example.test", roles: [role], tenant: tenant(),
    } } });
    if (path === "settings/tenant") {
      expect(route.request().method()).toBe("PATCH");
      const payload = route.request().postDataJSON();
      writes.push(payload);
      if (state.failure) return route.fulfill({ status: 503, json: { error: { message: "Unable to save the tenant name." } } });
      state.name = payload.name;
      return route.fulfill({ json: tenant() });
    }
    return route.fulfill({ json: responses[path] ?? { items: [], next_cursor: "" } });
  });
  return { state, writes };
}

test("IT admins rename their tenant, retain failed edits, and see the saved name after reload", async ({ page }, info) => {
  const { state, writes } = await setup(page);
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Tenant", exact: true });
  const input = card.getByRole("textbox", { name: "Name", exact: true });
  const save = card.getByRole("button", { name: "Save name", exact: true });
  await expect(input).toHaveValue(state.name);
  await expect(input).toHaveAttribute("maxlength", "200");
  await expect(save).toBeDisabled();
  await input.fill("   ");
  await expect(save).toBeDisabled();
  const name = "Acme Research & 开发";
  await input.fill(`  ${name}  `);
  state.failure = true;
  await save.click();
  await expect(card.getByRole("alert")).toHaveText("Unable to save the tenant name.");
  await expect(input).toHaveValue(`  ${name}  `);
  await expect(page.locator("aside").getByText(state.name, { exact: true })).toBeVisible();
  state.failure = false;
  await save.click();
  await expect(card.getByRole("status")).toHaveText("Tenant name saved.");
  await expect(input).toHaveValue(name);
  await expect(page.locator("aside").getByText(name, { exact: true })).toBeVisible();
  await expect(save).toBeDisabled();
  expect(writes).toEqual([{ name }, { name }]);
  await card.screenshot({ path: info.outputPath("tenant-name-saved.png"), animations: "disabled" });
  await page.reload();
  await expect(input).toHaveValue(name);
  await expect(card).toContainText("original-organization");
  await expect(card).toContainText("tenant-a");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await input.fill("A longer organization name ".repeat(7));
    await save.scrollIntoViewIfNeeded();
    await expect(save).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await card.screenshot({ path: info.outputPath(`tenant-name-${width}.png`), animations: "disabled" });
  }
});

for (const role of ["security_analyst", "security_leadership"]) {
  test(`${role} cannot edit the tenant name`, async ({ page }) => {
    const { writes } = await setup(page, role);
    await page.goto("/administration/settings");
    await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Save name" })).toHaveCount(0);
    expect(writes).toEqual([]);
  });
}
