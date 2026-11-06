import { expect, test } from "@playwright/test";
import { expectSelectSpacing } from "./select-spacing";

test("administration switch persists opt-out, preserves limits, and reports unavailable workers", async ({ page }, info) => {
  let role = "it_admin", failure = false;
  let stored = { enabled: true, version: 1, max_cost_usd_per_attempt: "2", hourly_cost_usd: "10", availability: { reason: "ready" } };
  const writes: unknown[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Operator", roles: [role],
      email: "operator@example.test", tenant: { id: "tenant", slug: "tenant", name: "Test workspace" } } } });
    if (path === "settings/session-detection") {
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON(); writes.push(body);
        if (failure) return route.fulfill({ status: 409, json: { error: { message: "Investigation settings changed. Refresh and try again." } } });
        stored = { ...stored, ...body, version: stored.version + 1, availability: { reason: body.enabled ? "worker_unavailable" : "tenant_disabled" } };
      }
      return route.fulfill({ json: stored });
    }
    if (path === "settings/model-keys") return route.fulfill({ json: {
      guardrail: { configured: true, masked: "configured", updated_at: null }, detection: { configured: true, masked: "configured", updated_at: null },
    } });
    if (path === "settings/telemetry-retention") return route.fulfill({ json: { mode: "30", cleanup_threshold_percent: 80,
      version: 1, message: "", status: "waiting", automatic_available: true, last_cleanup_at: null } });
    if (path === "settings/summary-reports") return route.fulfill({ json: { automatic: false, available: false, version: 0,
      destination: null, next_report_at: null, delivery: { pending: 0, failed: 0, last_sent_at: null } } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  await page.goto("/administration/settings");
  const card = page.getByRole("region", { name: "Session investigations", exact: true });
  const toggle = card.getByRole("switch", { name: "Session investigations", exact: true });
  await expect(toggle).toBeChecked();
  await expect(card).not.toContainText(/\$2|\$10/);
  await toggle.click();
  await expect(toggle).not.toBeChecked();
  expect(writes).toEqual([{ enabled: false, version: 1 }]);
  await page.reload();
  await expect(toggle).not.toBeChecked();
  await expect(card).toContainText("Existing evidence and reports remain available");
  await toggle.click();
  await expect(toggle).toBeChecked();
  await expect(card).toContainText("worker is not available");
  expect(writes[1]).toEqual({ enabled: true, version: 2 });
  failure = true;
  await toggle.click();
  await expect(card.getByRole("alert")).toContainText("settings changed");
  await expect(toggle).toBeChecked();
  failure = false;
  stored.availability.reason = "ready";
  await page.reload();
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await toggle.scrollIntoViewIfNeeded();
    await expect(toggle).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await card.screenshot({ path: info.outputPath(`session-detection-switch-${width}.png`), animations: "disabled" });
  }
  role = "security_leadership";
  await page.reload();
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(toggle).toHaveCount(0);
});

test("investigation settings preserve limits, save the budget policy, and restrict access to Security Analysts", async ({ page }, info) => {
  let role = "security_leadership";
  let failed = false;
  let stored = {
    enabled: true, version: 3, detector_config_version: 2, selection_policy: "legacy", model: "gpt-6.1-sol",
    investigation_percent: "1", sample_percent: "0", history_days: 7, action_risk_threshold: 70,
    urgent_risk_threshold: 95, session_high_risk_actions: 2, user_high_risk_actions: 3,
    risk_threshold: "120", idle_seconds: 60, delivery_grace_seconds: 30, gap_wait_seconds: 90,
    max_runtime_seconds: 120, max_tokens_per_attempt: 200000, max_cost_usd_per_attempt: "10",
    max_attempts: 2, max_concurrent: 3, hourly_attempts: 10, hourly_tokens: 2000000, hourly_cost_usd: "100",
    retry_delay_seconds: 60, gap_policy: "investigate",
  };
  const writes: Record<string, unknown>[] = [];
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Operator", roles: [role],
      email: "operator@example.test", tenant: { id: "tenant", slug: "tenant", name: "Tenant" } } } });
    if (path === "response/session-detection") {
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON();
        writes.push(body);
        if (failed) return route.fulfill({ status: 400, json: { error: { message: "invalid investigation percentages" } } });
        stored = { ...stored, ...body, version: stored.version + 1 };
      }
      return route.fulfill({ json: stored });
    }
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  await page.goto("/detection-rules");
  const settings = page.getByRole("region", { name: "Investigation settings" });
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(settings.getByRole("button", { name: "Save investigation settings" })).toHaveCount(0);
  role = "security_analyst";
  await page.reload();
  await expect(settings.getByRole("spinbutton", { name: "Random sample of sessions (%)" })).toHaveCount(0);
  await expect(settings).toContainText("requires the configured risk thresholds");
  await expect(settings).toContainText("within the service allowance and execution limits");
  await expect(settings).toContainText("Reusing live Guardrail scores makes no additional requests");
  await settings.getByRole("combobox", { name: "Selection policy" }).selectOption("risk_budget");
  await settings.getByRole("spinbutton", { name: "Recent history window (days)" }).fill("14");
  await settings.getByRole("button", { name: "Save investigation settings" }).click();
  await expect(settings.getByRole("status")).toHaveText("Investigation settings saved.");
  expect(writes[0]).not.toHaveProperty("sample_percent");
  expect(writes[0]).toMatchObject({ selection_policy: "risk_budget", history_days: 14, investigation_percent: "1",
    enabled: true });
  for (const key of ["model", "max_tokens_per_attempt", "max_cost_usd_per_attempt", "hourly_cost_usd", "hourly_tokens", "max_credits_per_attempt", "hourly_credits"]) expect(writes[0]).not.toHaveProperty(key);
  await expect(settings.getByText("Customer credit limits", { exact: true })).toHaveCount(0);
  expect(stored.max_cost_usd_per_attempt).toBe("10");
  await expect(settings.getByRole("spinbutton", { name: "Recent history window (days)" })).toHaveValue("14");
  failed = true;
  await settings.getByRole("spinbutton", { name: "Target sessions investigated (%)" }).fill("2");
  await settings.getByRole("button", { name: "Save investigation settings" }).click();
  await expect(settings.getByRole("alert")).toContainText("invalid investigation percentages");
  await expect(settings.getByRole("status")).toHaveCount(0);
  await settings.getByText("Runtime and evidence limits", { exact: true }).click();
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 640 }]) {
    await page.setViewportSize(viewport);
    const selects = settings.locator("select:visible");
    await expect(selects).toHaveCount(2);
    await expectSelectSpacing(selects);
    await settings.getByRole("button", { name: "Save investigation settings" }).scrollIntoViewIfNeeded();
    await expect(settings.getByRole("button", { name: "Save investigation settings" })).toBeInViewport();
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`investigation-settings-${viewport.width}.png`), fullPage: true, animations: "disabled" });
  }
});

test("credit limits receive a supported server contract without rounding amounts or changing old responses", async ({ page }, info) => {
  let limits: Record<string, unknown> = { max_credits_per_attempt: null, hourly_credits: null, weekly_credits: null };
  let version = 1;
  const writes: Record<string, unknown>[] = [];
  const settings = {
    enabled: true, detector_config_version: 2, selection_policy: "risk_budget",
    investigation_percent: "1", history_days: 7, action_risk_threshold: 70, urgent_risk_threshold: 95,
    session_high_risk_actions: 2, user_high_risk_actions: 3, risk_threshold: "120", idle_seconds: 60,
    delivery_grace_seconds: 30, gap_wait_seconds: 90, max_runtime_seconds: 120,
    max_attempts: 2, max_concurrent: 3, hourly_attempts: 10, retry_delay_seconds: 60, gap_policy: "investigate",
  };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Operator", roles: ["security_analyst"],
      email: "operator@example.test", tenant: { id: "tenant", slug: "tenant", name: "Test workspace" } } } });
    if (path === "response/session-detection") {
      if (route.request().method() === "PUT") {
        const body = route.request().postDataJSON(); writes.push(body);
        if (Object.hasOwn(body, "max_credits_per_attempt")) limits = { max_credits_per_attempt: body.max_credits_per_attempt, hourly_credits: body.hourly_credits };
        if (Object.hasOwn(body, "weekly_credits")) limits.weekly_credits = body.weekly_credits;
        version += 1;
      }
      return route.fulfill({ json: { ...settings, ...limits, version } });
    }
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  await page.goto("/detection-rules");
  const card = page.getByRole("region", { name: "Investigation settings" });
  const attempt = card.getByRole("textbox", { name: "Maximum credits per attempt" });
  const hourly = card.getByRole("textbox", { name: "Maximum credits per hour" });
  const weekly = card.getByRole("textbox", { name: "Maximum credits in seven days" });
  const save = card.getByRole("button", { name: "Save investigation settings" });
  await expect(attempt).toHaveValue("");
  await expect(hourly).toHaveValue("");
  await expect(weekly).toHaveValue("");
  await expect(card).toContainText("rolling seven days of confirmed charges plus all pending reservations");
  await save.click();
  await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
  expect(writes.at(-1)).toMatchObject({ max_credits_per_attempt: null, hourly_credits: null });
  for (const [perAttempt, perHour] of [["0", "0.000001"], ["9007199254.740991", "9007199254.740991"]]) {
    await attempt.fill(perAttempt); await hourly.fill(perHour); await save.click();
    await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
    expect(writes.at(-1)).toMatchObject({ max_credits_per_attempt: perAttempt, hourly_credits: perHour });
    await expect(attempt).toHaveValue(perAttempt);
    await expect(hourly).toHaveValue(perHour);
  }
  const written = writes.length;
  for (const [perAttempt, perHour] of [["", "1"], ["0.000001", "0"], ["-1", "1"], ["01", "1"], ["1e2", "100"], ["0.0000001", "1"], ["9007199254.740992", "9007199254.740992"]]) {
    await attempt.fill(perAttempt); await hourly.fill(perHour); await save.click();
    await expect(card.getByRole("alert")).toContainText("Enter both credit limits");
    expect(writes).toHaveLength(written);
  }
  await attempt.fill("0.125001"); await hourly.fill("100.000001"); await save.click();
  await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
  for (const value of ["200", "0.125001", "9007199254.740991"]) {
    await weekly.fill(value); await save.click();
    await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
    expect(writes.at(-1)).toMatchObject({ weekly_credits: value });
    await expect(weekly).toHaveValue(value);
  }
  const weeklyWritten = writes.length;
  for (const value of ["0.125", "-1", "1e2", "0.0000001", "9007199254.740992"]) {
    await weekly.fill(value); await save.click();
    await expect(card.getByRole("alert")).toContainText("Enter a valid seven-day credit limit");
    expect(writes).toHaveLength(weeklyWritten);
  }
  await weekly.fill("200"); await save.click();
  await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 320, height: 480 }]) {
    await page.setViewportSize(viewport);
    for (const control of [attempt, hourly, weekly, save]) {
      await control.scrollIntoViewIfNeeded();
      await expect(control).toBeInViewport();
      await control.focus();
      await expect(control).toBeFocused();
    }
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`credit-limits-${viewport.width}.png`), fullPage: true, animations: "disabled" });
  }
  await attempt.fill(""); await hourly.fill(""); await weekly.fill(""); await save.click();
  await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
  expect(writes.at(-1)).toMatchObject({ max_credits_per_attempt: null, hourly_credits: null, weekly_credits: null });

  limits = { max_credits_per_attempt: "1", hourly_credits: "2" };
  await page.reload();
  await expect(weekly).toHaveCount(0);
  await save.click();
  await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
  expect(writes.at(-1)).not.toHaveProperty("weekly_credits");

  for (const unsupported of [
    { max_credits_per_attempt: "1" },
    { max_credits_per_attempt: 0, hourly_credits: "1" },
    { max_credits_per_attempt: null, hourly_credits: "1" },
    { max_credits_per_attempt: "2", hourly_credits: "1" },
    { max_credits_per_attempt: "9007199254.740992", hourly_credits: "9007199254.740992" },
    { max_credits_per_attempt: "1", hourly_credits: "2", weekly_credits: "0" },
    { max_credits_per_attempt: "1", hourly_credits: "2", weekly_credits: 200 },
  ]) {
    limits = unsupported;
    await page.reload();
    await expect(attempt).toHaveCount(0);
    await expect(hourly).toHaveCount(0);
    await expect(card).toContainText("Credit limits are unavailable in this response.");
    await save.click();
    await expect(card.getByRole("status")).toHaveText("Investigation settings saved.");
    expect(writes.at(-1)).not.toHaveProperty("max_credits_per_attempt");
    expect(writes.at(-1)).not.toHaveProperty("hourly_credits");
  }
});
