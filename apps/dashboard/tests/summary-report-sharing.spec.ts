import { expect, test, type Page } from "@playwright/test";

async function setup(page: Page, available = true, role = "it_admin") {
  let settings = { automatic: false, available, version: 0, destination: "https://reports.example.test",
    next_report_at: null as string | null, delivery: { pending: 0, failed: 0, last_sent_at: null as string | null } };
  const writes: Record<string, unknown>[] = [];
  const sends: Record<string, unknown>[] = [];
  let previews = 0;
  let conflict = false;
  const report = { schema_version: 1, report_id: "12345678-1234-4234-8234-123456789abc",
    tenant_id: "22345678-1234-4234-8234-123456789abc", generated_at: "2026-10-16T10:00:00+00:00",
    window_start: "2026-10-15T10:00:00+00:00", window_end: "2026-10-16T10:00:00+00:00",
    backend_version: "2026.10.16+a675128" as string | null,
    counts: { checks: { total: 10000, evaluated: 9980, pending: 3, unavailable: 17, shadow: 10000, enforce: 0 },
      evaluated_decisions: { allow: 9900, warn: 40, ask: 20, deny: 20 },
      returned_decisions: { allow: 9980, warn: 0, ask: 0, deny: 0 },
      delivery: { delivered: 9950, timed_out: 20, failed: 5, unconfirmed: 25 },
      delivered_decisions: { allow: 9950, warn: 0, ask: 0, deny: 0 },
      findings: { total: 10, info: 0, low: 0, medium: 2, high: 7, critical: 1, marked_false_positive: 1 },
      investigations: { total: 20, finding: 8, no_finding: 10, inconclusive: 2, unknown: 0,
        source_complete: 18, source_incomplete: 2, source_unknown: 0 },
      latency_samples: { policy: 9900, e2e: 9900 } },
    latency_ms: { policy_p50: 105 as number | null, policy_p95: 300, policy_p99: 500,
      e2e_p50: 110, e2e_p95: 320, e2e_p99: 550 } };
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user: { id: "operator", name: "Operator",
      email: "operator@example.test", roles: [role], tenant: { id: report.tenant_id, slug: "acme", name: "Acme" } } } });
    if (path === "settings/summary-reports") {
      if (route.request().method() === "PUT") {
        const value = route.request().postDataJSON();
        writes.push(value);
        if (conflict) return route.fulfill({ status: 409, json: { error: { message: "Report settings changed. Refresh and try again" } } });
        settings = { ...settings, automatic: value.automatic, version: settings.version + 1,
          next_report_at: value.automatic ? "2026-10-17T10:00:00+00:00" : null };
      }
      return route.fulfill({ json: settings });
    }
    if (path === "settings/summary-reports/preview") {
      previews++;
      return route.fulfill({ json: { report, expires_at: "2026-10-16T11:00:00+00:00" } });
    }
    if (path === "settings/summary-reports/send") {
      sends.push(route.request().postDataJSON());
      if (conflict) return route.fulfill({ status: 409, json: { error: { message: "Report preview expired. Preview again" } } });
      settings.delivery.pending++;
      return route.fulfill({ status: 202, json: { report_id: report.report_id, status: "pending" } });
    }
    if (path === "settings/model-keys") return route.fulfill({ json: {
      routing: { mode: "intelligence", origin: "https://api.example.test", credential_configured: true,
        trust: "system", capability_status: "unverified" },
    } });
    if (path === "settings/support") return route.fulfill({ json: { slack_channel_url: "", version: 0, updated_at: null } });
    if (path === "settings/session-detection") return route.fulfill({ json: {
      enabled: true, version: 0, max_cost_usd_per_attempt: "2", hourly_cost_usd: "10", availability: { reason: "ready" },
    } });
    if (path === "settings/telemetry-retention") return route.fulfill({ json: {
      mode: null, version: 0, cleanup_threshold_percent: null, automatic_available: false,
      message: "No retention policy has been saved.", status: "unconfigured", last_cleanup_at: null,
    } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  await page.goto("/administration/settings");
  return { writes, sends, report, previews: () => previews, conflict: () => { conflict = true; },
    unavailable: () => { settings.available = false; }, delivered: () => {
    settings.delivery = { pending: 0, failed: 0, last_sent_at: "2026-10-16T10:01:00+00:00" };
  } };
}

test("manual sharing previews the exact snapshot and daily sharing needs a saved opt-in", async ({ page }, info) => {
  const state = await setup(page);
  const card = page.getByRole("region", { name: "Share reports with OpenSecura", exact: true });
  await expect(card.getByRole("checkbox")).not.toBeChecked();
  await expect(card.getByRole("button", { name: "Send report", exact: true })).toBeDisabled();
  await card.screenshot({ path: info.outputPath("report-sharing-card.png"), animations: "disabled" });
  await card.getByRole("button", { name: "Preview report", exact: true }).click();
  const html = card.getByRole("region", { name: "Formatted report", exact: true });
  await expect(card.getByRole("tab", { name: "HTML", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(html.getByText(state.report.tenant_id, { exact: true })).toBeVisible();
  await expect(html.getByText(state.report.report_id, { exact: true })).toBeVisible();
  await expect(html.getByText(state.report.backend_version!, { exact: true })).toBeVisible();
  for (const [title, values] of [
    ["Guardrail checks", ["10,000", "3", "9,980", "17", "10,000", "0"]],
    ["Delivery status", ["9,950", "20", "5", "25"]],
    ["Findings", ["10", "0", "0", "2", "7", "1", "1"]],
    ["Evaluated decisions", ["9,900", "40", "20", "20"]],
    ["Returned decisions", ["9,980", "0", "0", "0"]],
    ["Confirmed delivered decisions", ["9,950", "0", "0", "0"]],
    ["Investigations", ["20", "8", "10", "2", "0", "18", "2", "0"]],
    ["Policy latency", ["9,900", "105 ms", "300 ms", "500 ms"]],
    ["End-to-end latency", ["9,900", "110 ms", "320 ms", "550 ms"]],
  ] as const) {
    await expect(html.getByRole("region", { name: title, exact: true }).locator("dd")).toHaveText([...values]);
  }
  expect(state.sends).toHaveLength(0);
  for (const width of [1440, 390, 320]) {
    await page.setViewportSize({ width, height: width === 390 ? 640 : 1000 });
    for (const format of ["HTML", "JSON"]) {
      await card.getByRole("tab", { name: format, exact: true }).click();
      const preview = format === "HTML" ? html : card.getByLabel("Report JSON");
      if (format === "JSON") expect(JSON.parse(await preview.innerText())).toEqual(state.report);
      await preview.scrollIntoViewIfNeeded();
      await preview.evaluate((node) => { node.scrollTop = node.scrollHeight; });
      await expect.poll(() => preview.evaluate((node) => node.scrollTop + node.clientHeight >= node.scrollHeight - 1)).toBe(true);
      await expect.poll(() => preview.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    }
    await card.getByRole("button", { name: "Send report", exact: true }).scrollIntoViewIfNeeded();
    await expect(card.getByRole("button", { name: "Send report", exact: true })).toBeInViewport();
    await card.getByRole("tab", { name: "HTML", exact: true }).click();
    await html.evaluate((node) => { node.scrollTop = 0; });
    await card.locator('[data-slot="tabs"]').screenshot({ path: info.outputPath(`report-sharing-${width}.png`), animations: "disabled" });
  }
  expect(state.previews()).toBe(1);
  expect(state.sends).toHaveLength(0);
  await card.getByRole("button", { name: "Send report", exact: true }).click();
  await expect(card.getByText("Report queued. Refresh to check delivery status.")).toBeVisible();
  await expect(card.getByText("Pending reports: 1. Failed reports: 0.")).toBeVisible();
  expect(state.sends).toEqual([{ report_id: state.report.report_id }]);
  await expect(card.getByRole("button", { name: "Send report", exact: true })).toBeDisabled();
  state.delivered();
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card.getByText(/^Last delivered:/)).toBeVisible();
  await card.getByRole("checkbox").check();
  expect(state.writes).toHaveLength(0);
  await card.getByRole("button", { name: "Save report settings" }).click();
  await expect(card.getByText("Automatic sharing is on.", { exact: true })).toBeVisible();
  expect(state.writes).toEqual([{ automatic: true, version: 0 }]);
  await card.getByRole("checkbox").uncheck();
  await card.getByRole("button", { name: "Save report settings" }).click();
  await expect(card.getByText("Automatic sharing is off.", { exact: true })).toBeVisible();
  expect(state.writes[1]).toEqual({ automatic: false, version: 1 });
});

test("conflicts preserve the preview and do not claim delivery or saved consent", async ({ page }) => {
  const state = await setup(page);
  const card = page.getByRole("region", { name: "Share reports with OpenSecura", exact: true });
  await card.getByRole("button", { name: "Preview report", exact: true }).click();
  state.conflict();
  await card.getByRole("button", { name: "Send report", exact: true }).click();
  await expect(card.getByRole("alert")).toContainText("Report preview expired");
  await expect(card.getByRole("region", { name: "Formatted report", exact: true })).toBeVisible();
  await card.getByRole("tab", { name: "JSON", exact: true }).click();
  expect(JSON.parse(await card.getByLabel("Report JSON").innerText())).toEqual(state.report);
  await expect(card.getByText("No reports delivered yet.")).toBeVisible();
  await card.getByRole("checkbox").check();
  await card.getByRole("button", { name: "Save report settings" }).click();
  await expect(card.getByRole("alert")).toContainText("Report settings changed");
  await expect(card.getByText("Automatic sharing is off.", { exact: true })).toBeVisible();
});

test("unconfigured installations hide report sharing and non-admin roles cannot configure", async ({ page }, info) => {
  const response = page.waitForResponse("**/api/v1/settings/summary-reports");
  const state = await setup(page, false);
  await response;
  await expect(page.getByRole("region", { name: "Telemetry retention", exact: true })).toBeVisible();
  const card = page.getByRole("region", { name: "Share reports with OpenSecura", exact: true });
  await expect(card).toHaveCount(0);
  expect(state.previews()).toBe(0);
  expect(state.sends).toHaveLength(0);
  expect(state.writes).toHaveLength(0);
  await expect(page.getByRole("button", { name: "Check connection", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save support channel", exact: true })).toBeVisible();
  await page.screenshot({ path: info.outputPath("settings-without-report-sharing.png"), fullPage: true,
    animations: "disabled", style: "nextjs-portal { visibility: hidden; }" });
  await page.unrouteAll();
  await setup(page, true, "security_analyst");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(card).toHaveCount(0);
});

test("availability loading stays hidden, errors can retry, and removed configuration hides the card", async ({ page }) => {
  const state = await setup(page);
  const card = page.getByRole("region", { name: "Share reports with OpenSecura", exact: true });
  await expect(card.getByRole("checkbox")).toBeVisible();
  const endpoint = "**/api/v1/settings/summary-reports";
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  await page.route(endpoint, async (route) => {
    await pending;
    await route.fulfill({ status: 503, json: { error: { message: "Report settings unavailable" } } });
  });
  const request = page.waitForRequest(endpoint);
  await page.reload();
  await request;
  await expect(card).toHaveCount(0);
  release();
  await expect(card.getByRole("alert")).toContainText("Report settings unavailable");
  await page.unroute(endpoint);
  await card.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(card.getByRole("checkbox")).toBeVisible();
  state.unavailable();
  await card.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(card).toHaveCount(0);
  expect(state.sends).toHaveLength(0);
  expect(state.writes).toHaveLength(0);
});

test("HTML distinguishes missing values from zero and renders report text safely", async ({ page }) => {
  const state = await setup(page);
  state.report.backend_version = null;
  state.report.latency_ms.policy_p50 = null;
  state.report.latency_ms.e2e_p50 = 0;
  state.report.counts.findings.marked_false_positive = 9007199254740991;
  await page.setViewportSize({ width: 320, height: 640 });
  const card = page.getByRole("region", { name: "Share reports with OpenSecura", exact: true });
  await card.getByRole("button", { name: "Preview report", exact: true }).click();
  const html = card.getByRole("region", { name: "Formatted report", exact: true });
  await expect.poll(() => html.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await expect(html.getByRole("region", { name: "Report details", exact: true }).getByText("Unavailable")).toBeVisible();
  await expect(html.getByRole("region", { name: "Policy latency", exact: true }).locator("dd")).toHaveText(["9,900", "Unavailable", "300 ms", "500 ms"]);
  await expect(html.getByRole("region", { name: "End-to-end latency", exact: true }).locator("dd")).toHaveText(["9,900", "0 ms", "320 ms", "550 ms"]);
  await card.getByRole("tab", { name: "JSON", exact: true }).click();
  expect(JSON.parse(await card.getByLabel("Report JSON").innerText())).toEqual(state.report);
  // Even malformed upstream display text must stay inert in the browser.
  state.report.report_id = "32345678-1234-4234-8234-123456789abc";
  state.report.backend_version = '<img src=x onerror="window.reportScriptRan=true">';
  await card.getByRole("button", { name: "Preview report", exact: true }).click();
  await expect(card.getByRole("tab", { name: "HTML", exact: true })).toHaveAttribute("aria-selected", "true");
  await expect(html.getByText(state.report.backend_version, { exact: true })).toBeVisible();
  await expect(html.locator("img,script")).toHaveCount(0);
  expect(await page.evaluate(() => "reportScriptRan" in window)).toBe(false);
  expect(state.sends).toHaveLength(0);
});
