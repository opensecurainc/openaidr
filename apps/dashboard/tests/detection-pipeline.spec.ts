import { expect, test, type Page } from "@playwright/test";

const counts = {
  range: "30d",
  since: "2026-09-06T12:00:00Z",
  until: "2026-10-06T12:00:00Z",
  actions_scored: 128450,
  sessions_scored: 12400,
  sessions_inspected: 118,
  sessions_with_alerts: 23,
  alerts: 31,
  sessions_eligible: 12000,
  sessions_escalated: 120,
  selection_policy: "risk_budget", investigation_percent: "1", sample_percent: "0", history_days: 7,
  reports: 120, actionable_reports: 23, no_finding_reports: 95, inconclusive_reports: 2, pending_investigations: 3, sessions_selected: 123,
  availability: { tenant_enabled: true, scheduling_enabled: true, worker_ready: true, reason: "ready", checked_at: "2026-10-06T12:00:00Z" },
  criteria: { action_risk_threshold: 65, urgent_risk_threshold: 93, session_high_risk_actions: 4, user_high_risk_actions: 5,
    idle_seconds: 120, delivery_grace_seconds: 15, risk_threshold: "250", gap_policy: "retain", gap_wait_seconds: 30,
    max_concurrent: 2, hourly_attempts: 8, hourly_tokens: 800000, hourly_cost_usd: "4.50" },
};

async function mockApi(page: Page, result: (range: string) => unknown = (range) => ({ ...counts, range }), roles = ["security_analyst"]) {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me")) {
      return route.fulfill({ json: { user: {
        id: "viewer", name: "Test operator", email: "test@example.invalid", roles,
        tenant: { id: "tenant", name: "Test tenant", slug: "test" },
      } } });
    }
    if (url.pathname.endsWith("/detections/pipeline")) {
      const body = result(url.searchParams.get("range") || "30d");
      return body === null
        ? route.fulfill({ status: 503, json: { error: { message: "Pipeline is unavailable" } } })
        : route.fulfill({ json: body });
    }
    if (url.pathname.endsWith("/knowledge"))
      return route.fulfill({ json: { enabled: false, revision: 0, documents: [] } });
    if (url.pathname.endsWith("/detections/rankings"))
      return route.fulfill({ json: { group: url.searchParams.get("group"), band: url.searchParams.get("band"),
        selection_policy: "risk_budget", history_days: 7, until: counts.until, criteria: counts.criteria,
        summary: { total: 0, meets: 0, below: 0, unknown: 0 }, items: [], next_cursor: "" } });
    if (url.pathname.endsWith("/findings"))
      return route.fulfill({ json: { items: [
        { id: "fixture-alert", title: "Sensitive file sent to an external host",
          rule_name: "Session detection", severity: "high", status: "open",
          host: { hostname: "Example laptop", user: "Test operator" },
          created_at: counts.until },
      ], next_cursor: "" } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

const panel = (page: Page) => page.getByRole("region", { name: "Detection pipeline", exact: true });

test("pipeline follows the selected cohort without loading policy findings", async ({ page }, info) => {
  const requests: string[] = [];
  await mockApi(page, (range) => {
    requests.push(range);
    return { ...counts, range, actions_scored: range === "7d" ? 1000 : counts.actions_scored };
  });
  const findingRequests: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.endsWith("/findings")) findingRequests.push(request.url());
  });
  await page.goto("/detections");
  const pipeline = panel(page);
  await expect(pipeline.getByRole("button", { name: "30 days", exact: true })).toHaveAttribute("aria-pressed", "true");
  const stages = pipeline.getByRole("listitem");
  await expect(stages).toHaveCount(3);
  await expect(stages.nth(0)).toContainText("128,450");
  await expect(stages.nth(0)).toContainText("Across 12,400 sessions");
  await expect(stages.nth(1)).toContainText("118");
  await expect(stages.nth(2)).toContainText("23");
  await expect(stages.nth(2)).toContainText("31 alerts created");
  await expect(pipeline).toContainText("123 sessions selected for investigation");
  await expect(pipeline).toContainText("Configured target: 1%");
  await expect(pipeline.getByRole("definition")).toHaveText(["120", "23", "95", "2", "3"]);
  const findings = page.getByRole("region", { name: "Investigation reports", exact: true });
  expect((await findings.boundingBox())!.y).toBeLessThan((await pipeline.boundingBox())!.y);
  await page.screenshot({ path: info.outputPath("detection-pipeline-desktop.png"), fullPage: true, animations: "disabled" });

  await pipeline.getByRole("button", { name: "7 days", exact: true }).click();
  await expect(stages.nth(0)).toContainText("1,000");
  await expect(pipeline).toContainText("started in the last 7 days");
  await pipeline.getByRole("button", { name: "90 days", exact: true }).click();
  await expect(pipeline.getByRole("button", { name: "90 days", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(stages.nth(0)).toContainText("128,450");
  expect(requests.filter((range, index) => index === 0 || range !== requests[index - 1])).toEqual(["30d", "7d", "90d"]);
  expect(findingRequests).toEqual([]);
  await pipeline.getByText("How pipeline counts work", { exact: true }).click();
  await expect(pipeline).toContainText("Pending and inconclusive investigations are excluded");
});

test("pipeline distinguishes failed loads, stale counts, and a measured zero", async ({ page }) => {
  let mode = "fail";
  await mockApi(page, (range) => mode === "fail" ? null : mode === "zero" ? {
    ...counts, range, actions_scored: 0, sessions_scored: 0, sessions_inspected: 0,
    sessions_with_alerts: 0, alerts: 0, sessions_eligible: 0, sessions_escalated: 0, sessions_selected: 0,
    reports: 0, actionable_reports: 0, no_finding_reports: 0, inconclusive_reports: 0, pending_investigations: 0,
  } : { ...counts, range });
  await page.goto("/detections");
  const pipeline = panel(page);
  await expect(pipeline.getByRole("alert")).toContainText("Pipeline is unavailable");
  await expect(pipeline.getByRole("listitem")).toHaveCount(0);
  mode = "populated";
  await pipeline.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(pipeline.getByRole("listitem").first()).toContainText("128,450");
  mode = "fail";
  await pipeline.getByRole("button", { name: "Refresh detection pipeline" }).click();
  await expect(pipeline.getByRole("alert")).toContainText("Showing the last successful counts");
  await expect(pipeline.getByRole("listitem").first()).toContainText("128,450");
  await pipeline.getByRole("button", { name: "90 days", exact: true }).click();
  await expect(pipeline.getByRole("alert")).toBeVisible();
  await expect(pipeline.getByRole("listitem")).toHaveCount(0);
  mode = "zero";
  await pipeline.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(pipeline.getByRole("listitem")).toHaveCount(3);
  await expect(pipeline.getByRole("listitem").first()).toContainText("Across 0 sessions");
  await expect(pipeline).toContainText("0 sessions selected for investigation");
  await expect(pipeline.getByRole("status")).toContainText("No sessions have been selected in this date range.");
  await expect(pipeline).not.toContainText("Risk-based escalation: 0%");
});

test("pipeline stacks on phones and its range controls work from the keyboard", async ({ page }, info) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page);
  await page.goto("/detections");
  const pipeline = panel(page);
  const stages = pipeline.getByRole("listitem");
  await expect(stages).toHaveCount(3);
  const first = (await stages.nth(0).boundingBox())!;
  const second = (await stages.nth(1).boundingBox())!;
  expect(second.y).toBeGreaterThan(first.y);
  expect(second.x).toEqual(first.x);
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await pipeline.getByRole("button", { name: "7 days", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(pipeline.getByRole("button", { name: "7 days", exact: true })).toHaveAttribute("aria-pressed", "true");
  expect((await pipeline.getByRole("button", { name: "7 days", exact: true }).boundingBox())!.height).toBeGreaterThanOrEqual(40);
  await expect(stages.first()).toContainText("128,450");
  await page.screenshot({ path: info.outputPath("detection-pipeline-mobile.png"), fullPage: true, animations: "disabled" });
});

test("disabled detection explains zero inspections and lists session eligibility without inferring ownership", async ({ page }, info) => {
  let enabled = false;
  await mockApi(page, (range) => ({ ...counts, range, sessions_inspected: 0, sessions_selected: 0,
    sessions_with_alerts: 0, alerts: 0, reports: 0, actionable_reports: 0, no_finding_reports: 0, inconclusive_reports: 0, pending_investigations: 0,
    availability: { tenant_enabled: enabled, scheduling_enabled: enabled, worker_ready: enabled ? false : null, reason: enabled ? "worker_unavailable" : "tenant_disabled", checked_at: counts.until } }));
  const ids = [1, 2].map((n) => `a0b0c0d0-e0f0-4a0b-8c0d-${String(n).padStart(12, "0")}`);
  const decisions = [
    { status: "eligible", reason: "worker_unavailable", owner: { id: "owner", name: "Verified person", email: "person@example.test" }, history_available: true },
    { status: "waiting", reason: "evaluation_pending", owner: null, history_available: false },
  ];
  const requests: string[] = [];
  await page.route("**/api/v1/detections/eligibility?**", async (route) => {
    const url = new URL(route.request().url()); requests.push(url.searchParams.get("range") || "");
    const index = url.searchParams.has("cursor") ? 1 : 0;
    return route.fulfill({ json: { items: [{ id: ids[index], product: "codex-cli", hostname: "Example laptop", reported_user: "captured-person",
      started_at: counts.until, last_event_at: counts.until,
      eligibility: { ...decisions[index], ...(!enabled ? { status: "disabled", reason: "tenant_disabled" } : {}), evaluated_at: counts.until, next_evaluation_at: null, job_id: null, job_state: null } }],
      next_cursor: index ? "" : "next-page" } });
  });
  await page.goto("/detections");
  await expect(panel(page)).toContainText("Session investigations are off");
  await expect(panel(page).getByRole("status")).toContainText("Investigations are off for this tenant.");
  await expect(panel(page)).toContainText("Tenant detection: Off · Server scheduling: Off · Worker: Not reported");
  await expect(panel(page).getByRole("link", { name: "View investigation settings" })).toHaveAttribute("href", "/detection-rules");
  const eligibility = page.getByRole("region", { name: "Session eligibility", exact: true });
  await expect(eligibility).toContainText("Detection off");
  await page.screenshot({ path: info.outputPath("detection-disabled-desktop.png"), fullPage: true, animations: "disabled" });
  enabled = true;
  await panel(page).getByRole("button", { name: "Refresh detection pipeline" }).click();
  await expect(panel(page).getByRole("status")).toContainText("No ready investigation worker is available.");
  await eligibility.getByRole("button", { name: "Refresh eligibility" }).click();
  await expect(eligibility).toContainText("Eligible, waiting");
  await expect(eligibility).toContainText("no ready worker");
  await expect(eligibility).toContainText("Verified person");
  await expect(eligibility).toContainText("Recent user history available");
  await eligibility.getByRole("button", { name: /Load more/ }).click();
  await expect(eligibility).toContainText("captured-person");
  await expect(eligibility).toContainText("Reported OS user; ownership unverified");
  await expect(eligibility).toContainText("Session evidence only");
  await expect(eligibility.getByRole("link").first()).toHaveAttribute("href", `/sessions/${ids[0]}`);
  await eligibility.getByRole("textbox", { name: "Search detection eligibility" }).fill("person@example.test");
  const searched = page.waitForRequest((request) => new URL(request.url()).searchParams.get("q") === "person@example.test");
  await eligibility.getByRole("button", { name: "Search", exact: true }).click();
  await searched;
  await panel(page).getByRole("button", { name: "7 days", exact: true }).click();
  await expect.poll(() => requests.at(-1)).toBe("7d");
  await expect(eligibility).toContainText("started in the last 7 days");
  await page.screenshot({ path: info.outputPath("detection-eligibility-desktop.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(eligibility.getByRole("button", { name: "Search", exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  const tableContainer = eligibility.getByRole("region", { name: "Scrollable data table" });
  await tableContainer.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  expect(await tableContainer.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
  const reason = await eligibility.getByText("Eligible, waiting", { exact: true }).boundingBox();
  expect(reason!.x).toBeGreaterThanOrEqual(0);
  expect(reason!.x + reason!.width).toBeLessThanOrEqual(390);
  await page.screenshot({ path: info.outputPath("detection-eligibility-mobile.png"), fullPage: true, animations: "disabled" });
});

test("unknown readiness and failed eligibility loads remain explicit", async ({ page }) => {
  await mockApi(page, (range) => ({ ...counts, range, availability: undefined, criteria: undefined }));
  await page.route("**/api/v1/detections/eligibility?**", (route) => route.fulfill({ status: 503, json: { error: { message: "Eligibility unavailable" } } }));
  await page.goto("/detections");
  await expect(panel(page)).toContainText("Investigation readiness is not confirmed");
  await expect(panel(page)).not.toContainText("Session investigations are off");
  const eligibility = page.getByRole("region", { name: "Session eligibility", exact: true });
  await expect(eligibility.getByRole("alert")).toContainText("Eligibility unavailable");
  await expect(eligibility.getByText("No sessions match", { exact: true })).toHaveCount(0);
  await panel(page).getByRole("button", { name: "View detection start criteria" }).click();
  await expect(panel(page)).toContainText("Start criteria are not reported by this backend");
});

test("start criteria show the tenant's thresholds and distinguish selection from completed inspections", async ({ page }, info) => {
  let legacy = false;
  await mockApi(page, (range) => ({ ...counts, range, selection_policy: legacy ? "legacy" : "risk_budget",
    sessions_inspected: 0, sessions_with_alerts: 0, alerts: 0, sessions_escalated: 0, sessions_selected: 3,
    reports: 0, actionable_reports: 0, no_finding_reports: 0, inconclusive_reports: 0 }));
  await page.goto("/detections");
  const pipeline = panel(page);
  await expect(pipeline.getByRole("status")).toContainText("Investigations are awaiting reports");
  await pipeline.getByRole("button", { name: "View detection start criteria" }).focus();
  await page.keyboard.press("Enter");
  const criteria = pipeline.locator("details").filter({ has: page.getByText("When detection starts", { exact: true }) });
  await expect(criteria).toHaveAttribute("open", "");
  await expect(criteria).toContainText("Idle threshold: 120 seconds. Delivery grace: 15 seconds.");
  await expect(criteria).toContainText("High-risk action score: at least 65");
  await expect(criteria).toContainText("at least 4 distinct high-risk actions");
  await expect(criteria).toContainText("at least 5 distinct high-risk actions across at least two verified user sessions");
  await expect(criteria).toContainText("an action score of at least 93");
  await expect(criteria).not.toContainText("Random sample");
  await expect(criteria).toContainText("candidates that meet risk thresholds");
  await expect(criteria).toContainText("within a 1% investigation target");
  await expect(criteria).not.toContainText("The sample is part of that target");
  await expect(criteria).toContainText("8 attempts; 800000 tokens; 4.50 USD");
  await expect(criteria).toContainText("Urgent cases still obey execution and spending limits");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("detection-start-criteria-desktop.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(criteria.getByRole("link", { name: "View investigation settings" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("detection-start-criteria-mobile.png"), fullPage: true, animations: "disabled" });
  legacy = true;
  await pipeline.getByRole("button", { name: "Refresh detection pipeline" }).click();
  await expect(criteria).toContainText("accumulated session risk must be greater than 250");
  await expect(criteria).toContainText("Percentage targets do not apply");
  await expect(criteria).toContainText("without exceeding the risk threshold");
  await expect(criteria).not.toContainText("Urgent risk:");
  await expect(pipeline).not.toContainText("Configured target:");
});

test("rankings show highest scores first, exact threshold distances, and whole-population counts", async ({ page }, info) => {
  await mockApi(page);
  const requests: URL[] = [];
  await page.route("**/api/v1/detections/rankings?**", async route => {
    const url = new URL(route.request().url()); requests.push(url);
    const group = url.searchParams.get("group"), band = url.searchParams.get("band");
    const row = { product: "codex-cli", hostname: "Example laptop", reported_user: "reported-person", user_id: "user-a",
      user_name: "Avery Chen", user_email: "avery@example.test", session_count: 3, high_risk_sessions: 1,
      score_coverage: { status: "complete", assessed: 8, targets: 8, pending: 0 },
      updated_at: counts.until, last_event_at: counts.until };
    const items = group === "users" ? [
      { ...row, id: "user-a", rank: 1, peak: 98, high_actions: 6, band: "below" },
      { ...row, id: "user-b", user_id: "user-b", user_name: "Blair Kim", rank: 2, peak: 80, high_actions: 5, high_risk_sessions: 2, band: "meets" },
    ] : url.searchParams.get("cursor") ? [
      { ...row, id: "session-unscored", rank: 6, peak: null, high_actions: null, high_risk_sessions: null, band: "unknown",
        score_coverage: { status: "not_assessed", assessed: 0, targets: 8, pending: 0 } },
      { ...row, id: "session-pending", rank: 7, peak: null, high_actions: null, high_risk_sessions: null, band: "unknown",
        score_coverage: { status: "pending", assessed: 0, targets: 2, pending: 2 } },
      { ...row, id: "session-updating", rank: 8, peak: null, high_actions: null, high_risk_sessions: null, band: "unknown",
        score_coverage: { status: "updating", assessed: null, targets: null, pending: null } },
      { ...row, id: "session-older-api", rank: 9, peak: null, high_actions: null, high_risk_sessions: null, band: "unknown", score_coverage: undefined },
    ] : [
      { ...row, id: "session-highest", rank: 1, peak: 98, high_actions: 1, band: "meets" },
      { ...row, id: "session-below", rank: 2, peak: 92, high_actions: 3, band: "below",
        score_coverage: { status: "partial", assessed: 3, targets: 8, pending: 0 } },
      { ...row, id: "session-count", rank: 3, peak: 80, high_actions: 5, band: "meets" },
      { ...row, id: "session-fourth", rank: 4, peak: 75, high_actions: 2, band: "below" },
      { ...row, id: "session-fifth", rank: 5, peak: 65, high_actions: 1, band: "below" },
    ];
    return route.fulfill({ json: { group, band, selection_policy: "risk_budget", history_days: 7, until: counts.until, criteria: counts.criteria,
      summary: group === "users" ? { total: 12, meets: 3, below: 8, unknown: 1 } : { total: 68, meets: 5, below: 59, unknown: 4 },
      items: band === "all" ? items : items.filter(row => row.band === band),
      next_cursor: group === "sessions" && band === "all" && !url.searchParams.get("cursor") ? "second-page" : "" } });
  });
  await page.route("**/api/v1/session-investigations?**", route => route.fulfill({ json: { items: [{
    id: "report-example", snapshot_id: "snapshot-example", state: "completed", created_at: counts.until,
    title: "External upload reviewed", summary: "The report connects the upload with the user's request and supporting evidence.",
    outcome: "actionable_findings", severity: "high", confidence: "high", snapshot_current: true, configuration_current: true,
    subject: { ownership_verified: true, name: "Avery Chen", hostname: "Example laptop" },
  }], next_cursor: "" } }));
  await page.goto("/detections");
  const ranking = page.getByRole("region", { name: "Highest risk scores", exact: true });
  const table = ranking.getByRole("table", { name: "Detection risk rankings" });
  await expect(ranking).toContainText("Recent activity: 7 days");
  await expect(ranking).toContainText("score ≥ 65");
  await expect(ranking).toContainText("urgent score ≥ 93");
  await expect(ranking.getByRole("button", { name: "Meets threshold 5", exact: true })).toBeVisible();
  await expect(ranking.getByRole("button", { name: /^Close/ })).toHaveCount(0);
  await expect(table.getByRole("row").nth(1)).toContainText("98");
  await expect(table.getByRole("row")).toHaveCount(6);
  await expect(table.getByRole("row").nth(2)).toContainText("1 below urgent");
  await expect(table.getByRole("row").nth(2)).toContainText("3 / 4");
  await expect(table.getByRole("row").nth(2)).toContainText("1 short");
  await expect(table.getByRole("row").nth(2)).toContainText("Partially assessed · 3 / 8 actions");
  await expect(table.getByRole("link").first()).toHaveAttribute("href", "/sessions/session-highest");
  await expect(table.getByRole("link").first()).toHaveAttribute("title", "Session session-highest");
  // Five populated rows keep the ranking compact below the reports and pipeline.
  await ranking.screenshot({ path: info.outputPath("score-coverage-desktop.png"), animations: "disabled" });
  expect((await ranking.boundingBox())!.height).toBeLessThanOrEqual(540);
  const reports = page.getByRole("region", { name: "Investigation reports", exact: true });
  await expect(reports.getByRole("link", { name: "External upload reviewed" })).toBeVisible();
  expect((await reports.boundingBox())!.y).toBeLessThan((await ranking.boundingBox())!.y);
  expect((await reports.boundingBox())!.y).toBeLessThan((await page.getByRole("region", { name: "Session eligibility", exact: true }).boundingBox())!.y);
  await ranking.getByRole("button", { name: "Next", exact: true }).click();
  await expect(ranking).toContainText("Page 2");
  await expect(table).toContainText("Not assessed · 0 / 8 actions");
  await expect(table).toContainText("Assessment pending · 0 / 2 actions · 2 pending");
  await expect(table).toContainText("Updating summary");
  await expect(table).toContainText("Coverage unknown");
  await expect(table).not.toContainText("Awaiting scores");
  await expect(ranking.getByRole("button", { name: "Unknown 4", exact: true })).toBeVisible();
  await ranking.screenshot({ path: info.outputPath("score-status-desktop.png"), animations: "disabled" });
  await expect(table).toContainText("Unavailable");
  await expect(ranking.getByRole("button", { name: "Meets threshold 5", exact: true })).toBeVisible();
  await ranking.getByRole("button", { name: "Previous", exact: true }).click();
  await expect(table.getByRole("link").first()).toHaveAttribute("href", "/sessions/session-highest");
  await ranking.getByRole("button", { name: "Meets threshold 5", exact: true }).click();
  await expect(table.getByRole("row")).toHaveCount(3);
  await expect(ranking).toContainText("5 sessions in this filter");
  await ranking.getByRole("button", { name: "All 68", exact: true }).click();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("highest-session-scores.png"), fullPage: true, animations: "disabled" });
  await ranking.getByRole("button", { name: "Users", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(ranking).toContainText("5 high-risk actions across 2+ verified sessions");
  await expect(table.getByRole("columnheader", { name: "User pattern", exact: true })).toBeVisible();
  await expect(table.getByRole("row").nth(1)).toContainText("Avery Chen");
  await expect(table.getByRole("row").nth(1)).toContainText("98");
  await expect(table.getByRole("row").nth(1)).toContainText("Below");
  await expect(table.getByRole("row").nth(1)).toContainText("1 / 2");
  await expect(table.getByRole("row").nth(2)).toContainText("Blair Kim");
  await expect(requests.at(-1)!.searchParams.get("cursor")).toBe("");
  await expect(requests.at(-1)!.searchParams.get("band")).toBe("all");
  expect(requests.every(request => request.searchParams.get("limit") === "5")).toBe(true);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  const scroll = ranking.getByRole("region", { name: "Scrollable data table" });
  await scroll.evaluate(element => { element.scrollLeft = element.scrollWidth; });
  const comparison = await table.getByText("Below", { exact: true }).boundingBox();
  expect(comparison!.x).toBeGreaterThanOrEqual(0);
  expect(comparison!.x + comparison!.width).toBeLessThanOrEqual(390);
  await expect(ranking.getByRole("button", { name: "Refresh rankings" })).toBeVisible();
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: info.outputPath("highest-user-scores-mobile.png"), fullPage: true, animations: "disabled" });
});

test("unavailable rankings and legacy selection never show zero as a measured result", async ({ page }) => {
  await mockApi(page);
  let legacy = false;
  await page.route("**/api/v1/detections/rankings?**", route => legacy
    ? route.fulfill({ json: { group: "sessions", band: "all", selection_policy: "legacy", summary: null, items: [], next_cursor: "" } })
    : route.fulfill({ status: 404, json: { error: { message: "Rankings are unavailable" } } }));
  await page.goto("/detections");
  const ranking = page.getByRole("region", { name: "Highest risk scores", exact: true });
  await expect(ranking.getByRole("alert")).toContainText("Rankings are unavailable");
  await expect(ranking.getByRole("group", { name: "Filter by threshold comparison" })).toHaveCount(0);
  legacy = true;
  await ranking.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(ranking).toContainText("This tenant uses legacy selection");
  await expect(ranking.getByRole("table")).toHaveCount(0);
});
