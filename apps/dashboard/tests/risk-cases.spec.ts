import { test, expect, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { emptyRiskCases } from "./fixtures/risk-cases";
import { expectSelectSpacing } from "./select-spacing";

test.use({ launchOptions: { ignoreDefaultArgs: ["--hide-scrollbars"] } });
const user = { id: "u", name: "Security analyst", email: "analyst@example.test", roles: ["security_analyst"], tenant: { id: "t", name: "Example organization", slug: "test" } };
const subjects = ["avery.chen", "jordan.lee", "morgan.shah", "riley.brooks", "casey.rivera", "alex"];
const titles = ["Customer export to personal storage", "Production credentials in a tool request", "Authorized credential test fixture", "Unapproved production cleanup", "Untrusted package requested secrets", "Repeated downloads outside the project", "Long command with a retained investigation", "Project data copied to a temporary directory"];
function makeRow(index: number, kind: string) {
  return { id: `${kind}-${index}`, kind, identity_kind: kind === "users" && index === 5 ? "account" : "os_user", reported_user: subjects[index % subjects.length],
    accounts: [`${subjects[index % subjects.length]}@example.test`],
    hostname: index === 5 ? "Alex-Laptop" : "Avery-MacBook", product: "codex-cli", outcome: index % 3 === 1 ? "tp" : index % 3 === 2 ? "fp" : "review",
    opened_at: index < 3 ? "2026-10-21T15:00:00Z" : "2026-10-20T15:00:00Z", closed_at: null, version: 1,
    peak: 98 - index, session_count: kind === "users" ? 9 - index : 1, device_count: kind === "users" && index === 5 ? 2 : 1, report_count: 1,
    title: titles[index], summary: index === 0 ? "Repeated uploads of customer data" : titles[index] };
}

async function mockCases(page: Page) {
  const rows = { sessions: Array.from({ length: 8 }, (_, i) => makeRow(i, "sessions")), users: Array.from({ length: 6 }, (_, i) => makeRow(i, "users")) };
  const state = { failSave: false, failRead: false, malformed: false, noCases: false, legacy: false,
    snapshot: "legacy" as "legacy" | "pending" | "unavailable" | "current" | "stale",
    threshold: 70 as number | null | undefined, selectionPolicy: "risk_budget", peaks: null as (number | null)[] | null,
    summaries: null as { state: string; text: string | null; through: string | null }[] | null, requests: [] as string[],
    saved: [] as Record<string, unknown>[], reviewContext: null as Record<string, unknown> | null };
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url()), path = url.pathname.replace("/api/v1/", "");
    if (path === "auth/me") return route.fulfill({ json: { user } });
    if (path === "risk-cases") {
      state.requests.push(url.search);
      if (state.failRead) return route.fulfill({ status: 503, json: { error: "Cases unavailable" } });
      if (state.malformed) return route.fulfill({ json: { groups: {} } });
      const activity = url.searchParams.get("view") === "activity";
      const response: any = emptyRiskCases(activity ? "activity" : "cases");
      response.detection_threshold = state.threshold;
      response.selection_policy = state.selectionPolicy;
      if (state.legacy) delete response.view;
      for (const kind of ["sessions", "users"] as const) {
        for (const row of state.noCases ? [] : rows[kind]) { const bin = response.charts[kind].find((day: any) => day.day === row.opened_at.slice(0, 10)); bin[row.outcome] += 1; }
        const source = activity ? rows[kind].map((row, index) => ({ ...row, peak: state.peaks ? state.peaks[index] ?? null : index === 7 ? null : Math.max(0, 60 - index * 10),
          session_id: `10000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`, external_id: `captured-session-${index}`,
          last_activity_at: row.opened_at, activity_summary: state.summaries?.[index] })) : state.noCases ? [] : rows[kind];
        const filtered = source.filter((row) => (url.searchParams.get("outcome") === "all" || row.outcome === url.searchParams.get("outcome")) &&
          (!url.searchParams.get("day") || row.opened_at.startsWith(url.searchParams.get("day")!)) &&
          `${row.title} ${row.summary} ${row.reported_user} ${row.hostname} ${row.accounts.join(" ")}`.toLowerCase().includes((url.searchParams.get("q") || "").toLowerCase()));
        const offset = Number(url.searchParams.get(`${kind}_offset`) || 0);
        response.groups[kind] = { items: filtered.slice(offset, offset + 5), total: filtered.length, offset, limit: 5 };
      }
      if (activity && state.snapshot !== "legacy") {
        const pending = ["pending", "unavailable"].includes(state.snapshot);
        response.activity_snapshot = { state: state.snapshot, since: pending ? null : response.since,
          until: pending ? null : "2026-10-21T19:45:00Z", refresh_interval_seconds: 900,
          refresh_failed: ["unavailable", "stale"].includes(state.snapshot) };
        if (pending) response.groups = null;
      }
      return route.fulfill({ json: response });
    }
    if (path.startsWith("risk-cases/")) {
      const row = [...rows.sessions, ...rows.users].find((row) => row.id === path.split("/")[1])!;
      if (route.request().method() === "PATCH") {
        state.saved.push(route.request().postDataJSON());
        if (state.failSave) return route.fulfill({ status: 409, json: { error: "Case changed. Refresh before saving your verdict." } });
        const body = route.request().postDataJSON();
        expect(body.version).toBe(row.version);
        row.outcome = body.outcome; row.version += 1;
      }
      if (path.endsWith("/download")) return route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Retained case report</title><p>Jev evidence remains exact</p>" });
      state.reviewContext = { schema_version: 1, scope: "displayed_page", case_id: row.id, case_version: row.version, offset: 0, report_count: row.report_count,
        reports: [{ job_id: "10000000-0000-4000-8000-000000000001", snapshot_id: "20000000-0000-4000-8000-000000000001", attempt_id: "30000000-0000-4000-8000-000000000001", state: "completed", report_sha256: "a".repeat(64) }] };
      return route.fulfill({ json: { case: row, offset: 0, has_more: false, review_context: state.legacy ? undefined : state.reviewContext,
        reports: [{ job_id: "10000000-0000-4000-8000-000000000001", snapshot_id: "20000000-0000-4000-8000-000000000001", attempt_id: "30000000-0000-4000-8000-000000000001", session_id: null, state: "completed",
        report: { title: row.title, summary: "Jev evidence remains exact. " + row.summary, status: "finding", confidence: "high", findings: [], gaps: ["captured_evidence_only"], conclusion: "Retained evidence requires analyst review.", impact: { observed: "An upload was attempted.", potential: "Customer data may leave the approved environment." }, limitations: ["Execution was not confirmed."] },
      }] } });
    }
    if (path === "user-risk") return route.fulfill({ json: { items: [], total_findings: 0 } });
    if (path === "knowledge") return route.fulfill({ json: { enabled: false, revision: 0, documents: [] } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  return { rows, state };
}

test("case board filters both rankings, pages independently, and persists separate verdicts", async ({ page }) => {
  const { rows, state } = await mockCases(page);
  await page.goto("/user-risk?view=cases");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risky Sessions/Users");
  const sessions = page.getByRole("list", { name: "Sessions cases" }), users = page.getByRole("list", { name: "Users cases" });
  await expect(sessions.locator("li")).toHaveCount(5);
  await expect(users.locator("li")).toHaveCount(5);
  await page.getByRole("button", { name: "Next sessions", exact: true }).click();
  await expect(sessions.locator("li")).toHaveCount(3);
  await expect(users.locator("li").first()).toContainText(subjects[0]);
  await page.getByRole("button", { name: "Previous sessions", exact: true }).click();
  await page.getByLabel("Outcome for case sessions-0", { exact: true }).selectOption("tp");
  await expect(page.getByRole("status")).toHaveText("Case marked True positive.");
  expect(state.saved[0]).not.toHaveProperty("review_context");
  await expect(page.getByLabel("Outcome for case users-0", { exact: true })).toHaveValue("review");
  expect(rows.sessions[0].outcome).toBe("tp");
  await expect(sessions.locator("li").first()).toContainText("98 / 70");
  await expect(page.getByRole("list", { name: "Session cases by outcome totals" })).toContainText("TP 4");
  await page.reload();
  await expect(page.getByLabel("Outcome for case sessions-0", { exact: true })).toHaveValue("tp");
  await page.getByRole("group", { name: "Filter cases by outcome" }).getByRole("button", { name: "FP", exact: true }).click();
  await expect(sessions.locator("li")).toHaveCount(2);
  await expect(users.locator("li")).toHaveCount(2);
  await expect(page.getByRole("list", { name: "Session cases by outcome totals" })).toContainText("TP 4");
  await page.getByLabel("Search cases", { exact: true }).fill("morgan");
  await expect(sessions.locator("li")).toHaveCount(1);
  await expect(users.locator("li")).toHaveCount(1);
  await page.getByLabel("Search cases", { exact: true }).fill("");
  await page.getByRole("button", { name: "All outcomes", exact: true }).click();
  const chart = page.getByRole("group", { name: "Session cases by outcome. Select an opening day to filter cases.", exact: true });
  await chart.getByRole("button", { name: /^Oct 20:/ }).focus();
  await chart.getByRole("button", { name: /^Oct 20:/ }).press("Enter");
  await expect(sessions.locator("li")).toHaveCount(5);
  await expect(users.locator("li")).toHaveCount(3);
  await page.getByRole("button", { name: "Clear opening date filter" }).click();
  await expect(page.getByRole("region", { name: "Sessions", exact: true })).toContainText("8 matching cases");
});

test("risk lists refresh the configured threshold and keep missing or legacy thresholds unavailable", async ({ page }) => {
  const { state } = await mockCases(page);
  state.snapshot = "current";
  await page.goto("/user-risk");
  const activity = ["sessions", "users"].map((kind) => page.getByRole("list", { name: `Top ${kind} by observed risk` }));
  for (const list of activity) await expect(list.locator("li").first()).toContainText("60 / 70");
  state.threshold = 82;
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  for (const list of activity) await expect(list.locator("li").first()).toContainText("60 / 82");
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  const cases = ["Sessions", "Users"].map((kind) => page.getByRole("list", { name: `${kind} cases` }));
  for (const list of cases) await expect(list.locator("li").first()).toContainText("98 / 82");
  state.threshold = undefined;
  await page.getByRole("button", { name: "Refresh cases", exact: true }).click();
  for (const list of cases) await expect(list.locator("li").first()).toContainText("98 / N/A");
  await expect(page.getByText("Detection threshold unavailable (N/A).", { exact: false })).toBeVisible();
  state.selectionPolicy = "legacy";
  state.threshold = 70;
  await page.getByRole("button", { name: "Top activity", exact: true }).click();
  for (const list of activity) {
    await expect(list.locator("li").first()).toContainText("60 / N/A");
    await expect(list.locator("li").first()).not.toContainText("/ 100");
  }
});

test("sessions highlight scores at or above the current threshold independently of cases", async ({ page }, info) => {
  const { state } = await mockCases(page);
  state.noCases = true;
  state.snapshot = "current";
  state.peaks = [89, 70, 69.9, 0, null];
  await page.goto("/user-risk");
  const sessions = page.getByRole("list", { name: "Top sessions by observed risk" });
  await expect(sessions.getByText("Threshold reached", { exact: true })).toHaveCount(2);
  for (const index of [0, 1]) await expect(sessions.locator("li").nth(index)).toContainText("Threshold reached");
  for (const index of [2, 3, 4]) await expect(sessions.locator("li").nth(index)).not.toContainText("Threshold reached");
  await expect(page.getByRole("list", { name: "Session cases by outcome totals" })).toContainText("Under review 0");
  await expect(page.getByRole("list", { name: "Top users by observed risk" }).getByText("Threshold reached")).toHaveCount(0);
  for (const width of [1440, 390, 360]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    for (const item of await sessions.locator("li").all()) {
      expect(await item.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
    }
    for (const link of await sessions.getByRole("link").all()) {
      await link.scrollIntoViewIfNeeded();
      await expect(link).toBeInViewport();
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    if (width !== 360) await page.screenshot({ path: info.outputPath(`threshold-highlight-${width}.png`), fullPage: true, animations: "disabled" });
  }
  state.threshold = 90;
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.getByText("Threshold reached")).toHaveCount(0);
  state.threshold = undefined;
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.locator("li").first()).toContainText("89 / N/A");
  await expect(sessions.getByText("Threshold reached")).toHaveCount(0);
  state.threshold = 70;
  state.selectionPolicy = "legacy";
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.getByText("Threshold reached")).toHaveCount(0);
});

test("session activity summaries load independently of scores and preserve readable context", async ({ page }, info) => {
  const { state } = await mockCases(page);
  state.snapshot = "current";
  state.peaks = [89, 70, 69.9, 0, null];
  state.summaries = [
    { state: "pending", text: null, through: null },
    { state: "ready", text: "Updated authentication handling and ran the related tests.", through: "2026-10-21T15:00:00Z" },
    { state: "unavailable", text: null, through: null },
  ];
  await page.goto("/user-risk");
  const sessions = page.getByRole("list", { name: "Top sessions by observed risk" });
  await expect(sessions.locator("li").first()).toContainText("Summarizing captured activity…");
  await expect(sessions.locator("li").nth(1).getByLabel("Session activity summary")).toContainText(state.summaries[1].text!);
  await expect(sessions.getByText("Summary unavailable", { exact: true })).toHaveCount(3);
  await expect(page.getByRole("list", { name: "Top users by observed risk" }).getByLabel("Session activity summary")).toHaveCount(0);
  state.summaries[0] = { state: "ready", text: "Investigated failing authentication tests and requested changes to error handling.", through: "2026-10-21T15:00:00Z" };
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.locator("li").first()).toContainText(state.summaries[0].text!);
  await expect(sessions.locator("li").first()).toContainText("89 / 70");
  await expect(sessions.locator("li").first()).toContainText("captured-session-0");
  await expect(sessions.getByLabel("Session activity summary").first()).toHaveAttribute("title", /^AI summary of captured activity through/);
  for (const width of [1440, 390, 360]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    for (const item of await sessions.locator("li").all()) expect(await item.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
    for (const link of await sessions.getByRole("link").all()) {
      await link.scrollIntoViewIfNeeded();
      await expect(link).toBeInViewport();
    }
    await page.evaluate(() => window.scrollTo(0, 0));
    if (width !== 360) await page.screenshot({ path: info.outputPath(`session-summary-${width}.png`), fullPage: true, animations: "disabled" });
  }
  state.summaries[0].text = "Discussed Jev evidence <script>throw new Error('untrusted summary')</script>.";
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.getByLabel("Session activity summary").first()).toContainText(state.summaries[0].text);
  await expect(sessions.locator("script")).toHaveCount(0);
  state.summaries = null;
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(sessions.getByText("Summary unavailable", { exact: true })).toHaveCount(5);
});

test("top activity shows below-threshold and unscored sessions when no cases exist", async ({ page }, info) => {
  const { state } = await mockCases(page);
  state.noCases = true;
  await page.goto("/user-risk");
  const sessions = page.getByRole("list", { name: "Top sessions by observed risk" });
  const users = page.getByRole("list", { name: "Top users by observed risk" });
  await expect(sessions.locator("li")).toHaveCount(5);
  await expect(users.locator("li")).toHaveCount(5);
  await expect(sessions.locator("li").first()).toContainText("60 / 70");
  await expect(sessions.getByRole("link", { name: "View session" }).first()).toHaveAttribute("href", "/sessions/10000000-0000-4000-8000-000000000001");
  await expect(users.getByRole("link", { name: "Top session" }).first()).toHaveAttribute("href", "/sessions/10000000-0000-4000-8000-000000000001");
  await expect(page.getByRole("combobox")).toHaveCount(0);
  await expect(page.getByRole("list", { name: "Session cases by outcome totals" })).toContainText("Under review 0");
  await page.getByRole("button", { name: "Next sessions", exact: true }).click();
  await expect(sessions.locator("li")).toHaveCount(3);
  await expect(sessions).toContainText("0 / 70");
  await expect(sessions).toContainText("Not scored");
  await expect(users.locator("li")).toHaveCount(5);
  await page.getByLabel("Search activity", { exact: true }).fill("jordan");
  await expect(sessions.locator("li")).toHaveCount(2);
  await expect(users.locator("li")).toHaveCount(1);
  await page.getByLabel("Search activity", { exact: true }).fill("");
  for (const width of [1440, 390, 360]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(sessions.locator("li")).toHaveCount(5);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    for (const link of await sessions.getByRole("link").all()) {
      const box = (await link.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(width);
    }
    if (width !== 360) await page.screenshot({ path: info.outputPath(`top-activity-${width}.png`), fullPage: true, animations: "disabled" });
  }
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  await expect(page).toHaveURL(/view=cases/);
  await expect(page.getByText("No matching cases", { exact: true })).toHaveCount(2);
  await page.reload();
  await expect(page.getByRole("button", { name: "Cases", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Top activity", exact: true }).click();
  await expect(sessions.locator("li")).toHaveCount(5);
  state.legacy = true;
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("did not return complete activity rankings");
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  await expect(page.getByText("No matching cases", { exact: true })).toHaveCount(2);
  state.legacy = false;
  await page.getByRole("button", { name: "Top activity", exact: true }).click();
  await page.getByRole("group", { name: "Session cases by outcome. Select an opening day to filter cases.", exact: true }).getByRole("button").first().locator("rect").first().click();
  await expect(page).toHaveURL(/view=cases/);
  await expect(page.getByRole("button", { name: "Clear opening date filter" })).toBeVisible();
});

test("OS users stay distinct by device and retain searchable agent accounts", async ({ page }, info) => {
  const { rows } = await mockCases(page);
  const accounts = ["avery.chen@example.test", "avery.chen-with-a-long-reported-account@research.example.test"];
  for (const kind of ["sessions", "users"] as const) {
    rows[kind][0].accounts = accounts;
    rows[kind][1].reported_user = subjects[0];
    rows[kind][1].hostname = "Avery-Other-Laptop";
    rows[kind][1].accounts = accounts;
  }
  await page.goto("/user-risk");
  const users = page.getByRole("list", { name: "Top users by observed risk" });
  await expect(users.locator("li").first()).toContainText("OS user on one device · Avery-MacBook");
  await expect(users.locator("li").nth(1)).toContainText("OS user on one device · Avery-Other-Laptop");
  await expect(users.locator("li").first()).toContainText(`Reported agent accounts: ${accounts.join(", ")}`);
  await page.getByLabel("Search activity", { exact: true }).fill(accounts[1]);
  await expect(users.locator("li")).toHaveCount(2);
  await expect(page.getByRole("list", { name: "Top sessions by observed risk" }).locator("li")).toHaveCount(2);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    for (const item of await users.locator("li").all()) {
      expect(await item.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
    }
    await page.screenshot({ path: info.outputPath(`os-user-accounts-${width}.png`), fullPage: true, animations: "disabled" });
  }
  await page.getByLabel("Search activity", { exact: true }).fill("");
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  const cases = page.getByRole("list", { name: "Users cases" });
  await expect(cases.locator("li").first()).toContainText("Avery-MacBook");
  await expect(cases.locator("li").nth(1)).toContainText("Avery-Other-Laptop");
  await expect(cases.locator("li").first()).toContainText(accounts[1]);
  await page.getByRole("button", { name: "Next users", exact: true }).click();
  await expect(cases).toContainText("Historical account grouping");
});

test("reports preserve evidence, download HTML, and show save failures inside the dialog", async ({ page }, info) => {
  const { state } = await mockCases(page);
  await page.goto("/user-risk?view=cases");
  const open = page.getByRole("button", { name: "Report for case users-0", exact: true });
  await open.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("It is not an additional model assessment");
  await expect(dialog).toContainText("Jev evidence remains exact");
  await expect(dialog).toContainText("Other pages are not recorded as reviewed.");
  await page.screenshot({ path: info.outputPath("case-review-context.png"), animations: "disabled" });
  const displayedContext = structuredClone(state.reviewContext);
  await expect(dialog.getByRole("link", { name: "Open retained investigation" })).toHaveAttribute("href", /attempt=30000000.*snapshot=20000000/);
  state.failSave = true;
  await dialog.getByLabel("Outcome for case users-0", { exact: true }).selectOption("fp");
  await expect(dialog.getByRole("alert")).toContainText("Case changed. Refresh before saving your verdict.");
  expect(state.saved[0].review_context).toEqual(displayedContext);
  await expect(dialog.getByLabel("Outcome for case users-0", { exact: true })).toHaveValue("review");
  state.failSave = false;
  await dialog.getByLabel("Outcome for case users-0", { exact: true }).selectOption("fp");
  await expect(dialog.getByLabel("Outcome for case users-0", { exact: true })).toHaveValue("fp");
  expect(state.saved[1].review_context).toEqual(displayedContext);
  const downloadPromise = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Download HTML" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("case-users-0.html");
  expect(await readFile((await download.path())!, "utf8")).toContain("Jev evidence remains exact");
  await page.keyboard.press("Escape");
  await expect(open).toBeFocused();
  await expect(page.getByLabel("Outcome for case sessions-0", { exact: true })).toHaveValue("review");
});

test("case report outcome remains compatible with servers without review context", async ({ page }) => {
  const { state } = await mockCases(page);
  state.legacy = true;
  await page.goto("/user-risk?view=cases");
  await page.getByRole("button", { name: "Report for case sessions-0", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toContainText("Jev evidence remains exact");
  await expect(dialog).not.toContainText("Other pages are not recorded as reviewed.");
  await dialog.getByLabel("Outcome for case sessions-0", { exact: true }).selectOption("tp");
  await expect(dialog.getByLabel("Outcome for case sessions-0", { exact: true })).toHaveValue("tp");
  expect(state.saved[0]).toEqual({ outcome: "tp", version: 1 });
});

test("case board and report controls fit populated desktop and phone layouts", async ({ page }, info) => {
  await mockCases(page);
  await page.goto("/user-risk?view=cases");
  for (const width of [1440, 1280, 1024, 768, 390, 360]) {
    await page.setViewportSize({ width, height: 1080 });
    await expect(page.getByRole("list", { name: "Sessions cases" }).locator("li")).toHaveCount(5);
    await page.evaluate(() => document.fonts.ready);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await expectSelectSpacing(page.locator("select:visible"));
    for (const control of await page.getByRole("list", { name: "Sessions cases" }).locator("button, select").all()) {
      if (width <= 390) await expect(control).toHaveCSS("height", await control.evaluate((node) => node.tagName === "SELECT" ? "36px" : "40px"));
      const box = (await control.boundingBox())!;
      expect(box.x).toBeGreaterThanOrEqual(0); expect(box.x + box.width).toBeLessThanOrEqual(width);
      if (width <= 390) expect(box.height).toBeGreaterThanOrEqual(36);
    }
    if ([1440, 390].includes(width)) await page.screenshot({ path: info.outputPath(`risk-cases-${width}.png`), fullPage: true, animations: "disabled" });
  }
  await page.setViewportSize({ width: 360, height: 540 });
  await page.getByRole("button", { name: "Report for case sessions-0", exact: true }).click();
  const scroll = page.getByTestId("case-report-scroll");
  await expect(scroll).toContainText("Jev evidence remains exact");
  expect(await scroll.evaluate((node) => node.scrollHeight > node.clientHeight)).toBe(true);
  await scroll.evaluate((node) => { node.scrollTop = node.scrollHeight; });
  const dialog = page.getByRole("dialog");
  await expectSelectSpacing(dialog.locator("select:visible"));
  await expect(dialog.getByRole("button", { name: "Download HTML" })).toBeInViewport();
  await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
});

test("unavailable and malformed case responses never appear as an empty successful board", async ({ page }) => {
  const { state } = await mockCases(page);
  state.failRead = true;
  await page.goto("/user-risk?view=cases");
  await expect(page.locator("main").getByRole("alert")).toContainText("Cases unavailable");
  await expect(page.getByRole("list", { name: "Sessions cases" })).toHaveCount(0);
  state.failRead = false; state.malformed = true;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("did not return complete risk case data");
  state.malformed = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByRole("list", { name: "Sessions cases" }).locator("li")).toHaveCount(5);
  await page.getByText("Policy findings and user totals", { exact: true }).click();
  await expect(page.getByText("No user findings to summarize", { exact: true })).toBeVisible();
});

test("activity snapshots distinguish preparation, refresh failures, and saved results", async ({ page }, info) => {
  await page.clock.install();
  const { state } = await mockCases(page);
  state.snapshot = "pending";
  await page.goto("/user-risk");
  await expect(page.getByText("Preparing activity rankings…", { exact: true })).toBeVisible();
  await expect(page.getByText("No matching sessions", { exact: true })).toHaveCount(0);
  await expect(page.getByRole("list", { name: "Session cases by outcome totals" })).toBeVisible();
  state.snapshot = "unavailable";
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(page.getByText("Activity rankings are unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("The first update failed. It will retry automatically.", { exact: true })).toBeVisible();
  await expect(page.getByText("No matching sessions", { exact: true })).toHaveCount(0);
  state.snapshot = "current";
  await page.clock.fastForward(15000);
  const sessions = page.getByRole("list", { name: "Top sessions by observed risk" });
  await expect(sessions.locator("li")).toHaveCount(5);
  await expect(page.getByText(/Activity updated .*Activity rankings update every 15 minutes/)).toBeVisible();
  await expect(page.getByText("Activity rankings are unavailable", { exact: true })).toHaveCount(0);
  state.snapshot = "stale";
  await page.getByRole("button", { name: "Refresh activity", exact: true }).click();
  await expect(page.getByText("Activity rankings are out of date", { exact: true })).toBeVisible();
  await expect(page.getByText("The latest update failed. Showing the last successful rankings.", { exact: true })).toBeVisible();
  await expect(sessions.locator("li")).toHaveCount(5);
  await page.getByLabel("Search activity", { exact: true }).fill("jordan");
  await page.clock.fastForward(300);
  await expect(sessions.locator("li")).toHaveCount(2);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.getByText("Activity rankings are out of date", { exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`activity-snapshot-${width}.png`), fullPage: true, animations: "disabled" });
  }
  await page.getByRole("button", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("list", { name: "Sessions cases", exact: true })).toBeVisible();
  await expect(page.getByText("Activity rankings are out of date", { exact: true })).toHaveCount(0);
});
