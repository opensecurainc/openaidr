import { test, expect, type Page } from "@playwright/test";
import { historyFixture } from "./fixtures/guardrail-history";
import { activityFixture } from "./fixtures/activity-flow";
import { expectPublicNames } from "./public-names";
import type { Policy } from "../src/components/fixed-rules";
import type { RuleDraft } from "../src/components/fixed-rule-editor";

const user = {
  id: "u",
  name: "Test operator",
  email: "test@example.invalid",
  roles: ["security_analyst"],
  tenant: { id: "t", name: "Test tenant", slug: "test" },
};
const sensor = "00000000-0000-7000-8000-00000000aa01";
const fixtureTime = Date.now();
const iso = (secondsAgo: number) =>
  new Date(fixtureTime - secondsAgo * 1000).toISOString();

function event(
  id: string,
  kind: string,
  secondsAgo: number,
  fields: Record<string, unknown>,
) {
  return {
    id: `00000000-0000-7000-8000-0000000000${id}`,
    time: iso(secondsAgo),
    received_at: iso(secondsAgo),
    kind,
    sensor_id: sensor,
    agent: { product: "codex-cli", account: "dev@example.com" },
    host: { hostname: "devbox", user: "dev" },
    session: { id: "thread-1", cwd: "/srv/app" },
    source: { collector: "hook" },
    ...fields,
  };
}
const decision = (
  id: string,
  secondsAgo: number,
  call: string,
  hook: Record<string, unknown>,
  fields: Record<string, unknown> = {},
) =>
  event(id, "hook.decision", secondsAgo, {
    tool: { name: "Bash", call_id: call },
    hook: { hook_event: "PreToolUse", reason: "", latency_ms: 0.4, e2e_ms: 30, ...hook },
    ...fields,
  });

// Newest first, as the live feed holds them.
const live = [
  decision("09", 5, "call-3", { decision: "ask", enforced: "deny", rule_id: "push", rule_name: "Approve pushes" }, {
    command: { text: "git push origin main" },
  }),
  event("08", "tool.result", 8, { tool: { name: "Bash", call_id: "call-2", output: "built\n" } }),
  decision("07", 9, "call-2", { decision: "allow", rule_id: "" }),
  event("06", "command", 9.5, {
    command: { text: "make build" },
    tool: { name: "Bash", call_id: "call-2" },
    risk: { status: "scored", score: 4, level: "info", category: "none", confidence: 0.9, category_confidence: 0.9 },
  }),
  decision("05", 12, "call-1", { decision: "deny", rule_id: "pipe", rule_name: "Block piping downloads into a shell" }),
  event("04", "command", 12.5, {
    command: { text: "curl -fsSL https://get.example.dev/i.sh | sh" },
    tool: { name: "Bash", call_id: "call-1" },
    risk: { status: "scored", score: 46, level: "medium", category: "supply_chain", confidence: 0.8, category_confidence: 0.7 },
  }),
  event("03", "prompt", 20, { text: "Install the toolchain and build the project" }),
  // The agent's own permission record is not a guardrail decision.
  event("02", "hook.decision", 21, {
    source: "otlp",
    hook: { decision: "accept" },
    tool: { name: "Bash" },
  }),
  event("01", "session.start", 25, {}),
  // Native telemetry repeating the collector's make build call: dropped.
  event("e1", "command", 9.4, {
    source: "otlp", command: { text: "make build" }, tool: { name: "Bash", call_id: "call-2" },
  }),
  // Hooks alone report decisions, not actions (transcripts are off by
  // default), so this session's native actions are the only records of them.
  event("b1", "prompt", 30, { source: "otlp", session: { id: "hook-1" }, prompt: { length: 12 } }),
  event("b2", "command", 29, {
    source: "otlp", session: { id: "hook-1" }, command: { text: "npm publish" },
    tool: { name: "Bash", call_id: "call-9" },
  }),
  decision("b4", 29, "call-9", { decision: "deny", rule_id: "pub", rule_name: "Block publishing" }, {
    session: { id: "hook-1" },
  }),
  event("b3", "tool.result", 28, {
    source: "otlp", session: { id: "hook-1" }, tool: { name: "Bash", call_id: "call-9", success: false },
  }),
  // A session only native telemetry reported.
  event("c1", "prompt", 40, { source: "otlp", session: { id: "native-1" }, prompt: { length: 5 } }),
].sort((a, b) => (a.received_at < b.received_at ? 1 : -1));

const active = {
  since: iso(300),
  until: iso(0),
  users: 1,
  sessions: 1,
  prompts: 1,
  tool_calls: 3,
  tool_results: 1,
  decisions: 3,
  allow: 1,
  warn: 0,
  ask: 0,
  deny: 2,
  labels: [{ category: "supply_chain", level: "medium", count: 1 }],
  jev: {
    calls: 4, pending_calls: 1, failed_calls: 1, priced_calls: 2,
    cost_usd: 0.0032, latency_samples: 3, latency_p95_ms: 1820,
  },
};

const latency = (p50: number | null) => ({
  e2e_p50: p50, e2e_p95: p50 && p50 * 2, e2e_p99: p50 && p50 * 3,
  policy_p50: p50 && 0.5, policy_p95: p50 && 1, policy_p99: p50 && 2,
});
function stats(range: string) {
  const [count, bucket] = ({ "1h": [60, 60], "24h": [24, 3600], "7d": [28, 21600], "30d": [30, 86400] })[range] || [24, 3600];
  const since = Date.now() - count * bucket * 1000;
  return {
    source: "endpoints",
    range,
    since: new Date(since).toISOString(),
    until: iso(0),
    bucket_seconds: bucket,
    executions: { total: 400, failed: 8 },
    totals: { total: 200, allow: 150, warn: 10, ask: 15, deny: 25, legacy: 4, ...latency(250) },
    series: Array.from({ length: count }, (_, i) => ({
      start: new Date(since + i * bucket * 1000).toISOString(),
      executions: i % 4 ? { total: 10, failed: i % 4 === 1 ? 0 : 2 } : { total: 0, failed: 0 },
      ...(i % 3
        ? { total: 10, allow: 7, warn: 1, ask: 1, deny: 1, ...latency(200 + i) }
        : { total: 0, allow: 0, warn: 0, ask: 0, deny: 0, ...latency(null) }),
    })),
    rules: [
      { rule_id: "", rule_name: "", action: "deny", in_policy: false, total: 150, allow: 140, warn: 0, ask: 0, deny: 10, last_seen_at: iso(10), ...latency(240) },
      { rule_id: "push", rule_name: "Approve pushes", action: "ask", in_policy: true, total: 30, allow: 10, warn: 0, ask: 15, deny: 5, last_seen_at: iso(60), ...latency(260) },
      { rule_id: "gone", rule_name: "Old rule", action: "warn", in_policy: false, total: 20, allow: 0, warn: 10, ask: 0, deny: 10, last_seen_at: iso(600), ...latency(280) },
    ],
  };
}

function completedChecks(items: typeof live) {
  return items.filter((item) => item.kind !== "hook.decision" && item.kind !== "session.start" && (item.source as unknown) !== "otlp").map((item) => {
    const data = item as typeof item & { risk?: Record<string, unknown>; host?: { user?: string; hostname?: string }; tool?: { call_id?: string } };
    return {
      id: item.id, created_at: item.time, sensor_id: item.sensor_id,
      sensor_hostname: data.host?.hostname || "", sensor_username: data.host?.user || "",
      product: item.agent.product, session_id: item.session.id,
      hook_event: item.kind === "prompt" ? "UserPromptSubmit" : item.kind === "tool.result" ? "PostToolUse" : "PreToolUse",
      actions: [item], mode: "shadow", status: "evaluated", evaluated_decision: "allow",
      returned_decision: "allow", delivery_status: "unconfirmed", delivered_decision: null,
      assessment: data.risk?.status === "scored" ? data.risk : { status: "scored", score: 0, level: "info", category: "none" },
      reason: "", rule_name: "", failure_reason: "",
    };
  });
}

async function mockApi(
  page: Page,
  options: {
    roles?: string[];
    hookSettings?: () => Record<string, unknown>;
    saveHookSettings?: (body: Record<string, unknown>) => Promise<{ status?: number; json: unknown }>;
    classified?: (cursor: string) => Record<string, unknown>[] | Promise<Record<string, unknown>[]>;
    nextCursor?: () => string;
    failChecks?: () => boolean;
    failStats?: () => boolean;
    failLive?: () => boolean;
    ranges?: string[];
    initial?: typeof live;
    arrivals?: () => typeof live;
    risks?: () => { id: string; risk: Record<string, unknown> }[] | Promise<{ id: string; risk: Record<string, unknown> }[]>;
    active?: () => Record<string, unknown>;
    statistics?: (range: string) => Parameters<typeof historyFixture>[0];
  } = {},
) {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({ json: { user: { ...user, roles: options.roles || user.roles } } });
    if (url.pathname.endsWith("telemetry/overview"))
      return route.fulfill({ json: { service: null, generated_at: iso(0), devices: [] } });
    if (url.pathname.endsWith("response/hook-settings")) {
      if (route.request().method() === "PUT" && options.saveHookSettings)
        return route.fulfill(await options.saveHookSettings(route.request().postDataJSON()));
      return route.fulfill({ json: options.hookSettings?.() || { mode: "shadow", version: 0, updated_at: null } });
    }
    if (url.pathname.endsWith("response/policy"))
      return route.fulfill({ json: { version: 0, rules: [] } });
    if (url.pathname.endsWith("guardrail/flow")) {
      if (options.failChecks?.()) return route.fulfill({ status: 503, json: { error: { message: "Completed checks unavailable" } } });
      const records = await options.classified?.("") || completedChecks(options.initial || live);
      return route.fulfill({ json: activityFixture(records, url.searchParams).summary });
    }
    if (url.pathname.endsWith("guardrail/checks")) {
      if (options.failChecks?.()) return route.fulfill({ status: 503, json: { error: { message: "Completed checks unavailable" } } });
      const records = await options.classified?.(url.searchParams.get("cursor") || "") || completedChecks(options.initial || live);
      const source = url.searchParams.get("source") || "all";
      const items = url.searchParams.has("range") ? activityFixture(records, url.searchParams).checks : records.filter((record) => source === "all" || (source === "gateways" ? record.source === "gateway" : record.source !== "gateway"));
      return route.fulfill({ json: { items, next_cursor: options.nextCursor?.() || "" } });
    }
    if (url.pathname.endsWith("events/live")) {
      if (options.failLive?.()) return route.fulfill({ status: 503, json: { error: { message: "Live events unavailable" } } });
      const after = url.searchParams.get("after");
      return route.fulfill({
        json: {
          items: after ? options.arrivals?.() || [] : options.initial || live,
          cursor: "c1",
          more: false,
        },
      });
    }
    if (url.pathname.endsWith("guardrail/active"))
      return route.fulfill({ json: options.active?.() || active });
    if (url.pathname.endsWith("events/risks"))
      return route.fulfill({ json: { items: await options.risks?.() || [] } });
    if (url.pathname.endsWith("guardrail/stats")) {
      const range = url.searchParams.get("range") || "24h";
      options.ranges?.push(range);
      if (options.failStats?.())
        return route.fulfill({
          status: 503,
          json: { error: { message: "Statistics unavailable" } },
        });
      return route.fulfill({ json: historyFixture(options.statistics?.(range) || stats(range), url.searchParams.get("source") === "endpoints" ? "endpoints" : "all") });
    }
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

test("live activity sits below the flow with independent filters and pause controls", async ({ page }, info) => {
  const records = completedChecks(live).slice(0, 3);
  let arrivals: typeof live = [];
  await mockApi(page, { classified: () => records, arrivals: () => arrivals });
  await page.goto("/guardrail/live");
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  const flow = page.getByRole("region", { name: "Activity flow", exact: true });
  const feed = page.getByRole("region", { name: "Live agent activity" });
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  const detail = feed.getByRole("article");
  await expect(flow).toContainText("3 matching checks");
  await expect(flow.getByLabel("Guardrail measurements")).not.toContainText("USD");
  await expect(flow.getByRole("button", { name: "Guardrail cost details" })).toHaveCount(0);
  await expect(detail).toContainText("Install the toolchain and build the project");
  expect((await feed.boundingBox())!.y).toBeGreaterThanOrEqual((await flow.boundingBox())!.y + (await flow.boundingBox())!.height);
  expect((await actions.boundingBox())!.y).toBeGreaterThanOrEqual((await feed.boundingBox())!.y + (await feed.boundingBox())!.height);
  const nav = page.getByRole("navigation", { name: "Workspace navigation" });
  await expect(nav.getByRole("link", { name: "Live Activity", exact: true })).toHaveCount(0);
  await expect(nav.getByRole("link", { name: "Live Guardrail", exact: true })).toHaveAttribute("aria-current", "page");

  await feed.getByRole("button", { name: "Prompt", exact: true }).click();
  await expect(detail.locator('[data-category="tool"]')).toHaveCount(0);
  await expect(actions.getByRole("row")).toHaveCount(4);
  await feed.getByRole("button", { name: "Show all kinds" }).click();

  await flow.getByRole("button", { name: "Pause view" }).click();
  records.push({ ...records[0], id: "new-check", created_at: iso(0) });
  arrivals = [event("f1", "response", 0, { text: "Live response while checks are paused" })];
  await expect(detail).toContainText("Live response while checks are paused");
  await expect(flow).toContainText("3 matching checks");
  await expect(actions.getByRole("row")).toHaveCount(4);

  await feed.getByRole("button", { name: "Pause live updates" }).click();
  await flow.getByRole("button", { name: "Resume live" }).click();
  arrivals = [event("f2", "response", 0, { text: "Response after resuming the timeline" })];
  await expect(flow).toContainText("4 matching checks");
  await expect(actions.getByRole("row")).toHaveCount(5);
  await expect(detail).not.toContainText("Response after resuming the timeline");
  await feed.getByRole("button", { name: "Resume live updates" }).click();
  await expect(detail).toContainText("Response after resuming the timeline");
  await feed.getByRole("button", { name: "Pause live updates" }).click();

  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await expect(feed.getByRole("link", { name: "Explore evidence" })).toBeVisible();
    if (viewport.width < 1024) {
      await feed.getByRole("navigation", { name: "Sessions" }).getByRole("button").first().click();
      await expect(detail).toBeVisible();
      await feed.getByRole("button", { name: "Sessions", exact: true }).click();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(viewport.width);
    await feed.screenshot({ path: info.outputPath(`guardrail-live-activity-${viewport.width}.png`), animations: "disabled" });
  }
});

test("actions show completed prompt, call, result and explicit failures before delivery receipts", async ({ page }, info) => {
  const records = completedChecks(live).slice(0, 4);
  let shown: Record<string, unknown>[] = [];
  await mockApi(page, { classified: () => shown });
  await page.goto("/guardrail/live");
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  await expect(actions.getByText("No matching checks", { exact: true })).toBeVisible();
  // The telemetry feed already has actions, but no unfinished decision row appears.
  await expect(actions.getByRole("row")).toHaveCount(0);
  shown = records;
  await expect(actions.getByRole("row")).toHaveCount(5);
  await expect(actions.getByText("Delivery not confirmed", { exact: true })).toHaveCount(4);
  await expect(actions.getByText("Not recorded", { exact: true })).toHaveCount(0);
  await expect(actions.getByText("Risk not assessed", { exact: true })).toHaveCount(0);
  await actions.getByRole("combobox", { name: "Action type" }).click();
  await page.getByRole("option", { name: "Prompt", exact: true }).click();
  await expect(actions.getByRole("row")).toHaveCount(2);
  await expect(actions.getByRole("row").last()).toContainText("Allow · Shadow");
  await actions.getByRole("combobox", { name: "Action type" }).click();
  await page.getByRole("option", { name: "All actions" }).click();
  await page.getByRole("region", { name: "Activity flow", exact: true }).getByRole("button", { name: "Pause view", exact: true }).click();
  shown = [...records, { ...records[0], id: "failed", status: "unavailable", evaluated_decision: null,
    returned_decision: null, assessment: { status: "unavailable", reason: "timeout" }, failure_reason: "timeout" }];
  await page.getByRole("region", { name: "Activity flow", exact: true }).getByRole("button", { name: "Resume live", exact: true }).click();
  await expect(actions.getByRole("row")).toHaveCount(6);
  await expect(actions.getByText("Check failed · allowed", { exact: true })).toBeVisible();
  await expect(actions.getByText("Classification timed out").first()).toBeVisible();
  await page.screenshot({ path: info.outputPath("classified-actions-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  await expectPublicNames(page);
});

test.describe("in a browser outside UTC", () => {
  test.use({ timezoneId: "America/Los_Angeles", hasTouch: true });
test("guardrail history combines decision rates with counts, latency, and execution trends", async ({ page }, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const ranges: string[] = [];
  let fail = false;
  let missingSeries = false;
  let executions: { total: number; failed: number } | undefined = { total: 400, failed: 8 };
  await mockApi(page, { ranges, failStats: () => fail, statistics: (range) => {
    const data = stats(range);
    return { ...data, executions, series: data.series.map((row) => ({
      ...row, executions: missingSeries ? undefined : executions?.total ? row.executions : { total: 0, failed: 0 },
    })) };
  } });
  await page.setViewportSize({ width: 1600, height: 1080 });
  await page.goto("/guardrail/history?source=endpoints");
  await expect(page.locator("main")).toContainText("Review endpoint and gateway checks");
  await expect(page.locator("main")).not.toContainText(/legacy hooks?|managed.session/i);
  const historicalNotice = page.locator("aside").filter({ hasText: "Older records excluded from rates and latency" });
  await expect(historicalNotice).toContainText("4 decisions in this range came from sensors that recorded only matched rules.");
  await expect(historicalNotice).toContainText("They are left out of rates and latency.");
  await expect(page.locator("main")).not.toContainText("Some sensors need an update");
  await historicalNotice.screenshot({ path: info.outputPath("older-hook-records-notice.png"), animations: "disabled" });
  await page.getByText("Guardrail analytics", { exact: true }).click();
  await expect(page.getByText("Source filters all four charts.", { exact: false })).toBeVisible();
  await page.getByText("Guardrail analytics", { exact: true }).click();
  const metrics = page.getByRole("region", { name: "Guardrail metrics over time", exact: true });
  await expect(metrics.getByRole("region")).toHaveCount(4);
  await expect(metrics.getByRole("table")).toHaveCount(0);
  await expect(page.getByRole("tab", { name: "Data table" })).toHaveCount(0);
  await expect(page.getByTestId("stat-total")).toHaveText("200");
  await expect(metrics.getByText("Completed policy evaluations", { exact: true })).toBeVisible();
  await expect(metrics).not.toContainText(/checked calls|checked tool calls|\d+ calls/);
  await expect(page.getByTestId("stat-allow")).toHaveText("80%");
  await expect(metrics.getByText("160 checks", { exact: true })).toBeVisible();
  await expect(metrics.getByText("5.0% of evaluated checks have a warning")).toBeVisible();
  await expect(metrics.getByText("Evaluated decisions. Shadow mode allows all calls.")).toBeVisible();
  await expect(page.getByTestId("stat-ask")).toHaveText("7.5%");
  await expect(page.getByTestId("stat-deny")).toHaveText("13%");
  await expect(page.getByTestId("stat-latency")).toHaveText("250 ms");
  await expect(page.getByTestId("stat-failure")).toHaveText("2.0%");
  await expect(page.getByText("8 failures / 400 recorded attempts")).toBeVisible();
  await expect(page.getByText("p95 500 ms · p99 750 ms")).toBeVisible();
  await expect(page.getByText("4 decisions in this range came from sensors")).toBeVisible();
  await expect(metrics.getByRole("application")).toHaveCount(4);
  const plots = await metrics.getByRole("application").all();
  const tooltips = metrics.locator(".recharts-tooltip-wrapper");
  const expectSyncedReadouts = async (source: number) => {
    await expect(tooltips.nth(source)).toBeVisible();
    const timestamp = await tooltips.nth(source).locator("p").textContent();
    expect(timestamp).toBeTruthy();
    await expect(tooltips.locator("p")).toHaveText(Array(4).fill(timestamp));
    for (const tooltip of await tooltips.all()) await expect(tooltip).toBeVisible();
    await expect(metrics.locator(".recharts-tooltip-cursor")).toHaveCount(4);
  };
  const positions = await Promise.all(plots.map(async (plot) => (await plot.boundingBox())!.y));
  expect(Math.max(...positions) - Math.min(...positions)).toBeLessThanOrEqual(1);
  await page.screenshot({ path: info.outputPath("hook-metrics-desktop.png"), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.screenshot({ path: info.outputPath("hook-history-desktop.png"), animations: "disabled" });
  await page.setViewportSize({ width: 1600, height: 1080 });
  // Wait for ResizeObserver to update every SVG before sending keyboard input.
  await expect.poll(() => metrics.getByRole("application").evaluateAll((charts) => charts.every((chart) =>
    Math.abs(chart.getBoundingClientRect().width - chart.closest(".recharts-responsive-container")!.getBoundingClientRect().width) <= 1,
  ))).toBe(true);

  const rate = page.getByRole("application", { name: "Policy decision rates over time" });
  await expect(rate.getByText("0%", { exact: true })).toBeVisible();
  await expect(rate.getByText("100%", { exact: true })).toBeVisible();
  await rate.focus();
  await page.keyboard.press("ArrowLeft");
  const rateTooltip = metrics.getByRole("region", { name: "Policy decision rates", exact: true }).locator(".recharts-tooltip-wrapper");
  await expect(rateTooltip).toContainText("No data");
  await expectSyncedReadouts(1);
  await page.keyboard.press("ArrowRight");
  await expect(rateTooltip.getByRole("listitem").filter({ hasText: "Allow" })).toContainText("80%");
  await expect(rateTooltip.getByRole("listitem").filter({ hasText: "Ask" })).toContainText("10%");
  await expect(rateTooltip.getByRole("listitem").filter({ hasText: "Deny" })).toContainText("10%");
  await expectSyncedReadouts(1);

  const failure = page.getByRole("application", { name: "Failure rate over time" });
  await failure.focus();
  await page.keyboard.press("ArrowLeft");
  const failureTooltip = metrics.getByRole("region", { name: "Failure rate", exact: true }).locator(".recharts-tooltip-wrapper");
  await expect(failureTooltip).toContainText("No data");
  await page.keyboard.press("ArrowRight");
  await expect(failureTooltip).toContainText("0.0%");
  await page.keyboard.press("ArrowRight");
  await expect(failureTooltip).toContainText("20%");
  await expectSyncedReadouts(3);
  const latencyChart = page.getByRole("application", { name: "End-to-end latency over time" });
  const latencyCard = metrics.getByRole("region", { name: "End-to-end latency, p50", exact: true });
  await expect(latencyCard.getByText("p50 to p95", { exact: true })).toBeVisible();
  await expect(latencyCard.getByText("p95 to p99", { exact: true })).toBeVisible();
  await expect(latencyChart.locator(".recharts-area-area")).toHaveCount(2);
  await expect(rate.locator(".recharts-area-area")).toHaveCount(0);
  await expect(failure.locator(".recharts-area-area")).toHaveCount(0);
  await latencyChart.focus();
  await page.keyboard.press("ArrowRight");
  await expect(metrics.getByRole("region", { name: "End-to-end latency, p50", exact: true }).locator(".recharts-tooltip-wrapper")).toContainText("p99");
  await expectSyncedReadouts(2);
  for (const [index, plot] of plots.entries()) {
    const previousTimestamp = (await tooltips.nth(index).locator("p").textContent())!;
    const bounds = (await plot.locator(".recharts-cartesian-grid").boundingBox())!;
    await page.mouse.move(bounds.x + bounds.width * (0.25 + index * 0.15), bounds.y + bounds.height / 2);
    await expect(tooltips.nth(index).locator("p")).not.toHaveText(previousTimestamp);
    await expectSyncedReadouts(index);
  }
  await page.screenshot({ path: info.outputPath("hook-metrics-synchronized.png"), fullPage: true });
  await page.mouse.move(0, 0);
  for (const tooltip of await tooltips.all()) await expect(tooltip).not.toBeVisible();

  const rules = page.getByRole("region", { name: "Endpoint decisions by rule", exact: true }).getByRole("row");
  await expect(rules).toHaveCount(4);
  await expect(rules.getByRole("columnheader", { name: "Checks", exact: true })).toBeVisible();
  await expect(page.getByText("The model can restrict a check even when no fixed rule matches.", { exact: false })).toBeVisible();
  const unmatched = rules.filter({ hasText: "No rule matched" });
  await expect(unmatched.getByRole("cell").nth(1)).toHaveText("No fixed rule");
  await expect(unmatched.getByRole("cell").nth(4)).toHaveText("140");
  await expect(unmatched.getByRole("cell").nth(7)).toHaveText("10");
  await expect(rules.filter({ hasText: "Approve pushes" })).toContainText("15%");
  await expect(rules.filter({ hasText: "Old rule" })).toContainText("No longer in the policy");
  await page.getByRole("radio", { name: "UTC", exact: true }).check();
  await rate.focus();
  await page.keyboard.press("ArrowRight");
  await expect(rateTooltip).toContainText("UTC");
  await expectSyncedReadouts(1);
  const control = page.getByRole("group", { name: "Time range", exact: true });
  for (const [label, value] of [["Last hour", "1h"], ["Last 7 days", "7d"], ["Last 30 days", "30d"]]) {
    await control.getByRole("radio", { name: label, exact: true }).check();
    await expect.poll(() => ranges.at(-1)).toBe(value);
    await expect(metrics.getByRole("application")).toHaveCount(4);
  }
  await control.getByRole("radio", { name: "Last hour", exact: true }).focus();
  await page.keyboard.press("ArrowRight");
  await expect(control.getByRole("radio", { name: "Last 24 hours", exact: true })).toBeChecked();
  await expect.poll(() => ranges.at(-1)).toBe("24h");

  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    const bounds = (await control.boundingBox())!;
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(width);
  }
  await page.setViewportSize({ width: 390, height: 900 });
  await page.screenshot({ path: info.outputPath("hook-metrics-mobile.png"), fullPage: true });
  await historicalNotice.screenshot({ path: info.outputPath("older-hook-records-notice-mobile.png"), animations: "disabled" });
  await rate.scrollIntoViewIfNeeded();
  const touchPlot = (await rate.boundingBox())!;
  await page.touchscreen.tap(touchPlot.x + 90, touchPlot.y + touchPlot.height / 2);
  await expect(rateTooltip).toBeVisible();
  await expect(rateTooltip).toContainText("Ask");
  await expectSyncedReadouts(1);
  await latencyChart.scrollIntoViewIfNeeded();
  const latencyBounds = (await latencyChart.boundingBox())!;
  await page.touchscreen.tap(latencyBounds.x + 90, latencyBounds.y + latencyBounds.height / 2);
  await expect(latencyCard.locator(".recharts-tooltip-wrapper")).toContainText("p99");
  await expectSyncedReadouts(2);
  missingSeries = true;
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(page.getByTestId("stat-failure")).toHaveText("2.0%");
  await expect(metrics.getByText("Trend not recorded", { exact: true })).toBeVisible();
  for (const empty of [undefined, { total: 0, failed: 0 }]) {
    executions = empty;
    await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
    await expect(page.getByTestId("stat-failure")).toHaveText("Not recorded");
  }
  executions = { total: 40, failed: 0 };
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(page.getByTestId("stat-failure")).toHaveText("0.0%");
  fail = true;
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Statistics unavailable" })).toBeVisible();
  await expect(page.getByTestId("stat-total")).toHaveText("200");
  expect(errors).toEqual([]);
});

test("policy rates keep rare Shadow-mode denials visible without rounding allow to 100%", async ({ page }, info) => {
  let denied = 12;
  await mockApi(page, { statistics: (range) => {
    const data = stats(range);
    const counts = { total: 18340, allow: 18335 - denied, warn: 5, ask: 0, deny: denied };
    return { ...data, totals: { ...data.totals, ...counts, legacy: 0 },
      series: data.series.map((row) => ({ ...row, ...counts })) };
  } });
  await page.goto("/guardrail/history?source=endpoints");
  const rates = page.getByRole("region", { name: "Policy decision rates", exact: true });
  await expect(rates.getByTestId("stat-allow")).toHaveText(">99.9%");
  await expect(rates.getByTestId("stat-deny")).toHaveText("<0.1%");
  await expect(rates.getByText("12 checks", { exact: true })).toBeVisible();
  await expect(rates.getByText("<0.1% of evaluated checks have a warning")).toBeVisible();
  await expect(rates.getByText("Evaluated decisions. Shadow mode allows all calls.")).toBeVisible();
  for (const width of [1600, 320, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await rates.scrollIntoViewIfNeeded();
    for (const key of ["allow", "ask", "deny"]) {
      await expect.poll(() => rates.getByTestId(`stat-${key}`).evaluate((value) => value.scrollWidth - value.clientWidth)).toBeLessThanOrEqual(0);
    }
    await expect.poll(() => rates.evaluate((card) => card.scrollWidth - card.clientWidth)).toBeLessThanOrEqual(0);
  }
  await rates.screenshot({ path: info.outputPath("evaluated-decision-rates.png"), style: "nextjs-portal { visibility: hidden; }" });
  denied = 20;
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(rates.getByTestId("stat-allow")).toHaveText("99.9%");
  denied = 0;
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(rates.getByTestId("stat-allow")).toHaveText("100%");
  await expect(rates.getByTestId("stat-deny")).toHaveText("0.0%");
});

test("latency bands follow percentile bounds and preserve missing, zero, and isolated samples", async ({ page }, info) => {
  await mockApi(page, { statistics: (range) => {
    const data = stats(range);
    const samples = [null, 200, 300, null, 0, 100, null, 150, 225, null];
    const since = Date.parse("2026-10-08T23:58:00Z");
    return {
      ...data, since: new Date(since).toISOString(), until: new Date(since + samples.length * 60_000).toISOString(), bucket_seconds: 60,
      series: samples.map((value, i) => ({
        ...data.series[i], start: new Date(since + i * 60_000).toISOString(), ...latency(value),
        ...(i === 8 ? { e2e_p95: null } : {}),
      })),
    };
  } });
  await page.goto("/guardrail/history?source=endpoints");
  const card = page.getByRole("region", { name: "End-to-end latency, p50", exact: true });
  const chart = card.getByRole("application");
  const areas = chart.locator(".recharts-area-area");
  await expect(areas).toHaveCount(2);
  const lines = chart.locator(".recharts-line-curve");
  // Each filled polygon must follow its two observed percentile boundaries,
  // with separate subpaths across gaps, including a zero-valued interval.
  const points = (path: string) => [...path.matchAll(/[ML]([\d.]+),([\d.]+)/g)].map((match) => `${match[1]},${match[2]}`).sort();
  const first = (path: string) => path.split(/(?=M)/)[0];
  for (let i = 0; i < 2; i++) {
    const area = (await areas.nth(i).getAttribute("d"))!;
    expect(area.match(/M/g)).toHaveLength(3);
    const lower = (await lines.nth(i).getAttribute("d"))!;
    const upper = (await lines.nth(i + 1).getAttribute("d"))!;
    expect(points(first(area))).toEqual([...points(first(lower)), ...points(first(upper))].sort());
    expect(area).not.toMatch(/[CQ]/);
  }
  await chart.focus();
  await page.keyboard.press("ArrowLeft");
  const tooltip = card.locator(".recharts-tooltip-wrapper");
  await expect(tooltip.getByText("No data", { exact: true })).toHaveCount(3);
  for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight");
  await expect(tooltip.getByText("0.0 ms", { exact: true })).toHaveCount(3);
  for (let i = 0; i < 4; i++) await page.keyboard.press("ArrowRight");
  await expect(tooltip.getByRole("listitem").filter({ hasText: "p95" })).toContainText("No data");
  await expect(tooltip.getByRole("listitem").filter({ hasText: "p50" })).toContainText("225 ms");
  await page.screenshot({ path: info.outputPath("latency-bands-gaps.png"), fullPage: true });
});

test("execution failures remain visible without decisions and missing latency is explicit", async ({ page }) => {
  await mockApi(page, { statistics: (range) => {
    const data = stats(range);
    const empty = { total: 0, allow: 0, ask: 0, deny: 0, warn: 0, ...latency(null) };
    return { ...data, totals: { ...data.totals, ...empty, legacy: 0 }, rules: [],
      series: data.series.map((row) => ({ ...row, ...empty })) };
  } });
  await page.goto("/guardrail/history?source=endpoints");
  await expect(page.getByTestId("stat-total")).toHaveText("0");
  await expect(page.getByTestId("stat-allow")).toHaveText("No data");
  await expect(page.getByTestId("stat-latency")).toHaveText("No samples");
  await expect(page.getByText("No latency samples", { exact: true })).toBeVisible();
  await expect(page.getByRole("application", { name: "Failure rate over time" })).toBeVisible();
  await expect(page.getByRole("application", { name: "Policy decision rates over time" })).toHaveCount(0);
  await page.setViewportSize({ width: 320, height: 900 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
});
});

test("Guardrail Configuration saves confirmed modes and Live Guardrail keeps one Actions table with expandable decision details", async ({ page }, info) => {
  let settings = { mode: "shadow", version: 0, updated_at: null as string | null };
  let releaseSave: () => void = () => {};
  const waiting = new Promise<void>((resolve) => { releaseSave = resolve; });
  const saved: Record<string, unknown>[] = [];
  const record = {
    ...completedChecks(live)[0],
    id: "h1", sensor_hostname: "devbox", product: "codex-cli", hook_event: "PreToolUse",
    session_id: "thread-1", mode: "shadow", status: "evaluated", evaluated_decision: "deny",
    returned_decision: "allow", reason: "Jev deployment requires approval", rule_name: "", failure_reason: "",
    actions: [{ kind: "command", command: { text: "npm publish" }, tool: { name: "Bash" } }],
    created_at: iso(10), delivery_status: "unconfirmed", delivered_decision: null,
  };
  await mockApi(page, {
    roles: ["security_analyst"], hookSettings: () => settings,
    saveHookSettings: async (body) => {
      saved.push(body);
      await waiting;
      settings = { mode: String(body.mode), version: settings.version + 1, updated_at: iso(0) };
      return { json: settings };
    },
    classified: () => [record, {
      ...record, id: "h2", mode: "enforce", returned_decision: "deny", reason: "Publishing restricted",
      delivery_status: "timed_out", delivered_decision: "allow",
    }, {
      ...record, id: "h3", status: "unavailable", evaluated_decision: null, returned_decision: null,
      reason: "", failure_reason: "capture_disabled", delivery_status: "failed", delivered_decision: "allow",
      actions: [], assessment: null,
    }, {
      ...record, id: "h4", reason: "", rule_name: "Jev restrictions",
    }, {
      ...record, id: "h5", mode: "enforce", returned_decision: "deny", reason: "Publishing restricted",
      delivery_status: "delivered", delivered_decision: "deny", failure_reason: "provider_unavailable",
      assessment: { status: "unavailable", reason: "provider_unavailable" },
    }],
  });
  await page.goto("/guardrail/configuration");
  const policy = page.getByRole("region", { name: "Hook policy", exact: true });
  const shadow = policy.getByRole("radio", { name: "Shadow", exact: true });
  const enforce = policy.getByRole("radio", { name: "Enforce", exact: true });
  await expect(shadow).toBeChecked();
  await expect(policy.getByText("In both modes, a failed check silently allows the action. Hooks wait at most 2 seconds.")).toBeVisible();
  await policy.getByText("Hook scope and delivery", { exact: true }).click();
  await expect(policy.getByText("Policy rules are evaluated by the backend. Local secret redaction is a separate module.")).toBeVisible();
  await expect(policy).not.toContainText(/legacy|managed.session|local policy/i);
  await policy.getByText("Hook scope and delivery", { exact: true }).click();
  // The selected mode remains the last server-confirmed mode while saving.
  await enforce.click();
  await expect(enforce).toBeDisabled();
  await expect(shadow).toBeChecked();
  releaseSave();
  await expect(enforce).toBeChecked();
  await expect(enforce).toBeEnabled();
  await shadow.click();
  await expect(shadow).toBeChecked();
  await expect(policy.getByText("Record decisions and allow actions.")).toBeVisible();
  expect(saved).toEqual([{ mode: "enforce", version: 0 }, { mode: "shadow", version: 1 }]);

  // Live Guardrail no longer carries the mode control; the mode is set on Guardrail Configuration.
  await page.goto("/guardrail/live");
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  await expect(page.getByRole("region", { name: "Activity flow", exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Hook policy", exact: true })).toHaveCount(0);
  await expect(page.getByRole("radio", { name: "Enforce", exact: true })).toHaveCount(0);
  await expect(page.getByRole("navigation", { name: "Live Guardrail view" })).toHaveCount(0);
  await expect(page.locator("iframe")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Backend hook decisions", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Refresh decisions", exact: true })).toHaveCount(0);
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  await expect(actions).toHaveCount(1);
  const shadowRow = actions.getByRole("row").filter({ hasText: "Jev deployment requires approval" });
  await expect(shadowRow.getByText("Deny · Shadow", { exact: true })).toBeVisible();
  await expect(shadowRow.getByText("Returned: Allow", { exact: true })).toBeVisible();
  await expect(shadowRow.getByText("Delivery not confirmed", { exact: true })).toBeVisible();
  const reason = shadowRow.getByText("Jev deployment requires approval", { exact: true });
  await expect(reason).not.toBeVisible();
  const details = shadowRow.getByText("Decision details", { exact: true });
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(reason).toBeVisible();
  await expect(shadowRow.locator("details time")).toHaveAttribute("datetime", record.created_at);
  await expect(actions.getByText("Timed out · allowed", { exact: true })).toBeVisible();
  await expect(actions.getByText("Check failed · allowed", { exact: true })).toBeVisible();
  await expect(actions.getByText("Content capture is disabled", { exact: true }).first()).toBeVisible();
  const namedRule = actions.getByRole("row").filter({ hasText: "Guardrail restrictions" });
  await namedRule.getByText("Decision details", { exact: true }).click();
  await expect(namedRule.getByText("Guardrail restrictions", { exact: true })).toBeVisible();
  const modelFailure = actions.getByRole("row").filter({ hasText: "Classification service unavailable" });
  await expect(modelFailure.getByText("Deny · Enforce", { exact: true })).toBeVisible();
  await expect(modelFailure.getByText("Response sent: Deny", { exact: true })).toBeVisible();
  await expect(modelFailure.getByText(/Risk \d/)).toHaveCount(0);
  await expect(actions.getByText("Blocked", { exact: true })).toHaveCount(0);
  await actions.screenshot({ path: info.outputPath("hook-actions-desktop.png") });
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  await actions.screenshot({ path: info.outputPath("hook-actions-mobile.png") });
});

test("inconclusive risk displays zero with assessment and policy failure details", async ({ page }, info) => {
  const record = {
    ...completedChecks(live)[0],
    hook_event: "UserPromptSubmit",
    assessment: { status: "unscored", category: "unknown", score: null, level: null },
    failure_reason: "insufficient_evidence",
    actions: [{ kind: "prompt", text: "Review the proposed change" }],
  };
  await mockApi(page, { classified: () => [record, {
    ...record, id: "rule-denial", hook_event: "PreToolUse", mode: "enforce", evaluated_decision: "deny", returned_decision: "deny",
    reason: "Publishing requires approval", actions: [{ kind: "command", command: { text: "npm publish" } }],
  }, {
    ...record, id: "failed-check", hook_event: "PreToolUse", status: "unavailable", evaluated_decision: null, returned_decision: null,
    assessment: null, failure_reason: "evaluation_unavailable", reason: "All policy workers were busy.",
    actions: [{ kind: "command", command: { text: "git status" } }],
  }, {
    ...record, id: "old-failed-check", hook_event: "PreToolUse", status: "unavailable", evaluated_decision: null, returned_decision: null,
    assessment: null, failure_reason: "evaluation_unavailable", reason: "",
    actions: [{ kind: "command", command: { text: "git diff" } }],
  }] });
  await page.goto("/guardrail/live");
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  const badges = actions.getByText("Risk 0/100 · Minimal", { exact: true });
  await expect(badges).toHaveCount(2);
  await expect(badges.first()).toHaveAttribute("data-variant", "informational");
  await expect(badges.first()).toHaveAttribute("title", /Insufficient evidence/);
  const explanation = "Insufficient evidence: the model assessment was inconclusive. Displayed as Risk 0/100 · Minimal.";
  for (const text of ["Review the proposed change", "npm publish"]) {
    const row = actions.getByRole("row").filter({ hasText: text });
    await expect(row.getByText(explanation, { exact: true })).not.toBeVisible();
    await row.getByText("Decision details", { exact: true }).click();
    await expect(row.getByText(explanation, { exact: true })).toBeVisible();
  }
  const denied = actions.getByRole("row").filter({ hasText: "npm publish" });
  await expect(denied.getByText("Deny · Enforce", { exact: true })).toBeVisible();
  await expect(denied.getByText("Publishing requires approval", { exact: true })).toBeVisible();
  await expect(denied.getByRole("cell").last().locator("svg")).toHaveCount(0);
  for (const [command, detail] of [
    ["git status", "All policy workers were busy."],
    ["git diff", "The cause of this policy evaluation failure was not recorded."],
  ]) {
    const row = actions.getByRole("row").filter({ hasText: command });
    await expect(row.getByText("Check failed · allowed", { exact: true })).toBeVisible();
    await expect(row.getByText(/Risk \d/)).toHaveCount(0);
    const label = row.getByRole("cell").last();
    await expect(label).toHaveText("Policy evaluation was unavailable");
    const icon = label.locator("svg");
    await expect(icon).toBeVisible();
    await expect(icon).toHaveAttribute("aria-hidden", "true");
    await expect(icon).toHaveCSS("color", "rgb(135, 36, 32)");
    await row.getByText("Decision details", { exact: true }).click();
    await expect(row.getByText(detail, { exact: true })).toBeVisible();
  }
  await actions.screenshot({ path: info.outputPath("assessment-details-desktop.png") });
  await page.setViewportSize({ width: 390, height: 900 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
  const table = actions.getByRole("region", { name: "Scrollable data table" });
  await table.evaluate((element) => { element.scrollLeft = element.scrollWidth; });
  await badges.first().scrollIntoViewIfNeeded();
  expect(await table.evaluate((element) => element.scrollLeft)).toBeGreaterThan(0);
  await expect(badges.first()).toBeInViewport();
  await actions.screenshot({ path: info.outputPath("assessment-details-mobile.png") });
});

test("hook policy handles stale settings and denied saves without claiming a mode change", async ({ page }) => {
  let settings = { mode: "shadow", version: 0, updated_at: null as string | null };
  let failLoad = false;
  await mockApi(page, {
    roles: ["security_analyst"], hookSettings: () => settings,
    saveHookSettings: async () => {
      settings = { mode: "enforce", version: 1, updated_at: iso(0) };
      return { status: 409, json: { error: { message: "Hook settings changed. Refresh and try again." } } };
    },
  });
  await page.goto("/guardrail/configuration");
  const policy = page.getByRole("region", { name: "Hook policy", exact: true });
  await policy.getByRole("radio", { name: "Enforce", exact: true }).click();
  await expect(policy.getByRole("alert")).toContainText("Hook settings changed");
  await expect(policy.getByRole("radio", { name: "Enforce", exact: true })).toBeChecked();
  await page.route("**/api/v1/response/hook-settings", (route) => {
    if (route.request().method() === "PUT")
      return route.fulfill({ status: 403, json: { error: { message: "Administrator access required" } } });
    return failLoad
      ? route.fulfill({ status: 503, json: { error: { message: "Settings unavailable" } } })
      : route.fulfill({ json: settings });
  });
  await policy.getByRole("radio", { name: "Shadow", exact: true }).click();
  await expect(policy.getByRole("alert")).toContainText("Administrator access required");
  await expect(policy.getByRole("radio", { name: "Enforce", exact: true })).toBeChecked();
  failLoad = true;
  await policy.getByRole("button", { name: "Refresh mode" }).click();
  await expect(policy.getByRole("radio", { name: "Shadow", exact: true })).toBeDisabled();
  await expect(policy.getByText("Enforce (last confirmed)")).toBeVisible();
});

test("Security Leadership cannot inspect or change hook mode", async ({ page }) => {
  await mockApi(page, { roles: ["security_leadership"] });
  await page.goto("/guardrail/live");
  const policy = page.getByRole("region", { name: "Hook policy", exact: true });
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(policy.getByRole("radio")).toHaveCount(0);
  await expect(policy).toHaveCount(0);
  await page.goto("/guardrail/configuration");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(page.locator("iframe")).toHaveCount(0);
});

test("Guardrail Configuration is not loaded before sign-in", async ({ page }) => {
  const previews: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/previews/")) previews.push(request.url());
  });
  await page.route("**/api/v1/auth/me", (route) =>
    route.fulfill({ status: 401, json: { error: { message: "Sign in" } } }),
  );
  await page.route("**/api/v1/auth/config", (route) =>
    route.fulfill({ json: { mode: "local", password_login: true } }),
  );
  await page.goto("/guardrail/configuration");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.locator("iframe")).toHaveCount(0);
  expect(previews).toEqual([]);
});

test("Guardrail Configuration reads tenant rules and saves the confirmed hook mode", async ({ page }, info) => {
  const previews: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.startsWith("/previews/")) previews.push(request.url());
  });
  let settings = { mode: "shadow", version: 7, updated_at: null };
  const writes: Record<string, unknown>[] = [];
  await mockApi(page, {
    hookSettings: () => settings,
    saveHookSettings: async (body) => {
      writes.push(body);
      settings = { ...settings, mode: String(body.mode), version: settings.version + 1 };
      return { json: settings };
    },
  });
  await page.route("**/api/v1/response/policy", (route) => route.fulfill({ json: {
    version: 12, updated_at: iso(60), rules: [{
      id: "tenant-rule", name: "Require approval for tenant publishing", enabled: true,
      action: "ask", match: { command_regex: "npm publish", products: ["codex"] },
    }],
  } }));
  await page.goto("/guardrail/configuration");
  await expect(page.getByRole("heading", { level: 1, name: "Guardrail Configuration" })).toBeVisible();
  const mode = page.getByRole("region", { name: "Hook policy", exact: true });
  const rules = page.getByRole("region", { name: "Fixed rules", exact: true });
  await expect(mode.getByRole("radio", { name: "Shadow", exact: true })).toBeChecked();
  await expect(rules.getByRole("cell", { name: "Require approval for tenant publishing", exact: true })).toBeVisible();
  await expect(rules).toContainText("Command regex: npm publish");
  await mode.getByRole("radio", { name: "Enforce", exact: true }).click();
  await expect(mode).toContainText("Apply backend decisions at supported hooks.");
  expect(writes).toEqual([{ mode: "enforce", version: 7 }]);
  await page.reload();
  await expect(mode.getByRole("radio", { name: "Enforce", exact: true })).toBeChecked();
  await expect(page.locator("iframe")).toHaveCount(0);
  await expect(page.getByText("Sample data", { exact: true })).toHaveCount(0);
  expect(previews).toEqual([]);
  await page.screenshot({ path: info.outputPath("guardrail-configuration-live.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await mode.getByRole("radio", { name: "Shadow", exact: true }).click();
  await expect(mode.getByRole("radio", { name: "Shadow", exact: true })).toBeChecked();
});

test("Guardrail Configuration distinguishes unavailable settings from an empty tenant policy", async ({ page }) => {
  await mockApi(page);
  let failed = true;
  await page.route("**/api/v1/response/hook-settings", (route) => failed
    ? route.fulfill({ status: 503, json: { error: { message: "Hook settings unavailable" } } })
    : route.fulfill({ json: { mode: "shadow", version: 0, updated_at: null } }));
  await page.route("**/api/v1/response/policy", (route) => failed
    ? route.fulfill({ status: 503, json: { error: { message: "Tenant rules unavailable" } } })
    : route.fulfill({ json: { version: 0, rules: [] } }));
  await page.goto("/guardrail/configuration");
  const mode = page.getByRole("region", { name: "Hook policy", exact: true });
  const rules = page.getByRole("region", { name: "Fixed rules", exact: true });
  await expect(mode.getByRole("alert")).toContainText("Hook settings unavailable");
  await expect(rules.getByRole("alert")).toContainText("Tenant rules unavailable");
  await expect(mode.getByRole("radio")).toHaveCount(0);
  await expect(rules.getByText("No fixed rules", { exact: true })).toHaveCount(0);
  failed = false;
  await mode.getByRole("button", { name: "Retry", exact: true }).click();
  await rules.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(mode.getByRole("radio", { name: "Shadow", exact: true })).toBeChecked();
  await expect(rules.getByText("No fixed rules", { exact: true })).toBeVisible();
  await expect(page.locator("iframe")).toHaveCount(0);
});

const overviewSummary = {
  generated_at: "2026-10-21T22:00:00Z",
  sources: [
    { id: "1", path: "/", title: "Findings and coverage", scope: "Open and triaged findings now; sensor records now.", status: "available", captured_at: "2026-10-21T21:59:50Z", facts: { findings_open: { critical: 3, high: 11 } } },
    { id: "2", path: "/ai-skills", title: "AI Skills", scope: "All installed skills and their assessment coverage now.", status: "unavailable", captured_at: "2026-10-21T21:59:55Z", facts: {} },
    { id: "3", path: "/costs/agents", title: "AI Agent Costs", scope: "Estimated agent cost over the last 24 hours.", status: "available", captured_at: "2026-10-21T21:59:56Z", facts: { cost_usd: 1321.64 } },
    { id: "4", path: "/administration/app", title: "App Health", scope: "Sensor records now.", status: "available", captured_at: "2026-10-21T21:59:57Z", facts: { sensors_offline: 4 } },
  ],
  items: [
    { topic: "Detection", headline: "17", caption: "sessions over the risk threshold", text: "Warning: Investigations are off; 17 sessions meet the risk threshold (7d).", detail: "Session investigations are disabled. Review detection coverage before interpreting findings as a full assessment.", tone: "warning", citations: ["1"] },
    { topic: "Findings", headline: "14", caption: "open critical and high findings", text: "3 critical and 11 high findings remain open or triaged.", detail: "These are reported findings, not confirmed incidents. Review the underlying evidence.", tone: "critical", citations: ["1"] },
    { topic: "Coverage", headline: "4 of 9", caption: "sensor records offline", text: "Skill assessment coverage is unavailable; 4 of 9 sensor records are offline.", detail: "The skills source could not be read. Sensor counts describe enrollments, not unique physical devices.", tone: "warning", citations: ["1", "2", "3", "4"] },
    { topic: "Guardrail", text: "Shadow mode is active. Failed checks allow the action.", detail: "An evaluated denial does not prove enforcement. Native permissions still apply.", tone: "info", citations: ["1"] },
    { topic: "Assets", headline: "23", caption: "application groups awaiting a decision", text: "23 application groups await a decision.", detail: "Approval is separate from a security assessment.", tone: "high", citations: ["1"] },
    { topic: "Costs", headline: "$1,321.64", caption: "API-equivalent, last 24 hours", text: "$1,321.64 in API-equivalent cost over the last 24 hours.", detail: "Estimated API-equivalent pricing, not an invoice. All reported calls were priced.", tone: "info", citations: ["3"] },
  ],
};

async function mockOverview(page: Page, options: Parameters<typeof mockApi>[1] = {}) {
  const checks = Array.from({ length: 100 }, (_, i) => ({
    ...completedChecks(live)[i % completedChecks(live).length],
    id: `overview-${i}`, session_id: `session-${i % 6}`, sensor_username: ["alex", "sam", "jordan"][i % 3],
    sensor_hostname: ["eng-mac-01", "eng-win-02", "eng-mac-03"][i % 3],
    evaluated_decision: i < 93 ? "allow" : i === 93 ? null : i < 98 ? "deny" : null,
    status: i < 98 ? "evaluated" : "unavailable", mode: i < 80 ? "shadow" : "enforce",
    assessment: { status: "scored", score: i < 90 ? 0 : 80, level: i < 90 ? "info" : "high", category: i < 90 ? "none" : "secret_exfiltration" },
    product: ["claude-code", "codex-cli", "cursor"][i % 3],
    actions: completedChecks(live)[i % completedChecks(live).length].actions.map((action) => ({
      ...action, agent: { product: ["claude-code", "codex-cli", "cursor"][i % 3] },
      host: { user: ["alex", "sam", "jordan"][i % 3], hostname: ["eng-mac-01", "eng-win-02", "eng-mac-03"][i % 3] },
      session: { id: `session-${i % 6}`, cwd: ["payments-api", "internal-tools", "design-system"][i % 3] },
    })),
  }));
  await mockApi(page, { classified: () => checks, ...options });
  await page.route("**/api/v1/overview/summary", (route) => route.fulfill({ json:
    route.request().method() === "GET" ? { summary: overviewSummary, stale: false } : overviewSummary,
  }));
}

test("Overview replaces charts with a cited summary and the shared activity flow", async ({ page }, info) => {
  await mockOverview(page, { roles: ["it_admin", "security_analyst", "security_leadership"] });
  await page.goto("/");
  const summary = page.getByRole("region", { name: "AI summary", exact: true });
  const flow = page.getByRole("region", { name: "Activity flow", exact: true });
  await expect(summary).toContainText("3 critical and 11 high");
  // Topics label the icons, most urgent first, without repeating in the body or losing legacy items without headlines.
  await expect(summary.getByRole("article")).toHaveText([/^FindingsCritical14 open critical and high findings 3 critical/, /^AssetsHigh23 /, /^DetectionWarning17 /, /^CoverageWarning4 of 9 /, /^GuardrailInfoShadow mode/, /^CostsInfo\$1,321\.64 /]);
  for (const item of overviewSummary.items) {
    const card = summary.getByRole("article", { name: item.topic, exact: true });
    const heading = card.getByRole("heading", { level: 3, name: item.topic, exact: true });
    await expect(heading).toBeVisible();
    await expect(card.getByText(item.topic, { exact: true })).toHaveCount(1);
    await expect(card.locator(".summary-text")).not.toContainText(`${item.topic}.`);
    const icon = heading.locator("svg");
    await expect(icon).toBeVisible();
    await expect(icon).toHaveAttribute("aria-hidden", "true");
  }
  await expect(summary.getByRole("article", { name: "Detection", exact: true })).toContainText("Investigations are off");
  await expect(summary.getByRole("article", { name: "Detection", exact: true })).not.toContainText("Warning:");
  await expect(summary.getByRole("article", { name: "Costs", exact: true }).getByRole("link", { name: "Costs", exact: true })).toHaveAttribute("href", "/costs/agents");
  await expect(summary.getByRole("article", { name: "Findings", exact: true }).getByRole("link")).toHaveCount(0);
  await expect(flow.getByRole("button", { name: "Allow 93", exact: true })).toBeVisible();
  await expect(flow.getByLabel("Guardrail measurements")).not.toContainText("USD");
  await expect(flow.getByRole("button", { name: "Guardrail cost details" })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Open findings", exact: true })).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Live activity", exact: true })).toHaveCount(0);
  for (const viewport of [{ width: 1802, height: 1065 }, { width: 1440, height: 900 }, { width: 1366, height: 768 }, { width: 1280, height: 720 }, { width: 1200, height: 720 }]) {
    await page.setViewportSize(viewport);
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    await page.evaluate(() => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))));
    const crowdedHeaders = await summary.getByRole("article").evaluateAll((cards) => cards.filter((card) => {
      const icon = card.querySelector("svg")!.getBoundingClientRect();
      const heading = card.querySelector("h3")!;
      const label = heading.lastElementChild!.getBoundingClientRect();
      const badge = card.querySelector('[data-slot="badge"]')!.getBoundingClientRect();
      const bounds = card.getBoundingClientRect();
      const overlapsBadge = label.right > badge.left && label.top < badge.bottom && label.bottom > badge.top;
      return icon.width < 16 || icon.height < 16 || icon.left < bounds.left || icon.right > label.left ||
        Math.abs((icon.top + icon.bottom - label.top - label.bottom) / 2) > 1 ||
        label.right > bounds.right + 1 || overlapsBadge || badge.right > bounds.right + 1;
    }).map((card) => card.getAttribute("aria-label")));
    expect(crowdedHeaders, JSON.stringify(viewport)).toEqual([]);
    const diagram = flow.getByRole("region", { name: "Activity flow diagram", exact: true });
    const bounds = await diagram.boundingBox();
    const nodes = await flow.locator('[data-slot="flow-node"]').evaluateAll((nodes) => nodes.map((node) => {
      const box = node.getBoundingClientRect();
      return { top: box.top, bottom: box.bottom, width: box.width, height: box.height };
    }));
    expect(nodes.filter((box) => box.height < 39.5 || box.width <= 100 || box.top < bounds!.y - 0.5 || box.bottom > bounds!.y + bounds!.height + 0.5), JSON.stringify(viewport)).toEqual([]);
    expect(await diagram.evaluate((node) => node.scrollHeight - node.clientHeight)).toBeLessThanOrEqual(1);
    const footer = await flow.getByRole("button", { name: "Explore activity", exact: true }).boundingBox();
    const card = await flow.boundingBox();
    expect(footer!.y + footer!.height).toBeLessThanOrEqual(card!.y + card!.height);
    await flow.getByRole("button", { name: "Explore activity", exact: true }).scrollIntoViewIfNeeded();
    await expect(flow.getByRole("button", { name: "Explore activity", exact: true })).toBeInViewport();

    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath(`overview-${viewport.width}.png`), fullPage: true });
    if (viewport.width === 1802) await summary.screenshot({ path: info.outputPath("overview-summary-labels.png") });
  }
  await summary.getByRole("button", { name: "Source 2: AI Skills", exact: true }).click();
  const sources = page.getByRole("dialog", { name: "Summary sources", exact: true });
  await expect(sources).toContainText("Unavailable");
  await expect(sources.getByRole("link", { name: "Open page" }).nth(1)).toHaveAttribute("href", "/ai-skills");
  await sources.getByRole("button", { name: "Close", exact: true }).click();
  // Citations past the second collapse into a count that opens the first hidden source.
  const coverage = summary.getByRole("article", { name: "Coverage", exact: true });
  await expect(coverage.getByRole("button", { name: "Source 3: AI Agent Costs", exact: true })).toHaveCount(0);
  await coverage.getByRole("button", { name: "2 more sources", exact: true }).click();
  await expect(sources.locator("#summary-source-3")).toHaveClass(/border-primary/);
  await sources.getByRole("button", { name: "Close", exact: true }).click();
  await summary.getByRole("button", { name: "Full summary", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "AI summary", exact: true })).toContainText("not confirmed incidents");
  await expect(page.getByRole("dialog", { name: "AI summary", exact: true }).getByRole("heading", { level: 3 }).first()).toHaveText("CriticalFindings: 14 open critical and high findings");
  await page.keyboard.press("Escape");
  await flow.getByRole("button", { name: "Deny 4", exact: true }).click();
  await flow.getByRole("button", { name: "Explore activity", exact: true }).click();
  const actions = page.getByRole("dialog", { name: "Activity details", exact: true });
  await expect(actions.getByRole("row")).toHaveCount(5);
  await actions.getByRole("button", { name: "Close", exact: true }).click();
  await expect(flow.getByRole("button", { name: "Resume live", exact: true })).toBeVisible();
  await flow.getByRole("button", { name: "Resume live", exact: true }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
  for (const item of overviewSummary.items) {
    const card = summary.getByRole("article", { name: item.topic, exact: true });
    await card.scrollIntoViewIfNeeded();
    await expect(card.getByRole("heading", { level: 3, name: item.topic, exact: true })).toBeInViewport();
    await expect(card.locator("svg")).toBeInViewport();
    await expect(card.locator('[data-slot="badge"]')).toBeInViewport();
  }
  await flow.getByRole("button", { name: "Explore activity", exact: true }).click();
  await expect(actions).toBeVisible();
  await actions.getByRole("button", { name: "Close", exact: true }).click();
});

test("Overview keeps the previous summary when refresh fails and does not invent an empty success", async ({ page }, info) => {
  await mockOverview(page);
  await page.goto("/");
  const summary = page.getByRole("region", { name: "AI summary", exact: true });
  await expect(summary).toContainText("3 critical and 11 high");
  await page.setViewportSize({ width: 1280, height: 720 });
  let finishRefresh!: () => void;
  const pendingRefresh = new Promise<void>((resolve) => { finishRefresh = resolve; });
  await page.route("**/api/v1/overview/summary", async (route) => {
    await pendingRefresh;
    await route.fulfill({ status: 503, json: { error: "Assistant unavailable" } });
  });
  await summary.getByRole("button", { name: "Regenerate", exact: true }).click();
  await expect(summary.getByRole("status")).toHaveText("Refreshing summary…");
  await expect(summary.getByRole("status")).toBeVisible();
  try {
    const flow = page.getByRole("region", { name: "Activity flow", exact: true });
    await expect(flow.getByRole("button", { name: "Allow 93", exact: true })).toBeVisible();
    const footer = await flow.getByRole("button", { name: "Explore activity", exact: true }).boundingBox();
    const card = await flow.boundingBox();
    expect(footer!.y + footer!.height).toBeLessThanOrEqual(card!.y + card!.height);
    expect(await flow.getByRole("region", { name: "Activity flow diagram", exact: true }).evaluate((node) => node.scrollHeight - node.clientHeight)).toBeLessThanOrEqual(1);
    await flow.getByRole("button", { name: "Explore activity", exact: true }).scrollIntoViewIfNeeded();
    await expect(flow.getByRole("button", { name: "Explore activity", exact: true })).toBeInViewport();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath("overview-refresh.png"), fullPage: true });
  } finally {
    finishRefresh();
  }
  await expect(summary.getByRole("alert")).toContainText("Showing the previous summary");
  await expect(summary).toContainText("3 critical and 11 high");
  await page.reload();
  await expect(summary.getByRole("alert")).toContainText("Assistant unavailable");
  await expect(summary).not.toContainText("3 critical");
  await page.route("**/api/v1/overview/summary", (route) => route.fulfill({ json: { items: [] } }));
  await summary.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(summary.getByRole("alert")).toContainText("incomplete summary");
});

test("Overview shows a saved summary during generation and reuses the fresh result on reload", async ({ page }, info) => {
  await mockOverview(page);
  let saved = overviewSummary;
  let stale = true;
  let generations = 0;
  let finish!: () => void;
  const pending = new Promise<void>((resolve) => { finish = resolve; });
  await page.route("**/api/v1/overview/summary", async (route) => {
    if (route.request().method() === "GET") return route.fulfill({ json: { summary: saved, stale } });
    generations++;
    await pending;
    saved = { ...overviewSummary, generated_at: "2026-10-21T22:10:00Z", items: overviewSummary.items.map((item) =>
      item.topic === "Findings" ? { ...item, text: "2 critical and 8 high findings remain open or triaged." } : item) };
    stale = false;
    await route.fulfill({ json: saved });
  });
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto("/");
  const summary = page.getByRole("region", { name: "AI summary", exact: true });
  try {
    await expect(summary).toContainText("3 critical and 11 high");
    await expect(summary.getByRole("status")).toBeVisible();
    await expect(summary.getByRole("status")).toHaveText("Refreshing summary…");
    await expect(summary.getByRole("button", { name: "Regenerate", exact: true })).toBeDisabled();
    await summary.getByRole("button", { name: "Full summary", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "AI summary", exact: true })).toContainText("not confirmed incidents");
    await expect(page.getByRole("dialog", { name: "AI summary", exact: true })).toContainText("Summaries refresh hourly in the background.");
    await page.keyboard.press("Escape");
    await expect(page.getByRole("region", { name: "Activity flow", exact: true }).getByRole("button", { name: "Allow 93", exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    const viewChecks = page.getByRole("button", { name: "Explore activity", exact: true });
    await viewChecks.scrollIntoViewIfNeeded();
    await expect(viewChecks).toBeInViewport();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath("overview-saved-refresh.png"), fullPage: true });
  } finally {
    finish();
  }
  await expect(summary).toContainText("2 critical and 8 high");
  await expect(summary.getByRole("status")).toHaveCount(0);
  await page.reload();
  await expect(summary).toContainText("2 critical and 8 high");
  await expect(summary.getByRole("button", { name: "Regenerate", exact: true })).toBeEnabled();
  expect(generations).toBe(1);
});

for (const legacy of [false, true]) {
  test(`Overview explains a slow first generation and keeps the page usable${legacy ? " with an older API" : ""}`, async ({ page }, info) => {
    await mockOverview(page);
    let finish!: () => void;
    const pending = new Promise<void>((resolve) => { finish = resolve; });
    await page.route("**/api/v1/overview/summary", async (route) => {
      if (route.request().method() === "GET") return legacy
        ? route.fulfill({ status: 403, json: { error: "Your roles do not allow this action" } })
        : route.fulfill({ json: { summary: null, stale: true } });
      await pending;
      await route.fulfill({ json: overviewSummary });
    });
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.goto("/");
    const summary = page.getByRole("region", { name: "AI summary", exact: true });
    try {
      await expect(summary.getByRole("status")).toContainText("This can take about 20 seconds");
      await expect(summary.getByRole("button", { name: "Regenerate", exact: true })).toBeDisabled();
      const flow = page.getByRole("region", { name: "Activity flow", exact: true });
      await flow.getByRole("button", { name: "Allow 93", exact: true }).click();
      await flow.getByRole("button", { name: "Explore activity", exact: true }).click();
      await expect(page.getByRole("dialog", { name: "Activity details", exact: true })).toBeVisible();
      await page.keyboard.press("Escape");
      for (const viewport of [{ width: 1280, height: 720 }, { width: 390, height: 844 }]) {
        await page.setViewportSize(viewport);
        expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
        await expect(summary.getByRole("status")).toBeVisible();
        await flow.getByRole("button", { name: "Explore activity", exact: true }).scrollIntoViewIfNeeded();
        await expect(flow.getByRole("button", { name: "Explore activity", exact: true })).toBeInViewport();
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({ path: info.outputPath(`overview-loading-${viewport.width}.png`), fullPage: true });
      }
    } finally {
      finish();
    }
    await expect(summary).toContainText("3 critical and 11 high");
    await expect(summary.getByRole("status")).toHaveCount(0);
    await expect(summary.getByRole("button", { name: "Regenerate", exact: true })).toBeEnabled();
  });
}

test("Overview removes a saved summary when refresh loses authorization", async ({ page }) => {
  await mockOverview(page);
  await page.goto("/");
  const summary = page.getByRole("region", { name: "AI summary", exact: true });
  await expect(summary).toContainText("3 critical and 11 high");
  await page.route("**/api/v1/overview/summary", (route) => route.fulfill({ status: 403, json: { error: "Access denied" } }));
  await summary.getByRole("button", { name: "Regenerate", exact: true }).click();
  await expect(summary.getByRole("alert")).toContainText("Access denied");
  await expect(summary).not.toContainText("3 critical and 11 high");
  await expect(summary.getByRole("button", { name: "Full summary", exact: true })).toHaveCount(0);
});

for (const role of ["it_admin", "security_leadership"]) {
  test(`Overview never requests Guardrail evidence for ${role}`, async ({ page }) => {
    const paths: string[] = [];
    page.on("request", (request) => paths.push(new URL(request.url()).pathname));
    await mockOverview(page, { roles: [role] });
    await page.goto("/");
    await expect(page.getByRole("region", { name: "AI summary", exact: true })).toContainText("3 critical");
    await expect(page.getByText("Activity flow requires the Security Analyst role", { exact: true })).toBeVisible();
    expect(paths).not.toContain("/api/v1/guardrail/checks");
    expect(paths).not.toContain("/api/v1/guardrail/active");
    expect(paths).not.toContain("/api/v1/events/live");
    expect(paths).not.toContain("/api/v1/telemetry/overview");
  });
}

const payrollDraft: RuleDraft = {
  intent: "Block agents from reading files under /srv/payroll/",
  explanation: "Deny file-read events under /srv/payroll/. Other paths do not match this rule.",
  limitations: ["File reads hidden inside shell commands are not covered."],
  rule: { name: "Protect payroll files", action: "deny", reason: "Payroll files are restricted.",
    match: { kinds: ["file.read"], products: [], tool_name: "", command_regex: "", path_glob: "/srv/payroll/**", host_glob: "" } },
  examples: [
    { label: "Payroll file", value: "/srv/payroll/salaries.csv", expected_match: true },
    { label: "Public file", value: "/srv/public/readme.txt", expected_match: false },
  ].map((example) => ({ ...example, kind: "file.read", product: "codex-cli", tool_name: "Read", os: "linux", path_home: "/home/example" })),
};

async function mockRuleAuthoring(page: Page) {
  await mockApi(page);
  const state = { policy: { version: 1, rules: [] } as Policy, generation: "draft", conflict: false, stale: false,
    writes: [] as { method: string; path: string; body: Record<string, unknown> }[], previews: [] as Record<string, unknown>[] };
  await page.route("**/api/v1/response/policy", (route) => route.fulfill({ json: state.policy }));
  await page.route("**/api/v1/response/policy/rules/**", (route) => {
    const path = new URL(route.request().url()).pathname.split("/").pop()!;
    const body = route.request().postDataJSON();
    expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
    if (path === "generate") {
      if (state.generation === "error") return route.fulfill({ status: 503, json: { error: { message: "AI provider unavailable" } } });
      return route.fulfill({ json: state.generation === "draft" ? { status: "draft", draft: payrollDraft }
        : { status: "clarify", explanation: "Which production path should this rule cover?" } });
    }
    if (path === "preview") {
      state.previews.push(body);
      return route.fulfill({ json: { version: state.policy.version, passed: !state.conflict,
        results: payrollDraft.examples.map((example) => ({ label: example.label, expected_match: example.expected_match,
          matched: example.expected_match, passed: !state.conflict || !example.expected_match,
          shadowed: state.conflict && example.expected_match, action: example.expected_match ? state.conflict ? "warn" : "deny" : "allow",
          rule_name: state.conflict ? "Existing payroll warning" : "Protect payroll files", error: "" })) } });
    }
    state.writes.push({ method: route.request().method(), path, body });
    if (state.stale) {
      state.stale = false;
      state.policy = { ...state.policy, version: state.policy.version + 1 };
      return route.fulfill({ status: 409, json: { error: { message: "Fixed rules changed. Reload and test the draft again." } } });
    }
    expect(body.version).toBe(state.policy.version);
    if (path === "drafts") {
      const draft = body.draft as RuleDraft;
      state.policy = { ...state.policy, version: state.policy.version + 1,
        rules: [...state.policy.rules, { ...draft.rule, id: "generated-rule", enabled: false, source: "tenant_ai", authoring: draft }] };
    } else {
      state.policy = { ...state.policy, version: state.policy.version + 1,
        rules: state.policy.rules.map((rule) => ({ ...rule, enabled: body.enabled })) };
    }
    return route.fulfill({ json: { policy: state.policy, rule_id: "generated-rule" } });
  });
  return state;
}

test("fixed-rule authoring tests an editable draft, saves disabled, and explicitly enables", async ({ page }, info) => {
  const state = await mockRuleAuthoring(page);
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/guardrail/configuration");
  const rules = page.getByRole("region", { name: "Fixed rules", exact: true });
  await rules.getByRole("button", { name: "Create rule", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Describe your intent").fill(payrollDraft.intent);
  await dialog.getByRole("button", { name: "Generate draft", exact: true }).click();
  await expect(dialog.getByLabel("Rule name")).toHaveValue("Protect payroll files");
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeDisabled();
  expect(state.writes).toEqual([]);
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeEnabled();
  await dialog.getByLabel("Rule name").fill("Protect payroll records");
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeDisabled();
  const kinds = dialog.getByLabel("Event kinds (comma separated)");
  await kinds.fill("");
  await kinds.pressSequentially("file.read, file.write");
  await expect(kinds).toHaveValue("file.read, file.write");
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeEnabled();
  expect((state.previews.at(-1)?.draft as RuleDraft).rule.match.kinds).toEqual(["file.read", "file.write"]);
  await page.screenshot({ path: info.outputPath("fixed-rule-authoring.png"), animations: "disabled" });
  await dialog.getByRole("button", { name: "Save disabled rule" }).click();
  await expect(dialog.getByRole("status").filter({ hasText: "Rule saved disabled" })).toBeVisible();
  expect(state.policy.rules[0].enabled).toBe(false);
  await expect(dialog.getByRole("button", { name: "Enable rule", exact: true })).toBeDisabled();
  await dialog.getByRole("button", { name: "Close", exact: true }).last().click();
  await rules.getByRole("button", { name: "Review and enable" }).click();
  await expect(dialog.getByLabel("Rule name")).toHaveValue("Protect payroll records");
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await dialog.getByLabel("Test input 2").scrollIntoViewIfNeeded();
  await expect(dialog.getByLabel("Test input 2")).toBeInViewport();
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  await expect(dialog.getByRole("button", { name: "Enable rule", exact: true })).toBeInViewport();
  await dialog.getByRole("button", { name: "Enable rule", exact: true }).click();
  await expect(dialog).toBeHidden();
  await expect(rules.getByText("Enabled", { exact: true })).toBeVisible();
  expect(state.writes.map((entry) => entry.method)).toEqual(["POST", "PATCH"]);
  await rules.getByRole("button", { name: "Disable", exact: true }).click();
  await expect(rules.getByText("Disabled", { exact: true })).toBeVisible();
  expect(state.writes.at(-1)?.body.enabled).toBe(false);
  expect(errors).toEqual([]);
});

test("fixed-rule authoring retains drafts through clarification, conflict, and stale policy", async ({ page }) => {
  const state = await mockRuleAuthoring(page);
  state.generation = "clarify";
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/guardrail/configuration");
  await page.getByRole("button", { name: "Create rule", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Describe your intent").fill("Block production changes");
  await dialog.getByRole("button", { name: "Generate draft", exact: true }).click();
  await expect(dialog.getByRole("status")).toContainText("Which production path");
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toHaveCount(0);
  state.generation = "error";
  await dialog.getByRole("button", { name: "Generate draft", exact: true }).click();
  await expect(dialog.getByRole("alert")).toContainText("AI provider unavailable");
  expect(state.writes).toEqual([]);
  state.generation = "draft";
  await dialog.getByLabel("Describe your intent").fill(payrollDraft.intent);
  await dialog.getByRole("button", { name: "Generate draft", exact: true }).click();
  state.conflict = true;
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  const conflict = dialog.getByText(/Earlier rule.*Existing payroll warning/);
  await conflict.scrollIntoViewIfNeeded();
  await expect(conflict).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeDisabled();
  state.conflict = false;
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  state.stale = true;
  await dialog.getByRole("button", { name: "Save disabled rule" }).click();
  await expect(dialog.getByRole("alert")).toContainText("Fixed rules changed");
  await expect(dialog.getByLabel("Rule name")).toHaveValue("Protect payroll files");
  await expect(dialog.getByRole("button", { name: "Save disabled rule" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Test against current rules" }).click();
  await dialog.getByRole("button", { name: "Save disabled rule" }).click();
  await expect(dialog.getByRole("status").filter({ hasText: "Rule saved disabled" })).toBeVisible();
  expect(state.previews.at(-1)?.version).toBe(2);
  expect(state.policy.rules[0].enabled).toBe(false);
});

test("malicious link results distinguish reputation, incomplete checks, and enforcement", async ({ page }, info) => {
  const record = completedChecks(live)[0];
  const url = `https://malware.example.com/${"long-path-".repeat(30)}`;
  const links = {
    provider: "google_web_risk", checked: 1, skipped: 0, failed: 0, reasons: [],
    matches: [{ url, threat_types: ["MALWARE", "SOCIAL_ENGINEERING"], expires_at: iso(-300) }],
  };
  await mockApi(page, { classified: () => [
    { ...record, id: "link-match", mode: "shadow", evaluated_decision: "deny", returned_decision: "allow",
      reason: "Google Web Risk flagged a link for phishing, malware, or unwanted software.",
      assessment: { status: "unavailable", reason: "provider_unavailable", links: { ...links, status: "matched" } },
    },
    { ...record, id: "link-unlisted", assessment: { ...record.assessment,
      links: { ...links, status: "not_listed", matches: [] } } },
    { ...record, id: "link-partial", assessment: { ...record.assessment,
      links: { ...links, status: "partial", matches: [], skipped: 2, reasons: ["content_redacted", "urls_skipped"] } } },
    { ...record, id: "link-timeout", assessment: { ...record.assessment,
      links: { ...links, status: "unavailable", checked: 0, failed: 1, matches: [], reasons: ["timeout", "provider_unavailable"] } } },
  ] });
  await page.goto("/guardrail/live");
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  const flagged = actions.getByRole("row").filter({ hasText: "Flagged link" });
  await expect(flagged).toContainText("Deny · Shadow");
  await expect(flagged).toContainText("Returned: Allow");
  await flagged.getByText("Flagged link", { exact: true }).click();
  await expect(flagged.getByText(url, { exact: true })).toBeVisible();
  await expect(flagged).toContainText("Phishing or social engineering");
  await expect(flagged.getByRole("link")).toHaveCount(0);
  for (const label of ["No listed threats", "Link check incomplete", "Link check unavailable"]) {
    await actions.getByText(label, { exact: true }).click();
  }
  await expect(actions).toContainText("An unlisted URL is not proof of safety.");
  await expect(actions).toContainText("Some captured content was redacted.");
  await expect(actions).toContainText("A reputation lookup timed out.");
  await expect(actions).toContainText("The link reputation service was unavailable.");
  await flagged.getByText("Decision details", { exact: true }).click();
  await expect(flagged.getByText("Google Web Risk flagged a link for phishing, malware, or unwanted software.", { exact: true })).toBeVisible();
  await expect(actions.getByText(/^Google Web Risk ·/)).toHaveCount(0);
  await expect(actions.getByText(/^Link reputation ·/)).toHaveCount(4);
  await expectPublicNames(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await flagged.getByText(url, { exact: true }).scrollIntoViewIfNeeded();
    expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    await expect(flagged.getByText(url, { exact: true })).toBeVisible();
    await expect(flagged.getByText(url, { exact: true })).toBeInViewport({ ratio: 0.9 });
    expect(await flagged.getByText(url, { exact: true }).evaluate((element) => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
    await page.evaluate(() => window.scrollTo(0, 0));
    const clip = (await actions.boundingBox())!;
    await page.screenshot({ path: info.outputPath(`malicious-links-${width}.png`), fullPage: true, clip });
  }
});
