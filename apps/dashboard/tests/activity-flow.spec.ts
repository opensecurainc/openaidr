import { test, expect, type Page } from "@playwright/test";
import { activityFixture } from "./fixtures/activity-flow";

async function mockFlow(page: Page, options: { fail?: () => boolean; gatewayKind?: "kong" | "litellm"; onSummary?: () => void; onDetail?: (view: string, query: URLSearchParams) => Promise<void> } = {}) {
  const now = Date.now();
  const records: Record<string, unknown>[] = Array.from({ length: 256 }, (_, index) => {
    const user = Math.floor(index / 2);
    const username = ["pan.hu", "pengyu.zhang", "harry.lamps"][user] || `user.${String(user).padStart(3, "0")}`;
    return {
      id: `check-${index}`, created_at: new Date(now - (user < 64 ? index + 5 : 1200 + index) * 1000).toISOString(),
      sensor_id: `sensor-${user}`, sensor_hostname: `device-${user}`, sensor_username: username,
      product: user % 2 ? "claude-code" : "codex-cli", session_id: `session-${user}`, hook_event: "PreToolUse", mode: "shadow",
      status: index === 6 ? "unavailable" : "evaluated", evaluated_decision: index === 6 ? null : index < 5 ? "deny" : "allow",
      returned_decision: "allow", delivery_status: "unconfirmed", delivered_decision: null,
      assessment: index === 6 ? null : { status: "scored", score: index < 10 ? 60 : 0, level: index < 10 ? "high" : "info", category: index < 10 ? "supply_chain" : "none" },
      actions: [{ kind: "command", command: { text: `npm run project-${user}` }, session: { cwd: `/projects/project-${user}` }, agent: { product: user % 2 ? "claude-code" : "codex-cli" } }],
      reason: "", rule_name: "", failure_reason: index === 6 ? "assessment timeout" : "",
    };
  });
  records.push({
    id: "gateway-check", source: "gateway", created_at: new Date(now - 3000).toISOString(), gateway_id: "gateway-1", gateway_name: "Production gateway", gateway_kind: options.gatewayKind || "kong", node_id: "node-1", route_id: "chat", consumer_id: "caller-1", consumer_name: "pan.hu", application_name: "Support", mode: "enforce",
    status: "evaluated", evaluated_decision: "deny", returned_decision: "deny", outcome: "blocked", reason: "Secret detected", failure_reason: "",
    assessment: { status: "scored", category: "secret_exfiltration", score: 80, level: "high" }, messages: [], actions: [],
  });
  await page.route("**/api/v1/**", async route => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me")) return route.fulfill({ json: { user: { id: "analyst", email: "analyst@example.test", name: "Analyst", roles: ["security_analyst"], tenant: { id: "tenant-1", name: "Test" } } } });
    if (url.pathname.endsWith("telemetry/overview")) return route.fulfill({ json: { service: null, generated_at: new Date().toISOString(), devices: [] } });
    if (url.pathname.endsWith("guardrail/flow")) {
      if (url.searchParams.get("view") === "checks") options.onSummary?.();
      else await options.onDetail?.(url.searchParams.get("view") || "identities", url.searchParams);
      return options.fail?.() ? route.fulfill({ status: 503, json: { error: { message: "Summary unavailable" } } })
        : route.fulfill({ json: activityFixture(records, url.searchParams).summary });
    }
    if (url.pathname.endsWith("guardrail/checks")) {
      await options.onDetail?.("checks", url.searchParams);
      const items = activityFixture(records, url.searchParams).checks;
      const offset = Number(url.searchParams.get("cursor") || 0);
      return route.fulfill({ json: { items: items.slice(offset, offset + 100), next_cursor: offset + 100 < items.length ? String(offset + 100) : "" } });
    }
    if (url.pathname.endsWith("guardrail/active")) return route.fulfill({ json: { jev: { calls: 10, pending_calls: 0, failed_calls: 1, priced_calls: 8, cost_usd: 0.001, latency_samples: 9, latency_p95_ms: 180 } } });
    return route.fulfill({ json: { items: [], next_cursor: "", cursor: "", more: false } });
  });
  return records;
}

const flow = (page: Page) => page.getByRole("region", { name: "Activity flow", exact: true });

test("all identities contribute and a quiet identity beyond the first page is searchable", async ({ page }) => {
  await mockFlow(page);
  await page.goto("/guardrail/live");
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
  await expect(page.getByTestId("summary-identities")).toHaveText("129");
  await expect(page.getByRole("group", { name: "Top identities by completed checks" }).getByRole("button")).toHaveCount(10);
  await expect(flow(page).getByRole("button", { name: "119 more identities. Browse all identities" })).toBeVisible();
  const explorer = page.getByRole("region", { name: "Explore activity", exact: true });
  await explorer.getByRole("button", { name: "Next", exact: true }).click();
  await expect(explorer).toContainText("21 to 40 of 129");
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
  await flow(page).getByRole("button", { name: "Find an identity", exact: true }).first().click();
  const dialog = page.getByRole("dialog", { name: "Find an identity" });
  await dialog.getByRole("searchbox").fill("user.127");
  await expect(dialog.getByRole("row")).toHaveCount(2);
  await dialog.getByRole("button", { name: "Inspect OS user: user.127", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("2");
  await expect(flow(page).locator("[data-check-packet]")).toHaveCount(0);
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  await expect(page.getByRole("region", { name: "Actions", exact: true }).getByRole("row")).toHaveCount(3);
  await expect(page.getByRole("region", { name: "Actions", exact: true })).toContainText("npm run project-127");
  await flow(page).getByRole("button", { name: "All identities", exact: true }).click();
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  await expect(actions.getByRole("row")).toHaveCount(101);
  await actions.getByRole("button", { name: "Older checks" }).click();
  await expect(actions.getByRole("row")).toHaveCount(101);
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
  await flow(page).getByRole("button", { name: "Resume live" }).click();
  await expect(actions).toContainText("npm run project-0");
});

for (const gatewayKind of ["kong", "litellm"] as const) test(`${gatewayKind}: risk, decision and source filters preserve evaluated, returned and delivery evidence`, async ({ page }) => {
  await mockFlow(page, { gatewayKind });
  await page.goto("/guardrail/live");
  await flow(page).getByRole("button", { name: "Supply chain 9", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("9");
  await flow(page).getByRole("button", { name: "Deny 5", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("5");
  const actions = page.getByRole("region", { name: "Actions", exact: true });
  await expect(actions.getByRole("row")).toHaveCount(6);
  await expect(actions.getByRole("row").nth(1)).toContainText("Shadow");
  await expect(actions.getByRole("row").nth(1)).toContainText("Allow");
  await expect(actions.getByRole("row").nth(1)).toContainText("Delivery not confirmed");
  await flow(page).getByRole("button", { name: "All identities", exact: true }).click();
  await flow(page).getByRole("button", { name: "Check failed 1", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("1");
  await expect(actions).toContainText("Check failed");
  await flow(page).getByRole("combobox", { name: "Activity source" }).click();
  await page.getByRole("option", { name: "Gateways", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("1");
  await expect(page.getByTestId("summary-identities")).toHaveText("1");
  await expect(page.getByRole("region", { name: "Live agent activity" })).toHaveCount(0);
  await expect(flow(page).getByRole("button", { name: `Inspect ${gatewayKind === "kong" ? "Kong" : "LiteLLM"} gateway, 1 checks`, exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Checks", exact: true }).click();
  await expect(actions).toContainText("Reported outcome");
  await expect(actions).toContainText("Blocked");
});

test("source and session drill-down use the selected complete time window", async ({ page }) => {
  await mockFlow(page);
  await page.goto("/guardrail/live");
  await flow(page).getByRole("button", { name: "Inspect Codex, 128 checks", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("128");
  const sessions = page.getByRole("tabpanel", { name: "Sessions & routes" });
  await sessions.getByRole("button", { name: "Inspect /projects/project-0", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("2");
  await expect(page.getByRole("tab", { name: "Checks", exact: true })).toHaveAttribute("aria-selected", "true");
  await flow(page).getByRole("combobox", { name: "Activity time window" }).click();
  await page.getByRole("option", { name: "Last 15 minutes", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("129");
  await flow(page).getByRole("combobox", { name: "Activity time window" }).click();
  await page.getByRole("option", { name: "Last hour", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
});

for (const path of ["/guardrail/live", "/"]) test(`${path} shows two rows of five initials and keeps the full flow reachable`, async ({ page }, info) => {
  const errors: string[] = [];
  page.on("pageerror", error => errors.push(error.message));
  await mockFlow(page);
  await page.goto(path);
  const initials = page.getByRole("group", { name: "Top identities by completed checks" }).getByRole("button");
  await expect(initials).toHaveCount(10);
  for (const width of [1440, 1024, 390]) {
    await page.setViewportSize({ width, height: 1000 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    const boxes = await initials.evaluateAll(buttons => buttons.map(button => ({ x: button.getBoundingClientRect().x, y: button.getBoundingClientRect().y })));
    expect(new Set(boxes.map(box => Math.round(box.y))).size).toBe(2);
    expect(new Set(boxes.map(box => Math.round(box.x))).size).toBe(5);
    const diagram = page.getByRole("region", { name: "Activity flow diagram", exact: true });
    await diagram.getByRole("button", { name: "Unassessed 1", exact: true }).scrollIntoViewIfNeeded();
    await expect(diagram.getByRole("button", { name: "Unassessed 1", exact: true })).toBeInViewport();
    await diagram.evaluate(element => { element.scrollLeft = 0; });
    await flow(page).screenshot({ path: info.outputPath(`flow-${width}.png`) });
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  await initials.first().focus();
  await page.keyboard.press("Enter");
  await expect(page.getByTestId("summary-identities")).toHaveText("1");
  if (path === "/") {
    await flow(page).getByRole("button", { name: "Explore activity", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Activity details" })).toBeVisible();
  }
  expect(errors).toEqual([]);
});

test("unavailable summaries show an error and can be retried", async ({ page }) => {
  let fail = true;
  await mockFlow(page, { fail: () => fail });
  await page.goto("/guardrail/live");
  await expect(flow(page).getByRole("alert")).toContainText("Summary unavailable");
  await expect(page.getByTestId("stat-decisions")).toHaveCount(0);
  fail = false;
  await flow(page).getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
});


test("slow detail reads finish across live polling cycles and refresh after completion", async ({ page }) => {
  await page.clock.install();
  let summaryReads = 0;
  let delayedView = "identities";
  let release = () => {};
  let gate = new Promise<void>(resolve => { release = resolve; });
  const reads: Record<string, string[]> = { identities: [], sessions: [], checks: [] };
  await mockFlow(page, {
    onSummary: () => { summaryReads++; },
    onDetail: async (view, query) => {
      reads[view].push(query.get("until") || "");
      if (view === delayedView) await gate;
    },
  });
  await page.goto("/guardrail/live");
  for (const [view, label] of [["identities", "Identities"], ["sessions", "Sessions & routes"], ["checks", "Checks"]]) {
    if (view !== "identities") {
      delayedView = view;
      gate = new Promise<void>(resolve => { release = resolve; });
      await page.getByRole("tab", { name: label, exact: true }).click();
    }
    await expect.poll(() => reads[view].length).toBeGreaterThan(0);
    const initialReads = reads[view].length;
    const firstWindow = reads[view][0];
    for (let cycle = 0; cycle < 3; cycle++) {
      const before = summaryReads;
      await page.clock.runFor(5500);
      await expect.poll(() => summaryReads).toBeGreaterThan(before);
    }
    expect(new Set(reads[view])).toEqual(new Set([firstWindow]));
    release();
    const panel = page.getByRole("tabpanel", { name: label, exact: true });
    await expect(panel.getByRole("row")).toHaveCount(view === "checks" ? 101 : 21);
    // Once complete, a later refresh adopts a newer window without blanking the results.
    await page.clock.runFor(5500);
    await expect.poll(() => reads[view].length).toBeGreaterThan(initialReads);
    expect(reads[view].at(-1)).not.toBe(firstWindow);
    await expect(panel.getByRole("row")).toHaveCount(view === "checks" ? 101 : 21);
  }
  await flow(page).getByRole("button", { name: "Supply chain 9", exact: true }).click();
  await expect(page.getByTestId("stat-decisions")).toHaveText("9");
  await expect(page.getByRole("tabpanel", { name: "Checks", exact: true }).getByRole("row")).toHaveCount(10);
  await flow(page).getByRole("button", { name: "Pause view", exact: true }).click();
  await expect(flow(page).getByRole("button", { name: "Resume live", exact: true })).toBeVisible();
  const pinned = summaryReads;
  await page.clock.runFor(16000);
  expect(summaryReads).toBe(pinned);
  await flow(page).getByRole("button", { name: "Resume live", exact: true }).click();
  await expect.poll(() => summaryReads).toBeGreaterThan(pinned);
  await expect(page.getByTestId("stat-decisions")).toHaveText("9");
});

for (const selection of ["initials", "directory"]) test(`${selection}: identity stays live when a new Claude Code session starts`, async ({ page }, info) => {
  await page.clock.install();
  const records = await mockFlow(page);
  await page.goto("/guardrail/live");
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
  if (selection === "directory") {
    await flow(page).getByRole("button", { name: "Find an identity", exact: true }).first().click();
    const dialog = page.getByRole("dialog", { name: "Find an identity" });
    await dialog.getByRole("searchbox").fill("pan.hu");
    await dialog.getByRole("button", { name: "Inspect OS user: pan.hu", exact: true }).click();
  } else {
    await page.getByRole("button", { name: "Inspect OS user: pan.hu, 2 checks", exact: true }).click();
  }
  await expect(page.getByTestId("stat-decisions")).toHaveText("2");
  await expect(flow(page).getByRole("button", { name: "Pause view", exact: true })).toBeVisible();
  await expect(flow(page).locator("[data-check-packet]")).toHaveCount(0);
  records.push({ ...records[0], id: "new-claude-prompt", product: "claude-code", session_id: "new-claude-session",
    hook_event: "UserPromptSubmit", created_at: new Date().toISOString(),
    actions: [{ agent: { product: "claude-code" }, session: { cwd: "/projects/new-claude-session" } }],
  });
  records.push({ ...records[2], id: "another-identity-prompt", created_at: new Date().toISOString() });
  await page.clock.runFor(5500);
  await expect(page.getByTestId("stat-decisions")).toHaveText("3");
  await expect(page.getByTestId("stat-sessions")).toHaveText("2");
  await expect(flow(page).getByRole("button", { name: "Inspect Claude Code, 1 checks", exact: true })).toBeVisible();
  await expect(flow(page).locator("[data-check-packet]")).toHaveCount(1);
  await expect(flow(page).locator('[data-check-packet="endpoint:new-claude-prompt"]')).toHaveCount(1);
  await page.clock.runFor(300);
  if (selection === "initials") {
    // Freeze motion without taking a fixed history window, for a reproducible image.
    await page.clock.pauseAt(await page.evaluate(() => Date.now()));
    await flow(page).screenshot({ path: info.outputPath("identity-new-claude-session.png"), animations: "allow" });
  }
  await page.clock.runFor(5500);
  await expect(page.getByRole("tabpanel", { name: "Sessions & routes" })).toContainText("/projects/new-claude-session");
});

test("new turn checks animate once, follow their connectors, and honor pause and reduced motion", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "no-preference" });
  await page.clock.install();
  const records = await mockFlow(page);
  await page.goto("/guardrail/live");
  await expect(page.getByTestId("stat-decisions")).toHaveText("257");
  const packets = flow(page).locator("[data-check-packet]");
  await expect(packets).toHaveCount(0);
  await page.clock.runFor(5500);
  await expect(packets).toHaveCount(0);
  for (const [index, boundary] of ["UserPromptSubmit", "PreToolUse", "PostToolUse"].entries()) {
    records.push({ ...records[0], id: `turn-${index}`, hook_event: boundary, created_at: new Date().toISOString() });
  }
  await page.clock.runFor(5500);
  await expect(page.getByTestId("stat-decisions")).toHaveText("260");
  await expect(packets).toHaveCount(3);
  await page.clock.runFor(300);
  const dot = flow(page).locator('[data-check-packet="endpoint:turn-0"]');
  await expect(dot).toHaveAttribute("visibility", "visible");
  const position = () => dot.evaluate(element => [element.getAttribute("cx"), element.getAttribute("cy")]);
  const first = await position();
  await page.clock.runFor(200);
  expect(await position()).not.toEqual(first);
  const distance = await dot.evaluate(element => {
    const path = element.parentElement!.querySelector('[data-route="identities:endpoint:codex-cli"]') as unknown as SVGPathElement;
    const x = Number(element.getAttribute("cx")), y = Number(element.getAttribute("cy"));
    return Math.min(...Array.from({ length: 201 }, (_, i) => {
      const point = path.getPointAtLength(path.getTotalLength() * i / 200);
      return Math.hypot(point.x - x, point.y - y);
    }));
  });
  expect(distance).toBeLessThan(1);
  await flow(page).getByRole("button", { name: "Pause view", exact: true }).click();
  await expect(flow(page).getByRole("button", { name: "Resume live", exact: true })).toBeVisible();
  const stopped = await position();
  await page.clock.runFor(6000);
  expect(await position()).toEqual(stopped);
  await flow(page).getByRole("button", { name: "Resume live", exact: true }).click();
  await page.clock.runFor(6000);
  await expect(packets).toHaveCount(0);
  await page.clock.runFor(5500);
  await expect(packets).toHaveCount(0);
  records[records.length - 1] = { ...records[records.length - 1], assessment: { status: "scored", category: "none", score: 0 } };
  await page.clock.runFor(5500);
  await expect(packets).toHaveCount(0);
  await page.emulateMedia({ reducedMotion: "reduce" });
  records.push({ ...records[0], id: "reduced-motion-check", created_at: new Date().toISOString() });
  await page.clock.runFor(5500);
  await expect(page.getByTestId("stat-decisions")).toHaveText("261");
  await expect(packets).toHaveCount(0);
});
