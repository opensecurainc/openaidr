import { test, expect, type Page } from "@playwright/test";
import type { AgentEvent } from "../src/lib/api";
import { mockClipboard } from "./fixtures/clipboard";

const user = { id: "u", name: "Evidence reviewer", email: "review@example.invalid", roles: ["it_admin", "security_analyst", "security_leadership"], tenant: { id: "t", name: "Test tenant", slug: "test" } };
const command: AgentEvent = { id: "event-1", time: "2026-10-12T18:48:32Z", kind: "command", sensor_id: "sensor-1", session_id: "server-1", session: { id: "session-one", cwd: "/Users/panhu/projects/openaidr" }, host: { user: "panhu", hostname: "pan-m5.local" }, agent: { product: "codex-cli" }, command: { text: "git status" }, tool: { output: "Working tree clean" } };
const prompt: AgentEvent = { ...command, id: "event-2", time: "2026-10-12T18:48:18Z", kind: "prompt", text: "Simplify evidence search.", command: undefined, tool: undefined };

async function auth(page: Page) {
  await page.route("**/api/v1/**", route => new URL(route.request().url()).pathname.endsWith("auth/me")
    ? route.fulfill({ json: { user } }) : route.fulfill({ json: { items: [], next_cursor: "" } }));
}

test.describe("evidence search", () => {
  test.use({ timezoneId: "America/Los_Angeles" });

  test("WorkBuddy uses its product label and bundled publisher artwork", async ({ page }, info) => {
    await auth(page);
    await page.route("**/api/v1/events?*", route => route.fulfill({ json: {
      items: [prompt, command].map(item => ({ ...item, agent: { product: "workbuddy" } })), next_cursor: "",
    } }));
    await page.goto("/evidence");
    const sessions = page.getByRole("navigation", { name: "Matching sessions" });
    await expect(sessions.getByRole("button")).toContainText("WorkBuddy");
    const image = sessions.locator('[data-slot="agent-logo"]');
    await expect(image).toHaveAttribute("src", "/agent-icons/workbuddy.svg");
    await expect.poll(() => image.evaluate((node: HTMLImageElement) => node.complete && node.naturalWidth > 0)).toBe(true);
    await expect(page.getByRole("region", { name: "Session details", exact: true })).toContainText("WorkBuddy");
    await page.screenshot({ path: info.outputPath("workbuddy-evidence.png"), animations: "disabled" });
  });

  test("raw evidence copy stays reachable while scrolling and reports clipboard failures", async ({ page }, info) => {
    const retained = { ...command, tool: { input: {
      command: "  /usr/local/bin/jev --label '日本語 <>&'\r\n",
      records: Array.from({ length: 60 }, (_, i) => ({ id: i, path: `/workspace/${"long-path/".repeat(20)}` })),
    } } };
    await auth(page);
    await page.route("**/api/v1/events?*", route => route.fulfill({ json: { items: [retained], next_cursor: "" } }));
    await page.goto("/evidence");
    await mockClipboard(page);
    await page.getByRole("button", { name: /Open event event-1:/ }).click();
    await page.getByRole("button", { name: "View raw event" }).click();
    const dialog = page.getByRole("dialog", { name: "Event evidence" });
    const block = dialog.locator('[data-slot="code-block"]');
    const pre = block.locator("pre");
    const copy = block.getByRole("button", { name: "Copy text", exact: true });
    expect(await pre.textContent()).toBe(JSON.stringify(retained, null, 2));
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await expect(copy).toBeInViewport();
      await dialog.evaluate(node => Promise.all(node.getAnimations({ subtree: true }).map(animation => animation.finished)));
      const buttonBox = (await copy.boundingBox())!;
      const blockBox = (await block.boundingBox())!;
      expect(buttonBox.x + buttonBox.width).toBeCloseTo(blockBox.x + blockBox.width - 8, 0);
      expect(buttonBox.y).toBeCloseTo(blockBox.y + 8, 0);
      expect((await pre.boundingBox())!.x + (await pre.boundingBox())!.width).toBeLessThan(buttonBox.x);
      expect(await pre.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      expect(await pre.evaluate(node => node.scrollWidth > node.clientWidth)).toBe(true);
      await pre.evaluate(node => { node.scrollTop = node.scrollHeight; node.scrollLeft = node.scrollWidth; });
      await expect(copy).toBeInViewport();
      expect((await copy.boundingBox())!.y).toBeCloseTo(buttonBox.y, 0);
      await copy.focus();
      await page.keyboard.press("Enter");
      await expect(copy).toHaveAttribute("title", "Copied");
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify(retained, null, 2));
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await pre.evaluate(node => { node.scrollTop = 0; node.scrollLeft = 0; });
      await dialog.screenshot({ path: info.outputPath(`evidence-copy-${width}.png`), animations: "disabled" });
    }
    await expect(copy).toHaveAttribute("title", "Copy text");
    await page.evaluate(() => { navigator.clipboard.writeText = async () => { throw new Error("Clipboard blocked"); }; });
    await copy.click();
    await expect(copy.getByRole("status")).toHaveText("Copy failed. Select the text and copy it manually.");
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined }));
    await copy.click();
    await expect(copy).toHaveAttribute("title", /Copy failed/);
    await mockClipboard(page);
    await copy.click();
    await expect(copy).toHaveAttribute("title", "Copied");
  });

  test("filters search retained events and reset pagination without applying unfinished edits", async ({ page }, info) => {
    await auth(page);
    const reads: URL[] = [];
    let failed = false;
    await page.route("**/api/v1/events?*", route => {
      const url = new URL(route.request().url()); reads.push(url);
      if (failed) return route.fulfill({ status: 503, json: { error: { message: "Activity temporarily unavailable" } } });
      if (url.searchParams.get("username") === "nobody") return route.fulfill({ json: { items: [], next_cursor: "" } });
      return route.fulfill({ json: { items: url.searchParams.has("cursor") ? [prompt] : [command], next_cursor: url.searchParams.has("cursor") ? "" : "older-events" } });
    });
    let telemetryReads = 0;
    page.on("request", request => { if (request.url().includes("/telemetry/")) telemetryReads++; });
    await page.goto("/evidence");
    const activity = page.getByRole("region", { name: "Session activity" });
    await expect(activity).toContainText("git status");
    await expect(page.getByRole("heading", { name: "Telemetry exports", exact: true })).toHaveCount(0);
    const initial = reads.length;
    await page.getByLabel("User name", { exact: true }).fill("PAN");
    await page.getByLabel("Device name", { exact: true }).fill("pan-m5");
    await page.getByLabel("Session ID", { exact: true }).fill("session-one");
    await page.getByLabel("Date", { exact: true }).fill("2026-10-12");
    await page.getByRole("combobox", { name: "Activity type" }).click();
    await page.getByRole("option", { name: "Command", exact: true }).click();
    expect(reads.length).toBe(initial);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect.poll(() => reads.at(-1)?.searchParams.get("username")).toBe("PAN");
    const query = reads.at(-1)!.searchParams;
    expect(Object.fromEntries(query)).toMatchObject({ username: "PAN", hostname: "pan-m5", session: "session-one", kind: "command", since: "2026-10-12T07:00:00.000Z", before: "2026-10-13T07:00:00.000Z" });
    await page.getByRole("button", { name: "Load more", exact: true }).click();
    await expect(page.getByText("2 activities loaded", { exact: true })).toBeVisible();
    expect(reads.at(-1)!.searchParams.get("cursor")).toBe("older-events");
    expect(reads.at(-1)!.searchParams.get("session")).toBe("session-one");
    await expect(page.getByRole("navigation", { name: "Matching sessions" }).getByRole("button", { name: /Session ID: session-one$/ })).toHaveCount(1);
    await expect(page.getByRole("region", { name: "Session details", exact: true })).toContainText("2 matching activities loaded");
    await expect(activity.getByRole("button", { name: /^Open event/ }).first()).toHaveAttribute("aria-label", /event-2/);
    await page.getByRole("button", { name: /Open event event-1:/ }).click();
    await expect(page.getByRole("region", { name: "Activity details" })).toContainText("Working tree clean");
    await expect(page.getByRole("region", { name: "Activity details" })).toContainText("session-one");
    await page.getByRole("button", { name: "View raw event" }).click();
    await expect(page.getByRole("dialog", { name: "Event evidence" })).toContainText("git status");
    await page.keyboard.press("Escape");
    for (const width of [1440, 1024, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      await page.getByRole("button", { name: "Search", exact: true }).scrollIntoViewIfNeeded();
      await expect(page.getByRole("button", { name: "Search", exact: true })).toBeInViewport();
      if (width === 390) {
        await page.getByRole("navigation", { name: "Matching sessions" }).getByRole("button").first().click();
        await page.getByRole("region", { name: "Activity details" }).scrollIntoViewIfNeeded();
        await expect(page.getByRole("region", { name: "Activity details" })).toBeInViewport();
      }
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: info.outputPath(`evidence-${width}.png`), fullPage: true, animations: "disabled" });
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.getByRole("button", { name: "Clear filters", exact: true }).click();
    await expect.poll(() => reads.at(-1)?.search).toBe("?limit=50");
    await expect(page.getByLabel("Session ID", { exact: true })).toHaveValue("");
    await expect(page.getByLabel("Date", { exact: true })).toHaveValue("");
    await expect(page.getByRole("status").filter({ hasText: "1 activity loaded" })).toBeVisible();
    failed = true;
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Activity temporarily unavailable" })).toBeVisible();
    await expect(activity).toContainText("git status");
    failed = false;
    await page.getByLabel("User name", { exact: true }).fill("nobody");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.getByText("No activity found", { exact: true })).toBeVisible();
    await expect(activity).toHaveCount(0);
    expect(telemetryReads).toBe(0);
  });

  test("calendar dates respect DST and changing the display zone preserves the applied window", async ({ page }) => {
    await auth(page);
    const reads: URL[] = [];
    await page.route("**/api/v1/events?*", route => { reads.push(new URL(route.request().url())); return route.fulfill({ json: { items: [], next_cursor: "" } }); });
    await page.goto("/evidence");
    await expect(page.getByRole("button", { name: "Search", exact: true })).toBeEnabled();
    for (const [date, since, before] of [["2026-03-08", "2026-03-08T08:00:00.000Z", "2026-03-09T07:00:00.000Z"], ["2026-11-01", "2026-11-01T07:00:00.000Z", "2026-11-02T08:00:00.000Z"]]) {
      await page.getByLabel("Date", { exact: true }).fill(date);
      await page.getByRole("button", { name: "Search", exact: true }).click();
      await expect.poll(() => reads.at(-1)?.searchParams.get("since")).toBe(since);
      expect(reads.at(-1)!.searchParams.get("before")).toBe(before);
    }
    const beforeSwitch = reads.length;
    await page.getByRole("radio", { name: "UTC", exact: true }).check();
    await expect(page.getByText("Date (UTC)", { exact: true })).toBeVisible();
    expect(reads.length).toBe(beforeSwitch);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect.poll(() => reads.at(-1)?.searchParams.get("since")).toBe("2026-11-01T00:00:00.000Z");
    expect(reads.at(-1)!.searchParams.get("before")).toBe("2026-11-02T00:00:00.000Z");
  });

  test("session selection preserves every record and separates devices, agents, and missing identities", async ({ page }) => {
    await auth(page);
    const items: AgentEvent[] = [command, prompt,
      { ...command, id: "different-user", host: { ...command.host, user: "different-report" } },
      { ...command, id: "different-device", sensor_id: "sensor-2", session_id: "server-2" },
      { ...command, id: "different-agent", agent: { product: "claude-code" }, session_id: "server-3" },
      { ...command, id: "unattributed-1", session: undefined, session_id: null },
      { ...command, id: "unattributed-2", session: undefined, session_id: null },
      { ...command, id: "server-session", session: undefined, session_id: "server-fallback" },
      { ...command, id: "server-session-2", session: undefined, session_id: "server-fallback" },
    ];
    await page.route("**/api/v1/events?*", route => route.fulfill({ json: { items, next_cursor: "" } }));
    await page.goto("/evidence");
    const sessions = page.getByRole("navigation", { name: "Matching sessions" });
    const activity = page.getByRole("region", { name: "Session activity" });
    await expect(sessions.getByRole("button")).toHaveCount(6);
    await expect(sessions.getByRole("button", { name: /Session ID: session-one$/ })).toHaveCount(3);
    await expect(sessions.getByRole("button", { name: /Session not reported$/ })).toHaveCount(2);
    await expect(sessions.getByRole("button", { name: /Session ID: server-fallback$/ })).toHaveCount(1);
    const seen: string[] = [];
    for (const button of await sessions.getByRole("button").all()) {
      await button.focus();
      await page.keyboard.press("Enter");
      await expect(button).toHaveAttribute("aria-current", "true");
      const rows = activity.getByRole("button", { name: /^Open event/ });
      seen.push(...await rows.evaluateAll(elements => elements.map(element => element.getAttribute("aria-label")!.split(":")[0].replace("Open event ", ""))));
      if ((await rows.allTextContents()).some(text => text.includes("Simplify evidence search."))) {
        await expect(rows).toHaveCount(3);
        await expect(rows.first()).toHaveAttribute("aria-label", /event-2/);
        await activity.getByRole("button", { name: /^Open event different-user:/ }).click();
        await expect(activity.getByRole("region", { name: "Activity details" })).toContainText("different-report");
      }
    }
    expect(seen.sort()).toEqual(items.map(item => item.id).sort());
  });

  test("session panels scroll independently, retain selection on load and refresh, and fit narrow screens", async ({ page }, info) => {
    await auth(page);
    const sessionId = "019a80c6-80e0-7000-8000-000000000001";
    const sessionIds = [sessionId, ...Array.from({ length: 11 }, (_, index) => `019a80c6-80e0-7000-8000-${String(index + 2).padStart(12, "0")}`)];
    const main: AgentEvent[] = Array.from({ length: 18 }, (_, index) => ({
      ...command, id: `activity-${index}`, session: { ...command.session, id: sessionId },
      time: new Date(Date.parse(command.time) - index * 60_000).toISOString(),
      ...(index % 3 === 0 ? { kind: "prompt", text: "Review the dashboard changes and verify the evidence search filters.", command: undefined, tool: undefined }
        : index % 3 === 1 ? { kind: "tool.result", command: undefined, tool: { name: "exec_command", output: "All focused browser tests passed.\nNo errors found." } }
        : { command: { text: "git diff -- apps/dashboard/src/app/evidence/page.tsx" } }),
    }));
    const others: AgentEvent[] = sessionIds.slice(1).map((id, index) => ({
      ...prompt, id: `session-event-${index}`, time: new Date(Date.parse(command.time) - (index + 20) * 60_000).toISOString(),
      sensor_id: index % 2 ? "sensor-build" : "sensor-dev", session_id: `server-${index + 2}`, session: { id, cwd: `/Users/reviewer/projects/${"long-project-name/".repeat(12)}` },
      host: { user: "reviewer", hostname: index % 2 ? "build-mac.local" : "dev-workstation.local" },
      agent: { product: index % 2 ? "claude-code" : "codex-cli" }, text: `Review task ${index + 2} and check the implementation.`,
    }));
    let items = [...main, ...others];
    const older = { ...others[0], id: "older-activity", time: "2026-10-11T10:00:00Z", text: "Earlier activity in the selected session." };
    await page.route("**/api/v1/events?*", route => route.fulfill({ json: new URL(route.request().url()).searchParams.has("cursor")
      ? { items: [older], next_cursor: "" } : { items, next_cursor: "older" } }));
    await page.goto("/evidence");
    await page.getByLabel("Date", { exact: true }).fill("2026-10-12");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    const sessions = page.getByRole("navigation", { name: "Matching sessions" });
    const details = page.getByRole("region", { name: "Session details", exact: true });
    const activity = page.getByRole("region", { name: "Session activity" });
    await expect(sessions.getByRole("button")).toHaveCount(12);
    await expect(sessions.getByRole("button").first()).toHaveAttribute("aria-current", "true");
    for (const width of [1920, 1440, 1024, 390]) {
      await page.setViewportSize({ width, height: 900 });
      await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
      expect(await sessions.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true);
      if (width < 1024) {
        await expect(details).toBeHidden();
        await sessions.getByRole("button").first().click();
        await expect(sessions).toBeHidden();
        await expect(details).toBeVisible();
      }
      expect(await activity.evaluate(element => element.scrollHeight > element.clientHeight)).toBe(true);
      if (width >= 1024) {
        const left = (await sessions.boundingBox())!;
        const right = (await details.boundingBox())!;
        expect(left.x + left.width).toBeLessThanOrEqual(right.x + 1);
      }
      await activity.getByRole("button", { name: /^Open event/ }).last().scrollIntoViewIfNeeded();
      await expect(activity.getByRole("button", { name: /^Open event/ }).last()).toBeInViewport();
      if (width >= 1024) expect(await sessions.evaluate(element => element.scrollTop)).toBe(0);
      await activity.evaluate(element => element.scrollTop = 0);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: info.outputPath(`evidence-sessions-${width}.png`), fullPage: true, animations: "disabled" });
      if (width < 1024) {
        await details.getByRole("button", { name: "Sessions", exact: true }).click();
        await expect(sessions).toBeVisible();
      }
    }
    await page.setViewportSize({ width: 1440, height: 900 });
    const nextSession = sessions.getByRole("button", { name: new RegExp(`Session ID: ${sessionIds[1]}$`) });
    await nextSession.click();
    await expect(details).toContainText(sessionIds[1]);
    await expect(activity.getByRole("button", { name: /^Open event/ })).toHaveCount(1);
    await page.getByRole("button", { name: "Load more", exact: true }).click();
    await expect(activity.getByRole("button", { name: /^Open event/ })).toHaveCount(2);
    await expect(activity.getByRole("button", { name: /^Open event/ }).first()).toHaveAttribute("aria-label", /older-activity/);
    await expect(nextSession).toHaveAttribute("aria-current", "true");
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(activity.getByRole("button", { name: /^Open event/ })).toHaveCount(1);
    await expect(details).toContainText(sessionIds[1]);
    items = main;
    await page.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(sessions.getByRole("button")).toHaveCount(1);
    await expect(details).toContainText(sessionId);
    await expect(activity.getByRole("button", { name: /^Open event/ })).toHaveCount(18);
  });

  test("shared activity styles filter loaded records without merging evidence or changing the search", async ({ page }, info) => {
    await auth(page);
    const items: AgentEvent[] = [prompt,
      { ...command, tool: { name: "exec_command", call_id: "call-1" } },
      { ...command, id: "result", kind: "tool.result", command: undefined, tool: { name: "exec_command", call_id: "call-1", output: "README.md\nsrc/" } },
      { ...prompt, id: "response", kind: "response", text: "The working tree is clean." },
      { ...command, id: "allowed", kind: "hook.decision", command: undefined, source: { collector: "hook" }, hook: { hook_event: "PreToolUse", decision: "allow" } },
      { ...command, id: "denied", kind: "hook.decision", command: undefined, source: { collector: "hook" }, hook: { hook_event: "PreToolUse", decision: "deny" } },
      { ...command, id: "native", kind: "hook.decision", command: undefined, source: "otlp", hook: { hook_event: "tool_decision", decision: "approved" } },
      { ...prompt, id: "session-end", kind: "session.end", text: "Session ended" },
      { ...prompt, id: "sensor-event", kind: "sensor", text: "Sensor record" },
      { ...prompt, id: "older", time: "2026-10-11T18:48:18Z", text: "Earlier prompt with JeV as captured evidence." },
    ];
    let reads = 0;
    await page.route("**/api/v1/events?*", route => {
      reads++;
      return route.fulfill({ json: { items, next_cursor: "" } });
    });
    await page.goto("/evidence");
    await page.getByRole("button", { name: "Clear filters", exact: true }).click();
    const activity = page.getByRole("region", { name: "Session activity" });
    const details = page.getByRole("region", { name: "Session details", exact: true });
    const sessions = page.getByRole("navigation", { name: "Matching sessions" });
    const filters = details.getByRole("list", { name: "Filter timeline by category" });
    await expect(activity.locator("[data-event-id]")).toHaveCount(items.length);
    await expect(activity.getByRole("heading", { name: "Oct 11, 2026" })).toBeVisible();
    await expect(activity.getByRole("heading", { name: "Oct 12, 2026" })).toBeVisible();
    await expect(sessions.getByRole("heading", { name: /pan-m5.local/ })).toBeVisible();
    await expect(sessions.locator('[data-slot="agent-logo"]')).toHaveAttribute("src", "/agent-icons/codex.png");
    await expect(sessions.getByRole("button")).toContainText("Simplify evidence search.");
    const searchReads = reads;
    for (const [category, label, count] of [
      ["prompt", "Prompt", 2], ["tool", "Tool call", 1], ["result", "Tool result", 1],
      ["response", "Response", 1], ["decision", "Policy", 3], ["session", "Session", 1],
    ] as const) {
      const badge = activity.locator(`[data-category="${category}"] [data-variant="activity"]`).first();
      const chip = filters.getByRole("button", { name: label, exact: true });
      await expect(badge).toHaveText(label);
      const color = await badge.evaluate(element => getComputedStyle(element).backgroundColor);
      await expect(badge).toHaveCSS("color", "rgb(255, 255, 255)");
      await expect(chip).toHaveCSS("background-color", color);
      await chip.focus();
      await page.keyboard.press("Space");
      await expect(chip).toHaveAttribute("aria-pressed", "true");
      await expect(activity.locator("[data-event-id]")).toHaveCount(count);
      await expect(details).toContainText(`${count} shown`);
      await details.getByRole("button", { name: "Show all kinds" }).click();
      await expect(activity.locator("[data-event-id]")).toHaveCount(items.length);
    }
    expect(reads).toBe(searchReads);
    await expect(activity.locator('[data-event-id="allowed"]')).toContainText("Guardrail decision: allow");
    await expect(activity.locator('[data-event-id="denied"]')).toContainText("Guardrail decision: deny");
    await expect(activity.locator('[data-event-id="native"]')).toContainText("Agent permission: approved");
    await activity.getByRole("button", { name: /^Open event event-1:/ }).click();
    await activity.getByRole("button", { name: /^Open event older:/ }).click();
    await expect(activity.getByRole("region", { name: "Activity details" })).toHaveCount(1);
    await expect(activity.getByRole("region", { name: "Activity details" })).toContainText("Earlier prompt with JeV as captured evidence.");
    await filters.getByRole("button", { name: "Policy", exact: true }).click();
    await activity.getByRole("button", { name: /^Open event native:/ }).click();
    await expect(activity.getByRole("region", { name: "Activity details" })).toContainText("Native telemetry");
    await details.getByRole("button", { name: "Show all kinds" }).click();
    await page.screenshot({ path: info.outputPath("evidence-activity-styles.png"), fullPage: true, animations: "disabled" });
  });
});
