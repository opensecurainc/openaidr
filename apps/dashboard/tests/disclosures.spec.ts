import { test, expect, type Page } from "@playwright/test";
import type { Overview } from "@/lib/api";

async function mockApi(page: Page, role = "") {
  await page.route("**/api/v1/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("auth/me"))
      return route.fulfill({ json: { user: {
        id: "u", name: "Test operator", email: "test@example.invalid", roles: role ? [role] : ["it_admin", "security_analyst", "security_leadership"],
        tenant: { id: "t", name: "Test tenant", slug: "test" },
      } } });
    if (path.endsWith("telemetry/overview"))
      return route.fulfill({ json: {
        range: "24h", service: null, bucket_seconds: 3600,
        generated_at: "2026-09-30T00:00:00Z", window_start: "2026-09-29T00:00:00Z",
        summary: {
          exports: 0, records: 0, log_records: 0, metric_points: 0, spans: 0,
          devices: 0, online_devices: 0, offline_devices: 0, disabled_devices: 0,
          last_export_at: null,
        },
        activity: [], available_services: [], services: [], devices: [], recent_exports: [],
      } satisfies Overview });
    if (path.endsWith("response/session-detection"))
      return route.fulfill({ json: { enabled: false, version: 0, detector_config_version: 0, selection_policy: "risk_budget",
        investigation_percent: "1", sample_percent: "0", history_days: 7, action_risk_threshold: 70, urgent_risk_threshold: 95,
        session_high_risk_actions: 2, user_high_risk_actions: 3 } });
    if (path.endsWith("response/policy"))
      return route.fulfill({ json: { version: 1, rules: [], updated_at: null } });
    if (path.endsWith("response/company-policy"))
      return route.fulfill({ json: { revision: 0, prompt: "", updated_at: null } });
    if (path.endsWith("knowledge/library"))
      return route.fulfill({ json: { enabled: false, revision: 1, documents: [], retrieval_mode: "legacy", sources: [] } });
    if (path.endsWith("knowledge/mcp"))
      return route.fulfill({ json: { connections: [] } });
    if (path.endsWith("/events"))
      return route.fulfill({ json: {
        items: Array.from({ length: 50 }, (_, index) => ({
          id: `event-${index}`, time: "2026-09-30T00:00:00Z", kind: "command",
          command: { text: `echo event-${index}` },
          agent: { product: "Test agent" }, host: { hostname: "test-host" },
        })),
        next_cursor: "",
      } });
    if (path.endsWith("system/database"))
      return route.fulfill({ json: { ok: false, checked_at: new Date().toISOString(), latency_ms: null, pools: [], activity: null } });
    if (path.endsWith("system/status"))
      return route.fulfill({ json: {
        version: "test", services: [], database: { ok: true, latency_ms: 2 },
        ingest: { sensors_online: 0, events_last_hour: 0 },
      } });
    if (path.endsWith("system/metrics"))
      return route.fulfill({ json: {
        status: "waiting", message: "Waiting for the first host sample.",
        hostname: null, interval_seconds: 60, last_sample_at: null, samples: [],
      } });
    if (path.endsWith("costs/detections"))
      return route.fulfill({ json: {
        since: "2026-09-29T00:00:00Z", until: "2026-09-30T00:00:00Z", bucket_seconds: 3600,
        summary: { calls: 0, usage_calls: 0, priced_calls: 0, unpriced_calls: 0, pending_calls: 0, failed_calls: 0, input_tokens: null, output_tokens: null, tokens: null, cost_usd: null },
        series: [], by_model: [], by_purpose: [],
      } });
    if (path.endsWith("costs/agents/summary"))
      return route.fulfill({ json: {
        range: "24h", since: "2026-09-29T00:00:00Z", until: "2026-09-30T00:00:00Z",
        price_date: "2026-09-30", bucket_seconds: 3600,
        summary: {
          calls: 1, tokens: 100, cost_usd: null, priced_calls: 0, unpriced_calls: 1,
          reported_calls: 0, calculated_calls: 0, demo_calls: 0,
        },
        series: [], available_filters: { user: [], model: [], project: [], activity: [], reasoning_effort: [] },
        filters_truncated: { user: false, model: false, project: false, activity: false, reasoning_effort: false },
        pagination: Object.fromEntries(["user", "model", "project", "activity", "reasoning_effort"].map((dimension) => [dimension, {
          offset: 0, limit: 50, total: 0, maximum: null, sort: "cost_usd", order: "desc",
        }])),
        by_user: [], by_model: [], by_project: [], by_activity: [], by_reasoning_effort: [],
      } });
    if (path.endsWith("response/session-detection")) return route.fulfill({ json: { enabled: false, version: 1, detector_config_version: 2, selection_policy: "legacy", model: "gpt-6.1-sol" } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

const pages = [
  ["/security-posture", [["Configuration does not prove coverage", "Configured prevention rules do not confirm that actions are protected"]]],
  ["/detection-rules", [["Configuration does not prove coverage", "Enabled rules do not confirm that detection is running"]]],
  ["/evidence", [["Search coverage", "Search all retained agent events"]]],
  ["/administration/app", [["How sensor counts are reported", "Pending exports are reported by the sensor heartbeat"]]],
  ["/administration/server", [["Reading component status", "A missing heartbeat means the component has not reported"]]],
  ["/administration/users", [["Role permissions", "Users can have multiple roles."]]],
  ["/administration/enrollment", [["Separate enrollment and sensor credentials", "Enrollment tokens register devices"]]],
  ["/costs/agents", [["How cost estimates are calculated", "Estimates use agent-reported costs or published token rates"]]],
  ["/ai-supply-chain", [["How scan coverage works", "Each row is a reported scan location."]]],
  ["/costs/openaidr", [["How costs are measured", "Input and output tokens come from model responses."]]],
] as const;

test("dashboard explanations open on demand on narrow screens", async ({ page }) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await mockApi(page);
  await page.setViewportSize({ width: 390, height: 844 });
  for (const [path, disclosures] of pages) {
    await test.step(path, async () => {
      await page.goto(path);
      if (path === "/ai-supply-chain") {
        await page.getByRole("button", { name: "Collection details", exact: true }).click();
      }
      for (const [title, text] of disclosures) {
        const label = page.getByText(title, { exact: true });
        const explanation = page.getByText(text, { exact: false });
        await expect(label).toBeVisible();
        await expect(explanation).toBeHidden();
        await label.click();
        await expect(explanation).toBeVisible();
        expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
        await label.click();
        await expect(explanation).toBeHidden();
      }
      await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
    });
  }
  expect(errors).toEqual([]);
});

test("search explanations stay beside the data they describe", async ({ page }) => {
  await mockApi(page);
  await page.goto("/evidence");
  await expect(page.getByRole("searchbox", { name: "User name" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Matching sessions" }).getByRole("button")).toHaveCount(50);
  await expect(page.getByRole("region", { name: "Session activity" }).getByRole("button", { name: /^Open event/ })).toHaveCount(1);
  const label = page.getByText("Search coverage", { exact: true });
  await label.scrollIntoViewIfNeeded();
  await expect(label).toBeInViewport();
  await page.setViewportSize({ width: 390, height: 844 });
  await label.scrollIntoViewIfNeeded();
  await expect(label).toBeInViewport();
  const scope = page.getByText("Search all retained agent events", { exact: false });
  await expect(scope).toBeHidden();
  await label.click();
  await expect(scope).toBeVisible();
  await expect(scope).toContainText("session IDs match literal text, including partial IDs");
});

test("detection rules follow evidence search in desktop and mobile navigation", async ({ page }, info) => {
  await mockApi(page, "security_analyst");
  await page.route("**/api/v1/detections/rules", (route) => route.fulfill({ json: { items: [
    { id: "command", name: "Command review", description: "Review destructive commands.", severity: "high", enabled: true, findings_30d: 3 },
    { id: "guardrail", name: "JEV review", description: "JEV assessments.", severity: "medium", enabled: false, findings_30d: 0 },
  ] } }));
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await page.goto("/security-posture");
    await expect(page.getByRole("region", { name: "Prevention policy", exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Detection rules", exact: true })).toHaveCount(0);
    if (width === 390) await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    const nav = page.getByRole("navigation", { name: "Workspace navigation" });
    const group = nav.locator("div").filter({ has: page.getByText("Detection and Response", { exact: true }) });
    await expect(group.getByRole("link")).toHaveText(["Risky Sessions/Users", "Detection Queue", "Evidence Search", "Detection Rules"]);
    const link = group.getByRole("link", { name: "Detection Rules", exact: true });
    await expect(link).toHaveAttribute("href", "/detection-rules");
    await link.click();
    await expect(page).toHaveURL(/\/detection-rules$/);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Detection Rules");
    if (width === 1440) {
      await expect(link).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Detection and Response");
    } else {
      await expect(page.getByRole("dialog", { name: "Workspace navigation" })).toBeHidden();
    }
    const rules = page.getByRole("region", { name: "Detection rules", exact: true });
    await expect(rules.getByRole("switch")).toHaveCount(2);
    await expect(rules).toContainText("1 enabled of 2 configured rules. Finding counts cover the last 30 days.");
    await expect(rules.getByRole("heading", { level: 3 })).toHaveText(["Command review", "Guardrail review"]);
    const commandDescription = rules.getByText("Review destructive commands.", { exact: true });
    const guardrailDescription = rules.getByText("Guardrail assessments.", { exact: true });
    await expect(commandDescription).toBeHidden();
    await expect(guardrailDescription).toBeHidden();
    const commandSummary = rules.locator("summary").filter({ hasText: "Command review" });
    await commandSummary.focus();
    await page.keyboard.press("Enter");
    await expect(commandDescription).toBeVisible();
    await page.keyboard.press("Space");
    await expect(commandDescription).toBeHidden();
    const guardrailSummary = rules.locator("summary").filter({ hasText: "Guardrail review" });
    await guardrailSummary.click();
    await expect(guardrailDescription).toBeVisible();
    await guardrailSummary.click();
    await expect(guardrailDescription).toBeHidden();
    for (const text of ["high", "medium", "3 findings in 30 days", "0 findings in 30 days"]) {
      await expect(rules.getByText(text, { exact: true })).toBeVisible();
    }
    await expect(rules.getByRole("switch").first()).toBeChecked();
    await expect(rules.getByRole("switch").last()).not.toBeChecked();
    const explanation = page.getByText("Enabled rules do not confirm that detection is running", { exact: false });
    await expect(explanation).toBeHidden();
    await page.getByText("Configuration does not prove coverage", { exact: true }).click();
    await expect(explanation).toBeVisible();
    await expect(page.getByText("Disabling a rule stops new findings", { exact: false })).toBeVisible();
    await page.getByText("Configuration does not prove coverage", { exact: true }).click();
    await expect(explanation).toBeHidden();
    await expect(page.getByRole("region", { name: "Prevention policy", exact: true })).toHaveCount(0);
    await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`detection-rules-${width}.png`), fullPage: true });
    await expect(page.locator("main").getByRole("link", { name: "Check Server Health", exact: true })).toHaveCount(0);
  }
});

for (const [role, width] of [["security_analyst", 1440], ["security_analyst", 390]] as const) {
  test(`${role} can toggle detection rules at ${width}px`, async ({ page }, info) => {
    await mockApi(page, role);
    await page.setViewportSize({ width, height: 1080 });
    const items = [
      { id: "command", name: "Command review", description: "Review destructive commands.", severity: "high", enabled: true, findings_30d: 3 },
      { id: "guardrail", name: "JEV review", description: "JEV assessments.", severity: "medium", enabled: false, findings_30d: 0 },
    ];
    let releaseSave!: () => void;
    const saveGate = new Promise<void>((resolve) => { releaseSave = resolve; });
    const changes: { id: string; enabled: boolean }[] = [];
    await page.route("**/api/v1/detections/rules**", async (route) => {
      if (route.request().method() === "GET") return route.fulfill({ json: { items } });
      expect(route.request().method()).toBe("PATCH");
      expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
      const id = new URL(route.request().url()).pathname.split("/").at(-1)!;
      const body = route.request().postDataJSON();
      expect(Object.keys(body)).toEqual(["enabled"]);
      expect(typeof body.enabled).toBe("boolean");
      changes.push({ id, enabled: body.enabled });
      await saveGate;
      const item = items.find((item) => item.id === id)!;
      item.enabled = body.enabled;
      return route.fulfill({ json: item });
    });
    await page.goto("/detection-rules");
    const rules = page.getByRole("region", { name: "Detection rules", exact: true });
    const command = rules.getByRole("switch", { name: "Enable Command review", exact: true });
    const guardrail = rules.getByRole("switch", { name: "Enable Guardrail review", exact: true });
    await expect(command).toBeChecked();
    await expect(guardrail).not.toBeChecked();
    await expect(rules.locator("details[open]")).toHaveCount(0);
    await command.click();
    await expect(rules.locator("details[open]")).toHaveCount(0);
    await expect(rules.getByText("Saving…", { exact: true })).toBeVisible();
    await expect(command).toBeChecked();
    await expect(command).toBeDisabled();
    await expect(guardrail).toBeDisabled();
    await expect(rules.getByRole("button", { name: "Refresh", exact: true })).toBeDisabled();
    await expect.poll(() => changes).toEqual([{ id: "command", enabled: false }]);
    releaseSave();
    await expect(command).not.toBeChecked();
    await expect(rules).toContainText("0 enabled of 2 configured rules.");
    await rules.locator("summary").filter({ hasText: "Command review" }).click();
    await expect(rules.getByText("Review destructive commands.", { exact: true })).toBeVisible();
    await expect(guardrail).toBeEnabled();
    await guardrail.focus();
    await page.keyboard.press("Space");
    await expect(guardrail).toBeChecked();
    await expect(rules.getByText("Review destructive commands.", { exact: true })).toBeVisible();
    await expect(rules.getByText("Guardrail assessments.", { exact: true })).toBeHidden();
    expect(changes).toEqual([{ id: "command", enabled: false }, { id: "guardrail", enabled: true }]);
    await page.reload();
    await expect(command).not.toBeChecked();
    await expect(guardrail).toBeChecked();
    await expect(rules.locator("details[open]")).toHaveCount(0);
    await expect(rules).toContainText("1 enabled of 2 configured rules.");
    await expect(rules.getByText("3 findings in 30 days", { exact: true })).toBeVisible();
    await expect(rules.getByRole("alert")).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`detection-rule-toggles-${width}.png`), fullPage: true, animations: "disabled" });
  });
}

test("ten detection rules stay compact with full descriptions available", async ({ page }, info) => {
  await mockApi(page);
  const names = [
    "Codex session investigation", "Data upload command", "Destructive command",
    "Deletion after tool error", "Action blocked by policy", "Jev risk detection",
    "Write outside the workspace", "Secret file access", "Secret access followed by egress",
    "Tool install from unknown source",
  ];
  const items = names.map((name, index) => ({
    id: `rule-${index}`, name,
    description: `${name}: Review the captured action and its surrounding session context. Findings retain the observed evidence and outcome. Disabling this rule suppresses new findings while retaining existing records.`,
    severity: ["medium", "high", "high", "medium", "low", "medium", "medium", "medium", "critical", "high"][index],
    enabled: index !== 7, findings_30d: index === 4 ? 15886 : index === 2 ? 2 : 0,
  }));
  await page.route("**/api/v1/detections/rules", (route) => route.fulfill({ json: { items } }));
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
    await page.goto("/detection-rules");
    const rules = page.getByRole("region", { name: "Detection rules", exact: true });
    await expect(rules.getByRole("switch")).toHaveCount(10);
    await expect(rules.locator("details[open]")).toHaveCount(0);
    await expect(rules.getByText("15,886 findings in 30 days", { exact: true })).toBeVisible();
    const firstDescription = rules.getByText(items[0].description, { exact: true });
    await expect(firstDescription).toBeHidden();
    if (width === 1440) {
      expect((await rules.boundingBox())!.height).toBeLessThan(560);
      await expect(rules.getByRole("switch").last()).toBeInViewport();
    }
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`compact-detection-rules-${width}.png`), fullPage: true, animations: "disabled" });
    await rules.locator("summary").first().click();
    await expect(firstDescription).toBeVisible();
    await expect(rules.getByRole("switch").first()).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`compact-detection-rules-expanded-${width}.png`), fullPage: true, animations: "disabled" });
  }
});

test("IT Admin alone cannot view or toggle detection rules", async ({ page }) => {
  await mockApi(page, "it_admin");
  const mutations: string[] = [];
  await page.route("**/api/v1/detections/rules**", (route) => {
    if (route.request().method() !== "GET") mutations.push(route.request().method());
    return route.fulfill({ json: { items: [
      { id: "command", name: "Command review", description: "Review destructive commands.", severity: "high", enabled: true, findings_30d: 3 },
    ] } });
  });
  await page.goto("/detection-rules");
  const rules = page.getByRole("region", { name: "Detection rules", exact: true });
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(rules.getByRole("switch")).toHaveCount(0);
  expect(mutations).toEqual([]);
});

for (const failure of ["forbidden", "lost response"] as const) {
  test(`detection rule toggles reconcile ${failure} and permit retry`, async ({ page }) => {
    await mockApi(page);
    const item = { id: "command", name: "Command review", description: "Review destructive commands.", severity: "high", enabled: true, findings_30d: 3 };
    let failSave = true;
    let failRead = false;
    await page.route("**/api/v1/detections/rules**", (route) => {
      if (route.request().method() === "GET") {
        return failRead
          ? route.fulfill({ status: 503, json: { error: { message: "Rules unavailable" } } })
          : route.fulfill({ json: { items: [item] } });
      }
      if (failSave && failure === "forbidden") {
        return route.fulfill({ status: 403, json: { error: { message: "Requires admin role" } } });
      }
      item.enabled = route.request().postDataJSON().enabled;
      return failSave ? route.abort("failed") : route.fulfill({ json: item });
    });
    await page.goto("/detection-rules");
    const rules = page.getByRole("region", { name: "Detection rules", exact: true });
    const toggle = rules.getByRole("switch", { name: "Enable Command review", exact: true });
    await expect(toggle).toBeChecked();
    await toggle.click();
    await expect(rules.getByRole("alert")).toBeVisible();
    await expect(rules.getByText(item.description, { exact: true })).toBeHidden();
    await expect(toggle).toBeEnabled();
    await expect(toggle).toBeChecked({ checked: failure === "forbidden" });
    if (failure === "forbidden") await expect(rules.getByRole("alert")).toHaveText("Requires admin role");

    failSave = false;
    await toggle.click();
    await expect(toggle).toBeChecked({ checked: failure !== "forbidden" });
    await expect(rules.getByRole("alert")).toHaveCount(0);

    failRead = true;
    await rules.getByRole("button", { name: "Refresh", exact: true }).click();
    await expect(rules.getByRole("alert")).toContainText("Showing stale data");
    await expect(toggle).toBeDisabled();
    failRead = false;
    await rules.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(toggle).toBeEnabled();
    await expect(rules.getByRole("alert")).toHaveCount(0);
  });
}

test("disclosures preserve required actions and notices", async ({ page }, info) => {
  await mockApi(page);
  let policyUnavailable = true;
  await page.route("**/api/v1/response/policy", (route) => policyUnavailable
    ? route.fulfill({ status: 503, json: { error: { message: "Policy unavailable" } } })
    : route.fallback());
  await page.goto("/security-posture");
  const health = page.locator("main").getByRole("link", { name: "Check Server Health", exact: true });
  await expect(health).toBeVisible();
  const policy = page.getByRole("region", { name: "Prevention policy", exact: true });
  await expect(policy).toContainText("Tenant policy evaluated by the backend for installed hooks.");
  await expect(policy).not.toContainText("delivered to compatible sensor hooks");
  await expect(policy.getByRole("alert")).toContainText("Policy unavailable");
  await policy.screenshot({ path: info.outputPath("backend-policy-description.png"), animations: "disabled" });
  policyUnavailable = false;
  await policy.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(policy).toContainText("No prevention rules configured.");
  await expect(policy.getByRole("status")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Detection rules", exact: true })).toHaveCount(0);
  const [policyBox, main] = await Promise.all([
    policy.boundingBox(), page.locator("main").boundingBox(),
  ]);
  expect(policyBox!.width).toBeGreaterThan(main!.width * 0.8);
  expect(policyBox!.height).toBeLessThan(160);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(health).toBeVisible();
  await expect(page.getByText("Configured prevention rules do not confirm that actions are protected", { exact: false })).toBeHidden();
  await health.click();
  await expect(page).toHaveURL(/\/administration\/server$/);
  await expect(page.getByRole("heading", { name: "API health", exact: true })).toBeVisible();

  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.route("**/api/v1/response/policy", (route) => route.fulfill({ json: {
    version: 1, updated_at: null,
    rules: [{ id: "jev-review", name: "JEV review", reason: "Block requests to jev.example", action: "ask", enabled: true,
      match: { kinds: ["command"], products: ["JevAgent"], tool_name: "JevModel",
        command_regex: "/usr/local/bin/jev\\b", path_glob: "/tmp/JeV/**", host_glob: "jev.example" },
    }],
  } }));
  await page.goto("/security-posture");
  await expect(page.getByRole("heading", { name: "Guardrail review", exact: true })).toBeVisible();
  await expect(page.getByText("Block requests to jev.example", { exact: true })).toBeVisible();
  await page.goto("/company-knowledge#fixed-rules");
  await expect(page.getByText("Guardrail review", { exact: true })).toBeVisible();
  await expect(page.getByText("Block requests to jev.example", { exact: true })).toBeVisible();
  const rule = page.getByRole("row").filter({ has: page.getByText("Guardrail review", { exact: true }) });
  await expect.poll(() => rule.getByRole("listitem").allTextContents()).toEqual([
    "Kinds: command", "Products: JevAgent", "Tool: JevModel",
    "Command regex: /usr/local/bin/jev\\b", "Path: /tmp/JeV/**", "Host: jev.example",
  ]);
  await page.setViewportSize({ width: 390, height: 844 });

  await page.route("**/api/v1/auth/me", (route) => route.fulfill({ json: { user: {
    id: "u", name: "Test operator", email: "test@example.invalid", roles: ["security_leadership"],
    tenant: { id: "t", name: "Test tenant", slug: "test" },
  } } }));
  await page.goto("/administration/enrollment");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(page.locator("summary")).toHaveCount(0);

  await page.goto("/costs/agents");
  await expect(page.getByText("1 calls have no price available.", { exact: false })).toBeVisible();
  await expect(page.getByText("Cost estimates are unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("Estimates use agent-reported costs", { exact: false })).toBeHidden();
});
