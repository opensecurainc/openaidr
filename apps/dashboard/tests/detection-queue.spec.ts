import { expect, test, type Page } from "@playwright/test";

async function mockApi(page: Page, roles = ["security_analyst"]) {
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me")) {
      return route.fulfill({ json: { user: {
        id: "viewer", name: "Test operator", email: "test@example.invalid", roles,
        tenant: { id: "tenant", name: "Test tenant", slug: "test" },
      } } });
    }
    if (url.pathname.startsWith("/api/v1/detections/"))
      return route.fulfill({ status: 503, json: { error: { message: "Detection data unavailable" } } });
    if (url.pathname.endsWith("/knowledge"))
      return route.fulfill({ json: { enabled: false, revision: 0, documents: [] } });
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
}

const queue = (page: Page) => page.frameLocator('iframe[title="Detection Queue cases with sample data"]');

test("the Detection Queue preview lists sample cases and reads no detections", async ({ page }) => {
  const reads: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (/^\/api\/v1\/(detections|session-investigations|findings)/.test(path)) reads.push(path);
  });
  await mockApi(page);
  await page.goto("/detections/preview");
  await expect(page.getByRole("heading", { level: 1, name: "Detection Queue preview" })).toBeVisible();
  await expect(page.getByText("illustrative sample data", { exact: false }).first()).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Detection Queue view" })).toHaveCount(0);
  const cases = queue(page);
  // The console supplies navigation and the page title; the embedded copy hides its own.
  await expect(cases.locator(".sidebar")).toBeHidden();
  const titles = cases.locator("#reports tbody tr.clickable .name-btn");
  const respond = cases.locator(".ov-card", { hasText: "Need a response" }).locator(".ov-figure");
  await expect(respond).toHaveText("6");
  await cases.getByRole("link", { name: "Need a response" }).click();
  await expect(cases.locator("#report-signal")).toHaveValue("respond");
  await expect(titles).toHaveText([
    "One payload pushed at four destinations in 13 minutes",
    "Destructive migration run against the production database",
    "Attempted credential upload during repository review",
    "Customer export copied to a personal storage bucket",
    "Force-push overwrote main branch history",
    "Unpinned MCP server installed from an unverified repository",
  ]);
  // A case without an attack graph still opens in the drawer.
  await cases.getByRole("button", { name: "Attempted credential upload during repository review", exact: true }).click();
  const drawer = cases.locator("#drawer");
  await expect(drawer.getByRole("heading", { name: "Attempted credential upload during repository review" })).toBeVisible();
  await expect(drawer.getByText("Unconfirmed", { exact: true })).toBeVisible();
  await drawer.getByRole("button", { name: "Close" }).click();
  await cases.locator('#matrix button[data-cat="agent_compromise"][data-agent=""]').click();
  await expect(titles).toHaveText([
    "Unpinned MCP server installed from an unverified repository",
    "MCP tool output instructed the agent to read SSH keys",
  ]);
  await cases.locator('[data-range="7"]').click();
  await expect(respond).toHaveText("5");
  // On a phone, the tables and the outcome filter scroll inside their cards, not the page.
  await page.setViewportSize({ width: 390, height: 844 });
  const frame = page.frame({ url: "about:srcdoc" })!;
  await expect.poll(() => frame.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
  expect(reads).toEqual([]);
});

test("the top case opens its complete attack graph", async ({ page }) => {
  await mockApi(page);
  await page.goto("/detections/preview");
  const cases = queue(page);
  await cases.getByRole("button", { name: "One payload pushed at four destinations in 13 minutes", exact: true }).click();
  await expect(cases.locator("#drawer")).not.toBeVisible();
  await expect(cases.getByRole("heading", { name: "One payload pushed at four destinations in 13 minutes" })).toBeVisible();
  const graph = cases.getByRole("list", { name: "Attack graph entities" });
  const nodes = graph.getByRole("listitem");
  // Spine of four, three blocked dead ends, OpenAIDR AI Control, and the response.
  await expect(nodes).toHaveCount(9);
  for (const [name, stamp] of [
    ["Personal repo: achen-dev/ledgerly", "Blocked · GR-07"],
    ["Unapproved tool: gdrive-mcp 1.4.0", "Blocked · SC-02"],
    ["External host: filebin.net", "Blocked · GR-12"],
    ["Approved SaaS: VEND-884 · Jira Cloud", "Blocked · AI Control"],
  ]) {
    const node = nodes.filter({ hasText: name.split(": ")[1] });
    await expect(node).toHaveCount(1);
    await expect(node.locator(".stamp")).toHaveText(stamp);
    await expect(node).toHaveAttribute("aria-label", new RegExp(`^${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
  }
  // The destination no rule matched carries no Guardrail tag; the dead ends do.
  await expect(nodes.filter({ hasText: "VEND-884" }).locator(".cap")).toHaveText(["Supply Chain", "Security Posture"]);
  await expect(nodes.filter({ hasText: "achen-dev/ledgerly" }).locator(".cap")).toHaveText(["Guardrail"]);
  await expect(nodes.filter({ hasText: "OpenAIDR AI Control" })).toContainText("94");
  // The session transcript shows every tool call in order with its decision.
  const transcript = cases.getByRole("list", { name: "Session transcript" }).getByRole("listitem");
  await expect(transcript.filter({ hasText: "Tool call" })).toHaveCount(9);
  await expect(transcript.filter({ hasText: "Blocked" }).locator(".dec")).toHaveText([
    "Blocked · GR-07", "Blocked · SC-02", "Blocked · GR-12", "Blocked · OpenAIDR AI Control",
  ]);

  // Every node shows its full text, sits inside the graph frame, and overlaps no other node.
  const clipped = await nodes.evaluateAll((els) => els.filter((el) => el.scrollHeight > el.clientHeight + 1
    || [...el.querySelectorAll(".t, .s, .cap")].some((c) => c.scrollHeight > c.clientHeight + 1 || c.scrollWidth > c.clientWidth + 1))
    .map((el) => el.getAttribute("aria-label")));
  expect(clipped).toEqual([]);
  const boxes = await nodes.evaluateAll((els) => els.map((el) => {
    const r = el.getBoundingClientRect();
    return { l: r.left, t: r.top, r: r.right, b: r.bottom };
  }));
  const frameBox = await cases.locator(".graph").evaluate((el) => el.getBoundingClientRect().toJSON());
  for (const [i, a] of boxes.entries()) {
    expect(a.l >= frameBox.left && a.r <= frameBox.right && a.t >= frameBox.top - 10 && a.b <= frameBox.bottom).toBe(true);
    for (const b of boxes.slice(i + 1)) expect(a.r <= b.l || b.r <= a.l || a.b <= b.t || b.b <= a.t).toBe(true);
  }

  // At phone width the graph scrolls inside its card and the page does not.
  await page.setViewportSize({ width: 390, height: 844 });
  const frame = page.frame({ url: "about:srcdoc" })!;
  await expect.poll(() => frame.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
  const scroller = cases.getByLabel("Attack graph, scrolls horizontally");
  expect(await scroller.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
  await scroller.evaluate((el) => { el.scrollIntoView({ block: "center" }); el.scrollLeft = el.scrollWidth; });
  await expect(nodes.filter({ hasText: "Session terminated" })).toBeInViewport();

  await cases.getByRole("button", { name: "Back to Detection Queue" }).click();
  await expect(cases.locator("#reports")).toBeVisible();
});

test("the preview links to the live Detection Queue without loading sample cases there", async ({ page }) => {
  const reads: string[] = [];
  const previews: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/session-investigations") reads.push(path);
    if (path.startsWith("/previews/")) previews.push(path);
  });
  await mockApi(page);
  await page.goto("/detections/preview");
  await expect(page.locator('iframe[title="Detection Queue cases with sample data"]')).toBeVisible();
  previews.length = 0;
  await page.getByRole("link", { name: "Open live Detection Queue" }).click();
  await expect(page).toHaveURL(/\/detections$/);
  await expect(page.getByText("No investigation reports match", { exact: true })).toBeVisible();
  await expect(page.locator("iframe")).toHaveCount(0);
  await expect(page.getByText("Sample data", { exact: true })).toHaveCount(0);
  expect(reads.length).toBeGreaterThan(0);
  expect(previews).toEqual([]);
});

test("the Detection Queue is restricted to Security Analysts", async ({ page }) => {
  const previews: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/previews/") || /^\/api\/v1\/(detections|session-investigations)/.test(path))
      previews.push(path);
  });
  await mockApi(page, ["it_admin", "security_leadership"]);
  for (const path of ["/detections", "/detections/preview"]) {
    await page.goto(path);
    await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
    await expect(page.locator("iframe")).toHaveCount(0);
    await expect(page.getByRole("region", { name: "Investigation reports", exact: true })).toHaveCount(0);
  }
  expect(previews).toEqual([]);
});

test("the Detection Queue is not loaded before sign-in", async ({ page }) => {
  const previews: string[] = [];
  page.on("request", (request) => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/previews/") || /^\/api\/v1\/(detections|session-investigations)/.test(path))
      previews.push(path);
  });
  await page.route("**/api/v1/auth/me", (route) =>
    route.fulfill({ status: 401, json: { error: { message: "Sign in" } } }),
  );
  await page.route("**/api/v1/auth/config", (route) =>
    route.fulfill({ json: { mode: "local", password_login: true } }),
  );
  for (const path of ["/detections", "/detections/preview"]) {
    await page.goto(path);
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.locator("iframe")).toHaveCount(0);
  }
  expect(previews).toEqual([]);
});
