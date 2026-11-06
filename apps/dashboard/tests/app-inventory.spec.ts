import { test, expect, type Page } from "@playwright/test";
import { alertApi, alertExample } from "./endpoint-alert-fixture";

const scanned = "2026-10-18T09:00:00Z";

test("inventory preview uses the shared publisher artwork for coding agents", async ({ page }, info) => {
  await page.route("https://www.google.com/s2/favicons**", (route) => route.abort());
  await page.goto("/previews/ai-inventory.html");
  for (const [name, icon] of [
    ["Codex CLI", "codex.png"], ["Claude Code", "claude-code.png"],
    ["GitHub Copilot", "github-copilot.png"], ["Cursor", "cursor.png"],
    ["Windsurf", "windsurf.svg"],
  ]) {
    const row = page.getByRole("row").filter({ has: page.getByRole("button", { name, exact: true }) }).first();
    const image = row.locator(".app-logo img");
    await image.scrollIntoViewIfNeeded();
    await expect(image).toHaveAttribute("src", `/agent-icons/${icon}`);
    await expect.poll(() => image.evaluate((node: HTMLImageElement) => node.complete && node.naturalWidth > 0)).toBe(true);
  }
  await page.getByRole("button", { name: "Codex CLI", exact: true }).first().click();
  await expect(page.locator('.drawer-title img')).toHaveAttribute("src", "/agent-icons/codex.png");
  await page.screenshot({ path: info.outputPath("inventory-agent-icons.png") });
});

const deviceUser = (index: number) =>
  index < 2
    ? "alice"
    : index < 5
      ? "bob"
      : index === 5
        ? ""
        : `developer-${index}`;
function users(devices: number) {
  const counts = new Map<string, number>();
  for (let i = 0; i < devices; i++)
    counts.set(deviceUser(i), (counts.get(deviceUser(i)) ?? 0) + 1);
  return Array.from(counts, ([user, device_count]) => ({ user, device_count }));
}
function research(
  levels: (number | null)[] = [3, 3, 3, 3],
  confidence = "high",
  riskScore?: number | null,
) {
  const fact = (level: number | null) => ({
    level,
    reason: level === null
      ? "The retrieved documentation does not establish this capability."
      : "The product documentation supports this capability.",
    sources: level === null ? [] : ["https://example.com/capabilities"],
  });
  return {
    capability_score:
      confidence === "low" || levels.includes(null)
        ? null
        : Math.round(
            (levels.reduce<number>((sum, value) => sum + value!, 0) * 100) / 12,
          ),
    confidence,
    summary:
      "Documented capabilities; enabled settings on these devices are not verified.",
    report: undefined as {
      purpose: { reason: string; sources: string[] };
      harms: { damage: string; likelihood: string; sources: string[] }[];
    } | undefined,
    code_execution: fact(levels[0]),
    file_access: fact(levels[1]),
    external_transmission: fact(levels[2]),
    autonomy: fact(levels[3]),
    risk: {
      score:
        riskScore !== undefined
          ? riskScore
          : confidence === "low"
            ? null
            : levels.includes(null)
              ? 72
              : Math.round(
                  (levels.reduce<number>((sum, level) => sum + level!, 0) *
                    100) /
                    12,
                ),
      reason:
        "The researched capabilities and safeguards support this estimated risk; local settings are unverified.",
      sources: ["https://example.com/risk"],
    } as
      { score: number | null; provisional_score?: number | null; reason: string; sources: string[] } | undefined,
    reputation: {
      reason:
        "Documented security practices; community allegations are unconfirmed.",
      sources: ["https://example.com/security"],
    },
    controls: {
      reason:
        "Approval prompts and sandbox controls are available; their enabled state is unknown.",
      sources: ["https://example.com/controls"],
    },
  };
}
const apps = [
  ["claude-code", "Claude Code", "coding_agent", "approved", 18],
  ["codex", "Codex", "coding_agent", "approved", 14],
  ["chatgpt", "ChatGPT", "chat_assistant", "approved", 22],
  ["claude", "Claude", "chat_assistant", "approved", 9],
  ["cursor", "Cursor", "coding_agent", "unapproved", 5],
  ["opencode", "OpenCode", "coding_agent", "monitoring", 3],
  ["ollama", "Ollama", "local_model_runtime", "monitoring", 4],
  ["helper", "Internal Dev Helper", null, "monitoring", 2],
  ["chrome", "Google Chrome", "ordinary", "monitoring", 24],
  ["git", "Git", "ordinary", "monitoring", 18],
].map(([id, name, category, approval_status, device_count]) => ({
  id: id as string,
  name: name as string,
  category: category as string | null,
  approval_status: approval_status as string,
  device_count: device_count as number,
  users: users(device_count as number),
  needs_attention: category !== "ordinary",
  classification_status: category === null ? "pending" : "complete",
  checked_at: category === null ? null : scanned,
  assessment: (category === null
    ? null
    : research(
        category === "chat_assistant"
          ? [3, 2, 2, 2]
          : category === "local_model_runtime"
            ? [0, 2, 0, 1]
            : [3, 3, 3, 3],
      )) as ReturnType<typeof research> | null | undefined,
  research_status: undefined as string | undefined,
  assessment_status: (category === null ? "pending" : "complete") as
    string | undefined,
  approval_updated_at: null as string | null,
  reason: "The product documentation identifies this application.",
  sources: ["https://example.com/product"],
  display_name: undefined as string | undefined,
  reported_names: undefined as string[] | undefined,
  approval_scope: undefined as string | undefined,
  approval_conflict: undefined as boolean | undefined,
  software_type: undefined as string | undefined,
  is_builtin: undefined as boolean | undefined,
  review_required: undefined as boolean | undefined,
  review_reason: undefined as string | undefined,
}));
for (const app of apps)
  if (app.category === "ordinary") app.assessment!.risk!.score = null;
async function inventoryApi(page: Page) {
  const state = {
    roles: ["it_admin"],
    userId: "u",
    tenantId: "t",
    configured: true,
    reportingUsers: users(24),
    renewal: false,
    items: structuredClone(apps),
    installations: {} as Record<string, Record<string, string>[]>,
    readStatus: 200,
    writeStatus: 200,
    deviceStatus: 200,
    deviceReads: [] as string[],
    deviceIds: [] as string[],
    incompatible: false,
    delayRead: null as Promise<void> | null,
    delayWrite: null as Promise<void> | null,
    writes: [] as {
      id: string;
      body: { approved: boolean | null };
      csrf: string | undefined;
    }[],
  };
  await page.clock.setFixedTime(new Date("2026-10-18T09:15:00Z"));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({
        json: {
          user: {
            id: state.userId,
            name: "Test operator",
            email: "test@example.invalid",
            roles: state.roles,
            tenant: { id: state.tenantId, name: "Test tenant", slug: "test" },
          },
          session_renewal: state.renewal,
        },
      });
    if (url.pathname.endsWith("auth/config"))
      return route.fulfill({ json: { mode: "local", password_login: true } });
    if (
      ["auth/login", "auth/logout", "auth/renew"].some((path) =>
        url.pathname.endsWith(path),
      )
    )
      return route.fulfill({ status: 204 });
    if (url.pathname.endsWith("inventory/application-review")) {
      if (state.delayRead) await state.delayRead;
      return route.fulfill(
        state.readStatus !== 200
          ? {
              status: state.readStatus,
              json: { error: "Inventory unavailable" },
            }
          : {
              json: {
                items: state.items,
                device_count: state.items.length ? 24 : 0,
                users: state.items.length ? state.reportingUsers : [],
                classifier_configured: state.configured,
                ...(state.incompatible ? {} : { generated_at: scanned }),
              },
            },
      );
    }
    if (/application-review\/[^/]+\/devices$/.test(url.pathname)) {
      state.deviceReads.push(url.pathname);
      if (state.deviceStatus !== 200)
        return route.fulfill({
          status: state.deviceStatus,
          json: { error: "Devices unavailable" },
        });
      const app = state.items.find(
        (app) => app.id === url.pathname.split("/").at(-2),
      )!;
      const names = ["macbook-pro-07", "engineering-mac-12", "win-dev-04"];
      return route.fulfill({
        json: {
          id: app.id,
          name: app.name,
          items: Array.from({ length: app.device_count }, (_, i) => ({
            id: state.deviceIds[i] || `device-${i}`,
            name: names[i] || `workstation-${i}`,
            os: i === 2 ? "windows" : "darwin",
            user: deviceUser(i),
            versions: ["1.0"],
            last_seen_at: scanned,
            installations: state.installations[app.id],
          })),
        },
      });
    }
    if (/application-review\/[^/]+\/approval$/.test(url.pathname)) {
      const id = url.pathname.split("/").at(-2)!;
      const body = route.request().postDataJSON();
      state.writes.push({
        id,
        body,
        csrf: route.request().headers()["x-openaidr-csrf"],
      });
      if (state.delayWrite) await state.delayWrite;
      if (state.writeStatus !== 200)
        return route.fulfill({
          status: state.writeStatus,
          json: { error: "Approval unavailable" },
        });
      const app = state.items.find((app) => app.id === id)!;
      app.approval_status = body.approved === null ? "monitoring" : body.approved ? "approved" : "unapproved";
      if (body.approved === null) app.review_required = true;
      app.approval_updated_at = scanned;
      app.approval_conflict = false;
      return route.fulfill({
        json: { id, approved: body.approved, approval_updated_at: scanned },
      });
    }
    return route.fulfill({ json: { items: [], next_cursor: "" } });
  });
  return state;
}
const column = (page: Page, name: string) =>
  page.getByRole("region", { name: `${name} applications`, exact: true });
const reviewSummary = (page: Page) =>
  page.locator('[data-slot="review-summary"]');
async function change(
  page: Page,
  name: string,
  status: string,
  scope = page.locator("main"),
) {
  if ((await scope.getAttribute("role")) !== "dialog") {
    await scope
      .getByRole("button", { name: `Approval for ${name}`, exact: true })
      .click();
    await page
      .getByRole("button", {
        name: status === "Monitoring" ? "Move to monitoring" : status === "Approved" ? "Approve" : "Mark unapproved",
        exact: true,
      })
      .click();
  } else {
    await scope
      .getByRole("button", {
        name: status === "Monitoring" ? "Move to monitoring" : status === "Approved" ? "Approve" : "Mark unapproved",
        exact: true,
      })
      .click();
  }
}
async function fits(page: Page) {
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBe(true);
}

test("AI Apps tutorial loads on demand, plays, and closes without losing the current view", async ({ page }, info) => {
  const state = await inventoryApi(page);
  for (const app of state.items) {
    app.review_required = app.category !== "ordinary";
    app.software_type = "application";
  }
  const mediaRequests: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/tutorials/")) mediaRequests.push(request.url());
  });
  await page.goto("/ai-inventory");
  const trigger = page.getByRole("button", { name: "Watch tutorial", exact: true });
  await expect(trigger).toBeVisible();
  await page.getByPlaceholder("Find an app or package").fill("Codex");
  expect(mediaRequests).toEqual([]);

  for (const viewport of [
    { width: 1440, height: 900 },
    { width: 390, height: 844 },
    { width: 844, height: 390 },
  ]) {
    await page.setViewportSize(viewport);
    const title = (await page.getByRole("heading", { name: "AI Apps", exact: true }).boundingBox())!;
    const action = (await trigger.boundingBox())!;
    expect(action.x).toBeGreaterThanOrEqual(title.x + title.width);
    expect(action.x + action.width).toBeLessThanOrEqual(viewport.width);
    if (viewport.width === 1440) {
      await page.screenshot({ path: info.outputPath("ai-apps-tutorial-entry.png") });
    }
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "AI Apps tutorial", exact: true });
    await expect(dialog).toBeVisible();
    const video = dialog.getByLabel("AI Apps tutorial video", { exact: true });
    const player = (await video.elementHandle())!;
    await expect(dialog.getByRole("link", { name: "Open video in a new tab" })).toHaveAttribute("href", "/tutorials/ai-apps.mp4");
    await expect.poll(() => player.evaluate((node) => (node as HTMLVideoElement).paused)).toBe(true);
    await video.evaluate(async (node: HTMLVideoElement) => {
      node.muted = true;
      await node.play();
    });
    await expect.poll(() => player.evaluate((node) => (node as HTMLVideoElement).currentTime)).toBeGreaterThan(0);
    expect(await video.evaluate((node: HTMLVideoElement) => node.videoWidth)).toBe(1920);
    expect(await video.evaluate((node: HTMLVideoElement) => node.duration)).toBeCloseTo(159.08, 0);
    await fits(page);
    const bounds = (await dialog.boundingBox())!;
    expect(bounds.x).toBeGreaterThanOrEqual(0);
    expect(bounds.y).toBeGreaterThanOrEqual(0);
    expect(bounds.x + bounds.width).toBeLessThanOrEqual(viewport.width);
    expect(bounds.y + bounds.height).toBeLessThanOrEqual(viewport.height);
    expect(await dialog.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await dialog.getByRole("link", { name: "Open video in a new tab" }).scrollIntoViewIfNeeded();
    await expect(dialog.getByRole("link", { name: "Open video in a new tab" })).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`ai-apps-tutorial-${viewport.width}.png`) });
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect.poll(() => player.evaluate((node) => (node as HTMLVideoElement).paused)).toBe(true);
    await expect(trigger).toBeFocused();
    await expect(page.getByPlaceholder("Find an app or package")).toHaveValue("Codex");
  }
  expect(mediaRequests.some((url) => url.endsWith("/ai-apps.mp4"))).toBe(true);
  const range = await page.request.get("/tutorials/ai-apps.mp4", {
    headers: { Range: "bytes=0-31" },
  });
  expect(range.status()).toBe(206);
  expect(range.headers()["content-type"]).toContain("video/mp4");
  expect(await range.body()).toHaveLength(32);
  await page.goto("/ai-skills");
  await expect(page.getByRole("heading", { name: "AI Skills", exact: true })).toBeVisible();
  await expect(trigger).toHaveCount(0);
});

test("research progress separates queued work, retries, and completed evidence across the full inventory", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = {
    ...state.items[5],
    software_type: "application",
    review_required: true,
  };
  state.items = [
    { ...seed, id: "scored", name: "Scored app", research_status: "complete" },
    {
      ...seed,
      id: "active",
      name: "Active app",
      research_status: "researching",
      assessment: null,
      assessment_status: "pending",
    },
    {
      ...seed,
      id: "queued",
      name: "Queued app",
      research_status: "queued",
      assessment: null,
      assessment_status: "pending",
    },
    {
      ...seed,
      id: "retry",
      name: "Retry app",
      research_status: "retry_pending",
      assessment: null,
      assessment_status: "unavailable",
    },
    {
      ...seed,
      id: "partial",
      name: "Partial app",
      research_status: "complete",
      assessment: research([3, null, 2, 2]),
      assessment_status: "needs_identification",
    },
    {
      ...seed,
      id: "unknown",
      name: "Unknown app",
      research_status: "complete",
      category: null,
      classification_status: "unknown",
      assessment: research([null, null, null, null], "low"),
      assessment_status: "needs_identification",
    },
    {
      ...seed,
      id: "ordinary",
      name: "Ordinary app",
      research_status: "complete",
      category: "ordinary",
      assessment: null,
      needs_attention: false,
      review_required: false,
    },
  ];
  await page.clock.install();
  await page.goto("/ai-inventory");
  const progress = page.getByRole("status", {
    name: "Application research progress",
  });
  await expect(progress).toContainText("4 of 7 apps and packages processed");
  await expect(progress).toContainText("3 remaining");
  const details = progress.getByText(
    "1 queued · 1 researching · 1 retry pending · " +
      "1 ordinary software · 1 unidentified · 2 of 6 review apps risk-scored",
    { exact: true },
  );
  await expect(details).toBeVisible();
  const monitoring = column(page, "Monitoring");
  for (const [id, label] of [
    ["active", "Researching"],
    ["queued", "Research queued"],
    ["retry", "Retry pending"],
    ["unknown", "Needs identification"],
  ])
    await expect(
      monitoring.locator(`[data-application="${id}"]`),
    ).toContainText(label);
  await expect(reviewSummary(page)).toContainText("4 unscored");
  await page.getByPlaceholder("Find an app or package").fill("Scored app");
  await expect(progress).toContainText("4 of 7 apps and packages processed");
  await page.getByPlaceholder("Find an app or package").clear();
  await page.evaluate(() => document.fonts.ready);
  expect(
    await details.evaluate(
      (element) => element.getBoundingClientRect().height <=
        Number.parseFloat(getComputedStyle(element).lineHeight),
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath("application-research-progress.png"),
    fullPage: true,
  });
  await page.setViewportSize({ width: 390, height: 700 });
  await fits(page);
  await expect(progress).toBeVisible();
  expect(
    await progress.evaluate(
      (element) => element.scrollWidth <= element.clientWidth,
    ),
  ).toBe(true);
  await page.screenshot({
    path: info.outputPath("application-research-progress-mobile.png"),
    fullPage: true,
  });

  // The existing polling refresh updates the counts without resetting the page.
  state.items[1] = {
    ...state.items[1],
    research_status: "complete",
    assessment: research(),
    assessment_status: "complete",
  };
  await page.clock.fastForward(30_001);
  await expect(progress).toContainText("5 of 7 apps and packages processed");
  await expect(progress).toContainText("2 remaining");
  await expect(progress).toContainText(
    "1 queued · 0 researching · 1 retry pending",
  );
  state.configured = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(progress).toContainText("Application research paused");
  state.items[0].research_status = "invalid";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Application inventory may be out of date", { exact: true }),
  ).toBeVisible();
  await expect(progress).toContainText("5 of 7 apps and packages processed");
  state.items = state.items.map((app) => ({
    ...app,
    research_status: undefined,
  }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(progress).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

test("three columns replace charts and approvals move applications with distinct device details", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  await page.goto("/ai-inventory/preview");
  await expect(page).toHaveURL(/\/ai-inventory$/);
  await expect(
    page.getByText("Software context is unavailable", { exact: true }),
  ).toBeVisible();
  await expect(
    column(page, "Approved").locator("tr[data-application]"),
  ).toHaveCount(4);
  await expect(
    column(page, "Unapproved").locator("tr[data-application]"),
  ).toHaveCount(1);
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(3);
  await expect(page.getByRole("definition")).toHaveCount(0);
  await expect(reviewSummary(page)).toHaveText(
    "3 of 8 applications awaiting a decision across 24 devices and 20 users · Highest risk OpenCode on 3 devices · 1 unscored · Cursor is unapproved on 5 devices",
  );
  await page.evaluate(() => document.fonts.ready);
  for (const width of [1920, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    const summaryLines = await reviewSummary(page).evaluate(
      (node) =>
        node.getBoundingClientRect().height /
        parseFloat(getComputedStyle(node).lineHeight),
    );
    if (width === 1920) {
      expect(summaryLines).toBeCloseTo(1);
      await page.screenshot({
        path: info.outputPath("application-review-summary.png"),
        animations: "disabled",
      });
    } else {
      expect(summaryLines).toBeGreaterThan(1);
    }
    await fits(page);
    await expect(
      page.getByRole("button", { name: "Refresh", exact: true }),
    ).toBeInViewport();
  }
  await page.setViewportSize({ width: 1920, height: 1080 });
  await expect(page.getByRole("tab")).toHaveCount(0);
  await expect(
    page.getByRole("heading", { name: "Who uses AI applications" }),
  ).toHaveCount(0);
  await expect(page.locator("main h1")).toHaveCount(1);
  await expect(column(page, "Approved").locator("[data-open-app]")).toHaveText([
    "Claude Code",
    "Codex",
    "ChatGPT",
    "Claude",
  ]);
  await expect(
    column(page, "Approved").locator('[aria-label^="Risk score"]'),
  ).toHaveCount(0);
  await expect(column(page, "Approved").getByRole("columnheader", { name: "Risk score" })).toHaveCount(0);
  await expect(column(page, "Unapproved").getByRole("columnheader", { name: "Risk score" })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  const boxes = await page.evaluate(() =>
    ["Approved", "Unapproved", "Monitoring"].map((name) => {
      const box = document
        .querySelector(`section[aria-label="${name} applications"]`)!
        .getBoundingClientRect();
      const header = document.querySelector(
        `section[aria-label="${name} applications"] [data-slot="review-card-header"]`,
      )!;
      const style = getComputedStyle(header);
      const card = header.closest('[data-slot="card"]')!;
      return {
        x: box.x,
        y: box.y,
        right: box.right,
        bottom: box.bottom,
        background: style.backgroundColor,
        color: style.color,
        headerWidth: header.getBoundingClientRect().width,
        columnWidth: box.width,
        border: getComputedStyle(card).borderTopColor,
        labelSize: getComputedStyle(header.querySelector("h3")!).fontSize,
        iconWidth: header.querySelector("svg")!.getBoundingClientRect().width,
        icon: header.querySelector("svg")!.innerHTML,
      };
    }),
  );
  // Monitoring is the work queue on the left; Unapproved and Approved stack
  // beside it, and the stack ends level with the Monitoring card.
  const [approved, unapproved, monitoring] = boxes as [
    (typeof boxes)[number],
    (typeof boxes)[number],
    (typeof boxes)[number],
  ];
  expect(monitoring.y).toBeCloseTo(unapproved.y, 0);
  expect(monitoring.x).toBeLessThan(unapproved.x);
  expect(unapproved.x).toBeCloseTo(approved.x, 0);
  expect(unapproved.bottom).toBeLessThan(approved.y);
  expect(approved.bottom).toBeCloseTo(monitoring.bottom, 0);
  expect(monitoring.columnWidth).toBeGreaterThan(unapproved.columnWidth);
  for (const box of boxes) {
    expect(box.headerWidth).toBeGreaterThanOrEqual(box.columnWidth - 2);
    expect(box.background).not.toBe("rgba(0, 0, 0, 0)");
    expect(box.color).toBe("rgb(255, 255, 255)");
    expect(box.border).toBe(box.background);
    expect(box.labelSize).toBe("16px");
    expect(box.iconWidth).toBe(16);
  }
  for (const key of ["background", "icon"] as const)
    expect(new Set(boxes.map((box) => box[key])).size).toBe(3);
  // Supported scores keep their bands. Unsupported apps have no numeric bar.
  expect(
    await column(page, "Monitoring")
      .locator('[aria-label^="Risk score"] + span > span')
      .evaluateAll((bars) =>
        bars.map((bar) => [bar.getAttribute("style"), bar.className]),
      ),
  ).toEqual([
    ["width: 100%;", "block h-full rounded-xs bg-severity-critical"],
    ["width: 25%;", "block h-full rounded-xs bg-severity-medium"],
  ]);
  await expect(
    column(page, "Approved").locator(
      '[aria-label^="Risk score"] + span[aria-hidden]',
    ),
  ).toHaveCount(0);
  const rows = await page.locator("tr[data-application]").evaluateAll((nodes) =>
    nodes.map((row) => ({
      height: row.getBoundingClientRect().height,
      fontSize: getComputedStyle(row.querySelector("button")!).fontSize,
    })),
  );
  for (const row of rows) {
    expect(row.height).toBeLessThanOrEqual(80);
    expect(row.fontSize).toBe("14px");
  }
  await page.screenshot({
    path: info.outputPath("application-review.png"),
    fullPage: true,
    animations: "disabled",
  });
  await column(page, "Monitoring")
    .getByRole("button", { name: "OpenCode", exact: true })
    .click();
  const drawer = page.getByRole("dialog", { name: "OpenCode", exact: true });
  await expect(
    drawer
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
  for (const name of ["macbook-pro-07", "engineering-mac-12", "win-dev-04"])
    await expect(drawer.getByText(name, { exact: true })).toBeVisible();
  await drawer.getByText("Why this classification?", { exact: true }).click();
  await expect(drawer.getByRole("link", { name: /^Source 1/ })).toHaveAttribute(
    "href",
    "https://example.com/product",
  );
  await page.screenshot({
    path: info.outputPath("application-devices.png"),
    animations: "disabled",
  });
  await change(page, "OpenCode", "Approved", drawer);
  await expect(
    drawer.getByRole("button", { name: "Approve", exact: true }),
  ).toBeDisabled();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await expect(
    column(page, "Approved").locator("tr[data-application]"),
  ).toHaveCount(5);
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(2);
  await expect(
    column(page, "Approved").getByRole("button", {
      name: "OpenCode",
      exact: true,
    }),
  ).toBeFocused();
  await change(page, "OpenCode", "Unapproved");
  await expect(
    column(page, "Unapproved").getByRole("button", {
      name: "OpenCode",
      exact: true,
    }),
  ).toBeVisible();
  expect(state.writes).toEqual([
    { id: "opencode", body: { approved: true }, csrf: "1" },
    { id: "opencode", body: { approved: false }, csrf: "1" },
  ]);
  // Software filters scope the table only; the review cards stay complete.
  await page.getByRole("searchbox").fill("git");
  await expect(page.locator("tr[data-application]")).toHaveCount(8);
  await expect(applications(page).locator("tbody tr")).toHaveCount(1);
  await page.getByRole("button", { name: "Show 18 devices for Git" }).click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(18);
});

test("monitoring classifications and risk scores stay compact while review cards fit the viewport", async ({ page }, info) => {
  const state = await inventoryApi(page);
  const seed = state.items.find((app) => app.id === "ollama")!;
  const provisional = research([null, null, null, null], "low");
  provisional.risk!.provisional_score = 35;
  state.items = [
    ...state.items.filter((app) => app.approval_status !== "monitoring"),
    ...([
      ["ollama", "Ollama", "local_model_runtime", "complete", "application", 38],
      ["summarize", "Summarize CLI (@steipete/summarize)", "other_ai", "stale", "command_line_tool", 0],
      ["codebun", "CodeBun Desktop", "other_ai", "complete", "application", 100],
      ["glance", "Glance by Mirametrix", "other_ai", "stale", "application", 64],
      ["openaidr", "OpenSecura OpenAIDR", "other_ai", "complete", "application", 35],
    ] as const).map(([id, name, category, classification_status, software_type, riskScore]) => ({
      ...seed, id, name, category, classification_status, software_type,
      assessment: id === "openaidr" ? provisional : research([3, 3, 3, 3], "high", riskScore),
    })),
  ].map((app) => ({ ...app, review_required: true }));
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(monitoring.locator("tr[data-application]")).toHaveCount(5);
  await page.evaluate(() => document.fonts.ready);

  for (const width of [2048, 1536, 1440, 1280, 1024, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await fits(page);
    const provisionalRow = monitoring.locator('[data-application="openaidr"]');
    const score = provisionalRow.getByLabel("Risk score 35 out of 100", { exact: true });
    const band = provisionalRow.getByText("Moderate", { exact: true });
    const confidence = provisionalRow.getByText("Low confidence", { exact: true });
    if (width === 2048) {
      await page.screenshot({ path: info.outputPath("monitoring-risk-layout.png"), animations: "disabled" });
      await monitoring.screenshot({ path: info.outputPath("monitoring-risk-table.png"), animations: "disabled" });
    }
    const scoreBox = (await score.boundingBox())!;
    const bandBox = (await band.boundingBox())!;
    const confidenceBox = (await confidence.boundingBox())!;
    // Inline font metrics differ across engines; a wrapped line must not overlap.
    expect(Math.max(scoreBox.y, bandBox.y), `${width}px: score and band share a line`).toBeLessThan(Math.min(scoreBox.y + scoreBox.height, bandBox.y + bandBox.height));
    expect(confidenceBox.height, `${width}px: confidence uses one line`).toBeLessThanOrEqual(16);
    // Allow one pixel for fractional text metrics in the 20px + 16px lines.
    expect(confidenceBox.y + confidenceBox.height - scoreBox.y, `${width}px: risk uses at most two lines`).toBeLessThanOrEqual(37);
    for (const value of await monitoring.locator('[aria-label^="Risk score"]').all()) {
      const box = (await value.boundingBox())!;
      expect(Math.abs(box.x + box.width - scoreBox.x - scoreBox.width), `${width}px: risk values align across bands`).toBeLessThanOrEqual(1);
    }
    if (width === 2048 || width === 1280) {
      expect((await provisionalRow.boundingBox())!.height, `${width}px: provisional row stays compact`).toBeLessThanOrEqual(56);
    }
    if (width >= 1024) {
      const classifications = monitoring.locator("tbody tr td:nth-child(2)");
      for (const cell of await classifications.all()) {
        const text = await cell.evaluate((node) => {
          const range = document.createRange();
          range.selectNodeContents(node);
          return {
            height: range.getBoundingClientRect().height,
            lineHeight: parseFloat(getComputedStyle(node).lineHeight),
          };
        });
        expect(text.height, `${width}px: ${await cell.textContent()}`).toBeLessThanOrEqual(text.lineHeight);
      }
      for (const name of ["Monitoring", "Unapproved", "Approved"]) {
        const table = column(page, name).locator('[data-slot="table-container"]');
        expect(await table.evaluate((node) => node.scrollWidth <= node.clientWidth), `${width}px: ${name} fits`).toBe(true);
      }
    } else {
      await expect(monitoring.getByRole("columnheader", { name: "Classification" })).toBeHidden();
      await expect(monitoring.locator('[data-application="ollama"] td').first().getByText("Local model runtime")).toBeVisible();
      expect((await provisionalRow.locator("td").first().boundingBox())!.width).toBeGreaterThanOrEqual(160);
      const report = provisionalRow.getByRole("button", { name: "View report for OpenSecura OpenAIDR", exact: true });
      await report.scrollIntoViewIfNeeded();
      await expect(report).toBeInViewport();
      await expect(confidence).toBeInViewport();
      await page.screenshot({ path: info.outputPath("monitoring-risk-mobile.png"), animations: "disabled" });
    }
    const queue = (await monitoring.boundingBox())!;
    const unapproved = (await column(page, "Unapproved").boundingBox())!;
    if (width >= 1536) {
      expect(queue.y).toBeCloseTo(unapproved.y, 0);
      expect(unapproved.x).toBeGreaterThan(queue.x + queue.width);
    } else {
      expect(unapproved.y).toBeGreaterThan(queue.y + queue.height);
    }
    if (width === 2048) {
      const approved = (await column(page, "Approved").boundingBox())!;
      expect(queue.width).toBeGreaterThan(approved.width * 1.75);
      await page.screenshot({ path: info.outputPath("monitoring-classification-desktop.png"), animations: "disabled" });
    }
  }
});

test("device and user counts open focused lists while report links open assessments", async ({ page }, info) => {
  await inventoryApi(page);
  await page.goto("/ai-inventory");
  await expect(column(page, "Monitoring").getByRole("columnheader", { name: "Report", exact: true })).toBeVisible();
  await page.evaluate(() => document.fonts.ready);
  for (const name of ["Monitoring", "Unapproved", "Approved"]) {
    const width = await column(page, name).locator('[data-slot="table-container"]').evaluate((node) => ({ content: node.scrollWidth, available: node.clientWidth }));
    expect(width.content, `${name} columns fit without scrolling`).toBeLessThanOrEqual(width.available);
  }

  for (const [scope, name, devices, reportedUsers] of [
    [column(page, "Monitoring"), "OpenCode", 3, 2],
    [column(page, "Unapproved"), "Cursor", 5, 2],
    [column(page, "Approved"), "Codex", 14, 10],
    [applications(page), "OpenCode", 3, 2],
  ] as const) {
    await expect(scope.getByRole("columnheader", { name: "Report", exact: true })).toBeVisible();
    const drawer = page.getByRole("dialog", { name, exact: true });
    const deviceLink = scope.getByRole("button", { name: `Show ${devices} devices for ${name}`, exact: true });
    await deviceLink.click();
    await expect(drawer.getByRole("list", { name: "Installed devices" }).getByRole("listitem")).toHaveCount(devices);
    await expect(drawer.getByRole("heading", { name: `Installed devices (${devices})`, exact: true })).toBeInViewport();
    await expect(drawer.getByRole("region", { name: "Risk assessment", exact: true })).toHaveCount(0);
    await expect(drawer.getByRole("region", { name: "Software context", exact: true })).toHaveCount(0);
    await drawer.getByRole("button", { name: "Done", exact: true }).click();
    await expect(deviceLink).toBeFocused();

    const userLink = scope.getByRole("button", { name: `Show ${reportedUsers} users for ${name}`, exact: true });
    await userLink.focus();
    await page.keyboard.press("Enter");
    const users = drawer.getByRole("list", { name: "Reported users", exact: true });
    await expect(users.getByRole("listitem")).toHaveCount(reportedUsers);
    await expect(users.getByRole("listitem").filter({ hasText: "alice" })).toHaveText("alice2 devices");
    await expect(users.getByText("bob", { exact: true })).toBeVisible();
    await expect(drawer.getByRole("region", { name: "Risk assessment", exact: true })).toHaveCount(0);
    await expect(drawer.getByRole("list", { name: "Installed devices" })).toHaveCount(0);
    await page.keyboard.press("Escape");
    await expect(userLink).toBeFocused();

    const reportLink = scope.getByRole("button", { name: `View report for ${name}`, exact: true });
    await reportLink.click();
    await expect(drawer.getByRole("region", { name: "Risk assessment", exact: true })).toBeVisible();
    await drawer.getByRole("button", { name: "Done", exact: true }).click();
    await expect(reportLink).toBeFocused();
  }

  await page.getByRole("heading", { name: "AI Apps", exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: info.outputPath("ai-apps-report-column.png"), animations: "disabled" });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    for (const [kind, total, label] of [["devices", 3, "Installed devices"], ["users", 2, "Reported users"]] as const) {
      await column(page, "Monitoring").getByRole("button", { name: `Show ${total} ${kind} for OpenCode`, exact: true }).click();
      const drawer = page.getByRole("dialog", { name: "OpenCode", exact: true });
      await expect(drawer.getByRole("heading", { name: `${label} (${total})`, exact: true })).toBeInViewport();
      await expect(drawer.getByRole("button", { name: "Done", exact: true })).toBeInViewport();
      await fits(page);
      await page.screenshot({ path: info.outputPath(`ai-apps-${kind}-${width}.png`), animations: "disabled" });
      await drawer.getByRole("button", { name: "Done", exact: true }).click();
    }
  }
});

test("risk scores use researched estimates without changing with organization reach or filters", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = state.items[5];
  state.items.push(
    {
      ...seed,
      id: "all-agent",
      name: "All-device agent",
      device_count: 24,
      users: users(24),
    },
    {
      ...seed,
      id: "unknown",
      name: "Unclassified fleet app",
      category: null,
      classification_status: "unknown",
      assessment: research([null, null, null, null], "low"),
      assessment_status: "needs_identification",
      device_count: 24,
      users: users(24),
    },
    {
      ...seed,
      id: "wide-ai",
      name: "Fleet image tool",
      category: "other_ai",
      assessment: research([0, 1, 1, 1]),
      device_count: 24,
      users: users(24),
    },
    { ...state.items[6], id: "tie", name: "A local runtime" },
    {
      ...seed,
      id: "unattributed",
      name: "Unattributed tool",
      category: "other_ai",
      device_count: 1,
      assessment: research([0, 1, 1, 1]),
      users: [{ user: "", device_count: 1 }],
    },
  );
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(monitoring.locator("[data-open-app]")).toHaveText([
    "All-device agent",
    "OpenCode",
    "A local runtime",
    "Fleet image tool",
    "Ollama",
    "Unattributed tool",
    "Internal Dev Helper",
    "Unclassified fleet app",
  ]);
  await expect(monitoring.locator('[aria-label^="Risk score"]')).toHaveText([
    "100",
    "100",
    "25",
    "25",
    "25",
    "25",
  ]);
  await expect(
    monitoring.getByText("Needs identification", { exact: true }),
  ).toHaveCount(2);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: info.outputPath("application-review-priority.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.getByText("How risk scores work", { exact: true }).click();
  await expect(page.getByText(/Risk scores are AI estimates/)).toBeVisible();
  await page
    .getByRole("combobox", { name: "Endpoint user", exact: true })
    .click();
  await page.getByRole("option", { name: "bob", exact: true }).click();
  await expect(
    monitoring.locator('[data-application="opencode"] [data-open-devices]'),
  ).toHaveText("3");
  await expect(
    monitoring.locator(
      '[data-application="opencode"] [aria-label^="Risk score"]',
    ),
  ).toHaveText("100");
  await page
    .getByRole("button", { name: "Clear filters", exact: true })
    .click();
  state.reportingUsers = [{ user: "", device_count: 24 }];
  state.items = state.items.map((app) => ({
    ...app,
    users: [{ user: "", device_count: app.device_count }],
  }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    monitoring.locator(
      '[data-application="all-agent"] [aria-label^="Risk score"]',
    ),
  ).toHaveText("100");
  expect(state.writes).toEqual([]);
});

test("application report pairs concise harms with likelihood and keeps evidence expandable", async ({ page }, info) => {
  const state = await inventoryApi(page);
  const assessment = research([0, 1, 1, 0], "medium", 32);
  // Illustrative research data for the rendered report, not a measured risk rating.
  assessment.report = {
    purpose: {
      reason: "Runs AI models on your device for chat and connected apps, with optional cloud models.",
      sources: ["https://docs.ollama.com/faq"],
    },
    harms: [
      {
        damage: "Sensitive prompts could leave the device.",
        likelihood: "Lower with local-only use. Cloud models send prompts to Ollama for processing.",
        sources: ["https://docs.ollama.com/faq"],
      },
      {
        damage: "Other people could use your model service without permission.",
        likelihood: "Lower on localhost; higher if the unauthenticated API is exposed to a network.",
        sources: ["https://docs.ollama.com/api/authentication", "https://docs.ollama.com/faq"],
      },
      {
        damage: "Model workloads could slow other work or exhaust memory.",
        likelihood: "Higher with large models or parallel requests on a device with limited memory.",
        sources: ["https://docs.ollama.com/faq"],
      },
    ],
  };
  state.items = [{ ...state.items[6], assessment, software_type: "application" }];
  await page.goto("/ai-inventory");
  await column(page, "Monitoring").getByRole("button", { name: "Ollama", exact: true }).click();
  const drawer = page.getByRole("dialog", { name: "Ollama", exact: true });
  const report = drawer.getByRole("region", { name: "Risk assessment", exact: true });
  const harms = report.getByRole("table", { name: "Potential harm and likelihood" });
  await expect(report.getByRole("heading", { name: "What it does", exact: true })).toBeVisible();
  await expect(report.getByText(assessment.report.purpose.reason, { exact: true })).toBeVisible();
  await expect(harms.getByRole("columnheader")).toHaveText(["What could go wrong?", "How likely?"]);
  for (const [index, harm] of assessment.report.harms.entries())
    await expect(harms.locator("tbody tr").nth(index).getByRole("cell")).toHaveText([harm.damage, harm.likelihood]);
  await expect(report.getByText(assessment.risk!.reason, { exact: true })).not.toBeVisible();
  await expect(report.getByText(assessment.summary, { exact: true })).not.toBeVisible();
  await expect(report).toContainText("not a probability of harm");
  const evidence = report.locator("summary").filter({ hasText: "Evidence and available controls" });
  await expect(evidence).toBeInViewport({ ratio: 1 });
  await page.evaluate(() => document.fonts.ready);
  await drawer.screenshot({ path: info.outputPath("application-report.png"), animations: "disabled" });
  await evidence.focus();
  await page.keyboard.press("Enter");
  await expect(report.getByText(assessment.risk!.reason, { exact: true })).toBeVisible();
  await expect(report.getByText(assessment.summary, { exact: true })).toBeVisible();
  await expect(report.getByRole("link", { name: /https:\/\/docs.ollama.com\/api\/authentication/ })).toHaveAttribute("href", "https://docs.ollama.com/api/authentication");
  await evidence.click();
  await page.setViewportSize({ width: 390, height: 420 });
  const scroll = drawer.locator(".overflow-y-auto").first();
  expect(await scroll.evaluate((el) => el.scrollHeight > el.clientHeight)).toBe(true);
  expect(await scroll.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  expect(await harms.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  await harms.locator("tbody tr").last().scrollIntoViewIfNeeded();
  await expect(harms.locator("tbody tr").last()).toBeInViewport();
  await expect(drawer.getByRole("button", { name: "Done", exact: true })).toBeInViewport({ ratio: 1 });
  await drawer.screenshot({ path: info.outputPath("application-report-mobile.png"), animations: "disabled" });
  await evidence.scrollIntoViewIfNeeded();
  await evidence.click();
  await report.getByRole("link").last().scrollIntoViewIfNeeded();
  await expect(report.getByRole("link").last()).toBeInViewport();
  expect(await scroll.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(true);
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  // Missing evidence must show uncertainty even when a numeric score exists.
  state.items[0].assessment!.report!.harms = [];
  state.items[0].assessment_status = "stale";
  state.items[0].research_status = "retry_pending";
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(column(page, "Monitoring")).toContainText("Refresh delayed");
  await column(page, "Monitoring").getByRole("button", { name: "Ollama", exact: true }).click();
  await expect(harms).toContainText("Not established by the available evidence.");
  await expect(harms).toContainText("Unknown.");
  await expect(report).toContainText("Refresh delayed");
});

test("risk research exposes evidence and confidence while supporting partial capability evidence", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = {
    ...state.items[5],
    software_type: "application",
    is_builtin: false,
    review_required: true,
    review_reason: "Review organization permission for this application.",
  };
  const supported = research([3, 2, 2, 2]);
  supported.code_execution.reason =
    "The documented terminal mode runs arbitrary host commands and scripts.";
  supported.file_access.reason =
    "The documented agent reads and edits files in the selected workspace.";
  supported.external_transmission.reason =
    "The documented cloud mode automatically sends workspace context to its model provider.";
  supported.autonomy.reason =
    "The documented workflow completes multiple steps with required approval checkpoints.";
  state.items = [
    { ...seed, assessment: supported },
    {
      ...seed,
      id: "unknown",
      name: "OpenAIDR",
      category: null,
      classification_status: "unknown",
      assessment: null,
      assessment_status: "pending",
    },
    {
      ...seed,
      id: "weak",
      name: "Weak evidence",
      assessment: research([3, 3, 3, 3], "low"),
      assessment_status: "needs_identification",
    },
    {
      ...seed,
      id: "partial",
      name: "Partial evidence",
      assessment: research([3, null, 2, 2]),
      assessment_status: "needs_identification",
    },
    {
      ...seed,
      id: "zero",
      name: "Documented zero",
      category: "other_ai",
      assessment: research([0, 0, 0, 0]),
    },
  ];
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(monitoring.locator("[data-open-app]")).toHaveText([
    "OpenCode",
    "Partial evidence",
    "Documented zero",
    "OpenAIDR",
    "Weak evidence",
  ]);
  await expect(monitoring.locator('[aria-label^="Risk score"]')).toHaveText([
    "75",
    "72",
    "0",
  ]);
  await expect(
    monitoring.getByText("Needs identification", { exact: true }),
  ).toHaveCount(1);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: info.outputPath("application-assessment-review.png"),
    fullPage: true,
    animations: "disabled",
  });
  await monitoring
    .getByRole("button", { name: "OpenCode", exact: true })
    .click();
  const drawer = page.getByRole("dialog");
  const assessment = drawer.getByRole("region", {
    name: "Risk assessment",
  });
  await expect(assessment).toContainText("Risk score 75/100 · Critical risk");
  await expect(assessment).toContainText("Research confidence: high");
  await expect(assessment.getByRole("table", { name: "Potential harm and likelihood" })).toContainText("Not assessed in this report yet.");
  await expect(assessment.getByRole("table", { name: "Potential harm and likelihood" })).toContainText("Unknown.");
  await expect(assessment.getByText(supported.risk!.reason, { exact: true })).not.toBeVisible();
  await assessment
    .getByText("Evidence and available controls", { exact: true })
    .click();
  for (const name of [
    "Code execution",
    "File access",
    "External data transmission",
    "Autonomy",
    "Available controls",
    "Security history and community reputation",
  ])
    await expect(
      assessment.getByText(new RegExp(`^${name}`)).first(),
    ).toBeVisible();
  await expect(assessment.getByRole("link")).toHaveCount(7);
  await expect(assessment.getByRole("link").last()).toHaveAttribute(
    "href",
    "https://example.com/security",
  );
  await expect(assessment).toContainText("their enabled state is unknown");
  await assessment.scrollIntoViewIfNeeded();
  await page.screenshot({
    path: info.outputPath("application-assessment-evidence.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 420 });
  await expect(
    drawer.getByRole("button", { name: "Done", exact: true }),
  ).toBeInViewport();
  expect(await drawer.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(
    true,
  );
  await assessment.getByRole("link").last().scrollIntoViewIfNeeded();
  await expect(assessment.getByRole("link").last()).toBeInViewport();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1080 });
  state.items[0].assessment_status = "stale";
  state.items[0].classification_status = "stale";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    monitoring.locator('[data-application="opencode"]'),
  ).toContainText("Refresh delayed");
  // Old backends must never restore category weights or a numeric unknown score.
  state.items = state.items.map((app) => ({
    ...app,
    assessment: undefined,
    assessment_status: undefined,
  }));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    monitoring.getByText("Needs identification", { exact: true }),
  ).toHaveCount(1);
  await expect(
    monitoring.getByText("Awaiting risk assessment", { exact: true }),
  ).toHaveCount(4);
  await expect(monitoring.locator('[aria-label^="Risk score"]')).toHaveCount(0);
  await expect(page.locator('[data-slot="review-summary"]')).not.toContainText(
    "Highest risk",
  );
  state.items[0].assessment = research();
  state.items[0].assessment_status = "complete";
  state.items[0].assessment.controls.sources = ["javascript:alert(1)"];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Application inventory may be out of date", { exact: true }),
  ).toBeVisible();
  await expect(monitoring.locator('[aria-label^="Risk score"]')).toHaveCount(0);
  expect(state.writes).toEqual([]);
});

test("provisional risk estimates cover every confidence level and preserve research failures", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = {
    ...state.items[5],
    software_type: "application",
    review_required: true,
    research_status: "complete",
  };
  const provisional = (
    score: number,
    levels: (number | null)[] = [null, null, null, null],
  ) => {
    const value = research(levels, "low");
    value.risk!.provisional_score = score;
    value.risk!.sources = [];
    value.risk!.reason =
      "Provisional estimate from reported metadata; product identity and enabled capabilities are unverified.";
    value.summary = "Evidence is limited; enabled settings are unverified.";
    return value;
  };
  const sourcedCapabilities = research([3, 3, 3, 3], "high", null);
  sourcedCapabilities.risk!.provisional_score = 65;
  sourcedCapabilities.risk!.sources = [];
  state.items = [
    {
      ...seed,
      id: "high",
      name: "High confidence app",
      assessment: research([3, 2, 2, 2], "high", 80),
    },
    {
      ...seed,
      id: "risk-only",
      name: "Documented capabilities",
      assessment: sourcedCapabilities,
    },
    {
      ...seed,
      id: "medium",
      name: "Medium confidence app",
      assessment: research([3, null, 2, 2], "medium", 60),
    },
    {
      ...seed,
      id: "low",
      name: "Low confidence app",
      assessment: provisional(50, [3, 3, 3, 3]),
    },
    {
      ...seed,
      id: "unknown",
      name: "OpenAIDR",
      category: null,
      classification_status: "unknown",
      assessment: provisional(37),
      assessment_status: "needs_identification",
    },
    {
      ...seed,
      id: "zero",
      name: "Provisional zero",
      assessment: provisional(0),
    },
    {
      ...seed,
      id: "reference",
      name: "Unapproved reference",
      approval_status: "unapproved",
      assessment: research([3, 3, 3, 3], "high", 90),
    },
  ];
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(monitoring.locator('[aria-label^="Risk score"]')).toHaveText([
    "80",
    "65",
    "60",
    "50",
    "37",
    "0",
  ]);
  await expect(
    monitoring.getByText("Low confidence", { exact: true }),
  ).toHaveCount(4);
  await expect(
    monitoring.locator('[data-application="low"]'),
  ).not.toContainText("Similar");
  const sourcedRow = monitoring.locator('[data-application="risk-only"]');
  await expect(sourcedRow).toContainText("Similar to unapproved");
  await sourcedRow.getByRole("button", { name: "Documented capabilities", exact: true }).click();
  const sourcedDrawer = page.getByRole("dialog", { name: "Documented capabilities", exact: true });
  await expect(sourcedDrawer).toContainText("Risk score 65/100");
  await expect(sourcedDrawer).toContainText("Risk confidence: low · Capability confidence: high");
  await sourcedDrawer.getByText("Evidence and available controls", { exact: true }).click();
  await expect(sourcedDrawer.getByText("Code execution · 3/3", { exact: true })).toBeVisible();
  await sourcedDrawer.getByRole("button", { name: "Done", exact: true }).click();
  const unknownRow = monitoring.locator('[data-application="unknown"]');
  await expect(unknownRow).toContainText("Classification inconclusive");
  await expect(unknownRow).not.toContainText("Needs identification");
  await page.setViewportSize({ width: 1920, height: 1080 });
  await page.screenshot({
    path: info.outputPath("provisional-app-risk.png"),
    fullPage: true,
    animations: "disabled",
  });
  await unknownRow
    .getByRole("button", { name: "OpenAIDR", exact: true })
    .click();
  const drawer = page.getByRole("dialog", { name: "OpenAIDR", exact: true });
  const details = drawer.getByRole("region", {
    name: "Risk assessment",
    exact: true,
  });
  await expect(details).toContainText("Risk score 37/100");
  await expect(details).toContainText("Risk confidence: low · Capability confidence: low");
  await expect(details).toContainText("Product identity is unresolved");
  await expect(details).toContainText(
    "No public sources were cited for this estimate",
  );
  await expect(details.getByRole("link", { name: /Risk source/ })).toHaveCount(
    0,
  );
  await page.screenshot({
    path: info.outputPath("provisional-app-risk-details.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 420 });
  expect(await drawer.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(
    true,
  );
  await details.scrollIntoViewIfNeeded();
  await expect(details).toBeInViewport();
  await expect(
    drawer.getByRole("button", { name: "Done", exact: true }),
  ).toBeInViewport();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await fits(page);
  await page.setViewportSize({ width: 1440, height: 1080 });
  const unknown = state.items.find((app) => app.id === "unknown")!;
  unknown.research_status = "retry_pending";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(unknownRow).toContainText("Refresh delayed");
  await expect(unknownRow.locator('[aria-label^="Risk score"]')).toHaveText(
    "37",
  );
  // First-attempt failure has no estimate; it is not converted into a numeric default.
  unknown.assessment = null;
  unknown.assessment_status = "unavailable";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(unknownRow).toContainText("Retry pending");
  await expect(unknownRow.locator('[aria-label^="Risk score"]')).toHaveCount(0);
  unknown.research_status = "complete";
  unknown.assessment = provisional(37);
  delete unknown.assessment.risk!.provisional_score;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(unknownRow).toContainText("Needs identification");
  unknown.assessment.risk!.provisional_score = 101;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Application inventory may be out of date", { exact: true }),
  ).toBeVisible();
  await expect(unknownRow.locator('[aria-label^="Risk score"]')).toHaveCount(0);
  unknown.assessment.risk!.provisional_score = 37;
  unknown.assessment.confidence = "high";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Application inventory may be out of date", { exact: true }),
  ).toBeVisible();
  expect(state.writes).toHaveLength(0);
});

test("risk similarity flags use supported capabilities and update with unapproved decisions", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = {
    ...state.items[5],
    software_type: "application",
    review_required: true,
    research_status: "complete",
  };
  // Illustrative assessments exercise the UI; these are not verified product ratings.
  state.items = [
    {
      ...seed,
      id: "openclaw",
      name: "OpenClaw",
      approval_status: "unapproved",
      assessment: research([3, 3, 2, 3], "high", 88),
    },
    {
      ...seed,
      id: "agent",
      name: "Autonomous workspace agent",
      assessment: research([3, null, 2, 3], "medium", 82),
    },
    {
      ...seed,
      id: "chatgpt",
      name: "ChatGPT",
      category: "chat_assistant",
      approval_status: "approved",
      assessment: research([2, 1, 1, 1], "high", 30),
    },
    {
      ...seed,
      id: "weak",
      name: "Unverified agent",
      assessment: research([3, 3, 3, 3], "low"),
    },
    {
      ...seed,
      id: "chrome",
      name: "Google Chrome",
      category: "ordinary",
      assessment: null,
      needs_attention: false,
      review_required: false,
    },
    {
      ...seed,
      id: "paint",
      name: "Microsoft Paint",
      category: "ordinary",
      assessment: null,
      needs_attention: false,
      review_required: false,
    },
  ];
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(
    monitoring.getByRole("columnheader", { name: "Risk score", exact: true }),
  ).toBeVisible();
  await expect(monitoring.locator('[data-application="agent"]')).toContainText(
    "82",
  );
  await expect(monitoring.locator('[data-application="agent"]')).toContainText(
    "Similar to unapproved",
  );
  await expect(
    column(page, "Approved").getByText("Similar to unapproved", {
      exact: true,
    }),
  ).toHaveCount(0);
  await expect(
    monitoring.locator('[data-application="weak"]'),
  ).not.toContainText("Similar to unapproved");
  await expect(
    page.locator('tr[data-application="chrome"], tr[data-application="paint"]'),
  ).toHaveCount(0);
  await expect(applications(page).locator("tbody tr")).toHaveCount(6);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({
    path: info.outputPath("application-risk-review.png"),
    fullPage: true,
    animations: "disabled",
  });
  await monitoring
    .getByRole("button", {
      name: "Why Autonomous workspace agent is similar to unapproved apps",
      exact: true,
    })
    .click();
  const drawer = page.getByRole("dialog");
  const similarity = drawer.getByRole("region", {
    name: "Similar to unapproved apps",
    exact: true,
  });
  await expect(similarity).toContainText("OpenClaw");
  await expect(similarity).toContainText(
    "Code execution · External data transmission · Autonomy",
  );
  await expect(similarity).not.toContainText("File access");
  const risk = drawer.getByRole("region", {
    name: "Risk assessment",
    exact: true,
  });
  await expect(risk).toContainText("Risk score 82/100");
  await expect(risk).toContainText("Research confidence: medium");
  await risk
    .getByText("Evidence and available controls", { exact: true })
    .click();
  await expect(risk).toContainText("File access · Unverified");
  await expect(risk).toContainText("community allegations are unconfirmed");
  await risk.getByText("Evidence and available controls", { exact: true }).click();
  await drawer.getByRole("button", { name: "Approve", exact: true }).scrollIntoViewIfNeeded();
  await page.screenshot({
    path: info.outputPath("application-risk-evidence.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 420 });
  expect(await drawer.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(
    true,
  );
  await expect(
    drawer.getByRole("button", { name: "Done", exact: true }),
  ).toBeInViewport();
  await similarity.scrollIntoViewIfNeeded();
  await expect(similarity).toBeInViewport();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await fits(page);
  await page.screenshot({
    path: info.outputPath("application-risk-mobile.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await change(page, "OpenClaw", "Approved");
  await expect(
    monitoring.locator('[data-application="agent"]'),
  ).not.toContainText("Similar to unapproved");
  await expect(
    monitoring.locator('[data-application="agent"] [aria-label^="Risk score"]'),
  ).toHaveText("82");
  await change(page, "OpenClaw", "Unapproved");
  await expect(monitoring.locator('[data-application="agent"]')).toContainText(
    "Similar to unapproved",
  );
  await change(page, "Autonomous workspace agent", "Approved");
  await expect(
    column(page, "Approved").getByRole("button", {
      name: "Why Autonomous workspace agent is similar to unapproved apps",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    column(page, "Approved").locator(
      '[data-application="agent"] [aria-label^="Risk score"]',
    ),
  ).toHaveCount(0);
  await column(page, "Approved").getByRole("button", { name: "Autonomous workspace agent", exact: true }).click();
  await expect(risk).toContainText("Risk score 82/100");
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  state.items.find((app) => app.id === "openclaw")!.assessment = research(
    [3, 3, 2, 3],
    "low",
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Similar to unapproved", { exact: true }),
  ).toHaveCount(0);
  const legacy = state.items.find((app) => app.id === "agent")!;
  legacy.assessment!.risk = undefined;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    column(page, "Approved").locator('[data-application="agent"]'),
  ).not.toContainText("Awaiting risk assessment");
  await column(page, "Approved").getByRole("button", { name: "Autonomous workspace agent", exact: true }).click();
  await expect(risk).toContainText("Awaiting risk assessment");
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  legacy.assessment!.risk = {
    score: 101,
    reason: "Invalid score",
    sources: ["https://example.com/risk"],
  };
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("Application inventory may be out of date", { exact: true }),
  ).toBeVisible();
  expect(state.writes).toHaveLength(3);
});

test("close local model profiles are flagged without treating category or missing evidence as similarity", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  const seed = {
    ...state.items[5],
    category: "local_model_runtime",
    software_type: "application",
    review_required: true,
    research_status: "complete",
  };
  // Illustrative profiles, not verified product assessments.
  state.items = [
    {
      ...seed,
      id: "ollama",
      name: "Ollama",
      approval_status: "unapproved",
      assessment: research([0, 2, 0, 1], "high", 25),
    },
    {
      ...seed,
      id: "close",
      name: "Local model app",
      assessment: research([0, 1, 0, 1], "medium", 20),
    },
    {
      ...seed,
      id: "different",
      name: "Different runtime",
      assessment: research([0, 0, 2, 1], "high", 45),
    },
    {
      ...seed,
      id: "chat",
      name: "Chat assistant",
      category: "chat_assistant",
      assessment: research([0, 1, 0, 1], "high", 20),
    },
    {
      ...seed,
      id: "partial",
      name: "Unverified runtime",
      assessment: research([null, 2, null, 1], "medium", 25),
    },
    {
      ...seed,
      id: "weak",
      name: "Weak research runtime",
      assessment: research([0, 2, 0, 1], "low"),
    },
  ];
  await page.goto("/ai-inventory");
  const monitoring = column(page, "Monitoring");
  await expect(
    monitoring.getByText("Similar to unapproved", { exact: true }),
  ).toHaveCount(1);
  await monitoring
    .getByRole("button", {
      name: "Why Local model app is similar to unapproved apps",
      exact: true,
    })
    .click();
  const drawer = page.getByRole("dialog");
  const similarity = drawer.getByRole("region", {
    name: "Similar to unapproved apps",
    exact: true,
  });
  await expect(similarity).toContainText("Ollama");
  await expect(similarity).toContainText("Same category: Local model runtime");
  await expect(similarity).toContainText(
    "4 supported dimensions differ by at most one level in total",
  );
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  // Three supported dimensions can match; an unknown dimension contributes nothing.
  state.items.find((app) => app.id === "close")!.assessment = research(
    [0, null, 0, 1],
    "medium",
    20,
  );
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    monitoring.getByText("Similar to unapproved", { exact: true }),
  ).toHaveCount(1);
});

test("software context keeps built-ins and libraries in inventory and makes installations findable", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const seed = state.items[5];
  state.items = [
    {
      ...seed,
      id: "image-playground",
      name: "Image Playground",
      display_name: "Image Playground",
      category: "other_ai",
      software_type: "application",
      is_builtin: true,
      review_required: false,
      device_count: 6,
      users: users(6),
      review_reason:
        "Reported in the operating system's built-in application location.",
    },
    {
      ...seed,
      id: "clipboard",
      name: "@mariozechner/clipboard",
      display_name: "Clipboard utility",
      category: "ordinary",
      assessment: null,
      software_type: "library",
      needs_attention: false,
      review_required: false,
      device_count: 2,
      users: users(2),
      review_reason: "The available evidence identifies ordinary software.",
    },
    {
      ...seed,
      id: "pi-core",
      name: "@mariozechner/pi-agent-core",
      display_name: "Pi agent library",
      assessment: null,
      category: "other_ai",
      software_type: "library",
      review_required: false,
    },
    {
      ...seed,
      id: "pi-agent",
      name: "@mariozechner/pi-coding-agent",
      display_name: "Pi coding agent",
      software_type: "command_line_tool",
      review_required: true,
    },
    {
      ...seed,
      id: "unknown",
      name: "unknown-package",
      category: null,
      software_type: "package",
      assessment: null,
      assessment_status: "pending",
      review_required: false,
      classification_status: "unknown",
    },
    {
      ...seed,
      id: "handler",
      name: "Claude Code URL Handler",
      assessment: research([3, 3, 3, 3], "high", null),
      category: "other_ai",
      software_type: "helper",
      review_required: false,
    },
  ];
  const location =
    "/Users/Jev/workspace/a-project-with-a-long-name/node_modules/@mariozechner/clipboard";
  state.installations.clipboard = [
    {
      name: "@mariozechner/clipboard",
      identifier: "@mariozechner/clipboard",
      publisher: "",
      version: "1.0.0",
      source: "osquery-npm-packages",
      ecosystem: "npm",
      kind: "package",
      path: location,
      scope: "user",
      root: "/Users/Jev/workspace/a-project-with-a-long-name",
      environment: "Project packages",
    },
  ];
  await page.goto("/ai-inventory");
  await expect(
    page.getByText("Software context is unavailable", { exact: true }),
  ).toHaveCount(0);
  await expect(
    column(page, "Monitoring").locator("[data-open-app]"),
  ).toHaveText(["Pi coding agent"]);
  const software = applications(page);
  await expect(software.locator("tbody tr")).toHaveCount(6);
  await expect(software.getByRole("columnheader")).toHaveText([
    "Software",
    "AI classification",
    "Approval status",
    "Users",
    "Devices",
    "Report",
  ]);
  await page.setViewportSize({ width: 390, height: 700 });
  await fits(page);
  const scope = software.getByRole("group", { name: "AI classification filter" });
  const scopeButtons = scope.getByRole("button");
  await expect(scopeButtons).toHaveText([
    "All software", "AI software", "Not AI-focused", "Unknown",
  ]);
  for (const button of await scopeButtons.all()) {
    await button.scrollIntoViewIfNeeded();
    await expect(button).toBeInViewport({ ratio: 1 });
  }
  await page.screenshot({
    path: info.outputPath("software-filters-mobile.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await software.getByRole("button", { name: "Claude Code URL Handler", exact: true }).click();
  const helper = page.getByRole("dialog", { name: "Claude Code URL Handler", exact: true });
  await expect(helper.getByRole("region", { name: "Risk assessment", exact: true })).toContainText("Supporting software");
  await expect(helper).not.toContainText("Risk score 100");
  await helper.getByRole("button", { name: "Done", exact: true }).click();
  await expect(
    software.locator("tbody tr").filter({ hasText: "Image Playground" }),
  ).toContainText("Built-in app");
  await expect(
    software.locator("tbody tr").filter({ hasText: "Clipboard utility" }),
  ).toContainText("Outside approval review");
  await page.screenshot({
    path: info.outputPath("application-context-review.png"),
    fullPage: true,
    animations: "disabled",
  });
  await software.screenshot({
    path: info.outputPath("software-filters.png"),
    animations: "disabled",
  });
  const names = software.locator("tbody [data-open-app]");
  const allNames = await names.allTextContents();
  const groupedNames: string[] = [];
  for (const [label, expected] of [
    ["AI software", [
      "Claude Code URL Handler", "Image Playground", "Pi agent library", "Pi coding agent",
    ]],
    ["Not AI-focused", ["Clipboard utility"]],
    ["Unknown", ["unknown-package"]],
  ] as const) {
    const filter = software.getByRole("button", { name: label, exact: true });
    await filter.click();
    await expect(filter).toHaveAttribute("aria-pressed", "true");
    await expect(scope.getByRole("button", { pressed: true })).toHaveCount(1);
    await expect(names).toHaveText([...expected]);
    groupedNames.push(...(await names.allTextContents()));
  }
  expect(new Set(groupedNames).size).toBe(groupedNames.length);
  expect([...groupedNames].sort()).toEqual([...allNames].sort());
  await expect(software.locator("tbody")).toContainText("Classification inconclusive");
  await software
    .getByRole("button", { name: "All software", exact: true })
    .click();
  await expect(names).toHaveText(allNames);
  await page.getByRole("searchbox").fill("clipboard utility");
  await expect(software.locator("tbody tr")).toHaveCount(1);
  await page.getByRole("searchbox").fill("@mariozechner/clipboard");
  await expect(software.locator("tbody tr")).toHaveCount(1);
  await software
    .getByRole("button", { name: "Clipboard utility", exact: true })
    .click();
  const drawer = page.getByRole("dialog", {
    name: "Clipboard utility",
    exact: true,
  });
  await drawer.getByText("Installation guidance", { exact: true }).click();
  await expect(
    drawer.getByRole("region", { name: "Software context" }),
  ).toContainText("@mariozechner/clipboard");
  await expect(drawer).toContainText("may not appear in Applications");
  await expect(drawer).toContainText("owning app is not confirmed");
  await expect(
    drawer.getByText(location, { exact: true }).first(),
  ).toBeVisible();
  await expect(
    drawer.getByText("Project packages", { exact: true }).first(),
  ).toBeVisible();
  await expect(
    drawer.getByRole("button", { name: "Approve", exact: true }),
  ).toHaveCount(0);
  await page.screenshot({
    path: info.outputPath("application-package-details.png"),
    animations: "disabled",
  });
  await page.setViewportSize({ width: 390, height: 700 });
  await fits(page);
  expect(
    await drawer.evaluate(
      (element) => element.scrollWidth <= element.clientWidth,
    ),
  ).toBe(true);
  await expect(
    drawer.getByRole("button", { name: "Done", exact: true }),
  ).toBeInViewport();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("searchbox").fill("Image Playground");
  await software
    .getByRole("button", { name: "AI software", exact: true })
    .click();
  await software
    .getByRole("button", { name: "Image Playground", exact: true })
    .click();
  const builtIn = page.getByRole("dialog", {
    name: "Image Playground",
    exact: true,
  });
  await expect(builtIn).toContainText("Outside approval review");
  await builtIn.getByText("Installation guidance", { exact: true }).click();
  await expect(builtIn).toContainText("operating system's available controls");
  await expect(builtIn).toContainText("Installation location not reported.");
  await change(page, "Image Playground", "Unapproved", builtIn);
  await expect(
    builtIn.getByRole("button", { name: "Mark unapproved", exact: true }),
  ).toBeDisabled();
  await expect(
    builtIn.getByRole("region", { name: "Software context" }),
  ).toContainText("An organization approval decision is recorded");
  await builtIn.getByRole("button", { name: "Done", exact: true }).click();
  await expect(
    column(page, "Unapproved").locator("[data-open-app]"),
  ).toHaveText(["Image Playground"]);
  await expect(software.locator("tbody tr")).toHaveCount(1);
  await expect(software.locator("tbody tr")).toContainText("Unapproved");
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    column(page, "Unapproved").locator("[data-open-app]"),
  ).toHaveText(["Image Playground"]);
  await expect(software.locator("tbody tr")).toHaveCount(1);
  await expect(software.locator("tbody tr")).toContainText("Unapproved");
});

test("all installed apps rank by distinct users and user filters scope device and user details", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  await page.goto("/ai-inventory");
  const table = page.getByRole("table", {
    name: "All installed software",
    exact: true,
  });
  const rows = table.locator("tbody tr");
  await expect(rows).toHaveCount(10);
  await expect(
    table.getByRole("columnheader", { name: "Users", exact: true }),
  ).toHaveAttribute("aria-sort", "descending");
  const counts = await rows.evaluateAll((rows) =>
    rows.map((row) => Number(row.children[3].textContent)),
  );
  expect(counts).toEqual([...counts].sort((a, b) => b - a));
  await expect(rows.first()).toContainText("Google Chrome");
  await expect(
    rows.filter({ hasText: "OpenCode" }).locator("td").nth(3),
  ).toHaveText("2");
  await expect(rows.filter({ hasText: "Google Chrome" })).toContainText(
    "Outside approval review",
  );

  async function selectUser(name: string) {
    await page
      .getByRole("combobox", { name: "Endpoint user", exact: true })
      .click();
    await page.getByRole("option", { name, exact: true }).click();
  }
  await selectUser("bob");
  await expect(rows).toHaveCount(9);
  await expect(
    table.getByRole("button", { name: "Internal Dev Helper", exact: true }),
  ).toHaveCount(0);
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(3);
  await expect(
    column(page, "Monitoring").locator(
      '[data-application="opencode"] [data-open-devices]',
    ),
  ).toHaveText("3");
  await expect(
    rows.filter({ hasText: "OpenCode" }).locator("td").nth(3),
  ).toHaveText("1");
  const drawer = page.getByRole("dialog", { name: "OpenCode", exact: true });
  await table.getByRole("button", { name: "Show 1 users for OpenCode", exact: true }).click();
  await expect(drawer.getByRole("list", { name: "Reported users" }).getByRole("listitem")).toHaveText(["bob1 device"]);
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await column(page, "Monitoring").getByRole("button", { name: "Show 2 users for OpenCode", exact: true }).click();
  await expect(drawer.getByRole("list", { name: "Reported users" }).getByRole("listitem")).toHaveText(["alice2 devices", "bob1 device"]);
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await table
    .getByRole("button", { name: "Show 1 devices for OpenCode" })
    .click();
  await expect(
    drawer
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(1);
  await expect(drawer.getByText("win-dev-04", { exact: true })).toBeVisible();
  await expect(
    drawer.getByText("bob · windows", { exact: true }),
  ).toBeVisible();
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await expect(
    table.getByRole("button", { name: "Show 1 devices for OpenCode" }),
  ).toBeFocused();
  // Opened from a review card, the drawer lists every device.
  await column(page, "Monitoring")
    .getByRole("button", { name: "Show 3 devices for OpenCode" })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Done", exact: true })
    .click();
  await change(page, "OpenCode", "Approved");
  await expect(rows.filter({ hasText: "OpenCode" })).toContainText("Approved");
  await selectUser("alice");
  await expect(
    column(page, "Approved").getByRole("button", {
      name: "OpenCode",
      exact: true,
    }),
  ).toBeVisible();
  await expect(rows.filter({ hasText: "OpenCode" })).toContainText("Approved");
  await selectUser("Unattributed");
  await expect(rows).toHaveCount(6);
  expect(
    await rows.evaluateAll((rows) =>
      rows.map((row) => row.children[3].textContent),
    ),
  ).toEqual(Array(6).fill("0"));
  await table.getByRole("button", { name: "Show 0 users for Google Chrome", exact: true }).click();
  const unattributed = page.getByRole("dialog", { name: "Google Chrome", exact: true });
  await expect(unattributed.getByRole("list", { name: "Reported users" })).toHaveCount(0);
  await expect(unattributed.getByText("No reported users", { exact: true })).toBeVisible();
  await expect(unattributed).toContainText("1 device has no reported username and is excluded from the user count.");
  await unattributed.getByRole("button", { name: "Done", exact: true }).click();
  await table
    .getByRole("button", { name: "Show 1 devices for Google Chrome" })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByText("Unattributed · darwin", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(1);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Done", exact: true })
    .click();
  await selectUser("All users");
  await expect(rows).toHaveCount(10);
  await table
    .getByRole("button", { name: "Show 3 devices for OpenCode" })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
  await page
    .getByRole("dialog")
    .getByRole("button", { name: "Done", exact: true })
    .click();
  await page.screenshot({
    path: info.outputPath("installed-apps.png"),
    fullPage: true,
    animations: "disabled",
  });
  // Removing the selected user's installations must not fall back to all users.
  await selectUser("developer-23");
  state.items = [];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(rows).toHaveCount(0);
  await expect(
    page.getByText("No applications for this user", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("combobox", { name: "Endpoint user", exact: true }),
  ).toHaveText("developer-23");
});

test("read-only roles can inspect devices but cannot change approval", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  state.roles = ["security_leadership"];
  await page.goto("/ai-inventory");
  await expect(
    column(page, "Monitoring").getByRole("button", {
      name: "OpenCode",
      exact: true,
    }),
  ).toBeVisible();
  await expect(page.getByRole("button", { name: /Approval for/ })).toHaveCount(
    0,
  );
  await column(page, "Monitoring")
    .getByRole("button", { name: "OpenCode", exact: true })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
  await expect(
    page
      .getByRole("dialog")
      .getByRole("button", { name: "Approve", exact: true }),
  ).toHaveCount(0);
  expect(state.writes).toHaveLength(0);
});

test("refresh, incompatible responses, failed writes, and device failures preserve honest states", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  await page.goto("/ai-inventory");
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(3);
  state.writeStatus = 503;
  await change(page, "OpenCode", "Approved");
  await expect(page.locator("main").getByRole("alert")).toContainText(
    "Approval was not confirmed",
  );
  await expect(
    column(page, "Monitoring").getByRole("button", {
      name: "Approval for OpenCode",
    }),
  ).toBeEnabled();
  state.incompatible = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "incompatible" }),
  ).toBeVisible();
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(3);
  await expect(
    column(page, "Monitoring")
      .getByRole("button", { name: /Approval for/ })
      .first(),
  ).toBeDisabled();
  state.incompatible = false;
  state.readStatus = 503;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByRole("alert").filter({ hasText: "may be out of date" }),
  ).toBeVisible();
  state.readStatus = 200;
  state.deviceStatus = 503;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await column(page, "Monitoring")
    .getByRole("button", { name: "OpenCode", exact: true })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("alert")
      .filter({ hasText: "Unable to load devices" }),
  ).toBeVisible();
  await expect(page.getByRole("dialog").getByRole("list", { name: "Installed devices" })).toHaveCount(0);
  state.deviceStatus = 200;
  await page.getByRole("dialog").getByRole("button", { name: "Retry" }).click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
});

test("missing credentials and empty inventory do not imply successful classification", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  state.configured = false;
  state.items = [state.items.find((app) => app.id === "helper")!];
  await page.goto("/ai-inventory");
  await expect(
    page.getByText("Automatic classification is unavailable", { exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Configure the Intelligence API connection in Settings and enable", { exact: false })).toBeVisible();
  await expect(page.getByText("Detection OpenAI API key", { exact: false })).toHaveCount(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.getByText("Configure the Intelligence API connection in Settings and enable", { exact: false })).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    await page.screenshot({ path: info.outputPath(`classification-service-${width}.png`), fullPage: true });
  }
  await expect(column(page, "Monitoring")).toContainText(
    "Awaiting classification",
  );
  state.items = [];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.getByText("No applications reported", { exact: true }),
  ).toBeVisible();
  await expect(page.locator("tr[data-application]")).toHaveCount(0);
});

test("long names, bounded lists, phone layouts, and drawer controls remain reachable", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const observedName = `JevAgent ${"long-name-".repeat(25)}`;
  state.items.push(
    ...Array.from({ length: 70 }, (_, i) => ({
      ...state.items[5],
      id: `extra-${i}`,
      name: i === 1 ? "@vendor/jev-cli" : i ? `Tool ${i}` : observedName,
      display_name:
        i === 1 ? "Jev coding agent" : i ? `Tool ${i}` : observedName,
      reason: "The publisher describes JevAgent as an AI application.",
    })),
  );
  await page.goto("/ai-inventory");
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(50);
  expect(
    await column(page, "Monitoring").evaluate(
      (el) => el.getBoundingClientRect().height,
    ),
  ).toBeLessThanOrEqual(500);
  const list = column(page, "Monitoring").getByRole("region", {
    name: "Monitoring applications list",
    exact: true,
  });
  await list.scrollIntoViewIfNeeded();
  const headerY = (await column(page, "Monitoring")
    .getByRole("heading")
    .boundingBox())!.y;
  await list.focus();
  await page.keyboard.press("PageDown");
  await expect
    .poll(() => list.evaluate((el) => el.scrollTop))
    .toBeGreaterThan(0);
  expect(
    (await column(page, "Monitoring").getByRole("heading").boundingBox())!.y,
  ).toBeCloseTo(headerY, 0);
  expect(
    await column(page, "Approved")
      .getByRole("region")
      .evaluate((el) => el.scrollTop),
  ).toBe(0);
  await column(page, "Monitoring")
    .getByRole("button", { name: "Show more monitoring applications" })
    .click();
  await expect(
    column(page, "Monitoring").locator("tr[data-application]"),
  ).toHaveCount(73);
  await list
    .locator("tr[data-application]")
    .last()
    .getByRole("button", { name: /Approval for/ })
    .scrollIntoViewIfNeeded();
  await expect(
    list
      .locator("tr[data-application]")
      .last()
      .getByRole("button", { name: /Approval for/ }),
  ).toBeInViewport();
  await list.evaluate((el) => {
    el.scrollTop = 0;
  });
  await page
    .getByRole("heading", { name: "AI Apps", exact: true })
    .scrollIntoViewIfNeeded();
  await page.screenshot({
    path: info.outputPath("application-review-bounded.png"),
    fullPage: true,
    animations: "disabled",
  });
  await page.getByRole("searchbox").fill("jevagent");
  await expect(applications(page).locator("tbody tr")).toHaveCount(1);
  await expect(
    column(page, "Monitoring").getByRole("button", {
      name: `Approval for ${observedName}`,
      exact: true,
    }),
  ).toBeVisible();
  expect(
    await column(page, "Monitoring")
      .getByRole("button", { name: observedName, exact: true })
      .evaluate((el) => el.scrollWidth <= el.clientWidth + 1),
  ).toBe(true);
  await applications(page)
    .getByRole("button", { name: observedName, exact: true })
    .click();
  const evidence = page.getByRole("dialog", {
    name: observedName,
    exact: true,
  });
  await evidence.getByText("Why this classification?", { exact: true }).click();
  await expect(
    evidence.locator("details").filter({ hasText: "Why this classification?" }).getByText(
      "The publisher describes JevAgent as an AI application.",
      { exact: true },
    ),
  ).toBeVisible();
  await evidence.getByRole("button", { name: "Done", exact: true }).click();
  await page.getByRole("searchbox").fill("@vendor/jev-cli");
  await expect(
    column(page, "Monitoring").getByRole("button", {
      name: "Approval for Jev coding agent",
      exact: true,
    }),
  ).toBeVisible();
  await column(page, "Monitoring")
    .getByRole("button", { name: "Jev coding agent", exact: true })
    .click();
  const sourced = page.getByRole("dialog", {
    name: "Jev coding agent",
    exact: true,
  });
  await expect(
    sourced.getByRole("region", { name: "Software context" }),
  ).toContainText("@vendor/jev-cli");
  await sourced.getByRole("button", { name: "Done", exact: true }).click();
  await page.getByRole("searchbox").clear();
  for (const width of [1280, 1024, 820, 390]) {
    await page.setViewportSize({ width, height: 844 });
    await fits(page);
    expect(await list.evaluate((el) => el.clientHeight)).toBeLessThanOrEqual(
      448,
    );
  }
  await page.setViewportSize({ width: 390, height: 420 });
  expect(await list.evaluate((el) => el.clientHeight)).toBeLessThanOrEqual(252);
  await list
    .locator("tr[data-application]")
    .last()
    .getByRole("button", { name: /Approval for/ })
    .click();
  await expect(
    page.getByRole("button", { name: "Approve", exact: true }),
  ).toBeInViewport();
  await page.keyboard.press("Escape");
  await expect(
    list
      .locator("tr[data-application]")
      .last()
      .getByRole("button", { name: /Approval for/ }),
  ).toBeFocused();
  await page.setViewportSize({ width: 390, height: 844 });
  for (const control of await page
    .getByRole("group", { name: "Software filters" })
    .locator("input, [role=combobox]")
    .all()) {
    expect(
      await control.evaluate((el) => el.getBoundingClientRect().height),
    ).toBe(40);
  }
  await page.getByRole("searchbox").fill("opencode");
  await page.screenshot({
    path: info.outputPath("application-review-mobile.png"),
    fullPage: true,
    animations: "disabled",
  });
  await column(page, "Monitoring")
    .getByRole("button", { name: "OpenCode", exact: true })
    .click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("list", { name: "Installed devices" })
      .getByRole("listitem"),
  ).toHaveCount(3);
  await page.setViewportSize({ width: 390, height: 420 });
  await expect(
    page.getByRole("dialog").getByRole("button", { name: "Done", exact: true }),
  ).toBeInViewport();
  await fits(page);
  const drawer = page.getByRole("dialog");
  expect(await drawer.evaluate((el) => el.scrollWidth <= el.clientWidth)).toBe(
    true,
  );
  await drawer.getByText("Why this classification?", { exact: true }).click();
  await drawer.getByRole("link", { name: /^Source 1/ }).scrollIntoViewIfNeeded();
  await expect(drawer.getByRole("link", { name: /^Source 1/ })).toBeInViewport();
  await page.screenshot({
    path: info.outputPath("application-devices-mobile.png"),
    animations: "disabled",
  });
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
});

function overviewLink(page: Page) {
  return page
    .getByRole("link", { name: "Overview", exact: true })
    .and(page.locator('a[href="/"]'));
}

function applications(page: Page) {
  return page.getByRole("region", {
    name: "All installed software",
    exact: true,
  });
}
function applicationRow(page: Page, name: string) {
  return applications(page)
    .getByRole("row")
    .filter({ has: page.getByRole("button", { name, exact: true }) });
}
function observedUsers(page: Page, name: string) {
  return applicationRow(page, name).getByRole("cell").nth(3);
}
function approval(page: Page, name: string) {
  return applicationRow(page, name).getByRole("cell").nth(2);
}
test("return navigation keeps application inventory and its original timestamp during a failed refresh", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  await page.goto("/ai-inventory");
  const usage = observedUsers(page, "ChatGPT");
  await expect(usage).toHaveText("18");
  const timestamp = page.locator("main time[title]").first();
  const original = await timestamp.getAttribute("title");
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  await page.clock.setFixedTime(new Date("2026-10-18T09:15:20Z"));
  let release!: () => void;
  state.delayRead = new Promise<void>((resolve) => {
    release = resolve;
  });
  state.readStatus = 503;
  const requested = page.waitForRequest(
    "**/api/v1/inventory/application-review",
  );
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await requested;
  await expect(usage).toHaveText("18");
  await expect(timestamp).toHaveAttribute("title", original!);
  await expect(
    page.getByRole("button", { name: "Refreshing…", exact: true }),
  ).toBeDisabled();
  await applications(page).screenshot({
    path: info.outputPath("inventory-cached-navigation.png"),
    animations: "disabled",
  });
  release();
  await expect(
    page.getByText(/Application inventory may be out of date/),
  ).toBeVisible();
  await expect(usage).toHaveText("18");
  await expect(timestamp).toHaveAttribute("title", original!);
});

test("malformed refreshes keep a valid navigation snapshot without extending its 60-second age", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  await page.goto("/ai-inventory");
  const chatgpt = applicationRow(page, "ChatGPT");
  await expect(chatgpt).toBeVisible();
  await page.clock.setFixedTime(new Date("2026-10-18T09:15:20Z"));
  state.incompatible = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByText(/response is incompatible/)).toBeVisible();
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  let release!: () => void;
  state.delayRead = new Promise<void>((resolve) => {
    release = resolve;
  });
  await page.clock.setFixedTime(new Date("2026-10-18T09:15:20Z"));
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await expect(chatgpt).toBeVisible();
  await expect(page.getByText(/response is incompatible/)).toHaveCount(0);
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  await page.clock.setFixedTime(new Date("2026-10-18T09:16:01Z"));
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await expect(
    page.getByText("Loading applications…", { exact: true }),
  ).toBeVisible();
  await expect(chatgpt).toHaveCount(0);
  state.incompatible = false;
  release();
  await expect(chatgpt).toBeVisible();
});

test("an approval completed after navigation updates the current table and rejects an older GET", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  state.roles = ["it_admin"];
  await page.goto("/ai-inventory");
  await expect(
    page.getByRole("button", { name: "Approval for Cursor", exact: true }),
  ).toBeEnabled();
  let releaseSave!: () => void;
  state.delayWrite = new Promise<void>((resolve) => {
    releaseSave = resolve;
  });
  await change(page, "Cursor", "Approved");
  await expect.poll(() => state.writes.length).toBe(1);
  await page.keyboard.press("Escape");
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  const oldItems = structuredClone(state.items);
  let releaseRead!: () => void;
  const pendingRead = new Promise<void>((resolve) => {
    releaseRead = resolve;
  });
  await page.route("**/api/v1/inventory/application-review", async (route) => {
    await pendingRead;
    await route.fulfill({
      json: {
        items: oldItems,
        device_count: 24,
        users: users(24),
        classifier_configured: true,
        generated_at: scanned,
      },
    });
  });
  const requested = page.waitForRequest(
    "**/api/v1/inventory/application-review",
  );
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await requested;
  const cursor = approval(page, "Cursor");
  await expect(cursor).toHaveText("Unapproved");
  releaseSave();
  await expect(cursor).toHaveText("Approved");
  releaseRead();
  await expect(
    page.getByRole("button", { name: "Refresh", exact: true }),
  ).toBeEnabled();
  await expect(cursor).toHaveText("Approved");
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  let releaseReturn!: () => void;
  state.delayRead = new Promise<void>((resolve) => {
    releaseReturn = resolve;
  });
  await page.unroute("**/api/v1/inventory/application-review");
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await expect(cursor).toHaveText("Approved");
  releaseReturn();
  await expect(
    page.getByRole("button", { name: "Refresh", exact: true }),
  ).toBeEnabled();
});

for (const boundary of [
  "logout",
  "renewal 401",
  "renewal 403",
  "read 401",
  "read 403",
  "write 403",
  "late write 403",
]) {
  test(`cached application data and late approvals cannot cross ${boundary}`, async ({
    page,
  }) => {
    const state = await inventoryApi(page);
    state.roles = ["it_admin"];
    state.renewal = boundary.startsWith("renewal");
    let releaseDenial!: () => void;
    const denied = new Promise<void>((resolve) => {
      releaseDenial = resolve;
    });
    if (state.renewal) {
      await page.route("**/api/v1/auth/renew", async (route) => {
        await denied;
        await route.fulfill({
          status: Number(boundary.slice(-3)),
          json: { error: "Session denied" },
        });
      });
    }
    let releaseSave!: () => void;
    const save = new Promise<void>((resolve) => {
      releaseSave = resolve;
    });
    await page.route(
      "**/api/v1/inventory/application-review/cursor/approval",
      async (route) => {
        await save;
        await route.fulfill(
          boundary.endsWith("write 403")
            ? { status: 403, json: { error: "Session denied" } }
            : {
                json: {
                  id: "cursor",
                  approved: true,
                  approval_updated_at: scanned,
                },
              },
        );
      },
    );
    await page.goto("/ai-inventory");
    const chatgpt = observedUsers(page, "ChatGPT");
    await expect(chatgpt).toHaveText("18");
    const saving = page.waitForRequest(
      "**/api/v1/inventory/application-review/cursor/approval",
    );
    await change(page, "Cursor", "Approved");
    await saving;
    await page.keyboard.press("Escape");
    if (boundary === "logout" || boundary === "late write 403") {
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
    } else if (state.renewal) {
      releaseDenial();
    } else if (boundary === "write 403") {
      releaseSave();
    } else {
      await page.route(
        "**/api/v1/inventory/application-review",
        async (route) => {
          await denied;
          await route.fulfill({
            status: Number(boundary.slice(-3)),
            json: { error: "Session denied" },
          });
        },
      );
      await overviewLink(page).click();
      await expect(page.locator("main h1")).toHaveText("Overview");
      await page
        .getByRole("link", { name: "AI Apps", exact: true })
        .click();
      await expect(chatgpt).toHaveText("18");
      releaseDenial();
    }
    if (boundary === "read 403") {
      await expect(applicationRow(page, "ChatGPT")).toHaveCount(0);
      await page.getByRole("button", { name: "Sign out", exact: true }).click();
    }
    await expect(page).toHaveURL(/\/login$/);
    await expect(applications(page)).toHaveCount(0);
    await page.unroute("**/api/v1/auth/renew");
    await page.unroute("**/api/v1/inventory/application-review");
    state.renewal = false;
    // Also exercise a new account, a new tenant, and a changed role. The
    // separate login always creates a fresh dashboard provider.
    if (boundary === "logout") state.userId = "other";
    if (boundary === "renewal 401") state.tenantId = "other-tenant";
    if (boundary !== "read 401") state.roles = ["security_leadership"];
    state.items = structuredClone(apps).map((app) => ({
      ...app,
      device_count: 1,
      users: users(1),
    }));
    let releaseRead!: () => void;
    state.delayRead = new Promise<void>((resolve) => {
      releaseRead = resolve;
    });
    await page.getByLabel("Email address").fill("other@example.invalid");
    await page.getByLabel("Password", { exact: true }).fill("password123");
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.locator("main h1")).toHaveText("Overview");
    await page.getByRole("link", { name: "AI Apps", exact: true }).click();
    const rows = applications(page).getByRole("table").getByRole("button");
    await expect(
      page.getByText("Loading applications…", { exact: true }),
    ).toBeVisible();
    await expect(rows).toHaveCount(0);
    if (boundary !== "write 403") {
      const saved = page.waitForResponse(
        "**/api/v1/inventory/application-review/cursor/approval",
      );
      releaseSave();
      await saved;
      await expect(page).toHaveURL(/\/ai-inventory$/);
      await expect(rows).toHaveCount(0);
    }
    releaseRead();
    await expect(chatgpt).toHaveText("1");
    await expect(approval(page, "Cursor")).toHaveText("Unapproved");
  });
}

test("a late approval response cannot undo a newer approval saved after navigation", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  state.roles = ["it_admin"];
  let releaseFirst!: () => void;
  const first = new Promise<void>((resolve) => {
    releaseFirst = resolve;
  });
  let writes = 0;
  await page.route(
    "**/api/v1/inventory/application-review/cursor/approval",
    async (route) => {
      const approved = route.request().postDataJSON().approved as boolean;
      const timestamp = `2026-10-18T09:15:00.00000${++writes}Z`;
      const cursor = state.items.find((app) => app.id === "cursor")!;
      cursor.approval_status = approved ? "approved" : "unapproved";
      cursor.approval_updated_at = timestamp;
      if (writes === 1) await first;
      await route.fulfill({
        json: { id: "cursor", approved, approval_updated_at: timestamp },
      });
    },
  );
  await page.goto("/ai-inventory");
  await change(page, "Cursor", "Approved");
  await expect.poll(() => writes).toBe(1);
  await page.keyboard.press("Escape");
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  const cursor = approval(page, "Cursor");
  await expect(cursor).toHaveText("Approved");
  await change(page, "Cursor", "Unapproved");
  await expect(cursor).toHaveText("Unapproved");
  await page.keyboard.press("Escape");
  const finished = page.waitForResponse(
    "**/api/v1/inventory/application-review/cursor/approval",
  );
  releaseFirst();
  await finished;
  await expect(cursor).toHaveText("Unapproved");
  await overviewLink(page).click();
  await expect(page.locator("main h1")).toHaveText("Overview");
  let releaseRead!: () => void;
  state.delayRead = new Promise<void>((resolve) => {
    releaseRead = resolve;
  });
  await page.getByRole("link", { name: "AI Apps", exact: true }).click();
  await expect(cursor).toHaveText("Unapproved");
  releaseRead();
});

test("software filters combine and reset pages while the review keeps organization scope", async ({
  page,
}) => {
  const state = await inventoryApi(page);
  state.items.push(
    ...Array.from({ length: 15 }, (_, index) => ({
      ...state.items[8],
      id: `ordinary-${index}`,
      name: `Ordinary tool ${index}`,
    })),
  );
  await page.goto("/ai-inventory");
  const software = applications(page);
  const rows = software.locator("tbody tr");
  const next = software.getByRole("button", { name: "Next software page" });
  const previous = software.getByRole("button", {
    name: "Previous software page",
  });
  await expect(rows).toHaveCount(10);
  await next.click();
  await expect(software).toContainText("11–20 of 25 applications");
  await next.click();
  await expect(rows).toHaveCount(5);
  await expect(next).toBeDisabled();
  await software
    .getByRole("button", { name: "AI software", exact: true })
    .click();
  await expect(rows).toHaveCount(7);
  await expect(previous).toBeDisabled();
  await expect(software).toContainText("1–7 of 7 applications");
  await expect(software.locator("tbody")).not.toContainText("Internal Dev Helper");
  await software
    .getByRole("button", { name: "Unknown", exact: true })
    .click();
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText("Internal Dev Helper");
  await expect(rows).toContainText("Awaiting classification");
  await expect(previous).toBeDisabled();
  await expect(next).toBeDisabled();
  await expect(software).toContainText("1–1 of 1 applications");
  state.items.find((app) => app.id === "helper")!.classification_status =
    "unavailable";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(rows).toHaveCount(1);
  await expect(rows).toContainText("Classification unavailable");
  await software
    .getByRole("button", { name: "AI software", exact: true })
    .click();
  await expect(rows).toHaveCount(7);
  await page.getByRole("combobox", { name: "Application category" }).click();
  await page.getByRole("option", { name: "Coding agent", exact: true }).click();
  await expect(rows).toHaveCount(4);
  await expect(page.locator("tr[data-application]")).toHaveCount(8);
  await page.getByRole("combobox", { name: "Endpoint user" }).click();
  await page.getByRole("option", { name: "bob", exact: true }).click();
  await page.getByRole("searchbox").fill("open");
  await expect(rows).toHaveCount(1);
  await expect(column(page, "Monitoring")).toContainText("3 apps");
  await expect(column(page, "Approved")).toContainText("4 apps");
  await expect(reviewSummary(page)).toHaveText(
    "3 of 8 applications awaiting a decision across 24 devices and 20 users · Highest risk OpenCode on 3 devices · 1 unscored · Cursor is unapproved on 5 devices",
  );
  await change(page, "OpenCode", "Approved");
  await expect(reviewSummary(page)).toHaveText(
    "2 of 8 applications awaiting a decision across 24 devices and 20 users · Highest risk Ollama on 4 devices · 1 unscored · Cursor is unapproved on 5 devices",
  );
  await change(page, "Ollama", "Unapproved");
  await expect(reviewSummary(page)).toContainText("· 2 unapproved");
  await expect(column(page, "Unapproved")).toContainText("2 apps");
  await page
    .getByRole("button", { name: "Clear filters", exact: true })
    .click();
  await expect(rows).toHaveCount(7);
  await software
    .getByRole("button", { name: "Not AI-focused", exact: true })
    .click();
  await expect(software).toContainText("1–10 of 17 applications");
  await next.click();
  await expect(rows).toHaveCount(7);
  state.items = state.items.filter((app) => !app.id.startsWith("ordinary-"));
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(rows).toHaveCount(2);
  await expect(previous).toBeDisabled();
  await expect(software).toContainText("1–2 of 2 applications");
});

test("one Codex product explains scope, preserves installed names, and resolves conflicting approvals", async ({
  page,
}, info) => {
  const state = await inventoryApi(page);
  const codex = state.items.find((app) => app.id === "codex")!;
  Object.assign(codex, {
    approval_status: "unapproved",
    approval_conflict: true,
    approval_scope:
      "Approval covers all recognized Codex desktop app and CLI installations.",
    reported_names: ["ChatGPT", "@openai/codex"],
    device_count: 1,
    users: users(1),
  });
  state.installations.codex = [
    {
      name: "ChatGPT",
      identifier: "com.openai.codex",
      publisher: "OpenAI",
      version: "1",
      source: "osquery-apps",
      ecosystem: "",
      kind: "application",
      path: "/Applications/ChatGPT.app",
      scope: "system",
      root: "/Applications",
      environment: "",
    },
    {
      name: "@openai/codex",
      identifier: "@openai/codex",
      publisher: "OpenAI",
      version: "1",
      source: "osquery-npm-packages",
      ecosystem: "npm",
      kind: "package",
      path: "/opt/homebrew/lib/node_modules/@openai/codex",
      scope: "system",
      root: "/opt/homebrew/lib/node_modules",
      environment: "",
    },
  ];
  await page.goto("/ai-inventory");
  const unapproved = column(page, "Unapproved");
  await expect(
    unapproved
      .getByRole("row")
      .filter({
        has: page.getByRole("button", { name: "Codex", exact: true }),
      }),
  ).toContainText("Review previous approvals");
  await page.getByRole("searchbox").fill("@openai/codex");
  await expect(applicationRow(page, "Codex")).toBeVisible();
  await expect(applicationRow(page, "ChatGPT")).toHaveCount(0);
  await unapproved.getByRole("button", { name: "Codex", exact: true }).click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).toContainText(codex.approval_scope!);
  await expect(drawer).toContainText(
    "Previous installations had different approval decisions.",
  );
  await expect(
    drawer.getByText("/Applications/ChatGPT.app", { exact: true }),
  ).toBeVisible();
  await expect(
    drawer.getByText("@openai/codex", { exact: true }).first(),
  ).toBeVisible();
  await page.screenshot({
    path: info.outputPath("codex-approval-conflict.png"),
    animations: "disabled",
  });
  // Keeping an existing denial must be an available way to resolve a conflict.
  await drawer
    .getByRole("button", { name: "Mark unapproved", exact: true })
    .click();
  await expect(
    drawer.getByText(/Previous installations had different/),
  ).toHaveCount(0);
  await expect(
    drawer.getByRole("button", { name: "Mark unapproved", exact: true }),
  ).toBeDisabled();
  await drawer.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(
    drawer.getByRole("button", { name: "Approve", exact: true }),
  ).toBeDisabled();
  await page.keyboard.press("Escape");
  await page.getByRole("searchbox").fill("");
  await expect(
    column(page, "Approved").getByRole("button", {
      name: "Codex",
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    column(page, "Approved").getByRole("button", {
      name: "ChatGPT",
      exact: true,
    }),
  ).toBeVisible();
  expect(state.writes.map(({ id, body }) => [id, body.approved])).toEqual([
    ["codex", false],
    ["codex", true],
  ]);
  await page.screenshot({
    path: info.outputPath("codex-product-approval.png"),
    animations: "disabled",
  });
});

test("approved and unapproved apps return to monitoring and persist after refresh", async ({ page }, info) => {
  const state = await inventoryApi(page);
  const cursor = state.items.find(app => app.id === "cursor")!;
  cursor.review_required = false;
  await page.goto("/ai-inventory");
  state.writeStatus = 500;
  await change(page, "Cursor", "Monitoring");
  await expect(page.getByText("Approval was not confirmed", { exact: true })).toBeVisible();
  await expect(column(page, "Unapproved").locator('[data-application="cursor"]')).toHaveCount(1);
  state.writeStatus = 200;
  await change(page, "Cursor", "Monitoring");
  await expect(column(page, "Monitoring").getByRole("button", { name: "Approval for Cursor", exact: true })).toBeFocused();
  await expect(page.getByRole("status", { name: "Approval updates" })).toHaveText("Cursor moved to monitoring.");
  await column(page, "Approved").getByRole("button", { name: "Codex", exact: true }).click();
  const drawer = page.getByRole("dialog", { name: "Codex", exact: true });
  await change(page, "Codex", "Monitoring", drawer);
  await expect(drawer.getByRole("button", { name: "Move to monitoring", exact: true })).toBeDisabled();
  await expect(drawer).toContainText("This software is monitored by the organization.");
  await drawer.getByRole("button", { name: "Done", exact: true }).click();
  await page.reload();
  for (const name of ["Cursor", "Codex"]) {
    await expect(column(page, "Monitoring").getByRole("button", { name, exact: true })).toBeVisible();
  }
  await change(page, "Cursor", "Approved");
  await expect(column(page, "Approved").getByRole("button", { name: "Cursor", exact: true })).toBeVisible();
  await column(page, "Approved").getByRole("button", { name: "Approval for Cursor", exact: true }).click();
  await expect(page.getByRole("button", { name: "Move to monitoring", exact: true })).toBeEnabled();
  await page.screenshot({ path: info.outputPath("app-review-menu.png"), animations: "disabled" });
  await page.keyboard.press("Escape");
  await column(page, "Approved").getByRole("button", { name: "Cursor", exact: true }).click();
  await expect(page.getByRole("dialog", { name: "Cursor", exact: true })).toContainText("An organization approval decision is recorded for this software.");
  expect(state.writes.map(({ id, body }) => [id, body.approved])).toEqual([
    ["cursor", null], ["cursor", null], ["codex", null], ["cursor", true],
  ]);
});

for (const width of [1440, 390]) {
  test(`unapproved app notifications load organization recipients and preview before sending at ${width}px`, async ({ page }, info) => {
    const inventory = await inventoryApi(page);
    inventory.deviceIds = [1, 2, 3, 4, 5].map(index => `11111111-1111-4111-8111-${String(index).padStart(12, "0")}`);
    const alerts = await alertApi(page);
    await page.setViewportSize({ width, height: width === 390 ? 640 : 900 });
    await page.goto("/ai-inventory");
    await page.getByRole("combobox", { name: "Endpoint user" }).click();
    await page.getByRole("option", { name: "alice", exact: true }).click();
    const unapproved = column(page, "Unapproved");
    await expect(unapproved.getByRole("columnheader", { name: "Notify users", exact: true })).toBeVisible();
    for (const status of ["Approved", "Monitoring"]) {
      await expect(column(page, status).getByRole("columnheader", { name: "Notify users", exact: true })).toHaveCount(0);
    }
    expect(inventory.deviceReads).toHaveLength(0);
    expect(alerts.queries).toHaveLength(0);
    await fits(page);
    await unapproved.scrollIntoViewIfNeeded();
    if (width === 1440) {
      expect(await unapproved.locator('[data-slot="table-container"]').evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    }
    await page.screenshot({ path: info.outputPath(`app-review-actions-${width}.png`), animations: "disabled" });
    const trigger = unapproved.getByRole("button", { name: "Notify users for Cursor", exact: true });
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Notify users", exact: true });
    await expect(dialog.getByRole("checkbox")).toHaveCount(5);
    await expect(dialog.locator("input:checked")).toHaveCount(5);
    const reads = inventory.deviceReads.length;
    expect(reads).toBeGreaterThan(0);
    await expect(dialog).toContainText("across the organization");
    await expect(dialog.getByLabel("Title", { exact: true })).toHaveValue("Unapproved application: Cursor");
    await expect(dialog.getByLabel("Instructions", { exact: true })).toHaveValue(/not approved by your organization/);
    await expect(dialog.getByRole("button", { name: "Preview alert", exact: true })).toBeInViewport({ ratio: 1 });
    await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeInViewport({ ratio: 1 });
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (width === 390) {
      const scroll = dialog.getByTestId("endpoint-alert-scroll");
      expect(await scroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await scroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(dialog.getByLabel("Instructions", { exact: true })).toBeInViewport();
    }
    await dialog.screenshot({ path: info.outputPath(`app-notify-compose-${width}.png`), animations: "disabled" });
    for (const checkbox of await dialog.getByRole("checkbox").all()) await checkbox.uncheck();
    await expect(dialog.getByRole("button", { name: "Preview alert", exact: true })).toBeDisabled();
    await dialog.getByRole("checkbox", { name: /win-dev-04/ }).check();
    await dialog.getByRole("button", { name: "Preview alert", exact: true }).click();
    const preview = page.getByRole("dialog", { name: "Preview alert", exact: true });
    await expect(preview.getByRole("list", { name: "Selected devices" })).toHaveText("win-dev-04");
    expect(alerts.writes).toHaveLength(0);
    await preview.getByRole("button", { name: "Send to 1 device", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Alert details", exact: true })).toBeVisible();
    expect(alerts.writes).toHaveLength(1);
    expect(alerts.writes[0]).toMatchObject({ csrf: "1", body: {
      application_id: "cursor", sensor_ids: [inventory.deviceIds[2]], command: "", installed_version: "", required_version: "",
    } });
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
    await trigger.click();
    await expect(dialog.getByRole("checkbox")).toHaveCount(5);
    expect(inventory.deviceReads.length).toBeGreaterThan(reads);
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    expect(alerts.writes).toHaveLength(1);
  });
}

test("app notifications handle unavailable recipients and keep read-only roles from sending", async ({ page }) => {
  const inventory = await inventoryApi(page);
  const alerts = await alertApi(page);
  inventory.deviceStatus = 500;
  await page.goto("/ai-inventory");
  await column(page, "Unapproved").getByRole("button", { name: "Notify users for Cursor", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Notify users", exact: true });
  await expect(dialog.getByRole("alert")).toContainText("Could not load recipient devices");
  await expect(dialog.getByRole("button", { name: "Preview alert", exact: true })).toHaveCount(0);
  inventory.deviceStatus = 200;
  await dialog.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(dialog.getByRole("checkbox")).toHaveCount(5);
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  inventory.roles = ["security_leadership"];
  await page.reload();
  const unapproved = column(page, "Unapproved");
  await expect(unapproved.getByRole("button", { name: "Approval for Cursor", exact: true })).toHaveCount(0);
  await expect(unapproved.getByRole("button", { name: "Notify users for Cursor", exact: true })).toHaveCount(0);
  await unapproved.getByRole("button", { name: "View alerts for Cursor", exact: true }).click();
  const history = page.getByRole("dialog", { name: "Alerts", exact: true });
  await expect(history).toContainText("IT Admins and Security Analysts can send alerts");
  await expect(history.getByRole("button", { name: "New alert", exact: true })).toHaveCount(0);
  expect(alerts.writes).toHaveLength(0);
});

for (const width of [1440, 390]) {
  test(`endpoint alerts select recipients, preview, retry safely, and track receipts at ${width}px`, async ({page}, info) => {
    const inventory = await inventoryApi(page);
    inventory.items.find(item => item.id === 'opencode')!.name = 'LiteLLM';
    inventory.deviceIds = [1, 2, 3].map(index => `11111111-1111-4111-8111-${String(index).padStart(12, '0')}`);
    const alerts = await alertApi(page);
    await page.setViewportSize({width, height: width === 390 ? 640 : 900});
    await page.goto('/ai-inventory');
    await column(page, 'Monitoring').getByRole('button', {name:'LiteLLM', exact:true}).click();
    await page.getByRole('button', {name:'Alerts', exact:true}).click();
    await page.getByRole('button', {name:'New alert', exact:true}).click();
    const dialog = page.getByRole('dialog', {name:'New alert', exact:true});
    await expect(dialog.getByRole('checkbox')).toHaveCount(3);
    await expect(dialog.getByRole('checkbox').first()).not.toBeChecked();
    await expect(dialog.getByRole('button', {name:'Preview alert'})).toBeDisabled();
    await dialog.getByRole('checkbox', {name:/macbook-pro-07/}).check();
    await dialog.getByLabel('Title', {exact:true}).fill(alertExample.title);
    await dialog.getByLabel('Instructions', {exact:true}).fill(alertExample.message);
    await dialog.getByLabel('Command (optional)', {exact:true}).fill(alertExample.command);
    await dialog.getByLabel('Installed version (optional)', {exact:true}).fill(alertExample.installed_version);
    await expect(dialog.getByRole('button', {name:'Preview alert'})).toBeDisabled();
    await dialog.getByLabel('Required version (optional)', {exact:true}).fill(alertExample.required_version);
    const scroll = dialog.getByTestId('endpoint-alert-scroll');
    await expect.poll(() => scroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
    expect(await scroll.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await expect(dialog.getByRole('button', {name:'Preview alert'})).toBeInViewport({ratio:1});
    await dialog.getByRole('button', {name:'Preview alert'}).click();
    const preview = page.getByRole('dialog', {name:'Preview alert', exact:true});
    await expect(preview.getByRole('region', {name:'Alert message'})).toContainText(alertExample.command);
    await expect(preview.getByRole('list', {name:'Selected devices'})).toHaveText('macbook-pro-07');
    await expect(preview.getByText('Update required', {exact:true})).toHaveCount(0);
    await expect(preview.getByText('Need help with this update?')).toHaveCount(0);
    await preview.screenshot({path:info.outputPath('endpoint-alert-preview.png')});
    alerts.failSend = true;
    await preview.getByRole('button', {name:'Send to 1 device', exact:true}).click();
    await expect(preview.getByRole('alert')).toContainText('Send was not confirmed');
    await preview.getByRole('button', {name:'Send to 1 device', exact:true}).click();
    const detail = page.getByRole('dialog', {name:'Alert details', exact:true});
    await expect(detail.getByRole('list', {name:'Delivery status'})).toContainText('Pending receipt');
    expect(alerts.writes).toHaveLength(2);
    expect(alerts.writes[0]).toEqual(alerts.writes[1]);
    expect(alerts.writes[1].csrf).toBe('1');
    expect(alerts.writes[1].body).toEqual({...Object.fromEntries(['title','message','command','installed_version','required_version'].map(key => [key,alertExample[key as keyof typeof alertExample]])), application_id:'opencode', sensor_ids:[inventory.deviceIds[0]], request_id:expect.any(String)});
    alerts.received = true;
    await detail.getByRole('button', {name:'Refresh status'}).click();
    await expect(detail.getByRole('list', {name:'Delivery status'})).toContainText('Received by app');
    alerts.acknowledged = true;
    await detail.getByRole('button', {name:'Refresh status'}).click();
    await expect(detail.getByRole('list', {name:'Delivery status'})).toContainText('Acknowledged');
    await detail.getByRole('button', {name:'Back to history'}).click();
    const history = page.getByRole('dialog', {name:'Alerts', exact:true});
    await expect(history.getByRole('list', {name:'Alert history'})).toContainText('1 sent · 1 received by app · 1 acknowledged');
    await fits(page);
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog', {name:'LiteLLM', exact:true})).toBeVisible();
  });
}

test('endpoint alerts keep leadership read only and report unsupported backends', async ({page}) => {
  const inventory = await inventoryApi(page);
  inventory.roles = ['security_leadership'];
  const alerts = await alertApi(page);
  alerts.sent = true;
  await page.goto('/ai-inventory');
  await column(page, 'Monitoring').getByRole('button', {name:'OpenCode', exact:true}).click();
  await page.getByRole('button', {name:'Alerts', exact:true}).click();
  const history = page.getByRole('dialog', {name:'Alerts', exact:true});
  await expect(history.getByRole('button', {name:'New alert'})).toHaveCount(0);
  await history.getByRole('button', {name:alertExample.title, exact:true}).click();
  await expect(page.getByRole('list', {name:'Delivery status'})).toContainText('Pending receipt');
  await page.getByRole('button', {name:'Back to history'}).click();
  alerts.unavailable = true;
  await history.getByRole('button', {name:'Refresh history'}).click();
  await expect(history.getByRole('alert')).toContainText('deploy the endpoint alerts API first');
  expect(alerts.writes).toHaveLength(0);
});
