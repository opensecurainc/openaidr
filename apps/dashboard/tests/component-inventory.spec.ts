import { test, expect, type Page } from "@playwright/test";
import { expectOverviewCards } from "./overview-cards";
import { alertApi } from "./endpoint-alert-fixture";

const stamp = "2026-10-01T12:00:00Z";
const sensor = "11111111-1111-4111-8111-111111111111";
const rootId = "22222222-2222-4222-8222-222222222222";
const location = {
  sensor_id: sensor,
  hostname: "dev-mac",
  os: "darwin",
  scope: "user",
  user: "alex",
  environment: "",
  root: "/Users/alex/project/node_modules",
  source: "osquery-npm-packages",
};
const component = {
  ...location,
  id: "component-1",
  root_id: rootId,
  kind: "package",
  ecosystem: "npm",
  identifier: "@example/agent-tools",
  name: "@example/agent-tools",
  version: "2.4.0",
  path: `${location.root}/@example/agent-tools`,
  publisher: "Example team",
  architecture: "",
  evidence: "installed",
  root_status: "partial",
  root_collected_at: stamp,
  last_seen_at: "2026-09-30T12:00:00Z",
  metadata: {
    repository_url: "https://example.invalid/agent-tools",
    license: "MIT",
  },
};
const root = {
  ...location,
  id: rootId,
  platform: "darwin",
  status: "partial",
  component_count: 1,
  relationship_count: 0,
  message: "A package manifest could not be read.",
  collected_at: stamp,
  last_success_at: "2026-09-30T12:00:00Z",
};

const queue = (page: Page) => page.getByRole("region", { name: "Components needing attention", exact: true });
const categoryButton = (page: Page, label: string) => page.getByRole("button", { name: `Show ${label}`, exact: true });
async function openComponents(page: Page) {
  const toggle = page.getByRole("button", { name: "All components", exact: true });
  if (await toggle.getAttribute("aria-expanded") !== "true") await toggle.click();
}
const loadedCoverage = (page: Page) => page.getByRole("region", { name: "Loaded scan coverage", exact: true });
const records = (page: Page) => page.getByRole("region", { name: "All components", exact: true });
const recordCount = (page: Page) => records(page).locator("h2 + span");

async function mockApi(
  page: Page,
  respond: (url: URL) => { status?: number; json: unknown },
) {
  await page.clock.setFixedTime(new Date(stamp));
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.endsWith("auth/me"))
      return route.fulfill({
        json: {
          user: {
            id: "viewer",
            name: "Inventory reviewer",
            email: "viewer@example.invalid",
            roles: ["security_leadership"],
            tenant: {
              id: "tenant",
              name: "Synthetic inventory review",
              slug: "review",
            },
          },
        },
      });
    if (url.pathname === "/api/v1/inventory/attention-history") return route.fulfill({ json: { timezone: "UTC", scope: "tenant", checks_enabled: true, days: Array.from({ length: 30 }, (_, i) => ({ date: new Date(Date.UTC(2026, 8, 2 + i)).toISOString().slice(0, 10), captured_at: null, categories: null })) } });
    if (url.pathname.includes("/inventory/"))
      return route.fulfill(respond(url));
    return route.fulfill({
      status: 503,
      json: { error: { message: "Telemetry unavailable" } },
    });
  });
}

test("supply chain shows all components by default, paginates, filters on the server, and retains records after failed refreshes", async ({
  page,
}, testInfo) => {
  const requests: URL[] = [];
  let fail = false;
  await mockApi(page, (url) => {
    requests.push(url);
    if (url.pathname.endsWith("/relationships"))
      return { json: { items: [], next_cursor: "" } };
    if (fail)
      return {
        status: 503,
        json: { error: { message: "Inventory temporarily unavailable" } },
      };
    const query = url.searchParams;
    const source = query.get("source");
    const isRoots = url.pathname.endsWith("/roots");
    if (isRoots && source !== "osquery-npm-packages")
      return { json: { items: [], next_cursor: "" } };
    if (isRoots)
      return {
        json: {
          items: query.has("cursor")
            ? [
                {
                  ...root,
                  id: "root-2",
                  root: "discovery",
                  status: "unavailable",
                  message: "Default locations could not be discovered.",
                  last_success_at: null,
                  component_count: 0,
                },
              ]
            : [{ ...root, source }],
          next_cursor: query.has("cursor") ? "" : "roots +/cursor",
        },
      };
    if (query.has("q")) return { json: { items: [], next_cursor: "" } };
    return {
      json: {
        items: [
          {
            ...component,
            source,
            id: `${source}-${query.has("cursor") ? "component-2" : component.id}`,
            name:
              source === "osquery-python-packages"
                ? "example-python-agent"
                : source === "openaidr-mcp-servers"
                  ? "project-files"
                  : source === "openaidr-plugins"
                    ? "review-plugin"
                    : query.has("cursor")
                      ? "example-runtime"
                      : component.name,
            evidence:
              source === "openaidr-mcp-servers"
                ? "configured"
                : source === "openaidr-plugins"
                  ? "declared"
                  : "installed",
            version: source === "openaidr-mcp-servers" ? "" : component.version,
          },
        ],
        next_cursor: query.has("cursor") ? "" : "components +/cursor",
      },
    };
  });
  await page.goto("/ai-supply-chain");
  await expect(page.getByRole("button", { name: "All components", exact: true })).toHaveAttribute("aria-expanded", "true");
  await expect(records(page)).toBeVisible();
  await expect(records(page).getByRole("button", { name: "All", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect(records(page).locator("tbody tr")).toHaveCount(4);
  // Selecting a category scopes the All components table only.
  await categoryButton(page, "npm packages").click();
  requests.length = 0;
  const table = records(page);
  const coverage = page.getByRole("region", {
    name: "Scan coverage",
    exact: true,
  });
  await expect(
    table.getByText(component.name, { exact: true }),
  ).toBeVisible();
  await expect(table.getByRole("table")).toHaveCount(1);
  await expect(queue(page)).toContainText("No known vulnerabilities in loaded records");
  await expect(coverage).toHaveCount(0);
  await expect(
    loadedCoverage(page).getByText(/1\+? partial/),
  ).toBeVisible();
  await expect(
    table.getByText("Vulnerabilities not assessed", { exact: true }),
  ).toBeVisible();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  await page.screenshot({
    path: testInfo.outputPath("supply-chain.png"),
    fullPage: true,
    animations: "disabled",
  });
  const details = table.getByRole("button", {
    name: `View details for ${component.name}`,
    exact: true,
  });
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("dialog").getByText("Installed", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText(component.user, { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(details).toBeFocused();

  await table.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(
    table.getByText("2 records loaded", { exact: true }),
  ).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("cursor")).toBe(
    "components +/cursor",
  );
  const collection = page.getByRole("button", {
    name: /Collection details|View scan locations/,
    exact: true,
  });
  await collection.click();
  await expect(coverage.getByText(root.message, { exact: true })).toBeVisible();
  await coverage
    .getByRole("button", { name: "Load more", exact: true })
    .click();
  await expect(
    coverage.getByText("2 scan locations loaded", { exact: true }),
  ).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("cursor")).toBe("roots +/cursor");
  await expect(
    coverage.getByText("No successful scan reported", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(collection).toBeFocused();

  fail = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    page.locator("main").getByRole("alert").filter({ hasText: "Inventory:" }),
  ).toContainText("Showing the last loaded records.");
  await expect(page.locator("main").getByRole("alert").filter({ hasText: "Scan coverage:" })).toContainText("Showing the last loaded scan results.");
  await collection.click();
  await expect(coverage.getByRole("alert")).toContainText(
    "Showing the last loaded scan results.",
  );
  await page.keyboard.press("Escape");
  await expect(
    table.getByText("2 records loaded", { exact: true }),
  ).toBeVisible();
  fail = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    table.getByText("1 record loaded", { exact: true }),
  ).toBeVisible();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);

  await table
    .getByRole("button", { name: "Filter by device dev-mac", exact: true })
    .click();
  await expect(
    page.getByText("Device: dev-mac", { exact: true }),
  ).toBeVisible();
  await expect
    .poll(
      () =>
        requests.filter((url) => url.searchParams.get("sensor_id") === sensor)
          .length,
    )
    .toBe(8);
  await collection.click();
  await coverage
    .getByRole("button", {
      name: `View records from ${root.root}`,
      exact: true,
    })
    .click();
  await expect
    .poll(() => requests.at(-1)?.searchParams.get("root_id"))
    .toBe(rootId);
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(collection).toBeFocused();
  const beforeSearch = requests.length;
  await page
    .getByRole("searchbox", { name: "Search inventory" })
    .fill("literal %_+path");
  await expect(
    table.getByText("No matching records", { exact: true }),
  ).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("q")).toBe("literal %_+path");
  expect(requests.at(-1)?.searchParams.has("cursor")).toBe(false);
  expect(
    requests
      .slice(beforeSearch)
      .every((url) => url.pathname.endsWith("/components")),
  ).toBe(true);
  await collection.click();
  await expect(coverage.getByText(root.root, { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");

  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await categoryButton(page, "Python packages")
    .click();
  await expect(
    page.getByRole("searchbox", { name: "Search inventory" }),
  ).toHaveValue("");
  await expect(
    table.getByText("example-python-agent", { exact: true }),
  ).toBeVisible();
  expect(requests.at(-1)?.searchParams.has("sensor_id")).toBe(false);
  expect(requests.at(-1)?.searchParams.has("root_id")).toBe(false);
  await categoryButton(page, "MCP servers").click();
  await table
    .getByRole("button", {
      name: "View details for project-files",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("dialog").getByText("Configured", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator("tbody tr")).toContainText("Version not reported");
  await categoryButton(page, "Plugins").click();
  await table
    .getByRole("button", {
      name: "View details for review-plugin",
      exact: true,
    })
    .click();
  await expect(
    page.getByRole("dialog").getByText("Declared", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  expect(requests.every((url) => url.searchParams.get("limit") === "50")).toBe(
    true,
  );
});

test("plugin details show declared skill relationships with pagination, retention, and isolated errors", async ({
  page,
}, testInfo) => {
  const plugin = {
    ...component,
    id: "plugin-1",
    name: "repository-tools",
    identifier: "repository-tools",
    kind: "plugin",
    source: "openaidr-plugins",
    evidence: "declared",
    root: "/Users/alex/plugins",
    path: "/Users/alex/plugins/repository-tools/.claude-plugin/plugin.json",
  };
  const skill = {
    ...component,
    id: "skill-1",
    name: "repository-review",
    identifier: "repository-review",
    kind: "skill",
    source: "openaidr-skills",
    version: "1.0",
    root: "/Users/alex/plugins/repository-tools/skills",
    path: "/Users/alex/plugins/repository-tools/skills/review/SKILL.md",
  };
  const link = {
    id: "link-1",
    from_component_id: plugin.id,
    to_component_id: skill.id,
    from_component: plugin,
    to_component: skill,
    kind: "provides",
    evidence: "declared",
    path: plugin.path,
    last_seen_at: "2026-09-30T12:00:00Z",
    root_status: "partial",
  };
  const requests: URL[] = [];
  let failMore = true;
  await mockApi(page, (url) => {
    if (url.pathname.endsWith("/relationships")) {
      requests.push(url);
      const id = url.searchParams.get("component_id");
      expect(url.searchParams.get("kind")).toBe("provides");
      expect(url.searchParams.get("evidence")).toBe("declared");
      expect(url.searchParams.has("source")).toBe(false);
      if (id === "plugin-2") return { json: { items: [], next_cursor: "" } };
      if (url.searchParams.has("cursor") && failMore)
        return {
          status: 503,
          json: { error: { message: "Relationships temporarily unavailable" } },
        };
      return {
        json: {
          items: [
            url.searchParams.has("cursor")
              ? {
                  ...link,
                  id: "link-2",
                  to_component_id: "skill-2",
                  to_component: {
                    ...skill,
                    id: "skill-2",
                    name: "Jev release-notes",
                    path: `${skill.root}/release/SKILL.md`,
                  },
                }
              : link,
          ],
          next_cursor:
            id === plugin.id && !url.searchParams.has("cursor")
              ? "links +/cursor"
              : "",
        },
      };
    }
    if (url.pathname.endsWith("/roots"))
      return { json: { items: [], next_cursor: "" } };
    return {
      json: {
        items: url.searchParams.get("source") === "openaidr-plugins"
          ? [plugin, { ...plugin, id: "plugin-2", identifier: "empty-plugin", name: "empty-plugin" }] : [],
        next_cursor: "",
      },
    };
  });
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  await page.getByRole("button", { name: "Show Plugins", exact: true }).click();
  const trigger = page.getByRole("button", {
    name: "View details for repository-tools",
    exact: true,
  });
  await expect(trigger).toBeVisible();
  expect(requests).toHaveLength(0);
  await trigger.focus();
  await page.keyboard.press("Enter");
  const relationships = page.getByRole("region", {
    name: "Declared relationships",
  });
  await expect(
    relationships.getByText("Provides:", { exact: true }),
  ).toBeVisible();
  await expect(
    relationships.getByText(skill.name, { exact: true }),
  ).toBeVisible();
  await expect(
    relationships.getByText(
      "Scan incomplete; earlier evidence may be retained",
      { exact: true },
    ),
  ).toBeVisible();
  await expect(
    relationships.getByText(`Declared in: ${plugin.path}`, { exact: true }),
  ).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath("plugin-relationships.png"),
    animations: "disabled",
  });
  await relationships
    .getByRole("button", { name: "Load more", exact: true })
    .click();
  await expect(relationships.getByRole("alert")).toContainText(
    "Relationships temporarily unavailable",
  );
  await expect(
    relationships.getByText(skill.name, { exact: true }),
  ).toBeVisible();
  failMore = false;
  await relationships
    .getByRole("button", { name: "Load more", exact: true })
    .click();
  await expect(
    relationships.getByText("Jev release-notes", { exact: true }),
  ).toBeVisible();
  expect(requests.at(-1)?.searchParams.get("cursor")).toBe("links +/cursor");
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await page
    .getByRole("button", { name: "View details for empty-plugin", exact: true })
    .click();
  await expect(
    relationships.getByText("No declared relationships reported.", {
      exact: true,
    }),
  ).toBeVisible();
  await expect(
    relationships.getByText(skill.name, { exact: true }),
  ).toHaveCount(0);
  await page.keyboard.press("Escape");
});

test("unreported, failed, and empty scans stay distinct from API failures", async ({
  page,
}) => {
  let state:
    | "unreported"
    | "failed"
    | "empty"
    | "unavailable"
    | "paged"
    | "error" = "unreported";
  await mockApi(page, (url) => {
    if (state === "error")
      return {
        status: 503,
        json: { error: { message: "Scan API unavailable" } },
      };
    return {
      json: {
        items:
          url.pathname.endsWith("/roots") && url.searchParams.get("source") === "osquery-npm-packages" && state !== "unreported"
            ? [
                {
                  ...root,
                  source: "osquery-npm-packages",
                  component_count: 0,
                  last_success_at: ["empty", "paged"].includes(state)
                    ? stamp
                    : null,
                  status:
                    state === "failed"
                      ? "error"
                      : state === "unavailable"
                        ? "unavailable"
                        : "ok",
                  message:
                    state === "failed"
                      ? "Manifest directory could not be read."
                      : "",
                },
              ]
            : [],
        next_cursor:
          state === "paged" && url.pathname.endsWith("/roots")
            ? "next-location"
            : "",
      },
    };
  });
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  const coverage = loadedCoverage(page);
  await expect(
    coverage.getByText("No scan locations reported", { exact: true }),
  ).toBeVisible();
  state = "failed";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(coverage).toContainText("1 failed");
  await page
    .getByRole("button", { name: /Collection details|View scan locations/, exact: true })
    .click();
  await expect(
    page.getByRole("dialog").getByText("Failed", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("dialog").getByText("No successful scan reported", { exact: true }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(
    records(page).getByText("No records reported", { exact: true }),
  ).toBeVisible();
  state = "empty";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    coverage.getByText("1 successful", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("No scan locations reported", { exact: true }),
  ).toHaveCount(0);
  state = "paged";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    coverage.getByText("1+ successful", { exact: true }),
  ).toBeVisible();
  await expect(
    coverage.getByText("More locations available in scan details; these are loaded counts.", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Scans succeeded for 1 location", { exact: true }),
  ).toHaveCount(0);
  state = "unavailable";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(
    coverage.getByText("1 unavailable", { exact: true }),
  ).toBeVisible();
  await expect(
    page.getByText("Loaded scans succeeded", { exact: true }),
  ).toHaveCount(0);
  state = "error";
  await page.reload();
  await openComponents(page);
  await expect(page.locator("main").getByRole("alert")).toHaveCount(2);
  await expect(
    page.getByText("No records reported", { exact: true }),
  ).toHaveCount(0);
  await expect(
    page.getByText("No scan locations reported", { exact: true }),
  ).toHaveCount(0);
  await expect(coverage.getByText("Scan coverage unavailable", { exact: true })).toBeVisible();
  await expect(page.getByText("Successful", { exact: true })).toHaveCount(0);
});

test("scan coverage keeps long locations and scan results inside the card", async ({ page }, testInfo) => {
  const hostname = "Hongqiangs-MacBook-Air.local";
  const longRoot = "/Library/Frameworks/Python.framework/Versions/3.14/lib/python3.14/site-packages";
  const message = `Component metadata collection could not complete this scan: ${longRoot}`;
  const scans = Array.from({ length: 12 }, (_, i) => ({
    ...root, id: `scan-${i}`, hostname: i === 1 ? "" : hostname,
    root: longRoot, status: i % 2 ? "unavailable" : "error", message,
    last_success_at: i % 2 ? null : root.last_success_at,
  }));
  await mockApi(page, (url) => ({ json: {
    items: url.pathname.endsWith("/roots") && url.searchParams.get("source") === root.source ? scans : [],
    next_cursor: "",
  } }));
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  const coverage = loadedCoverage(page);
  await expect(coverage).toContainText("6 failed");
  await expect(coverage).toContainText("6 unavailable");
  for (const width of [1440, 1280, 1024, 390]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole("button", { name: "View scan locations", exact: true }).click();
    const dialog = page.getByRole("dialog");
    const table = dialog.getByRole("table");
    await expect(table.locator("tbody tr")).toHaveCount(scans.length);
    await expect(table.locator("tbody tr").first()).toContainText("Failed");
    await expect(table.getByText(longRoot, { exact: true }).first()).toBeVisible();
    await expect(table.getByText(message, { exact: true }).first()).toBeVisible();
    const last = table.locator("tbody tr").last();
    await last.getByText("No successful scan reported", { exact: true }).scrollIntoViewIfNeeded();
    await expect(last.getByText("No successful scan reported", { exact: true })).toBeInViewport();
    await expect.poll(() => dialog.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await dialog.screenshot({ path: testInfo.outputPath(`scan-coverage-${width}.png`), animations: "disabled" });
    await page.keyboard.press("Escape");
    await expect(page.getByRole("button", { name: "View scan locations" })).toBeFocused();
  }
});

test("the skills layout preview filters sample skills and reads no inventory", async ({ page }) => {
  const reads: string[] = [];
  await mockApi(page, (url) => {
    reads.push(url.pathname);
    return { json: { items: [], next_cursor: "" } };
  });
  await page.goto("/ai-skills/preview");
  await expect(page.getByText("illustrative sample data", { exact: false }).first()).toBeVisible();
  const preview = page.frameLocator('iframe[title="AI Skills preview with sample data"]');
  // The console supplies navigation and the page title; the embedded copy hides its own.
  await expect(preview.locator(".sidebar")).toBeHidden();
  const names = preview.locator("#skills tbody tr.clickable .name-btn");
  await preview.getByRole("link", { name: "Modified copies" }).click();
  await expect(names).toHaveText(["webapp-testing", "acme-review"]);
  await preview.getByRole("link", { name: "Shell and web tools" }).click();
  await expect(preview.locator("#skill-signal")).toHaveValue("shellweb");
  await expect(names).toHaveText(["acme-review", "deploy-helper", "incident-runbook"]);
  await preview.getByRole("button", { name: "acme-review", exact: true }).click();
  const drawer = preview.locator("#drawer");
  await expect(drawer.getByRole("heading", { name: "acme-review" })).toBeVisible();
  await expect(drawer.getByText("WebFetch", { exact: true })).toBeVisible();
  await expect(drawer.getByText("edited", { exact: true }).first()).toBeVisible();
  await drawer.getByRole("button", { name: "Close" }).click();
  await preview.getByRole("button", { name: "Clear filters" }).click();
  await preview.locator('#skills [data-source="system"]').click();
  await expect(names).toHaveText(["skill-installer", "skill-creator"]);
  // On a phone, the tables and the source filter scroll inside their cards, not the page.
  await page.setViewportSize({ width: 390, height: 844 });
  const frame = page.frame({ url: "about:srcdoc" })!;
  await expect.poll(() => frame.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBe(0);
  // Sample data only: the preview reads no inventory endpoints.
  expect(reads).toEqual([]);
});

test("skills inventory is not loaded before sign-in", async ({ page }) => {
  const previews: string[] = [];
  page.on("request", (request) => {
    if (request.url().includes("/previews/") || request.url().includes("/inventory/")) previews.push(request.url());
  });
  await page.route("**/api/v1/auth/me", (route) =>
    route.fulfill({ status: 401, json: { error: { message: "Sign in" } } }),
  );
  await page.route("**/api/v1/auth/config", (route) =>
    route.fulfill({ json: { mode: "local", password_login: true } }),
  );
  await page.goto("/ai-skills");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.locator("iframe")).toHaveCount(0);
  expect(previews).toEqual([]);
});

const scanTime = new Date().toISOString();
const assessedSkill = {
  id: "a".repeat(64), name: "release-helper", installations: 5, devices: 3,
  last_seen_at: scanTime, needs_attention: true, scan_status: "complete", risk_score: 85,
  scopes: ["project"], collection_incomplete: false,
  sha256: "a".repeat(64), size_bytes: 1536, bundle_complete: true,
  approval_status: "unapproved", approval_updated_at: null,
};
const scanRows = [
  assessedSkill,
  { ...assessedSkill, id: "bundle-2", name: "repo-bootstrap", installations: 3, devices: 2, scan_status: "partial", risk_score: null, retained_score: 65 },
  { ...assessedSkill, id: "bundle-3", name: "workspace-sync", installations: 1, devices: 1, scopes: ["user"], risk_score: 25 },
  { ...assessedSkill, id: "bundle-4", name: "docs", approval_status: "approved", installations: 4, devices: 4, scopes: ["user"], needs_attention: false, risk_score: 20 },
  { ...assessedSkill, id: "bundle-5", name: "docx", approval_status: "approved", installations: 4, devices: 4, scopes: ["user"], needs_attention: false, risk_score: 0, size_bytes: 0 },
  { ...assessedSkill, id: "bundle-6", name: "chrome-browser", approval_status: "monitoring", installations: 1, devices: 1, needs_attention: false, scan_status: "pending", risk_score: null, sha256: null, size_bytes: null, bundle_complete: null },
  { ...assessedSkill, id: "bundle-7", name: "deep-research", approval_status: "monitoring", installations: 1, devices: 1, needs_attention: false, scan_status: "partial", risk_score: null, retained_score: 25, collection_incomplete: true, bundle_complete: false },
  { ...assessedSkill, id: "bundle-8", name: "computer-use", approval_status: "monitoring", installations: 1, devices: 1, needs_attention: false, scan_status: "stale", risk_score: null, retained_score: 0, size_bytes: undefined, bundle_complete: undefined },
];
const scanInventory = {
  enabled: true, items: scanRows, next_cursor: "", total: 8,
  summary: { installed: 8, installations: 20, attention: 3, assessed: 4, pending: 4, incomplete: 3 },
};
/** The list API scopes items by status; the review cards each ask for one status. */
const scanPage = (status: string | null, review: string | null = "all") => {
  let items = status === "attention" ? scanRows.filter((row) => row.needs_attention)
    : status === "assessed" ? scanRows.filter((row) => row.scan_status === "complete")
    : status === "pending" ? scanRows.filter((row) => row.scan_status !== "complete") : scanRows;
  if (review && review !== "all") items = items.filter(row => row.approval_status === review);
  return { ...scanInventory, items, total: items.length };
};
const skillQueue = (page: Page) => page.getByRole("region", { name: "Unapproved skills", exact: true });
const skillsPending = (page: Page) => page.getByRole("region", { name: "Monitoring skills", exact: true });
const skillsCleared = (page: Page) => page.getByRole("region", { name: "Approved skills", exact: true });
const allSkills = (page: Page) => page.getByRole("region", { name: "All skills", exact: true });
const skillSummary = (page: Page) => page.locator('[data-slot="review-summary"]');
const scanDetail = {
  id: assessedSkill.id, name: assessedSkill.name, sha256: "a".repeat(64),
  size_bytes: 1536, approval_status: "unapproved", approval_updated_at: null,
  scan_status: "complete", completed_at: scanTime, error: "",
  metadata: { description: "Prepare a project release.", tools: ["Bash", "Read"] },
  manifest: { complete: true, files: [{ path: "SKILL.md", size: 1024 }, { path: "scripts/release.sh", size: 512 }] },
  report: { complete: true, mode: "static", score: 85, scanner_version: "2.12.0", needs_attention: true,
    issues: [{ rule: "DE1", severity: "HIGH", title: "Credential exfiltration", description: "Sends credentials to an external host.", file: "scripts/release.sh", line: 12, remediation: "Remove the credential upload." }] },
  installations_truncated: false,
  installations: [{ id: "installation-1", hostname: "review-mac", sensor_id: "sensor-1", path: `/Users/reviewer/${"long-project-path/".repeat(8)}skills/release-helper`, scope: "project", version: "1", root_status: "ok", last_seen_at: scanTime }],
};

async function skillReviewApi(page: Page, role = "it_admin") {
  const state = { failSave: false, writes: [] as Record<string, unknown>[],
    rows: [{ ...assessedSkill }, { ...assessedSkill, id: "b".repeat(64), sha256: "b".repeat(64), name: "docx", approval_status: "approved", needs_attention: false, risk_score: 0 },
      { ...assessedSkill, id: "c".repeat(64), sha256: "c".repeat(64), name: "workspace-sync", approval_status: "monitoring" },
      { ...assessedSkill, id: "uncollected", sha256: null, name: "uncollected-review", size_bytes: null, bundle_complete: null, needs_attention: false, scan_status: "pending", risk_score: null }],
  };
  await mockApi(page, url => {
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    if (url.pathname.endsWith("/skills")) {
      const review = url.searchParams.get("review");
      const items = state.rows.filter(row => (!review || review === "all" || row.approval_status === review)
        && (!url.searchParams.get("q") || row.name.includes(url.searchParams.get("q")!)));
      return { json: { ...scanInventory, items, total: items.length,
        summary: { installed: state.rows.length, installations: state.rows.reduce((sum, row) => sum + row.installations, 0),
          attention: state.rows.filter(row => row.needs_attention).length, assessed: 3, pending: 1, incomplete: 0 },
      } };
    }
    const row = state.rows.find(item => item.id === url.pathname.split("/").at(-1));
    return { json: { ...scanDetail, ...row, installations: scanDetail.installations } };
  });
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { user: { id: "reviewer", name: "Reviewer", email: "reviewer@example.invalid", roles: [role], tenant: { id: "tenant", name: "Review", slug: "review" } } } }));
  await page.route("**/api/v1/inventory/skills/*/approval", route => {
    const body = route.request().postDataJSON();
    state.writes.push(body);
    if (state.failSave) return route.fulfill({ status: 409, json: { error: { message: "Skill content changed; refresh before reviewing" } } });
    const id = new URL(route.request().url()).pathname.split("/").at(-2)!;
    const row = state.rows.find(item => item.id === id)!;
    row.approval_status = body.approved === null ? "monitoring" : body.approved ? "approved" : "unapproved";
    return route.fulfill({ json: { id, ...body, approval_updated_at: scanTime } });
  });
  return state;
}

test("skills approval choices persist, handle failures, and keep scan evidence in details", async ({ page }, testInfo) => {
  const state = await skillReviewApi(page);
  await page.goto("/ai-skills");
  await expect(skillsCleared(page).getByRole("columnheader", { name: "Risk score" })).toHaveCount(0);
  await expect(skillQueue(page).getByRole("columnheader", { name: "Notify users" })).toBeVisible();
  await skillQueue(page).getByRole("button", { name: "Approval for uncollected-review" }).click();
  await expect(page.getByRole("button", { name: "Approve", exact: true })).toBeDisabled();
  await expect(page.getByText("Complete collection is required to approve.", { exact: false })).toBeVisible();
  await page.keyboard.press("Escape");
  state.failSave = true;
  await skillQueue(page).getByRole("button", { name: "Approval for release-helper" }).click();
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Skill content changed" })).toBeVisible();
  await expect(skillQueue(page).getByRole("button", { name: "View details for release-helper" })).toBeVisible();
  state.failSave = false;
  for (const [from, action, to] of [
    [skillQueue, "Approve", skillsCleared], [skillsCleared, "Move to monitoring", skillsPending],
    [skillsPending, "Mark unapproved", skillQueue], [skillQueue, "Move to monitoring", skillsPending],
  ] as const) {
    await from(page).getByRole("button", { name: "Approval for release-helper" }).click();
    await page.getByRole("button", { name: action, exact: true }).click();
    await expect(to(page).getByRole("button", { name: "View details for release-helper" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeFocused();
    if (action === "Approve") {
      await expect(to(page).getByLabel("Risk score 85 out of 100")).toHaveCount(0);
      await to(page).getByRole("button", { name: "View details for release-helper" }).click();
      await expect(page.getByRole("dialog").getByLabel("Risk score 85 out of 100")).toBeVisible();
      await expect(page.getByRole("dialog").getByRole("heading", { name: "Credential exfiltration" })).toBeVisible();
      await page.keyboard.press("Escape");
    }
  }
  expect(state.writes.map(body => body.approved)).toEqual([true, true, null, false, null]);
  expect(state.writes.every(body => body.sha256 === assessedSkill.sha256)).toBe(true);
  await page.reload();
  await expect(skillsPending(page).getByRole("button", { name: "View details for release-helper" })).toBeVisible();
  await skillsPending(page).getByRole("button", { name: "View details for release-helper" }).click();
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Credential exfiltration" })).toBeVisible();
  await expect(page.getByRole("dialog").getByLabel("Risk score 85 out of 100")).toBeVisible();
  await page.keyboard.press("Escape");
  await skillsPending(page).getByRole("button", { name: "Approval for release-helper" }).click();
  await page.getByRole("button", { name: "Mark unapproved", exact: true }).click();
  await expect(skillQueue(page).getByRole("button", { name: "Approval for release-helper" })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("skill-review-actions.png"), animations: "disabled" });
  await skillQueue(page).getByRole("button", { name: "Approval for release-helper" }).click();
  await page.screenshot({ path: testInfo.outputPath("skill-review-menu.png"), animations: "disabled" });
});

async function skillNotificationApi(page: Page) {
  const installations = [
    { ...scanDetail.installations[0], sensor_id: sensor, hostname: "review-mac" },
    { ...scanDetail.installations[0], id: "installation-2", sensor_id: rootId, hostname: "review-linux" },
    { ...scanDetail.installations[0], id: "installation-3", sensor_id: sensor, version: "2" },
  ];
  const detail = { id: assessedSkill.id, items: installations.map(record => ({ id: record.sensor_id, name: record.hostname, versions: [record.version] })) };
  const state = { roles: ["security_analyst"], detail: detail as unknown, status: 200, reads: [] as URL[] };
  await mockApi(page, url => {
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    if (url.pathname.endsWith("/skills")) return { json: scanPage(url.searchParams.get("status"), url.searchParams.get("review")) };
    state.reads.push(url);
    return { status: state.status, json: state.status === 200 ? state.detail : { error: { message: "Installations unavailable" } } };
  });
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { user: {
    id: "operator", name: "Test operator", email: "test@example.invalid", roles: state.roles,
    tenant: { id: "tenant", name: "Test tenant", slug: "test" },
  } } }));
  return { state, detail, alerts: await alertApi(page) };
}

for (const width of [1440, 390]) {
  test(`skills notifications load recipients on demand and preview selected devices at ${width}px`, async ({ page }, info) => {
    const { state, alerts } = await skillNotificationApi(page);
    await page.setViewportSize({ width, height: width === 390 ? 640 : 900 });
    await page.goto("/ai-skills");
    const queue = skillQueue(page);
    await expect(queue.getByRole("columnheader", { name: "Notify users", exact: true })).toBeVisible();
    for (const other of [skillsPending(page), skillsCleared(page), allSkills(page)])
      await expect(other.getByRole("columnheader", { name: "Notify users", exact: true })).toHaveCount(0);
    const trigger = queue.getByRole("button", { name: `Notify users for ${assessedSkill.name}`, exact: true });
    await expect(trigger).toBeVisible();
    expect(state.reads).toHaveLength(0);
    expect(alerts.queries).toHaveLength(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await queue.screenshot({ path: info.outputPath(`skills-notify-${width}.png`), animations: "disabled" });
    await page.getByRole("searchbox", { name: "Search skills" }).fill("docx");
    await trigger.click();
    const dialog = page.getByRole("dialog", { name: "Notify users", exact: true });
    await expect(dialog.getByRole("checkbox")).toHaveCount(2);
    expect(new Set(state.reads.map(url => url.pathname))).toEqual(new Set([`/api/v1/inventory/skills/${assessedSkill.id}/devices`]));
    const reads = state.reads.length;
    await expect(dialog.getByRole("checkbox", { name: /review-mac/ })).toHaveAccessibleName(/1, 2/);
    await expect(dialog.getByRole("checkbox").first()).toBeChecked();
    await expect(dialog.getByRole("checkbox").last()).toBeChecked();
    await expect(dialog).toContainText("Devices with this skill across the organization");
    await expect(dialog.getByLabel("Title", { exact: true })).toHaveValue(`Unapproved skill: ${assessedSkill.name}`);
    await expect(dialog.getByLabel("Instructions", { exact: true })).toHaveValue(/not approved by your organization/);
    await expect(dialog.getByLabel("Command (optional)", { exact: true })).toHaveCount(0);
    await dialog.getByRole("checkbox", { name: /review-linux/ }).uncheck();
    await expect(dialog.getByRole("button", { name: "Preview alert" })).toBeEnabled();
    await expect(dialog.getByRole("button", { name: "Preview alert" })).toBeInViewport({ ratio: 1 });
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (width === 390) {
      const scroll = dialog.getByTestId("endpoint-alert-scroll");
      expect(await scroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await scroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(dialog.getByLabel("Instructions", { exact: true })).toBeInViewport();
    }
    await dialog.screenshot({ path: info.outputPath(`skills-notify-compose-${width}.png`), animations: "disabled" });
    await dialog.getByRole("button", { name: "Preview alert" }).click();
    const preview = page.getByRole("dialog", { name: "Preview alert", exact: true });
    await expect(preview.getByRole("list", { name: "Selected devices" })).toHaveText("review-mac");
    expect(alerts.writes).toHaveLength(0);
    await preview.getByRole("button", { name: "Send to 1 device", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Alert details" })).toContainText("Pending receipt");
    expect(alerts.writes).toHaveLength(1);
    expect(alerts.writes[0]).toMatchObject({ csrf: "1", body: {
      application_id: `skill:${assessedSkill.id}`, sensor_ids: [sensor], command: "", installed_version: "", required_version: "",
    } });
    expect(alerts.queries[0].searchParams.get("application_id")).toBe(`skill:${assessedSkill.id}`);
    await page.keyboard.press("Escape");
    await expect(trigger).toBeFocused();
    await trigger.click();
    await dialog.getByRole("button", { name: "View history", exact: true }).click();
    await expect(page.getByRole("list", { name: "Alert history" })).toContainText("1 sent");
    expect(state.reads.length).toBeGreaterThan(reads);
  });
}

test("skills notifications reject unavailable or mismatched recipients and keep read-only roles from sending", async ({ page }) => {
  const { state, detail, alerts } = await skillNotificationApi(page);
  state.status = 503;
  await page.goto("/ai-skills");
  const trigger = skillQueue(page).getByRole("button", { name: `Notify users for ${assessedSkill.name}`, exact: true });
  await trigger.click();
  const dialog = page.getByRole("dialog", { name: "Notify users", exact: true });
  await expect(dialog.getByRole("alert")).toContainText("Could not load recipient devices");
  await expect(dialog.getByRole("button", { name: "Preview alert" })).toHaveCount(0);
  state.status = 200;
  for (const invalid of [{ ...detail, id: "another-skill" }, { ...detail, items: [{ id: null }] }]) {
    state.detail = invalid;
    await dialog.getByRole("button", { name: "Retry", exact: true }).click();
    await expect(dialog.getByRole("alert")).toContainText("The skill devices response is incompatible");
    await expect(dialog.getByRole("button", { name: "Preview alert" })).toHaveCount(0);
  }
  state.detail = { ...detail, items: [] };
  await dialog.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(dialog.getByRole("button", { name: "Preview alert" })).toBeDisabled();
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  state.detail = detail;
  state.roles = ["security_leadership"];
  await page.reload();
  await expect(skillQueue(page).getByRole("button", { name: /^Notify users for/ })).toHaveCount(0);
  await skillQueue(page).getByRole("button", { name: `View alerts for ${assessedSkill.name}`, exact: true }).click();
  const history = page.getByRole("dialog", { name: "Alerts", exact: true });
  await expect(history).toContainText("IT Admins and Security Analysts can send alerts");
  await expect(history.getByRole("button", { name: "New alert", exact: true })).toHaveCount(0);
  await expect(history.getByRole("checkbox")).toHaveCount(0);
  expect(alerts.writes).toHaveLength(0);
});

test("skills scanner inventory shows compact summaries, distinct risk scores, and accessible details", async ({ page }, testInfo) => {
  const reads: URL[] = [];
  await mockApi(page, url => {
    reads.push(url);
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    if (url.pathname.endsWith("/skills")) return { json: scanPage(url.searchParams.get("status"), url.searchParams.get("review")) };
    const id = url.pathname.split("/").at(-1);
    return { json: id === "bundle-7" ? { ...scanDetail, id, name: "deep-research", scan_status: "partial", manifest: { ...scanDetail.manifest, complete: false }, report: { ...scanDetail.report, complete: false, score: 25 } } : scanDetail };
  });
  await page.goto("/ai-skills");
  await expect(page.getByRole("region", { name: "Skills overview" })).toHaveCount(0);
  await expect(skillSummary(page)).toHaveText(
    "3 of 8 skills need attention · 4 fully assessed (50%) · 3 incomplete or outdated · 1 awaiting assessment · 20 installations",
  );
  // Review decisions are independent of scan results. Approved rows hide scores.
  const queue = skillQueue(page);
  await expect(queue).toContainText("3 skills");
  await expect(queue.locator("tbody tr")).toHaveCount(3);
  await expect(queue.locator("tbody tr").first()).toContainText("release-helper");
  await expect(queue.locator("tbody tr").first()).toContainText("Project");
  await expect(queue.locator("tbody tr").first()).toContainText("85Critical");
  expect(await queue.locator('[aria-label^="Risk score"] + span > span').evaluateAll((bars) =>
    bars.map((bar) => [bar.getAttribute("style"), bar.className.split(" ").at(-1)]))).toEqual([
    ["width: 85%;", "bg-severity-critical"], ["width: 65%;", "bg-severity-high"], ["width: 25%;", "bg-severity-medium"],
  ]);
  const pending = skillsPending(page);
  await expect(pending).toContainText("3 skills");
  await expect(pending.locator("tbody tr")).toHaveText([/chrome-browser.*1Not available/, /deep-research.*125MediumPartial assessment/, /computer-use.*10LowStale assessment/]);
  const cleared = skillsCleared(page);
  await expect(cleared).toContainText("2 skills");
  await expect(cleared.locator("tbody tr")).toHaveText([/docs.*4/, /docx.*4/]);
  await page.evaluate(() => document.fonts.ready);
  const boxes = await page.evaluate(() =>
    ["Unapproved skills", "Monitoring skills", "Approved skills"].map((name) => {
      const box = document.querySelector(`section[aria-label="${name}"]`)!.getBoundingClientRect();
      const header = document.querySelector(`section[aria-label="${name}"] [data-slot="review-card-header"]`)!;
      return { x: box.x, y: box.y, bottom: box.bottom, width: box.width, background: getComputedStyle(header).backgroundColor, color: getComputedStyle(header).color };
    }));
  const [queueBox, pendingBox, clearedBox] = boxes as [(typeof boxes)[number], (typeof boxes)[number], (typeof boxes)[number]];
  expect(queueBox.y).toBeCloseTo(pendingBox.y, 0);
  expect(pendingBox.x).toBeLessThan(queueBox.x);
  expect(queueBox.bottom).toBeLessThan(clearedBox.y);
  expect(clearedBox.bottom).toBeCloseTo(pendingBox.bottom, 0);
  expect(queueBox.width).toBeGreaterThan(pendingBox.width);
  for (const box of boxes) expect(box.color).toBe("rgb(255, 255, 255)");
  expect(new Set(boxes.map((box) => box.background)).size).toBe(3);
  const skills = allSkills(page);
  await expect(skills.getByRole("row")).toHaveCount(9);
  await expect(skills.getByRole("row").filter({ hasText: "workspace-sync" })).toContainText("Needs attention");
  await expect(skills.getByRole("row").filter({ hasText: "workspace-sync" })).toContainText("25Medium");
  await expect(skills.getByRole("row").filter({ hasText: "docx" })).toContainText("See details");
  await expect(skills.getByRole("cell", { name: "Not available", exact: true })).toHaveCount(1);
  await expect(skills.getByRole("columnheader", { name: "Bundle size", exact: true })).toBeVisible();
  await expect(skills.getByRole("columnheader", { name: "Bundle SHA-256", exact: true })).toBeVisible();
  await expect(queue.getByRole("row").filter({ hasText: "repo-bootstrap" })).toContainText("65HighPartial assessment");
  await expect(skills.getByRole("row").filter({ hasText: "deep-research" })).toContainText("25MediumPartial assessment");
  await expect(skills.getByRole("row").filter({ hasText: "computer-use" })).toContainText("0LowStale assessment");
  const releaseRow = skills.getByRole("row").filter({ hasText: "release-helper" });
  await expect(releaseRow.getByRole("cell", { name: "1.5 KiB", exact: true })).toHaveAttribute("title", "1,536 bytes collected");
  await expect(skills.getByRole("row").filter({ hasText: "docx" }).getByRole("cell", { name: "0 B", exact: true })).toBeVisible();
  await expect(skills.getByRole("row").filter({ hasText: "chrome-browser" }).getByRole("cell", { name: "Not collected", exact: true })).toHaveCount(2);
  await expect(skills.getByRole("row").filter({ hasText: "deep-research" })).toContainText("Partial collection");
  await expect(skills.getByRole("row").filter({ hasText: "computer-use" })).toContainText("Not reported");
  const hashTrigger = releaseRow.getByRole("button", { name: "View bundle SHA-256 for release-helper" });
  await expect(hashTrigger).toHaveText("aaaaaaaa…");
  await expect(hashTrigger).toHaveAttribute("title", assessedSkill.sha256);
  await expect(page.locator("main iframe")).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath("skills-scanning.png"), fullPage: true, animations: "disabled" });
  const trigger = skills.getByRole("button", { name: "View details for release-helper", exact: true });
  await trigger.click();
  const drawer = page.getByRole("dialog");
  await expect(drawer).not.toContainText("NVIDIA SkillSpector");
  await expect(drawer.getByText("Static analysis only", { exact: true })).toBeVisible();
  await expect(drawer.getByRole("heading", { name: "Credential exfiltration" })).toBeVisible();
  await drawer.getByRole("tab", { name: "Files", exact: true }).click();
  await expect(drawer.getByText("a".repeat(64), { exact: true })).toBeVisible();
  await expect(drawer.getByText("1.5 KiB (1,536 bytes)", { exact: true })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await hashTrigger.click();
    await expect(drawer.getByRole("tab", { name: "Files", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(drawer.getByText(assessedSkill.sha256, { exact: true })).toBeVisible();
    await expect.poll(() => drawer.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.keyboard.press("Escape");
    await expect(hashTrigger).toBeFocused();
    await trigger.click();
    await drawer.getByRole("tab", { name: "Installations", exact: true }).click();
    const path = drawer.getByText(scanDetail.installations[0].path, { exact: true });
    await expect(path).toBeVisible();
    await expect(path).toHaveCSS("font-size", "14px");
    await expect(path).toHaveCSS("font-weight", "400");
    await expect.poll(() => drawer.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await drawer.getByRole("button", { name: "Close details", exact: true }).click();
    await expect(drawer).toHaveCount(0);
  }
  // The same skill opens from a stacked card.
  await pending.getByRole("button", { name: "View details for deep-research" }).click();
  await expect(drawer.getByText("Retained score", { exact: true })).toBeVisible();
  await expect(drawer.getByText("This retained result does not establish", { exact: false })).toBeVisible();
  await expect(drawer.getByText("Coverage details were not recorded", { exact: false })).toBeVisible();
  await drawer.getByRole("tab", { name: "Files", exact: true }).click();
  await expect(drawer.getByText("Collection incomplete", { exact: true })).toBeVisible();
  await expect(drawer.getByText("this hash does not identify the full folder", { exact: false })).toBeVisible();
  expect(reads.some(url => url.pathname.endsWith("/components"))).toBe(false);
});

test("skills partial scores explain scanner coverage and retain scores after a failed retry", async ({ page }, testInfo) => {
  let failed = false;
  let complete = false;
  const file = `references/${"nested-folder/".repeat(12)}guide.md`;
  await mockApi(page, url => {
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    const skill = { ...assessedSkill, scan_status: complete ? "complete" : failed ? "failed" : "partial", risk_score: complete ? 100 : null, retained_score: 100 };
    if (url.pathname.endsWith("/skills")) return { json: {
      ...scanInventory, items: ["approved", "monitoring"].includes(url.searchParams.get("review") || "") ? [] : [skill], total: 1,
      summary: { installed: 1, installations: 5, attention: 1, assessed: complete ? 1 : 0, pending: complete ? 0 : 1, incomplete: complete ? 0 : 1 },
    } };
    return { json: { ...scanDetail, scan_status: skill.scan_status,
      error: failed ? "Scan timed out." : "", report: { ...scanDetail.report, score: 100, complete, finding_text_truncated: true,
        coverage: { reasons: complete ? [] : [
          { code: "reference_missing_input", message: "Referenced input is missing from the bundle.", file, line: 12, target: "references/guide.md", analyzer: "references" },
          { code: "reference_generated_output", message: "Generated output: this shell redirection creates the file at runtime.", file: "SKILL.md", line: 18, target: "reports/output.json", analyzer: "references" },
        ], truncated: !complete } } } };
  });
  await page.goto("/ai-skills");
  await expect(skillQueue(page)).toContainText("100CriticalPartial assessment");
  await expect(skillSummary(page)).toContainText("0 fully assessed (0%)");
  await expect(skillSummary(page)).toContainText("1 incomplete or outdated · 0 awaiting assessment");
  await expect(skillsCleared(page)).toContainText("No approved skills");
  const partial = skillQueue(page).getByRole("button", { name: "Partial assessment for release-helper", exact: true });
  await expect(partial).toHaveAttribute("title", "Partial assessment. View assessment details.");
  await page.evaluate(() => document.fonts.ready);
  for (const width of [1440, 1024, 768, 390]) {
    await page.setViewportSize({ width, height: 900 });
    for (const region of [skillQueue(page), allSkills(page)]) {
      const cell = region.getByRole("cell").filter({ has: page.getByLabel("Risk score 100 out of 100", { exact: true }) });
      const [score, badge, icon] = await cell.evaluate(node =>
        [node.querySelector('[aria-label="Risk score 100 out of 100"]')!, node.querySelector('[data-slot="badge"]')!, node.querySelector("button")!]
          .map(element => { const box = element.getBoundingClientRect(); return { x: box.x, right: box.right, center: box.y + box.height / 2 }; }));
      expect(Math.abs(score.center - badge.center)).toBeLessThanOrEqual(2);
      expect(Math.abs(score.center - icon.center)).toBeLessThanOrEqual(2);
      expect(icon.x).toBeGreaterThanOrEqual(badge.right);
    }
    if (width === 1440) expect((await skillQueue(page).locator("tbody tr").first().boundingBox())!.height).toBeLessThanOrEqual(42);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await page.setViewportSize({ width: 1440, height: 900 });
  await skillQueue(page).screenshot({ path: testInfo.outputPath("skill-risk-inline.png"), animations: "disabled" });
  await partial.focus();
  await expect(partial).toBeFocused();
  await page.keyboard.press("Enter");
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByText("Referenced input is missing from the bundle.", { exact: true })).toBeVisible();
  await expect(drawer.getByText(`${file}:12`, { exact: true })).toBeVisible();
  await expect(drawer.getByText("Target: references/guide.md", { exact: true })).toBeVisible();
  await expect(drawer.getByText("Generated output: this shell redirection creates the file at runtime.", { exact: true })).toBeVisible();
  await expect(drawer.getByText("SKILL.md:18", { exact: true })).toBeVisible();
  await expect(drawer.getByText("Target: reports/output.json", { exact: true })).toBeVisible();
  await expect(drawer.getByText("Coverage details were shortened", { exact: false })).toBeVisible();
  await expect(drawer.getByText("Some finding details were shortened", { exact: false })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath("skill-coverage-details.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 600 });
  await expect.poll(() => drawer.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  await drawer.getByRole("button", { name: "Close details", exact: true }).click();
  await expect(partial).toBeFocused();
  failed = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(skillQueue(page)).toContainText("100CriticalPrevious assessment");
  await expect(allSkills(page)).toContainText("Scan failed");
  await skillQueue(page).getByRole("button", { name: "Previous assessment for release-helper", exact: true }).click();
  await expect(drawer.getByRole("alert")).toHaveText("Scan timed out.");
  await expect(drawer.getByText("Referenced input is missing from the bundle.", { exact: true })).toBeVisible();
  await drawer.getByRole("button", { name: "Close details", exact: true }).click();
  failed = false;
  complete = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(skillSummary(page)).toContainText("1 fully assessed (100%)");
  await expect(skillQueue(page)).not.toContainText("Partial assessment");
  await expect(skillQueue(page).getByRole("button", { name: /assessment for release-helper/ })).toHaveCount(0);
  await skillQueue(page).getByRole("button", { name: "View details for release-helper" }).click();
  await expect(drawer.getByText("Some finding details were shortened", { exact: false })).toBeVisible();
  await expect(drawer.getByText("The scanner reported no coverage limitations.", { exact: true })).toBeVisible();
  await expect(drawer.getByText("This retained result does not establish", { exact: false })).toHaveCount(0);
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.screenshot({ path: testInfo.outputPath("skill-finding-text-warning.png"), fullPage: true, animations: "disabled" });
});

test("skills scanner pagination and filters use server scores and preserve honest failure states", async ({ page }) => {
  await page.clock.install();
  const reads: URL[] = [];
  let failure = 0;
  let failStatus: string | null = null;
  await mockApi(page, url => {
    reads.push(url);
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    if (failStatus && url.searchParams.get("review") === failStatus) return { status: 503, json: { error: { message: `${failStatus} list unavailable` } } };
    if (failure) return { status: failure, json: { error: { message: failure === 403 ? "Access denied" : "Inventory temporarily unavailable" } } };
    if (url.pathname.endsWith(`/${assessedSkill.id}`)) return { json: scanDetail };
    const more = url.searchParams.has("cursor") && Boolean(url.searchParams.get("cursor"));
    const filtered = url.searchParams.get("q") || url.searchParams.get("scope") !== "all" || url.searchParams.get("status") !== "all";
    const status = url.searchParams.get("status");
    const review = url.searchParams.get("review");
    // Keep one review card empty to exercise retained empty results.
    if (review === "monitoring") return { json: { ...scanInventory, items: [], total: 0, next_cursor: "", summary: { ...scanInventory.summary, installed: 57 } } };
    return { json: { ...scanInventory, total: filtered ? 1 : 57,
      summary: { ...scanInventory.summary, installed: 57 },
      items: filtered ? [{ ...assessedSkill, approval_status: review === "approved" ? "approved" : "unapproved" }] : Array.from({ length: more ? 7 : 50 }, (_, i) => ({ ...assessedSkill, approval_status: review === "approved" ? "approved" : "unapproved", id: `bundle-${more ? i + 50 : i}`, name: `skill-${more ? i + 50 : i}` })),
      next_cursor: more || filtered ? "" : "risk_desc:-85:cursor-1" } };
  });
  await page.goto("/ai-skills");
  const skills = allSkills(page);
  await expect(skills.getByText("1–50 of 57 skills", { exact: true })).toBeVisible();
  await expect(skillSummary(page)).toContainText("3 of 57 skills need attention");
  await skills.getByRole("button", { name: "Next page" }).click();
  await expect(skills.getByText("51–57 of 57 skills", { exact: true })).toBeVisible();
  expect(reads.at(-1)?.searchParams.get("cursor")).toBe("risk_desc:-85:cursor-1");
  await skills.getByRole("button", { name: "Sort risk score ascending" }).click();
  await expect(skills.getByText("1–50 of 57 skills", { exact: true })).toBeVisible();
  expect(reads.at(-1)?.searchParams.get("sort")).toBe("risk_asc");
  expect(reads.at(-1)?.searchParams.get("cursor")).toBe("");
  await page.getByRole("combobox", { name: "Scope filter" }).click();
  await page.getByRole("option", { name: "Project", exact: true }).click();
  await expect(skills.getByText("1–1 of 1 skills", { exact: true })).toBeVisible();
  expect(reads.at(-1)?.searchParams.get("scope")).toBe("project");
  await page.getByRole("searchbox", { name: "Search skills" }).fill("release");
  await expect.poll(() => reads.at(-1)?.searchParams.get("q")).toBe("release");
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await page.getByRole("button", { name: "Show not fully assessed", exact: true }).click();
  await expect.poll(() => reads.at(-1)?.searchParams.get("status")).toBe("pending");
  await expect(page.getByRole("button", { name: "Show not fully assessed", exact: true })).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "Show needs attention", exact: true }).click();
  await expect(page.getByRole("button", { name: "Show needs attention", exact: true })).toHaveAttribute("aria-pressed", "true");
  await expect.poll(() => reads.at(-1)?.searchParams.get("status")).toBe("attention");
  expect(reads.at(-1)?.searchParams.get("q")).toBe("");
  expect(reads.at(-1)?.searchParams.get("scope")).toBe("all");
  await expect(page.getByRole("searchbox", { name: "Search skills" })).toHaveValue("");
  await expect(skills.getByRole("button", { name: "View details for release-helper" })).toBeVisible();
  const cleared = skillsCleared(page);
  await expect(cleared).toContainText("57 skills");
  await expect(cleared).toContainText("Showing the first 50 of 57");
  await expect(cleared.getByRole("columnheader", { name: "Risk score" })).toHaveCount(0);
  await cleared.getByRole("button", { name: "Show all in All skills", exact: true }).click();
  await expect.poll(() => reads.at(-1)?.searchParams.get("review")).toBe("approved");
  await expect(page.getByRole("combobox", { name: "Approval filter" })).toContainText("Approved");
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await page.getByRole("button", { name: "Show needs attention", exact: true }).click();
  await expect(skills.getByRole("button", { name: "View details for release-helper" })).toBeVisible();
  // One card's refresh fails while the table succeeds: retained populated and
  // empty results are labeled, and a successful retry clears the warning.
  const queue = skillQueue(page);
  const pending = skillsPending(page);
  await expect(pending).toContainText("No monitoring skills");
  failStatus = "unapproved";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(queue.getByRole("alert")).toContainText("Unapproved list refresh failed: unapproved list unavailable Showing previously loaded results");
  await expect(queue.getByRole("button", { name: "View details for skill-0", exact: true })).toBeVisible();
  await expect(pending.getByRole("alert")).toHaveCount(0);
  await expect(page.locator("main").getByRole("alert")).toHaveCount(1);
  failStatus = "monitoring";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(pending.getByRole("alert")).toContainText("Monitoring list refresh failed");
  await expect(pending).toContainText("No monitoring skills");
  await expect(queue.getByRole("alert")).toHaveCount(0);
  failStatus = null;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  failure = 503;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert").filter({ hasText: "Inventory temporarily unavailable" })).toHaveCount(4);
  await expect(page.locator("main").getByRole("alert").filter({ hasText: "Showing previously loaded records" })).toBeVisible();
  await expect(skills.getByRole("button", { name: "View details for release-helper" })).toBeVisible();
  failure = 0;
  await skills.getByRole("button", { name: "View details for release-helper" }).click();
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Credential exfiltration" })).toBeVisible();
  failure = 403;
  await page.clock.fastForward(30_001);
  await expect(page.getByRole("dialog").getByRole("heading", { name: "Credential exfiltration" })).toHaveCount(0);
  await expect(page.getByRole("dialog")).toContainText("Assessment unavailable");
  await page.getByRole("dialog").getByRole("button", { name: "Close", exact: true }).click();
  await expect(skills.getByRole("button", { name: "View details for release-helper" })).toHaveCount(0);
  await expect(skillSummary(page)).toContainText("Unknown");
});

test("skills scanner empty, disabled, incompatible, and unavailable inventory remain distinct", async ({ page }) => {
  let state = "empty";
  await mockApi(page, url => {
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    if (state === "error") return { status: 503, json: { error: { message: "Inventory unavailable" } } };
    if (state === "incompatible") return { json: { items: [], next_cursor: "" } };
    return { json: { ...scanInventory, enabled: false, items: [], total: 0, summary: { installed: 0, installations: 0, attention: 0, assessed: 0, pending: 0, incomplete: 0 } } };
  });
  await page.goto("/ai-skills");
  await expect(page.getByText("Skill scanning is disabled", { exact: true })).toBeVisible();
  await expect(page.getByText("No skills reported", { exact: true })).toBeVisible();
  state = "incompatible";
  await page.reload();
  await expect(page.locator("main").getByRole("alert")).toContainText("Inventory response is incompatible");
  await expect(page.getByText("No skills reported", { exact: true })).toHaveCount(0);
  state = "error";
  await page.reload();
  await expect(page.locator("main").getByRole("alert")).toContainText("Inventory unavailable");
  await expect(skillSummary(page)).toContainText("Unknown");
  await expect(skillQueue(page)).toContainText("Unapproved list unavailable");
  await expect(page.getByText("No skills reported", { exact: true })).toHaveCount(0);
  await expect(page.getByText("No unapproved skills", { exact: true })).toHaveCount(0);
});

test("supply chain attention counts, affected-device sorting and category pagination use reported evidence", async ({ page }, testInfo) => {
  const reads: URL[] = [];
  const vulnerable = { ...component, vulnerability: { provider: "OSV", status: "complete", reason: "", checked_at: stamp,
    findings: [{ id: "GHSA-example", aliases: [], source_ids: ["GHSA-example"], summary: "Example vulnerability",
      severity: "low", fixed_versions: [], severity_vectors: [] }] } };
  let fail = false;
  let unavailable = false;
  await mockApi(page, (url) => {
    reads.push(url);
    const source = url.searchParams.get("source");
    if (unavailable || source === "openaidr-plugins" && fail)
      return { status: 503, json: { error: { message: "Inventory unavailable" } } };
    if (url.pathname.endsWith("/roots"))
      return { json: { items: source === "osquery-npm-packages" ? [root] : [], next_cursor: "" } };
    if (source !== "osquery-npm-packages")
      return { json: {
        items: source === "osquery-python-packages" ? [{ ...component, source, id: "python-1", version: "", root_status: "ok" }] : [],
        next_cursor: source === "osquery-python-packages" && !url.searchParams.has("cursor") ? "python +/cursor" : "",
      } };
    return { json: {
      items: url.searchParams.has("cursor")
        ? [{ ...vulnerable, id: "component-3", sensor_id: "device-3", hostname: "third-mac", version: "3.0.0" }]
        : [vulnerable, { ...component, id: "component-2", sensor_id: "device-2", hostname: "other-mac", root_status: "ok" },
          ...[1, 2, 3].map((i) => ({ ...vulnerable, id: `widespread-${i}`, sensor_id: `wide-device-${i}`, hostname: `wide-device-${i}`, identifier: "widespread-tools", name: "widespread-tools" })),
          ...[1, 2].map((i) => ({ ...component, id: `clean-${i}`, identifier: "complete-tools", name: "complete-tools", root_status: "ok", version: `${i}.0.0` }))],
      next_cursor: url.searchParams.has("cursor") ? "" : "npm +/cursor",
    } };
  });
  await page.goto("/ai-supply-chain/preview");
  await openComponents(page);
  await expect(page).toHaveURL(/\/ai-supply-chain$/);
  await expect(page.getByRole("heading", { level: 1, name: "AI Supply Chain", exact: true })).toBeVisible();
  await expect(page.locator("iframe")).toHaveCount(0);
  await expect(page.getByRole("region", { name: "Inventory overview" })).toHaveCount(0);
  await expect(page.getByRole("tab")).toHaveCount(0);
  const npmButton = categoryButton(page, "npm packages");
  const pythonButton = categoryButton(page, "Python packages");
  await expect(page.getByRole("combobox", { name: "Attention reason" })).toHaveCount(0);
  await expect(recordCount(page)).toHaveText("4+");
  await expect(page.locator('[data-slot="review-summary"]')).toHaveText(
    "2+ of 4+ loaded components need attention.",
  );
  await expect(page.getByRole("searchbox", { name: "Search inventory" })).toHaveCSS("height", "32px");
  await page.evaluate(() => document.fonts.ready);
  const attentionBox = await queue(page).boundingBox();
  const coverageBox = await loadedCoverage(page).boundingBox();
  expect(coverageBox!.y).toBeGreaterThanOrEqual(attentionBox!.y + attentionBox!.height);
  expect(coverageBox!.width).toBeCloseTo(attentionBox!.width, 0);
  await expect(page.getByRole("region", { name: "Component categories", exact: true })).toHaveCount(0);
  const attentionList = queue(page);
  await expect(attentionList.getByRole("row")).toHaveCount(3);
  await expect(attentionList.getByRole("row").nth(1)).toContainText("widespread-tools");
  await expect(attentionList.getByRole("row").nth(1).getByRole("cell").nth(2)).toContainText("3");
  const affectedCell = attentionList.getByRole("row").nth(1).getByRole("cell").nth(2);
  await expect(affectedCell).toHaveText("3");
  await affectedCell.getByRole("button").hover();
  const affectedList = page.getByRole("dialog", { name: "Affected devices for widespread-tools", exact: true });
  await expect(affectedList.getByRole("listitem")).toHaveCount(3);
  for (const name of ["wide-device-1", "wide-device-2", "wide-device-3"]) await expect(affectedList).toContainText(name);
  await page.screenshot({ path: testInfo.outputPath("affected-devices-hover.png"), fullPage: true, animations: "disabled" });
  await page.getByRole("heading", { level: 1 }).hover();
  await expect(affectedList).toHaveCount(0);
  const npmRow = attentionList.getByRole("row").filter({ hasText: component.name });
  await expect(npmRow.getByRole("cell").nth(2).locator(".number")).toHaveText("1");
  await expect(attentionList.getByText("complete-tools", { exact: true })).toHaveCount(0);
  await records(page).getByRole("button", { name: "Load more", exact: true }).click();
  await expect(npmRow.getByRole("cell").nth(2).locator(".number")).toHaveText("2");
  await expect(npmRow).toContainText("2.4.0, 3.0.0");
  expect(reads.filter((url) => url.searchParams.has("cursor"))
    .map((url) => [url.searchParams.get("source"), url.searchParams.get("cursor")]).sort()).toEqual([
      ["osquery-npm-packages", "npm +/cursor"], ["osquery-python-packages", "python +/cursor"],
    ]);
  const trigger = npmRow.getByRole("button", { name: `View details for ${component.name}` });
  await trigger.click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByRole("region", { name: "Component records" })).toContainText("3 loaded records on 3 devices");
  await drawer.getByRole("button", { name: /third-mac · 3.0.0/ }).click();
  await expect(drawer.locator("dd").filter({ hasText: /^3\.0\.0$/ })).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  // Sorting and the category selection scope the table; the queue keeps its
  // most-affected-first order.
  const table = records(page);
  await page.getByRole("combobox", { name: "Sort components" }).click();
  await page.getByRole("option", { name: "Component name", exact: true }).click();
  await expect(table.locator("tbody tr").first()).toContainText(component.name);
  await expect(attentionList.getByRole("row").nth(1)).toContainText("widespread-tools");
  await npmButton.click();
  await expect(npmButton).toHaveAttribute("aria-pressed", "true");
  await expect(table.getByText("complete-tools", { exact: true })).toBeVisible();
  await expect(table.locator("tbody tr").filter({ hasText: "complete-tools" })).toContainText("1.0.0, 2.0.0");
  await expect(table.locator("tbody tr").filter({ hasText: "complete-tools" })).not.toContainText("Review evidence");
  await pythonButton.click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(table.locator("tbody tr")).toContainText("Vulnerabilities not assessed");
  await expect(table.locator("tbody tr")).toContainText("Version not reported");
  await expect(attentionList.getByRole("row")).toHaveCount(3);
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(4);
  await page.getByRole("button", { name: "Show Python packages", exact: true }).click();
  await expect(table.locator("tbody tr")).toHaveCount(1);
  await expect(pythonButton).toHaveAttribute("aria-pressed", "true");
  await page.getByRole("button", { name: "All", exact: true }).click();
  fail = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert").filter({ hasText: "Inventory:" })).toContainText("Plugins: Inventory unavailable");
  // A failed category keeps the loaded queue rows but never claims a clean result.
  await expect(attentionList).toContainText("Plugins inventory unavailable");
  await expect(attentionList).toContainText("Unknown");
  await expect(attentionList).not.toContainText("Unknown components");
  await expect(attentionList.getByRole("row")).toHaveCount(3);
  fail = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  await page.getByRole("combobox", { name: "Device", exact: true }).click();
  await page.getByRole("option", { name: "other-mac", exact: true }).click();
  await expect.poll(() => reads.at(-1)?.searchParams.get("sensor_id")).toBe("device-2");
  await expect(page.getByText("Device: other-mac", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const version = npmRow.locator(".font-mono").first();
    await expect(version).toHaveCSS("font-family", /GeistMono/);
    await expect(version).toHaveCSS("font-size", "14px");
    const scroller = page.getByRole("region", { name: "Scrollable data table", exact: true });
    if (viewport.width < 640) {
      await scroller.focus();
      await expect(scroller).toBeFocused();
      await scroller.press("ArrowRight", { delay: 100 });
      await expect.poll(() => scroller.evaluate((node) => node.scrollLeft)).toBeGreaterThan(0);
      await scroller.evaluate((node) => { node.scrollLeft = 0; });
    }
    await trigger.click();
    await expect(drawer).toBeVisible();
    await expect.poll(() => drawer.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await drawer.getByRole("button", { name: "Close", exact: true }).last().click();
    await expect(drawer).toHaveCount(0);
    await expect(trigger).toBeFocused();
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: testInfo.outputPath(`supply-chain-attention-${viewport.width}.png`), fullPage: true, animations: "disabled" });
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  expect(reads.every((url) => url.searchParams.get("source") !== "openaidr-skills")).toBe(true);
  unavailable = true;
  await page.reload();
  await openComponents(page);
  await expect(page.locator("main").getByRole("alert")).toHaveCount(2);
  await expect(recordCount(page)).toHaveText("Unknown");
  await expect(page.locator('[data-slot="review-summary"]')).toContainText("counts are unavailable");
  await expect(loadedCoverage(page)).toContainText("Scan coverage unavailable");
  await expect(attentionList).toContainText("Inventory unavailable");
  await expect(page.getByText("No records reported", { exact: true })).toHaveCount(0);
  await expect(page.getByText("No known vulnerabilities in loaded records", { exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 600 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test("collection gaps and missing versions do not trigger attention and remain available in details", async ({ page }, testInfo) => {
  const oldScan = "2026-09-20T12:00:00Z";
  const fresh = Array.from({ length: 8 }, (_, i) => ({ ...component, id: `fresh-${i}`,
    name: `reported-package-${i}`, identifier: `reported-package-${i}`, last_seen_at: stamp }));
  const retained = { ...component, id: "retained", root_id: "old-root", sensor_id: "old-enrollment",
    name: "retained-tools", identifier: "retained-tools", root_collected_at: oldScan,
    last_seen_at: "2026-09-19T12:00:00Z",
    vulnerability: { provider: "OSV", status: "complete", reason: "", checked_at: stamp, findings: [] } };
  const currentCopy = { ...retained, id: "current-copy", root_id: rootId, sensor_id: sensor,
    hostname: "current-mac", root_collected_at: stamp, last_seen_at: stamp, version: "3.0.0" };
  let legacy = false;
  let failPython = false;
  await mockApi(page, (url) => {
    if (failPython && url.searchParams.get("source") === "osquery-python-packages" && url.pathname.endsWith("/components"))
      return { status: 503, json: { error: { message: "Python inventory unavailable" } } };
    if (url.searchParams.get("source") !== "osquery-npm-packages")
      return { json: { items: [], next_cursor: "" } };
    return { json: { items: url.pathname.endsWith("/roots")
      ? [{ ...root, component_count: 8 }, { ...root, id: "old-root", sensor_id: "old-enrollment", collected_at: oldScan }]
      : [...fresh, currentCopy, retained].map((record) => legacy ? { ...record, root_collected_at: undefined } : record), next_cursor: "" } };
  });
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  const attentionList = queue(page);
  const table = records(page);
  await expect(attentionList).toContainText("0 of 9 loaded");
  await expect(attentionList).toContainText("No known vulnerabilities in loaded records");
  await expect(attentionList.getByRole("button", { name: /^View details for/ })).toHaveCount(0);
  const retainedRow = table.locator("tbody tr").filter({ hasText: "retained-tools" });
  const coverage = loadedCoverage(page);
  await expect(coverage).toContainText("2 partial");
  await expect(coverage).toContainText("Latest loaded scan Just now");
  await expect(coverage.getByText(root.message, { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: /Collection details|View scan locations/, exact: true }).click();
  await expect(page.getByRole("dialog").getByText(root.message, { exact: true })).toHaveCount(2);
  await page.keyboard.press("Escape");
  await expect(table.locator("tbody tr")).toHaveCount(9);
  const freshRow = table.locator("tbody tr").filter({ hasText: "reported-package-0" });
  await expect(freshRow).not.toContainText("Presence not confirmed");
  await expect(retainedRow).toContainText("Just now");
  await expect(table.getByText("Scan incomplete", { exact: true })).toHaveCount(0);
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`location-coverage-${viewport.width}.png`), fullPage: true, animations: "disabled" });
    await freshRow.getByRole("button", { name: "View details for reported-package-0", exact: true }).click();
    const drawer = page.getByRole("dialog");
    await expect(drawer).toContainText("This record was reported in the latest scan of that location.");
    await expect(drawer).toContainText("Last seen Just now");
    await expect.poll(() => drawer.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`record-collection-${viewport.width}.png`), animations: "disabled" });
    await drawer.getByRole("button", { name: "Close", exact: true }).last().click();
  }
  await table.getByRole("button", { name: "View details for retained-tools", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: /dev-mac · 2.4.0/ }).click();
  await expect(page.getByRole("dialog")).toContainText("This record was retained from an earlier scan.");
  await expect(page.getByRole("dialog")).toContainText("Last seen 12d ago");
  await page.keyboard.press("Escape");
  legacy = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(retainedRow).not.toContainText("Presence not confirmed");
  await freshRow.getByRole("button", { name: "View details for reported-package-0", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("record freshness is unknown");
  await expect(page.getByRole("dialog")).not.toContainText("This record was reported in the latest scan");
  await page.keyboard.press("Escape");
  currentCopy.version = "";
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await retainedRow.getByRole("button", { name: "View details for retained-tools", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("button", { pressed: true })).toContainText("Version not reported");
  await page.keyboard.press("Escape");
  await expect(attentionList).toContainText("No known vulnerabilities in loaded records");
  await expect(attentionList.getByRole("button", { name: /^View details for/ })).toHaveCount(0);
  // One failed category with nothing vulnerable elsewhere: no reassurance.
  failPython = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.locator("main").getByRole("alert").filter({ hasText: "Inventory:" })).toContainText("Python packages: Python inventory unavailable");
  await expect(attentionList).toContainText("Python packages inventory unavailable");
  await expect(attentionList).not.toContainText("No known vulnerabilities in loaded records");
  await expect(attentionList).toContainText("Unknown");
  await expect(table.locator("tbody tr")).toHaveCount(9);
});

test("only known vulnerabilities trigger attention, including retained findings after failed checks", async ({ page }, testInfo) => {
  const finding = {
    id: "CVE-2026-1111", aliases: ["GHSA-example"], source_ids: ["GHSA-example"],
    summary: "Example vulnerable package behavior", severity: "high",
    fixed_versions: ["3.0.0"], severity_vectors: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
  };
  const assessment = { provider: "OSV", status: "complete", reason: "", checked_at: "2026-10-01T08:00:00Z", findings: [finding] };
  let resolved = false;
  let retryFailed = true;
  await mockApi(page, (url) => {
    const source = url.searchParams.get("source");
    if (url.pathname.endsWith("/roots")) return { json: { items: [], next_cursor: "" } };
    const alpha = { ...component, root_status: "ok", vulnerability: { ...assessment, findings: resolved ? [] : [finding] } };
    const items = source === "osquery-npm-packages" ? [
      { ...alpha, id: "healthy-copy", sensor_id: "device-3", hostname: "healthy-mac", version: "3.0.0",
        root_status: "partial", last_seen_at: "2026-10-01T11:00:00Z", vulnerability: { ...assessment, findings: [] } },
      alpha,
      { ...alpha, id: "same-device-copy", path: "/second/node_modules/example" },
      { ...alpha, id: "other-device-copy", sensor_id: "device-2", hostname: "other-mac", version: "2.5.0",
        vulnerability: { ...assessment, findings: resolved ? [] : [{ ...finding, id: "GHSA-example", aliases: ["CVE-2026-1111"] }] } },
      ...[1, 2, 3].map((index) => ({ ...component, id: `wide-${index}`, identifier: "widespread-tools", name: "widespread-tools",
        sensor_id: `wide-device-${index}`, hostname: `wide-device-${index}`, root_status: "ok",
        vulnerability: { ...assessment, status: retryFailed ? "unavailable" : "stale", reason: "OSV check due" } })),
      { ...component, id: "retained-only", identifier: "retained-only", name: "retained-only",
        vulnerability: { ...assessment, status: "unavailable", findings: [] } },
      { ...component, id: "unknown-only", identifier: "unknown-only", name: "unknown-only", root_collected_at: undefined,
        vulnerability: { ...assessment, status: "stale", findings: [] } },
      { ...component, id: "version-only", identifier: "version-only", name: "version-only", root_status: "ok", version: "" },
    ] : source === "osquery-python-packages" ? [
      { ...component, source, id: "python-pending", name: "pending-python", root_status: "ok", vulnerability: { ...assessment, status: "pending", checked_at: null, findings: [] } },
    ] : source === "openaidr-mcp-servers" ? [
      { ...component, source, id: "mcp-unknown", name: "unknown-server", root_status: "ok", vulnerability: undefined },
    ] : [];
    return { json: { items, next_cursor: "" } };
  });
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  const npmButton = categoryButton(page, "npm packages");
  const attentionList = queue(page);
  const table = records(page);
  await expect(attentionList).toContainText("2 of 7 loaded");
  await expect(recordCount(page)).toHaveText("7");
  await expect(attentionList.getByRole("row")).toHaveCount(3);
  await expect(page.getByRole("combobox", { name: "Attention reason" })).toHaveCount(0);
  await expect(attentionList.getByRole("row").nth(1)).toContainText("widespread-tools");
  await expect(attentionList.getByRole("row").nth(1).getByRole("cell").nth(2).locator(".number")).toHaveText("3");
  const alphaRow = attentionList.getByRole("row").filter({ hasText: component.name });
  await expect(alphaRow.getByRole("cell").nth(2).locator(".number")).toHaveText("2");
  await expect(alphaRow).toContainText("1 known vulnerability");
  await expect(alphaRow.getByText("Max CVSS 9.8", { exact: true })).toBeVisible();
  await expect(alphaRow).toContainText("v3.1 · Base");
  await expect(alphaRow).not.toContainText("healthy-mac");
  await expect(alphaRow).not.toContainText("Presence not confirmed");
  await alphaRow.getByRole("button", { name: `Show 2 affected devices for ${component.name}` }).hover();
  const affectedDevices = page.getByRole("dialog", { name: `Affected devices for ${component.name}`, exact: true });
  await expect(affectedDevices.getByRole("listitem")).toHaveCount(2);
  await expect(affectedDevices).toContainText("dev-mac");
  await expect(affectedDevices).toContainText("other-mac");
  await expect(affectedDevices).not.toContainText("healthy-mac");
  await page.getByRole("heading", { level: 1 }).hover();
  await expect(affectedDevices).toHaveCount(0);
  const trigger = alphaRow.getByRole("button", { name: `View details for ${component.name}` });
  await trigger.click();
  const drawer = page.getByRole("dialog");
  await expect(drawer.getByRole("button", { pressed: true })).toContainText("dev-mac · 2.4.0");
  const findings = drawer.getByRole("region", { name: "Vulnerability findings" });
  await expect(findings.locator("li")).toHaveCount(1);
  await expect(findings).toContainText("2 affected devices · 3 loaded records");
  await expect(findings.getByText("High", { exact: true })).toBeVisible();
  await expect(findings.locator("li").getByText("CVSS 9.8", { exact: true }).first()).toBeVisible();
  await expect(findings.getByRole("link")).toHaveAttribute("href", "https://osv.dev/vulnerability/GHSA-example");
  await expect(findings.getByText("3.0.0", { exact: true }).first()).toBeVisible();
  await findings.getByText("Source severity vectors", { exact: true }).click();
  await expect(findings.getByText(/CVSS_V3:/)).toBeVisible();
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await expect.poll(() => drawer.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await drawer.screenshot({ path: testInfo.outputPath(`osv-findings-${viewport.width}.png`), animations: "disabled" });
  }
  await drawer.getByRole("button", { name: "Close", exact: true }).last().click();
  await expect(trigger).toBeFocused();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(attentionList.getByRole("row")).toHaveCount(3);
  await attentionList.getByRole("button", { name: "View details for widespread-tools" }).click();
  await expect(findings).toContainText("Vulnerability check unavailable");
  await expect(findings.getByText("Max CVSS 9.8", { exact: true })).toBeVisible();
  await expect(findings).toContainText("Previous findings remain visible");
  await expect(findings.locator("li")).toHaveCount(1);
  await page.keyboard.press("Escape");
  retryFailed = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(attentionList.getByRole("row").first()).toBeVisible();
  await expect(attentionList.getByRole("row").filter({ hasText: "widespread-tools" })).toContainText("Vulnerability check outdated");
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: testInfo.outputPath("osv-inventory.png"), fullPage: true, animations: "disabled" });
  resolved = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(alphaRow).toHaveCount(0);
  await npmButton.click();
  await expect(table.locator("tbody tr")).toHaveCount(5);
  await expect(table.locator("tbody tr").filter({ hasText: "retained-only" })).toContainText("Vulnerability check unavailable");
  await expect(table.locator("tbody tr").filter({ hasText: "unknown-only" })).toContainText("Vulnerability check outdated");
  await expect(table.locator("tbody tr").filter({ hasText: "version-only" })).toContainText("Version not reported");
  const tableAlpha = table.locator("tbody tr").filter({ hasText: component.name });
  await expect(tableAlpha.getByRole("cell").nth(2).locator(".number")).toHaveText("3");
  await expect(tableAlpha).toContainText("1h ago");
  await categoryButton(page, "Python packages").click();
  await expect(table.locator("tbody tr")).toContainText("Vulnerability check pending");
  await categoryButton(page, "MCP servers").click();
  await expect(table.locator("tbody tr")).toContainText("Vulnerabilities not assessed");
});

test("CVSS scores aggregate aliases and package copies, with explicit missing scores", async ({ page }, testInfo) => {
  const vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
  const finding = {
    id: "CVE-2026-1111", aliases: ["GHSA-example"], source_ids: ["GHSA-example"],
    summary: "Example vulnerability with multiple source vectors", severity: "high",
    fixed_versions: ["3.0.0"], severity_vectors: [{ type: "CVSS_V3", score: vector.replace("C:H/I:H/A:H", "C:N/I:N/A:H") }],
  };
  const missing = { ...finding, id: "GHSA-no-vector", aliases: [], source_ids: ["GHSA-no-vector"],
    summary: "Example advisory without a usable score", severity: "critical", severity_vectors: [{ type: "CVSS_V3", score: "9.9" }] };
  const assessment = { provider: "OSV", status: "complete", reason: "", checked_at: stamp, findings: [finding] };
  const items = [
    { ...component, vulnerability: { ...assessment, findings: [finding, missing, {
      ...finding, id: "GHSA-v4", aliases: [], source_ids: ["GHSA-v4"], severity: "unknown",
      severity_vectors: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }],
    }] } },
    { ...component, id: "other-copy", sensor_id: "other-device", hostname: "other-mac", version: "2.5.0",
      vulnerability: { ...assessment, findings: [{ ...finding, id: "GHSA-example", aliases: [finding.id],
        severity_vectors: [{ type: "CVSS_V3", score: vector }] }] } },
    { ...component, id: "unscored", identifier: "unscored-package", name: "unscored-package",
      vulnerability: { ...assessment, findings: [missing] } },
    { ...component, id: "zero", identifier: "zero-score-package", name: "zero-score-package",
      vulnerability: { ...assessment, findings: [{ ...finding, severity_vectors: [{ type: "CVSS_V3", score: vector.replace("C:H/I:H/A:H", "C:N/I:N/A:N") }] }] } },
  ];
  await mockApi(page, (url) => ({ json: { items: url.pathname.endsWith("/components") && url.searchParams.get("source") === "osquery-npm-packages" ? items : [], next_cursor: "" } }));
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  const row = queue(page).getByRole("row").filter({ hasText: component.name });
  await expect(row).toContainText("3 known vulnerabilities");
  await expect(row).toContainText("Scores available for 2 of 3 vulnerabilities");
  await expect(row.getByText("Max CVSS 9.8", { exact: true })).toBeVisible();
  await expect(records(page).getByRole("row").filter({ hasText: component.name })).toContainText("Max CVSS 9.8");
  await expect(queue(page).getByRole("row").filter({ hasText: "unscored-package" })).toContainText("CVSS unavailable");
  await expect(queue(page).getByRole("row").filter({ hasText: "zero-score-package" })).toContainText("Max CVSS 0.0");
  for (const viewport of [{ width: 1440, height: 900 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: testInfo.outputPath(`cvss-inventory-${viewport.width}.png`), fullPage: true, animations: "disabled" });
    await row.getByRole("button", { name: `View details for ${component.name}` }).click();
    const drawer = page.getByRole("dialog");
    const findings = drawer.getByRole("region", { name: "Vulnerability findings" });
    await expect(findings.locator("li")).toHaveCount(3);
    const scored = findings.locator("li").filter({ has: page.getByRole("link", { name: finding.id, exact: true }) });
    await expect(scored.getByText("CVSS 9.8", { exact: true }).first()).toBeVisible();
    await expect(findings.locator("li").filter({ has: page.getByRole("link", { name: "GHSA-v4", exact: true }) })).toContainText("CVSS 9.3");
    await expect(findings.locator("li").filter({ has: page.getByRole("link", { name: missing.id, exact: true }) })).toContainText("CVSS unavailable");
    await scored.getByText("Source severity vectors", { exact: true }).click();
    await expect(scored.getByText("CVSS 7.5", { exact: true })).toBeVisible();
    await expect(scored.getByText(`CVSS_V3: ${vector}`, { exact: true })).toBeVisible();
    await expect.poll(() => drawer.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await drawer.screenshot({ path: testInfo.outputPath(`cvss-details-${viewport.width}.png`), animations: "disabled" });
    await drawer.getByRole("button", { name: "Close", exact: true }).last().click();
  }
});

test.describe("affected device count", () => {
  test.use({ hasTouch: true });
  test("reveals the complete list on hover, focus and tap and filters by any device", async ({ page }, testInfo) => {
    const longName = `long-hostname-${"engineering-".repeat(12)}mac`;
    const devices = Array.from({ length: 14 }, (_, index) => ({ ...component, id: `copy-${index}`, sensor_id: `device-${index}`,
      hostname: index < 2 ? "shared-hostname" : index === 2 ? longName : index === 3 ? "" : `workstation-${index}`,
      vulnerability: { provider: "OSV", status: "complete", reason: "", checked_at: stamp, findings: [{
        id: "GHSA-example", aliases: [], source_ids: ["GHSA-example"], summary: "Example vulnerability", severity: "high", fixed_versions: [], severity_vectors: [],
      }] },
    }));
    const rows = [...devices, { ...devices[0], id: "duplicate-copy" }, { ...component, id: "healthy-copy", sensor_id: "healthy-device", hostname: "healthy-device" }];
    const reads: URL[] = [];
    await mockApi(page, (url) => {
      reads.push(url);
      const selected = url.searchParams.get("sensor_id");
      return { json: { items: url.pathname.endsWith("/components") && url.searchParams.get("source") === "osquery-npm-packages"
        ? rows.filter((row) => !selected || row.sensor_id === selected) : [], next_cursor: "" } };
    });
    await page.goto("/ai-supply-chain");
  await openComponents(page);
    const cell = queue(page).getByRole("row").nth(1).getByRole("cell").nth(2);
    const count = cell.getByRole("button", { name: `Show 14 affected devices for ${component.name}` });
    const list = page.getByRole("dialog", { name: `Affected devices for ${component.name}`, exact: true });
    await expect(cell).toHaveText("14");
    await expect(list).toHaveCount(0);
    await count.hover();
    await expect(list.getByRole("listitem")).toHaveCount(14);
    await expect(list.getByRole("button", { name: "Filter by device shared-hostname", exact: true })).toHaveCount(2);
    await expect(list).not.toContainText("healthy-device");
    await expect(count).not.toBeFocused();
    await list.hover();
    await expect(list).toBeVisible();
    await page.getByRole("heading", { level: 1 }).hover();
    await expect(list).toHaveCount(0);
    await count.focus();
    await expect(list).toBeVisible();
    await count.press("ArrowDown");
    await expect(list.getByRole("button").first()).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(list).toHaveCount(0);
    await expect(count).toBeFocused();
    await count.press("Enter");
    await expect(list.getByRole("button").first()).toBeFocused();
    await page.screenshot({ path: testInfo.outputPath("affected-devices-desktop.png"), fullPage: true, animations: "disabled" });
    await page.keyboard.press("Escape");
    await page.setViewportSize({ width: 390, height: 600 });
    // Move focus off the count before checking a real touch activation.
    await page.getByRole("heading", { level: 1 }).tap();
    await count.tap();
    await expect(list).toBeVisible();
    await expect(list.getByRole("button", { name: `Filter by device ${longName}`, exact: true })).toHaveText(longName);
    await expect(list.getByRole("button", { name: "Filter by device device-3", exact: true })).toHaveCSS("font-family", /GeistMono/);
    await expect.poll(() => list.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    const bounds = await list.boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
    expect(bounds!.y).toBeGreaterThanOrEqual(0);
    expect(bounds!.y + bounds!.height).toBeLessThanOrEqual(600);
    expect(await list.evaluate((node) => node.scrollHeight > node.clientHeight)).toBe(true);
    const last = list.getByRole("button", { name: "Filter by device workstation-13", exact: true });
    await last.scrollIntoViewIfNeeded();
    await page.screenshot({ path: testInfo.outputPath("affected-devices-phone.png"), animations: "disabled" });
    await last.tap();
    await expect(list).toHaveCount(0);
    await expect(page.getByText("Device: workstation-13", { exact: true })).toBeVisible();
    await expect.poll(() => reads.filter((url) => url.pathname.endsWith("/components")).at(-1)?.searchParams.get("sensor_id")).toBe("device-13");
    await expect(cell).toHaveText("1");
  });
});

test("supply chain reads only after sign-in and clears inventory on denied refresh", async ({ page }) => {
  let reads = 0;
  await page.route("**/api/v1/**", (route) => {
    if (new URL(route.request().url()).pathname.includes("/inventory/")) reads++;
    return route.fulfill({ status: 401, json: { error: { message: "Sign in" } } });
  });
  await page.goto("/ai-supply-chain/preview");
  await expect(page).toHaveURL(/\/login$/);
  expect(reads).toBe(0);
  await page.unroute("**/api/v1/**");
  let denied = false;
  await mockApi(page, (url) => denied
    ? { status: 403, json: { error: { message: "Access denied" } } }
    : { json: { items: url.pathname.endsWith("/components") ? [{ ...component, source: url.searchParams.get("source"), id: url.searchParams.get("source") }] : [], next_cursor: "" } });
  await page.goto("/ai-supply-chain");
  await openComponents(page);
  await expect(page.getByRole("button", { name: `View details for ${component.name}` }).first()).toBeVisible();
  denied = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("button", { name: `View details for ${component.name}` })).toHaveCount(0);
});

test('endpoint alerts use the loaded component scope and deduplicate device recipients', async ({page}) => {
  const source = 'osquery-python-packages';
  const identifier = 'litellm';
  await mockApi(page, url => ({json:{items:url.pathname.endsWith('/components') && url.searchParams.get('source') === source
    ? [
      {...component, id:'python-a', source, identifier, name:'LiteLLM', version:'1.105.0'},
      {...component, id:'python-b', source, identifier, name:'LiteLLM', version:'1.104.0', path:'/another/environment'},
      {...component, id:'python-c', source, identifier, name:'LiteLLM', version:'1.105.0', sensor_id:'33333333-3333-4333-8333-333333333333', hostname:'dev-linux'},
    ] : [], next_cursor:''}}));
  await page.route('**/api/v1/auth/me', route => route.fulfill({json:{user:{id:'analyst',name:'Test analyst',email:'test@example.invalid',roles:['security_analyst'],tenant:{id:'tenant',name:'Test tenant',slug:'test'}}}}));
  const alerts = await alertApi(page);
  await page.goto('/ai-supply-chain');
  await openComponents(page);
  await records(page).getByRole('button', {name:'View details for LiteLLM',exact:true}).click();
  await page.getByRole('button', {name:'Alerts', exact:true}).click();
  await page.getByRole('button', {name:'New alert', exact:true}).click();
  const dialog = page.getByRole('dialog', {name:'New alert',exact:true});
  await expect(dialog.getByRole('checkbox')).toHaveCount(2);
  await expect(dialog).toContainText('Only devices in the loaded component records are available');
  await expect(dialog.getByRole('checkbox', {name:/dev-mac/})).toHaveAccessibleName(/1.105.0, 1.104.0/);
  await dialog.getByRole('checkbox', {name:/dev-linux/}).check();
  await dialog.getByLabel('Title', {exact:true}).fill('Security team instructions');
  await dialog.getByLabel('Instructions', {exact:true}).fill('<script>not executed</script>');
  await dialog.getByRole('button', {name:'Preview alert'}).click();
  const preview = page.getByRole('dialog', {name:'Preview alert',exact:true});
  await expect(preview.getByRole('region', {name:'Alert message'})).toContainText('<script>not executed</script>');
  await expect(preview.locator('script')).toHaveCount(0);
  await preview.getByRole('button', {name:'Send to 1 device',exact:true}).click();
  await expect(page.getByRole('dialog', {name:'Alert details',exact:true})).toBeVisible();
  expect(alerts.writes[0].body.application_id).toBe(`component:${JSON.stringify([source,identifier])}`);
  expect(alerts.writes[0].body.sensor_ids).toEqual(['33333333-3333-4333-8333-333333333333']);
  expect(alerts.writes[0].body.command).toBe('');
});


test("skill analysis controls enforce admin editing without disclosing provider accounting", async ({ page }, testInfo) => {
  let settings = { mode: "off", model: "gpt-6-luna", pilot_size: 5, budget_usd: 5,
    measured_usd: 0.1234, reserved_usd: 0.5, remaining_usd: 4.3766, calls: 8, unpriced_calls: 1,
    pending: 0, running: 0, completed: 4, failed: 1, worker_available: true, key_configured: true };
  const writes: unknown[] = [];
  await mockApi(page, url => url.pathname.endsWith("/roots")
    ? { json: { items: [], next_cursor: "" } } : { json: scanPage(url.searchParams.get("status"), url.searchParams.get("review")) });
  await page.route("**/api/v1/inventory/skills/llm", route => {
    if (route.request().method() === "PUT") {
      const body = route.request().postDataJSON();
      writes.push(body);
      settings = { ...settings, ...body };
    }
    return route.fulfill({ json: settings });
  });
  await page.goto("/ai-skills");
  const trigger = page.getByRole("button", { name: "AI scan", exact: true });
  await trigger.click();
  let dialog = page.getByRole("dialog", { name: "AI skill analysis" });
  await expect(dialog).not.toContainText(/GPT-6 Luna|gpt-6-luna|\bOpenAI\b|\$0\.1234/);
  await expect(dialog).toContainText("An IT admin can change scan settings.");
  await expect(dialog.getByRole("button", { name: "Run 5-bundle pilot" })).toHaveCount(0);
  await page.keyboard.press("Escape");
  await expect(trigger).toBeFocused();
  await page.route("**/api/v1/auth/me", route => route.fulfill({ json: { user: {
    id: "admin", name: "IT administrator", email: "admin@example.invalid", roles: ["it_admin"],
    tenant: { id: "tenant", name: "Synthetic inventory review", slug: "review" },
  } } }));
  await page.reload();
  await trigger.click();
  dialog = page.getByRole("dialog", { name: "AI skill analysis" });
  await expect(dialog.getByLabel("Total allowance (USD)")).toHaveCount(0);
  await expect(dialog).not.toContainText(/Measured cost|\$0\.50/);
  await dialog.getByRole("button", { name: "Run 5-bundle pilot" }).click();
  await expect(dialog.getByText("Pilot", { exact: true })).toBeVisible();
  expect(writes).toEqual([{ mode: "pilot" }]);
  await dialog.getByRole("button", { name: "Scan new and changed", exact: true }).click();
  await expect(dialog.getByText("New and changed skills", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Pause", exact: true })).toBeEnabled();
  await page.screenshot({ path: testInfo.outputPath("skill-llm-controls-desktop.png"), animations: "disabled" });
  await page.setViewportSize({ width: 390, height: 680 });
  await dialog.getByRole("button", { name: "Pause", exact: true }).click();
  await expect(dialog.getByText("Paused", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await expect(dialog.getByRole("button", { name: "Run 5-bundle pilot" })).toBeEnabled();
  await expect.poll(async () => {
    const bounds = await dialog.boundingBox();
    return Boolean(bounds && bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= 390 && bounds.y + bounds.height <= 680);
  }).toBe(true);
  await dialog.getByRole("button", { name: "Close", exact: true }).scrollIntoViewIfNeeded();
  await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeInViewport();
  await page.screenshot({ path: testInfo.outputPath("skill-llm-controls-mobile.png"), animations: "disabled" });
  settings = { ...settings, key_configured: false, worker_available: false };
  await page.keyboard.press("Escape");
  await trigger.click();
  await expect(dialog).toContainText("Intelligence service required");
  await expect(dialog.getByRole("button", { name: "Run 5-bundle pilot" })).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Scan new and changed", exact: true })).toBeDisabled();
});

async function notificationApi(page: Page, deviceCount = 2) {
  const session = { roles: ['security_analyst'] };
  const affected = Array.from({ length: deviceCount }, (_, index) => ({ ...component,
    id: `affected-${index}`, sensor_id: `33333333-3333-4333-8333-${String(index).padStart(12, '0')}`,
    hostname: `affected-device-${index}`, root_status: 'ok',
    vulnerability: { provider: 'OSV', status: 'complete', reason: '', checked_at: stamp,
      findings: [{ id: 'GHSA-example', aliases: [], source_ids: ['GHSA-example'], summary: 'Example vulnerability', severity: 'high',
        severity_vectors: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], fixed_versions: ['3.0.0'] }] },
  }));
  await mockApi(page, url => ({ json: { items: url.pathname.endsWith('/components') && url.searchParams.get('source') === component.source
    ? [...affected, { ...affected[0], id: 'duplicate-installation', version: '2.5.0', path: '/another/project' },
      { ...component, id: 'unaffected', sensor_id: sensor, hostname: 'healthy-device', version: '3.0.0' }]
    : [], next_cursor: '' } }));
  await page.route('**/api/v1/auth/me', route => route.fulfill({ json: { user: {
    id: 'operator', name: 'Test operator', email: 'test@example.invalid', roles: session.roles,
    tenant: { id: 'tenant', name: 'Test tenant', slug: 'test' },
  } } }));
  return { session, affected, alerts: await alertApi(page) };
}

for (const width of [1440, 390]) {
  test(`supply chain notifications preview affected recipients and send only selected devices at ${width}px`, async ({ page }, info) => {
    const { affected, alerts } = await notificationApi(page);
    await page.setViewportSize({ width, height: width === 390 ? 640 : 900 });
    await page.goto('/ai-supply-chain');
    const row = queue(page).getByRole('row').filter({ hasText: component.name });
    await expect(queue(page).getByRole('columnheader', { name: 'Notify users', exact: true })).toBeVisible();
    await expect(row.getByRole('cell').nth(2)).toHaveText('2');
    const trigger = row.getByRole('button', { name: `Notify users for ${component.name}`, exact: true });
    await expect(trigger).toBeVisible();
    expect(alerts.queries).toHaveLength(0);
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await queue(page).screenshot({ path: info.outputPath(`supply-chain-notify-${width}.png`), animations: 'disabled' });
    await trigger.click();
    const dialog = page.getByRole('dialog', { name: 'Notify users', exact: true });
    await expect(dialog.getByRole('checkbox')).toHaveCount(2);
    await expect(dialog.getByRole('checkbox', { name: /affected-device-0/ })).toHaveAccessibleName(/2.4.0, 2.5.0/);
    await expect(dialog.getByRole('checkbox').first()).toBeChecked();
    await expect(dialog.getByRole('checkbox').last()).toBeChecked();
    await expect(dialog).not.toContainText('healthy-device');
    await expect(dialog).toContainText('Only affected devices in the loaded component records');
    await expect(dialog.getByLabel('Title', { exact: true })).toHaveValue(`Security update needed: ${component.name}`);
    await expect(dialog.getByLabel('Instructions', { exact: true })).toHaveValue(/Known vulnerabilities were found/);
    await expect(dialog.getByLabel('Command (optional)', { exact: true })).toHaveCount(0);
    for (const checkbox of await dialog.getByRole('checkbox').all()) await checkbox.uncheck();
    await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeDisabled();
    await dialog.getByRole('checkbox', { name: /affected-device-1/ }).check();
    await dialog.getByLabel('Title', { exact: true }).fill('');
    await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeDisabled();
    await dialog.getByLabel('Title', { exact: true }).fill(`Security update needed: ${component.name}`);
    await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeEnabled();
    await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeInViewport({ ratio: 1 });
    await expect(dialog.getByRole('button', { name: 'Cancel', exact: true })).toBeInViewport({ ratio: 1 });
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (width === 390) {
      const scroll = dialog.getByTestId('endpoint-alert-scroll');
      expect(await scroll.evaluate(node => node.scrollHeight > node.clientHeight)).toBe(true);
      await scroll.evaluate(node => { node.scrollTop = node.scrollHeight; });
      await expect(dialog.getByLabel('Instructions', { exact: true })).toBeInViewport();
    }
    await dialog.screenshot({ path: info.outputPath(`supply-chain-notify-compose-${width}.png`), animations: 'disabled' });
    await dialog.getByRole('button', { name: 'Preview alert' }).click();
    const preview = page.getByRole('dialog', { name: 'Preview alert', exact: true });
    await expect(preview.getByRole('list', { name: 'Selected devices' })).toHaveText('affected-device-1');
    expect(alerts.writes).toHaveLength(0);
    await preview.getByRole('button', { name: 'Edit', exact: true }).click();
    await expect(dialog.getByRole('checkbox', { name: /affected-device-1/ })).toBeChecked();
    await dialog.getByRole('button', { name: 'Preview alert' }).click();
    await preview.getByRole('button', { name: 'Send to 1 device', exact: true }).click();
    const detail = page.getByRole('dialog', { name: 'Alert details', exact: true });
    await expect(detail.getByRole('list', { name: 'Delivery status' })).toContainText('Pending receipt');
    expect(alerts.writes).toHaveLength(1);
    expect(alerts.writes[0].body).toMatchObject({
      application_id: `component:${JSON.stringify([component.source, component.identifier])}`,
      sensor_ids: [affected[1].sensor_id], command: '', installed_version: '', required_version: '',
    });
    expect(alerts.writes[0].csrf).toBe('1');
    await page.keyboard.press('Escape');
    await expect(trigger).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(dialog).toBeVisible();
    await dialog.getByRole('button', { name: 'View history', exact: true }).click();
    await expect(page.getByRole('list', { name: 'Alert history' })).toContainText('1 sent');
    await page.getByRole('button', { name: 'New alert', exact: true }).click();
    await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
    expect(alerts.writes).toHaveLength(1);
  });
}

test('supply chain notifications keep read-only roles and unavailable backends from sending', async ({ page }) => {
  const { session, alerts } = await notificationApi(page);
  session.roles = ['security_leadership'];
  await page.goto('/ai-supply-chain');
  await expect(queue(page).getByRole('button', { name: /^Notify users for/ })).toHaveCount(0);
  await queue(page).getByRole('button', { name: `View alerts for ${component.name}`, exact: true }).click();
  const history = page.getByRole('dialog', { name: 'Alerts', exact: true });
  await expect(history).toContainText('IT Admins and Security Analysts can send alerts');
  await expect(history.getByRole('button', { name: 'New alert', exact: true })).toHaveCount(0);
  await expect(history.getByRole('checkbox')).toHaveCount(0);
  session.roles = ['it_admin'];
  alerts.unavailable = true;
  await page.reload();
  await queue(page).getByRole('button', { name: `Notify users for ${component.name}`, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Notify users', exact: true });
  await expect(dialog.getByRole('alert')).toContainText('Could not load alerts');
  await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeDisabled();
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
  alerts.unavailable = false;
  await page.route('**/api/v1/endpoint-alerts?**', route => route.fulfill({ json: { items: [] } }));
  await queue(page).getByRole('button', { name: `Notify users for ${component.name}`, exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('The alert response is incompatible');
  await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeDisabled();
  expect(alerts.writes).toHaveLength(0);
});

test('supply chain notifications require a manual selection above the 100-device limit', async ({ page }) => {
  const { alerts } = await notificationApi(page, 101);
  await page.goto('/ai-supply-chain');
  await queue(page).getByRole('button', { name: `Notify users for ${component.name}`, exact: true }).click();
  const dialog = page.getByRole('dialog', { name: 'Notify users', exact: true });
  await expect(dialog.getByRole('checkbox')).toHaveCount(101);
  await expect(dialog.locator('input:checked')).toHaveCount(0);
  await expect(dialog).toContainText('Select up to 100 devices');
  await expect(dialog.getByRole('button', { name: 'Preview alert' })).toBeDisabled();
  await dialog.getByRole('checkbox').first().check();
  await dialog.getByRole('button', { name: 'Preview alert' }).click();
  await expect(page.getByRole('list', { name: 'Selected devices' })).toHaveText('affected-device-0');
  expect(alerts.writes).toHaveLength(0);
});
