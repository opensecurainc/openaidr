import { test, expect, type Page } from "@playwright/test";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { mockChartData } from "./fixtures/chart-layout";
import { historyFixture } from "./fixtures/guardrail-history";
import type { Gateway, GatewayDetail, GatewayOverview, GatewayRequestDetail } from "../src/lib/gateways";

const time = "2026-10-12T11:00:00Z";
const gateway: Gateway = { id: "gateway-a", name: "Production Kong", kind: "kong", environment: "production", enabled: true, mode: "shadow", capture_content: false, policy_rule_ids: [], version: 1, status: "reporting", node_count: 2, last_seen_at: time, created_at: time, updated_at: time };
const overview: GatewayOverview = { window_hours: 24, gateways: { total: 3, reporting: 1, stale: 1, never_seen: 1, disabled: 0 }, requests: { total: 28, evaluated: 25, unavailable: 3, allowed: 20, denied: 5, would_deny: 4, blocked: 1, fail_open: 3, forwarded: 19, unconfirmed: 5 }, policy_latency_ms: { p50: null, p95: 91 }, coverage: "observed_only" };
const request: GatewayRequestDetail = { id: "request-a", gateway_id: gateway.id, gateway_name: gateway.name, request_id: "plugin-generated-id", node_id: "kong-node-1", route_id: "chat-route", service_id: "model-service", consumer_id: "authenticated-consumer", provider: "Jev-provider", model: "jev-model", protocol: "openai.chat", stream: true, status: "evaluated", mode: "shadow", evaluated_decision: "deny", returned_decision: "allow", outcome: null, status_code: null, latency_ms: null, policy_latency_ms: 82.6, reason: "Configured reason preserves Jev evidence.", failure_reason: "", created_at: time, completed_at: time, messages: [{ role: "user", content: "Original Jev evidence with [REDACTED]." }], assessment: { status: "scored", score: 90, category: "data_exfiltration", level: "critical", confidence: 0.95, model: "jev-1.13.0" }, usage: null, settings_version: 1, policy_version: 4 };

async function mockGateways(page: Page, roles = ["it_admin", "security_analyst"]) {
  await mockChartData(page);
  let current = { ...gateway };
  let credential: GatewayDetail["credential"] = { id: "credential-1", created_at: time, revoked_at: null };
  let created: Gateway | null = null;
  const writes: { method: string; path: string; body: Record<string, unknown> | null }[] = [];
  const reads: URL[] = [];
  const state = { failOverview: false, failInstances: false, emptyInstances: false, paginateInstances: false, conflictPolicy: false, emptyRequests: false, connected: false, roles };
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const key = url.pathname.replace("/api/v1/", "");
    const method = route.request().method();
    if (key === "auth/me") return route.fulfill({ json: { user: { id: "u", name: "Gateway operator", email: "operator@example.invalid", roles: state.roles, tenant: { id: "t", name: "Test tenant", slug: "test" } } } });
    if (key === "response/policy") return route.fulfill({ json: { version: 4, rules: [
      { id: "rule-prompt", name: "Restrict Kong prompts", enabled: true, action: "deny", reason: "Literal Jev policy reason.", match: { kinds: ["prompt"], products: ["kong"] } },
      { id: "rule-litellm", name: "Restrict LiteLLM prompts", enabled: true, action: "deny", reason: "Preserve the configured reason.", match: { products: ["litellm"] } },
      { id: "rule-tool", name: "Command restriction", enabled: true, action: "deny", match: { command_regex: "rm" } },
      { id: "rule-provider", name: "Provider host restriction", enabled: true, action: "deny", match: { host_glob: "api.example.com" } },
    ] } });
    if (!key.startsWith("gateways")) return route.fallback();
    if (method !== "GET") writes.push({ method, path: key, body: route.request().postData() ? route.request().postDataJSON() : null });
    else reads.push(url);
    if (key === "gateways/overview") return state.failOverview ? route.fulfill({ status: 503, json: { error: "Metrics unavailable" } }) : route.fulfill({ json: { ...overview, gateways: { ...overview.gateways, total: overview.gateways.total + (created ? 1 : 0), never_seen: overview.gateways.never_seen + (created ? 1 : 0) } } });
    if (key === "gateways/requests") {
      if (state.emptyRequests) return route.fulfill({ json: { items: [], next_cursor: "" } });
      if (url.searchParams.has("cursor")) return route.fulfill({ json: { items: [{ ...request, id: "request-last", gateway_name: "Last request", status: "unavailable", evaluated_decision: null, returned_decision: null, outcome: "fail_open", messages: null }], next_cursor: "" } });
      const items = Array.from({ length: 24 }, (_, index) => ({ ...request, id: index ? `request-${index}` : request.id, gateway_name: index ? `Kong request ${index + 1}` : gateway.name }));
      return route.fulfill({ json: { items, next_cursor: "page-2" } });
    }
    if (key.startsWith("gateways/requests/")) return route.fulfill({ json: key.endsWith("request-last") ? { ...request, id: "request-last", status: "unavailable", evaluated_decision: null, returned_decision: null, outcome: "fail_open", reason: "", failure_reason: "capture_disabled", messages: null, assessment: null } : { ...request, consumer_name: "Alice Example", application_name: "Support assistant" } });
    if (key === "gateways") {
      if (method === "POST") {
        created = { ...gateway, ...route.request().postDataJSON(), id: "gateway-new", status: "never_seen", node_count: 0, last_seen_at: null };
        return route.fulfill({ status: 201, json: { gateway: created, credential: { id: "credential-new", token: "oagt_once_create", created_at: time } } });
      }
      if (state.failInstances) return route.fulfill({ status: 503, json: { error: "Instances unavailable" } });
      if (state.emptyInstances) return route.fulfill({ json: { items: [], next_cursor: "" } });
      const items = [current,
        { ...gateway, id: "gateway-b", name: "Staging LiteLLM", kind: "litellm", environment: "staging", status: "stale", mode: "enforce", node_count: 1 },
        { ...gateway, id: "gateway-c", name: "Development Kong", environment: "development", status: "never_seen", node_count: 0, last_seen_at: null },
        ...(created ? [created] : []),
      ];
      const more = state.paginateInstances && !url.searchParams.has("cursor");
      return route.fulfill({ json: { items: state.paginateInstances ? more ? items.slice(0, 1) : items.slice(1) : items, next_cursor: more ? "instances-2" : "" } });
    }
    if (key.endsWith("/settings") && method === "PUT") {
      if (state.conflictPolicy) return route.fulfill({ status: 409, json: { error: "Version conflict" } });
      current = { ...current, ...route.request().postDataJSON(), version: current.version + 1 };
      return route.fulfill({ json: current });
    }
    if (key.endsWith("/credentials") && method === "POST") {
      credential = { id: "credential-2", created_at: time, revoked_at: null };
      return route.fulfill({ json: { ...credential, token: "oagt_once_rotate" } });
    }
    if (key.includes("/credentials/") && method === "DELETE") {
      credential = { ...credential!, revoked_at: time };
      return route.fulfill({ json: { revoked: true } });
    }
    if (method === "PATCH") { current = { ...current, ...route.request().postDataJSON(), version: current.version + 1 }; return route.fulfill({ json: current }); }
    const isNew = key.endsWith("gateway-new");
    const detail = isNew ? created! : current;
    if (isNew && state.connected) { detail.status = "reporting"; detail.node_count = 2; detail.last_seen_at = time; }
    return route.fulfill({ json: { gateway: detail, credential, coverage: "observed_only", nodes: isNew && !state.connected ? [] : [
      { node_id: detail.kind === "litellm" ? "litellm-worker-1" : "kong-node-1", plugin_version: "2026.10.23+abcdef0", gateway_version: detail.kind === "litellm" ? "1.106.2" : undefined, kong_version: detail.kind === "kong" ? "3.9" : undefined, last_seen_at: time, status: "reporting", dropped_events: 0 },
      { node_id: detail.kind === "litellm" ? "litellm-worker-2" : "kong-node-2", plugin_version: "2026.10.22+1234567", gateway_version: detail.kind === "litellm" ? "1.106.2" : undefined, kong_version: detail.kind === "kong" ? "3.9" : undefined, last_seen_at: time, status: "stale", dropped_events: null },
    ], routes: isNew && !state.connected ? [] : [{ node_id: detail.kind === "litellm" ? "litellm-worker-1" : "kong-node-1", route_id: "chat-route", service_id: "model-service", protocol: "openai.chat", last_seen_at: time }] } });
  });
  return { writes, reads, state };
}

async function screenshot(page: Page, name: string, fullPage = true) {
  if (!process.env.OPENAIDR_GATEWAY_SCREENSHOTS) return;
  await mkdir(process.env.OPENAIDR_GATEWAY_SCREENSHOTS, { recursive: true });
  await page.evaluate(() => { document.scrollingElement!.scrollTop = 0; });
  await page.screenshot({ path: path.join(process.env.OPENAIDR_GATEWAY_SCREENSHOTS, `${name}.png`), fullPage, animations: "disabled" });
}

test("overview reports unknown metrics and role-limited navigation without inventing health", async ({ page }) => {
  const { state, reads } = await mockGateways(page, ["security_leadership"]);
  await page.goto("/gateways/overview");
  await expect(page.getByRole("heading", { name: "Gateway Overview" })).toBeVisible();
  await expect(page.locator("dt", { hasText: "Policy latency p50" }).locator("..")).toContainText("Unavailable");
  await expect(page.locator("dt", { hasText: /^Disabled$/ }).locator("..")).toContainText("0");
  await expect(page.getByText("Reported routes do not prove full gateway coverage.", { exact: false })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Instances", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Connect gateway", exact: true })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "View requests", exact: true })).toHaveCount(0);
  await screenshot(page, "gateway-overview-leadership");
  state.failOverview = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Metrics unavailable" })).toBeVisible();
  expect(reads.some((url) => url.pathname.endsWith("/requests"))).toBe(false);
  expect(reads.some((url) => url.pathname === "/api/v1/gateways")).toBe(false);
  await page.goto("/gateways/instances/gateway-a");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  expect(reads.some((url) => url.pathname.endsWith("/gateway-a"))).toBe(false);
  await page.goto("/guardrail/history?source=gateways");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  expect(reads.some((url) => url.pathname.endsWith("/requests"))).toBe(false);
});

test("overview embeds paginated instances and keeps navigation and controls reachable", async ({ page }) => {
  const { state, reads } = await mockGateways(page);
  state.paginateInstances = true;
  await page.goto("/gateways/overview");
  const navigation = page.getByRole("navigation", { name: "Workspace navigation", exact: true });
  await expect(navigation.locator('a[href="/gateways/overview"]')).toHaveAttribute("aria-current", "page");
  await expect(navigation.getByRole("link", { name: "Instances", exact: true })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Gateway health", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Instances", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Model requests", exact: true })).toBeVisible();
  await expect(page.getByText("Observed coverage", { exact: true })).toHaveCount(1);
  await page.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(page.getByRole("link", { name: "Staging LiteLLM", exact: true })).toBeVisible();
  await expect(page.getByText("3 instances loaded", { exact: true })).toBeVisible();
  expect(reads.some((url) => url.pathname === "/api/v1/gateways" && url.searchParams.get("cursor") === "instances-2")).toBe(true);
  const table = page.getByRole("region", { name: "Scrollable data table", exact: true });
  expect(await table.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
  await screenshot(page, "gateway-overview");
  await page.setViewportSize({ width: 390, height: 720 });
  await page.getByRole("button", { name: "Connect gateway", exact: true }).scrollIntoViewIfNeeded();
  await expect(page.getByRole("button", { name: "Connect gateway", exact: true })).toBeInViewport();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  expect(await table.evaluate((node) => node.scrollWidth > node.clientWidth)).toBe(true);
  await table.evaluate((node) => { node.scrollLeft = node.scrollWidth; });
  expect(await table.evaluate((node) => node.scrollLeft)).toBeGreaterThan(0);
  await page.getByRole("button", { name: "Open navigation", exact: true }).click();
  const mobileNavigation = page.getByRole("dialog").getByRole("navigation");
  await expect(mobileNavigation.getByRole("link", { name: "Instances", exact: true })).toHaveCount(0);
  await mobileNavigation.locator('a[href="/gateways/overview"]').click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await table.evaluate((node) => { node.scrollLeft = 0; });
  await screenshot(page, "gateway-overview-mobile");
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("link", { name: "Production Kong", exact: true }).click();
  await expect(page).toHaveURL(/\/gateways\/instances\/gateway-a$/);
  await expect(navigation.locator('a[href="/gateways/overview"]')).toHaveAttribute("aria-current", "page");
  await page.getByRole("link", { name: "Gateway overview", exact: true }).click();
  await expect(page).toHaveURL(/\/gateways\/overview$/);
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toBeVisible();
});

test("overview keeps instances available when metrics fail and handles list errors and empty results", async ({ page }) => {
  const { state } = await mockGateways(page);
  state.failOverview = true;
  await page.goto("/gateways/overview");
  await expect(page.getByRole("alert").filter({ hasText: "Metrics unavailable" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Connect gateway", exact: true })).toBeEnabled();
  state.failOverview = false;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  const total = page.locator("dt", { hasText: /^Requests$/ }).locator("..");
  await expect(total).toContainText("28");
  state.failInstances = true;
  await page.getByRole("button", { name: "Refresh instances", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Instances unavailable" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toBeVisible();
  await expect(total).toContainText("28");
  state.failInstances = false;
  state.emptyInstances = true;
  await page.getByRole("button", { name: "Refresh instances", exact: true }).click();
  await expect(page.getByText("No gateway connections", { exact: true })).toBeVisible();
  await expect(page.getByRole("main").getByRole("alert")).toHaveCount(0);
  await expect(total).toContainText("28");
});

test("IT admin creates one-time credentials, rotates, revokes, and cannot edit policy", async ({ page }) => {
  const { writes, reads, state } = await mockGateways(page, ["it_admin"]);
  await page.goto("/gateways/instances");
  await expect(page).toHaveURL(/\/gateways\/overview$/);
  await page.getByRole("button", { name: "Connect gateway", exact: true }).click();
  await expect(page.getByLabel("Gateway plugin", { exact: true })).toHaveText("Kong");
  await screenshot(page, "gateway-connect");
  await page.getByLabel("Name", { exact: true }).fill("Staging Kong");
  await page.getByLabel("Environment", { exact: true }).fill("staging");
  await page.getByRole("button", { name: "Create connection", exact: true }).click();
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveValue("oagt_once_create");
  expect(writes[0]).toMatchObject({ method: "POST", path: "gateways", body: { name: "Staging Kong", environment: "staging", kind: "kong" } });
  expect(await page.evaluate(() => JSON.stringify(localStorage) + JSON.stringify(sessionStorage))).not.toContain("oagt_once");
  await page.getByRole("button", { name: "Clear credential", exact: true }).click();
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Continue to setup", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Integration credential", exact: true })).toBeVisible();
  await page.reload();
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Rotate credential", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("previous credential becomes invalid immediately");
  await page.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(writes).toHaveLength(1);
  await page.getByRole("button", { name: "Rotate credential", exact: true }).click();
  await page.getByRole("button", { name: "Confirm credential", exact: true }).click();
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveValue("oagt_once_rotate");
  await expect(page.locator("pre")).toContainText(["KONG_LUA_PACKAGE_PATH", "{vault://env/openaidr-gateway-token}"]);
  await expect(page.locator("pre").filter({ hasText: "backend_url" })).not.toContainText("oagt_once");
  await expect(page.locator("pre").filter({ hasText: "KONG_LUA_PACKAGE_PATH" })).toContainText("KONG_NGINX_MAIN_ENV='OPENAIDR_GATEWAY_TOKEN'");
  state.roles = ["security_analyst"];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByRole("button", { name: "Rotate credential", exact: true })).toHaveCount(0);
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveCount(0);
  state.roles = ["it_admin"];
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByRole("button", { name: "Rotate credential", exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page.getByLabel("Policy mode", { exact: true })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Save gateway policy", exact: true })).toHaveCount(0);
  await page.getByRole("tab", { name: "Setup", exact: true }).click();
  await expect(page.locator("pre").filter({ hasText: "KONG_LUA_SSL_TRUSTED_CERTIFICATE" })).toContainText("KONG_LUA_SSL_VERIFY_DEPTH=5");
  await screenshot(page, "gateway-setup");
  await expect(page.getByLabel("Gateway credential", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "Revoke credential", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("still allows model traffic under fail-open");
  await page.getByRole("button", { name: "Confirm revoke", exact: true }).click();
  await expect(page.getByText("No active credential.", { exact: false })).toBeVisible();
  expect(writes.at(-1)).toMatchObject({ method: "DELETE", path: "gateways/gateway-new/credentials/credential-2" });
  await page.goto("/gateways/requests");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await page.goto("/guardrail/history?source=gateways");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  expect(reads.some((url) => url.pathname.endsWith("/requests"))).toBe(false);
});

test("LiteLLM uses shared credentials and policy controls with its own setup", async ({ page }) => {
  const { writes, state } = await mockGateways(page);
  await page.goto("/gateways/overview");
  await page.getByRole("button", { name: "Connect gateway", exact: true }).click();
  await page.getByLabel("Gateway plugin", { exact: true }).click();
  await page.getByRole("option", { name: "LiteLLM", exact: true }).click();
  await page.getByLabel("Name", { exact: true }).fill("Staging LiteLLM");
  await page.getByRole("button", { name: "Create connection", exact: true }).click();
  expect(writes[0].body).toMatchObject({ kind: "litellm", name: "Staging LiteLLM" });
  await page.getByRole("button", { name: "Clear credential", exact: true }).click();
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await expect(page.locator("dt", { hasText: /^Instances$/ }).locator("..")).toContainText("4");
  await expect(page.locator("dt", { hasText: /^Awaiting connection$/ }).locator("..")).toContainText("2");
  await expect(page.getByText("4 instances loaded", { exact: true })).toBeVisible();
  await page.locator('a[href="/gateways/instances/gateway-new"]').click();
  await expect(page.getByRole("heading", { name: "Install on LiteLLM", exact: true })).toBeVisible();
  await expect(page.getByText("Contract validation only", { exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Install on Kong", exact: true })).toHaveCount(0);
  await expect(page.getByText("Awaiting a node heartbeat", { exact: true })).toBeVisible();
  state.connected = true;
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(page.getByRole("columnheader", { name: "Gateway version", exact: true })).toBeVisible();
  await expect(page.getByRole("row").filter({ hasText: "litellm-worker-1" })).toContainText("1.106.2");
  await page.getByLabel("OpenAIDR backend origin", { exact: true }).fill("https://tenant.example.invalid");
  await expect(page.locator("pre").filter({ hasText: "OPENAIDR_BACKEND_URL" })).toContainText("https://tenant.example.invalid");
  await expect(page.locator("pre").filter({ hasText: "callbacks" })).toContainText("openaidr_litellm.plugin");
  await expect(page.locator("pre").filter({ hasText: "OPENAIDR_BACKEND_URL" })).not.toContainText("oagt_once");
  await screenshot(page, "gateway-litellm-setup");
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page.getByText("Restrict LiteLLM prompts", { exact: true })).toBeVisible();
  await expect(page.getByText("Restrict Kong prompts", { exact: true })).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 720 });
  await page.getByRole("tab", { name: "Setup", exact: true }).click();
  await page.getByLabel("OpenAIDR backend origin", { exact: true }).scrollIntoViewIfNeeded();
  await expect(page.getByLabel("OpenAIDR backend origin", { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("analyst manages independent policy with version conflicts and eligible rules only", async ({ page }) => {
  const { writes, state } = await mockGateways(page, ["security_analyst"]);
  await page.goto("/gateways/overview");
  await expect(page.getByRole("button", { name: "Connect gateway", exact: true })).toHaveCount(0);
  await page.getByRole("link", { name: "Production Kong", exact: true }).click();
  await expect(page.getByText("chat-route", { exact: true })).toBeVisible();
  await expect(page.getByText("2026.10.23+abcdef0", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: "Setup", exact: true }).click();
  await expect(page.getByRole("button", { name: "Rotate credential", exact: true })).toHaveCount(0);
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page.getByLabel("Name", { exact: true })).toBeDisabled();
  await expect(page.getByLabel("Policy mode", { exact: true })).toContainText("Shadow");
  await page.getByLabel("Policy mode", { exact: true }).click();
  await page.getByRole("option", { name: "Enforce", exact: true }).click();
  await page.getByRole("checkbox", { name: "Permit prompt content capture", exact: false }).check();
  await page.getByRole("checkbox", { name: "Restrict Kong prompts", exact: false }).check();
  await expect(page.getByText("Command restriction", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Provider host restriction", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Literal Jev policy reason.", { exact: true })).toBeVisible();
  await expect(page.getByText("Selected static rules apply only after a successful assessment", { exact: false })).toBeVisible();
  state.conflictPolicy = true;
  await page.getByRole("button", { name: "Save gateway policy", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "Refresh the instance" })).toBeVisible();
  state.conflictPolicy = false;
  await page.getByRole("button", { name: "Save gateway policy", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Gateway policy saved." }).first()).toBeVisible();
  expect(writes.at(-1)).toMatchObject({ method: "PUT", path: "gateways/gateway-a/settings", body: { version: 1, mode: "enforce", capture_content: true, policy_rule_ids: ["rule-prompt"] } });
  expect(writes.every((write) => !write.path.includes("hook-settings"))).toBe(true);
  await page.reload();
  await page.getByRole("tab", { name: "Settings", exact: true }).click();
  await expect(page.getByLabel("Policy mode", { exact: true })).toContainText("Enforce");
  await expect(page.getByRole("checkbox", { name: "Permit prompt content capture", exact: false })).toBeChecked();
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 720 });
    await page.getByRole("button", { name: "Save gateway policy", exact: true }).scrollIntoViewIfNeeded();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    expect(await page.evaluate(() => document.scrollingElement!.scrollTop)).toBeGreaterThan(0);
    await expect(page.getByRole("button", { name: "Save gateway policy", exact: true })).toBeInViewport();
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  await screenshot(page, "gateway-instance-settings");
});

test("gateway entry points open shared history with the correct gateway filter", async ({ page }) => {
  const { reads } = await mockGateways(page, ["security_analyst"]);
  await page.goto("/gateways/overview");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    if (width < 1024) await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    const nav = page.getByRole("navigation", { name: "Workspace navigation" });
    await expect(nav.locator('a[href="/gateways/overview"]')).toHaveCount(1);
    await expect(nav.locator('a[href="/gateways/instances"]')).toHaveCount(0);
    await expect(nav.getByRole("link", { name: "Requests", exact: true })).toHaveCount(0);
    if (width < 1024) await page.keyboard.press("Escape");
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("link", { name: "View requests", exact: true }).click();
  await expect(page).toHaveURL("/guardrail/history?source=gateways");
  await expect(page.getByRole("heading", { name: "Guardrail History", exact: true })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Gateway", exact: true })).toHaveText("All");
  await page.goto("/gateways/instances/gateway-a");
  await page.getByRole("link", { name: "View requests", exact: true }).click();
  await expect(page).toHaveURL("/guardrail/history?source=gateways&gateway_id=gateway-a");
  await expect(page.getByRole("combobox", { name: "Gateway", exact: true })).toHaveText("Production Kong");
  await expect.poll(() => reads.some((url) => url.pathname.endsWith("/requests") && url.searchParams.get("gateway_id") === "gateway-a")).toBe(true);
  const history = page.getByRole("navigation", { name: "Workspace navigation" }).getByRole("link", { name: "Guardrail History", exact: true });
  await expect(history).toHaveAttribute("aria-current", "page");
  await history.click();
  await expect(page).toHaveURL("/guardrail/history");
  await expect(page.getByRole("combobox", { name: "Source", exact: true })).toHaveText("All");
  await page.goBack();
  await expect(page.getByRole("combobox", { name: "Source", exact: true })).toHaveText("Gateways");
  await expect(page.getByRole("combobox", { name: "Gateway", exact: true })).toHaveText("Production Kong");
});

test("legacy request links preserve filters, pagination, decision distinctions and redacted evidence", async ({ page }) => {
  const { reads, state } = await mockGateways(page, ["security_analyst"]);
  await page.goto("/gateways/requests?gateway_id=gateway-a");
  await expect(page).toHaveURL("/guardrail/history?source=gateways&gateway_id=gateway-a");
  await expect(page.getByRole("combobox", { name: "Source", exact: true })).toHaveText("Gateways");
  await expect(page.getByRole("combobox", { name: "Gateway", exact: true })).toContainText("Production Kong");
  const first = page.getByRole("row").filter({ has: page.getByRole("link", { name: "Production Kong", exact: true }) });
  await expect(first).toContainText("Would deny");
  await expect(first).toContainText("Allow");
  await expect(first).toContainText("Unconfirmed");
  await expect(first).toContainText("Guardrail");
  await expect(first).not.toContainText("Jev");
  await page.getByLabel("Requested model", { exact: true }).fill("requested-model");
  await page.getByLabel("Route ID", { exact: true }).fill("chat-route");
  await page.getByRole("combobox", { name: "Outcome", exact: true }).click();
  await page.getByRole("option", { name: "Unconfirmed", exact: true }).click();
  await page.getByRole("button", { name: "Apply filters", exact: true }).click();
  await expect.poll(() => reads.some((url) => url.searchParams.get("model") === "requested-model" && url.searchParams.get("route_id") === "chat-route" && url.searchParams.get("outcome") === "unconfirmed" && url.searchParams.get("gateway_id") === "gateway-a")).toBe(true);
  await page.getByRole("button", { name: "Load more", exact: true }).click();
  await expect(page.getByRole("link", { name: "Last request", exact: true })).toBeVisible();
  await page.setViewportSize({ width: 390, height: 720 });
  const table = page.getByRole("region", { name: "Scrollable data table", exact: true });
  await table.scrollIntoViewIfNeeded();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(390);
  expect(await table.evaluate((node) => node.scrollWidth > node.clientWidth)).toBe(true);
  await table.evaluate((node) => { node.scrollLeft = node.scrollWidth; });
  expect(await table.evaluate((node) => node.scrollLeft)).toBeGreaterThan(0);
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("heading", { name: "Guardrail History", exact: true }).scrollIntoViewIfNeeded();
  await screenshot(page, "gateway-request-history", false);
  await page.getByRole("link", { name: "Production Kong", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Gateway Request", exact: true })).toBeVisible();
  await expect(page.getByText("Configured reason preserves Jev evidence.", { exact: true })).toBeVisible();
  await expect(page.locator("pre").filter({ hasText: "Original Jev evidence" })).toContainText("[REDACTED]");
  await expect(page.locator("dt", { hasText: "Usage and cost" }).locator("..")).toContainText("Unavailable");
  await expect(page.locator("dt", { hasText: "Caller name" }).locator("..")).toContainText("Alice Example");
  await expect(page.locator("dt", { hasText: "Application" }).locator("..")).toContainText("Support assistant");
  await expect(page.getByText("Would deny in Shadow", { exact: true })).toBeVisible();
  await expect(page.getByText("No confirmed enforcement or dispatch outcome", { exact: false })).toBeVisible();
  await screenshot(page, "gateway-request-detail");
  await page.getByRole("link", { name: "All gateway requests", exact: true }).click();
  await expect(page).toHaveURL("/guardrail/history?source=gateways");
  await expect(page.getByRole("combobox", { name: "Gateway", exact: true })).toHaveText("All");
  await page.goto("/gateways/requests/request-last");
  await expect(page.getByText("No content assessment is available.", { exact: false })).toBeVisible();
  await expect(page.getByText("Provider completion is not confirmed.", { exact: false })).toBeVisible();
  state.emptyRequests = true;
  await page.goto("/gateways/requests");
  await expect(page).toHaveURL("/guardrail/history?source=gateways");
  await expect(page.getByText("No matching gateway requests", { exact: true })).toBeVisible();
});

test("History filters one chart set with shared ranges, retaining gateway links", async ({ page }, info) => {
  const errors: string[] = [];
  page.on("pageerror", (error) => errors.push(error.message));
  const { reads } = await mockGateways(page, ["security_analyst"]);
  const statistics: URL[] = [];
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.pathname.endsWith("guardrail/stats")) statistics.push(url);
  });
  await page.goto("/guardrail/history");
  const source = page.getByRole("combobox", { name: "Source", exact: true });
  const metrics = page.getByRole("region", { name: "Guardrail metrics over time", exact: true });
  await expect(source).toHaveText("All");
  await expect(metrics.getByRole("region")).toHaveCount(4);
  await expect(page.getByRole("tab", { name: /Endpoints|Gateways/ })).toHaveCount(0);
  await expect(metrics.getByTestId("stat-total")).toHaveText("336");
  await expect(metrics.getByTestId("stat-latency")).toHaveText("180 ms");
  await expect(metrics.getByTestId("stat-failure")).toHaveText("8.0%");
  await expect(metrics.getByText("48 failures / 600 recorded attempts", { exact: true })).toBeVisible();
  await expect(metrics.getByText("48 Not evaluated · 24 Pending or unconfirmed", { exact: true })).toBeVisible();
  await expect(metrics.getByText("Hook failure rate", { exact: true })).toHaveCount(0);
  await expect(metrics.getByText("Policy unavailable rate", { exact: true })).toHaveCount(0);
  await expect(metrics.getByRole("heading", { name: "Failure rate", exact: true })).toHaveAttribute("title", /did not return a valid decision in time/);
  await expect(page.getByText("Charts cover all selected sources. Request ledger filters apply only to the ledger.")).toBeVisible();
  await expect.poll(() => statistics.at(-1)?.searchParams.get("view")).toBe("unified");
  expect(await page.locator("[id]").evaluateAll((nodes) => {
    const ids = nodes.map((node) => node.id);
    return ids.filter((id, i) => ids.indexOf(id) !== i);
  })).toEqual([]);
  for (const width of [1600, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(0);
    for (const name of ["stat-total", "stat-latency", "stat-failure"]) {
      const latency = metrics.getByTestId(name);
      await latency.scrollIntoViewIfNeeded();
      await expect(latency).toBeVisible();
    }
    await page.getByRole("heading", { name: "Guardrail History", exact: true }).scrollIntoViewIfNeeded();
    await source.scrollIntoViewIfNeeded();
    await expect(source).toBeVisible();
  }
  await page.setViewportSize({ width: 1600, height: 1080 });
  await page.getByRole("radio", { name: "Last 7 days", exact: true }).check();
  await expect.poll(() => statistics.at(-1)?.searchParams.get("range")).toBe("7d");
  await expect.poll(() => reads.some((url) => url.pathname.endsWith("/requests") &&
    Date.parse(url.searchParams.get("until") || "") - Date.parse(url.searchParams.get("since") || "") === 7 * 86400000)).toBe(true);
  await page.getByText("Time and node filters", { exact: true }).click();
  await page.getByLabel("Start time (local)", { exact: true }).fill("2026-08-01T00:00");
  await page.getByLabel("End time (local)", { exact: true }).fill("2026-08-31T00:00");
  await page.getByRole("button", { name: "Apply filters", exact: true }).click();
  await expect.poll(() => reads.some((url) => url.pathname.endsWith("/requests") &&
    url.searchParams.get("since")?.startsWith("2026-08-01") && url.searchParams.get("until")?.startsWith("2026-08-31"))).toBe(true);
  await expect(page.getByRole("radio", { name: "Last 7 days", exact: true })).toBeChecked();
  await page.getByRole("button", { name: "Clear filters", exact: true }).click();
  await expect.poll(() => {
    const query = reads.filter((url) => url.pathname.endsWith("/requests")).at(-1)!.searchParams;
    return Date.parse(query.get("until") || "") - Date.parse(query.get("since") || "");
  }).toBe(7 * 86400000);
  await source.click();
  await page.getByRole("option", { name: "Gateways", exact: true }).click();
  await expect(page).toHaveURL("/guardrail/history?source=gateways");
  await expect(metrics.getByRole("region")).toHaveCount(4);
  await expect(metrics.getByTestId("stat-latency")).toHaveText("160 ms");
  await expect(metrics.getByTestId("stat-deny")).toHaveText("25%");
  await expect(metrics.getByTestId("stat-failure")).toHaveText("20%");
  await expect(page.getByRole("radio", { name: "Last 7 days", exact: true })).toBeChecked();
  await expect.poll(() => statistics.at(-1)?.searchParams.get("source")).toBe("gateways");
  await page.reload();
  await expect(source).toHaveText("Gateways");
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toHaveAttribute("href", "/gateways/requests/request-a");
  await source.click();
  await page.getByRole("option", { name: "Endpoints", exact: true }).click();
  await expect(metrics.getByTestId("stat-latency")).toHaveText("200 ms");
  await expect(metrics.getByRole("region")).toHaveCount(4);
  await expect(page.getByRole("heading", { name: "Gateway request ledger", exact: true })).toHaveCount(0);
  await source.click();
  await page.getByRole("option", { name: "All", exact: true }).click();
  await expect(metrics.getByTestId("stat-failure")).toHaveText("8.0%");
  await page.screenshot({ path: info.outputPath("guardrail-history-unified.png"), fullPage: true, animations: "disabled" });
  await page.setViewportSize({ width: 1600, height: 1500 });
  await page.getByRole("heading", { name: "Guardrail History", exact: true }).scrollIntoViewIfNeeded();
  await screenshot(page, "guardrail-history-unified", false);
  expect(errors).toEqual([]);
});

test("History collapses an empty source and rejects incompatible legacy metrics", async ({ page }) => {
  await mockGateways(page, ["security_analyst"]);
  await page.setViewportSize({ width: 1600, height: 1080 });
  const counts = { total: 12, allow: 10, warn: 0, ask: 0, deny: 2, legacy: 0,
    e2e_p50: 220, e2e_p95: 440, e2e_p99: 660, policy_p50: 80, policy_p95: 120, policy_p99: 160 };
  const data = { source: "endpoints", range: "24h", since: "2026-10-11T11:00:00Z", until: time,
    bucket_seconds: 3600, totals: counts, executions: { total: 15, failed: 3 },
    series: [{ ...counts, start: "2026-10-11T11:00:00Z", executions: { total: 15, failed: 3 } }],
    rules: [{ ...counts, rule_id: "", rule_name: "", action: "allow", in_policy: false, last_seen_at: time }] };
  let legacy = false;
  await page.route("**/api/v1/guardrail/stats?**", (route) => route.fulfill({ json: legacy ? data : historyFixture(data, "all") }));
  await page.goto("/guardrail/history?source=all");
  await expect(page.getByTestId("stat-total")).toHaveText("12");
  await expect(page.getByTestId("stat-failure")).toHaveText("20%");
  await expect(page.getByRole("region", { name: "Guardrail metrics over time" }).getByRole("region")).toHaveCount(4);
  await expect(page.getByText("No gateway data in this range.", { exact: true })).toBeVisible();
  await expect(page.getByRole("region", { name: "Gateway history", exact: true })).toHaveCount(0);
  await screenshot(page, "guardrail-history-empty-gateway", false);
  legacy = true;
  await page.getByRole("button", { name: "Refresh guardrail statistics" }).click();
  await expect(page.locator("main").getByRole("alert")).toContainText("Statistics are unavailable for the selected source.");
  await expect(page.getByTestId("stat-total")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toBeVisible();
});

test("History keeps missing gateway metrics explicit and the ledger accessible during an outage", async ({ page }) => {
  await mockGateways(page, ["security_analyst"]);
  let failed = true;
  const counts = { total: 0, allow: 0, warn: 0, ask: 0, deny: 0,
    e2e_p50: null, e2e_p95: null, e2e_p99: null, policy_p50: null, policy_p95: null, policy_p99: null };
  await page.route("**/api/v1/guardrail/stats?**", (route) => failed
    ? route.fulfill({ status: 503, json: { error: "Statistics unavailable" } })
    : route.fulfill({ json: historyFixture({ source: "gateways", range: "24h", since: "2026-10-11T11:00:00Z", until: time,
      bucket_seconds: 3600, totals: { ...counts, legacy: 0 }, availability: { total: 0, unavailable: 0 },
      series: [{ ...counts, start: "2026-10-11T11:00:00Z", availability: { total: 0, unavailable: 0 } }], rules: [] }, "gateways") }));
  await page.goto("/guardrail/history?source=gateways");
  await expect(page.locator("main").getByRole("alert")).toContainText("Statistics unavailable");
  await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toBeVisible();
  await expect(page.getByTestId("stat-total")).toHaveCount(0);
  failed = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(page.getByTestId("stat-allow")).toHaveText("No data");
  await expect(page.getByTestId("stat-latency")).toHaveText("No samples");
  await expect(page.getByTestId("stat-failure")).toHaveText("Not recorded");
  await expect(page.getByRole("application")).toHaveCount(0);
});

test("Evidence source tabs preserve gateway evidence links", async ({ page }) => {
  await mockGateways(page, ["security_analyst"]);
  for (const destination of ["/evidence"]) {
    await page.goto(destination);
    await expect(page.getByRole("tab", { name: "Endpoints", exact: true })).toHaveAttribute("aria-selected", "true");
    await page.getByRole("tab", { name: "Gateways", exact: true }).click();
    await expect(page).toHaveURL(`${destination}?source=gateways`);
    await page.reload();
    await expect(page.getByRole("tab", { name: "Gateways", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("heading", { name: "Gateway request ledger", exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Production Kong", exact: true })).toHaveAttribute("href", "/gateways/requests/request-a");
    await page.getByRole("tab", { name: "Endpoints", exact: true }).click();
    await expect(page).toHaveURL(`${destination}?source=endpoints`);
    await page.reload();
    await expect(page.getByRole("tab", { name: "Endpoints", exact: true })).toHaveAttribute("aria-selected", "true");
    await expect(page.getByRole("heading", { name: "Gateway request ledger", exact: true })).toHaveCount(0);
  }
});
