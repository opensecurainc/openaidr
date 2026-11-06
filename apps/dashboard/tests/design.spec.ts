import { activityFixture } from "./fixtures/activity-flow";
import { creditFixture } from "./fixtures/credits";
import { mkdir } from "node:fs/promises";
import { emptyRiskCases } from "./fixtures/risk-cases";
import { test, expect, type Page } from "@playwright/test";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { TimeZoneProvider, useTimeZone } from "../src/components/time-zone-context";
import { navigation, type NavigationPage } from "../src/lib/navigation";
import { desktopInstallCommand } from "../src/lib/install-command";
import { mockClipboard } from "./fixtures/clipboard";
import { historyFixture } from "./fixtures/guardrail-history";
import type { GuardrailStats } from "../src/lib/guardrail";

const now = Date.UTC(2026, 9, 1, 12);
const stamp = (hours = 0) => new Date(now - hours * 3600000).toISOString();
const user = {
  id: "u",
  name: "Design reviewer",
  email: "review@example.invalid",
  roles: ["it_admin", "security_analyst", "security_leadership"],
  tenant: { id: "t", name: "Synthetic design review", slug: "design" },
};
const finding = {
  id: "f",
  title: "Unusual command execution",
  severity: "high",
  status: "open",
  rule_name: "Command review",
  category: "destructive_command",
  created_at: stamp(),
  host: { hostname: "review-workstation", user: "reviewer" },
  account: "review@example.invalid",
};
const exported = {
  id: "x",
  batch_id: "b",
  sensor_id: "s",
  hostname: "review-workstation",
  signal: "logs",
  record_count: 4,
  service_names: ["review-agent"],
  received_at: stamp(),
  demo: true,
};
const device = {
  id: "s",
  label: "Review workstation",
  hostname: "review-workstation",
  os: "linux",
  arch: "amd64",
  status: "online",
  sensor_version: "1.0",
  last_heartbeat_at: stamp(),
  latest_export_at: stamp(),
  exports: 1,
  log_records: 4,
  metric_points: 2,
  spans: 1,
  telemetry_queue_depth: 0,
};
const telemetry = {
  range: "24h",
  generated_at: stamp(),
  window_start: stamp(24),
  bucket_seconds: 3600,
  summary: {
    exports: 1,
    records: 7,
    log_records: 4,
    metric_points: 2,
    spans: 1,
    devices: 1,
    online_devices: 1,
    offline_devices: 0,
    disabled_devices: 0,
    last_export_at: stamp(),
  },
  activity: Array.from({ length: 25 }, (_, i) => ({
    start: stamp(24 - i),
    exports: 1,
    log_records: (i % 4) * 2,
    metric_points: i % 3,
    spans: i % 2,
  })),
  available_services: ["review-agent"],
  services: [
    {
      name: "review-agent",
      exports: 1,
      log_records: 4,
      metric_points: 2,
      spans: 1,
      last_export_at: stamp(),
    },
  ],
  devices: [device],
  recent_exports: [exported],
};
const total = {
  cost_usd: 0.01101408,
  calls: 2,
  priced_calls: 2,
  unpriced_calls: 0,
  reported_calls: 2,
  calculated_calls: 0,
  demo_calls: 0,
  tokens: 262240,
  usage_calls: 2,
  pending_calls: 0,
  failed_calls: 0,
  input_tokens: 260000,
  output_tokens: 2240,
};
const costs = {
  range: "24h",
  since: stamp(24),
  until: stamp(),
  price_date: "2026-10-01",
  bucket_seconds: 3600,
  summary: total,
  series: Array.from({ length: 25 }, (_, i) => ({
    ...total,
    time: stamp(24 - i),
    cost_usd: i === 24 ? total.cost_usd : 0,
    calls: i === 24 ? 2 : 0,
  })),
  available_filters: {
    user: ["reviewer"],
    model: ["review-model"],
    project: ["review"],
    activity: ["coding"],
    reasoning_effort: ["high"],
  },
  filters_truncated: {
    user: false,
    model: false,
    project: false,
    activity: false,
    reasoning_effort: false,
  },
  pagination: Object.fromEntries(
    ["user", "model", "project", "activity", "reasoning_effort"].map((dimension) => [
      dimension,
      {
        offset: 0,
        limit: 50,
        total: 1,
        maximum: total.cost_usd,
        sort: "cost_usd",
        order: "desc",
      },
    ]),
  ),
  by_user: [{ ...total, name: "reviewer" }],
  by_model: [{ ...total, name: "review-model" }],
  by_project: [{ ...total, name: "review" }],
  by_activity: [{ ...total, name: "coding" }],
  by_reasoning_effort: [{ ...total, name: "high" }],
  by_purpose: [{ ...total, name: "detection" }],
};
const policy = {
  version: 1,
  updated_at: stamp(),
  rules: [
    {
      id: "p",
      name: "Review sensitive commands",
      enabled: true,
      action: "warn",
      reason: "Review commands affecting sensitive files.",
      match: { kinds: ["command"] },
    },
  ],
};
const app = {
  id: "a",
  sensor_id: "s",
  hostname: "review-workstation",
  os: "linux",
  source: "linux-dpkg",
  identifier: "review-agent",
  name: "Review agent",
  version: "1.0",
  path: "/opt/review-agent",
  publisher: "Example",
  architecture: "amd64",
  kind: "package",
  scope: "system",
  last_seen_at: stamp(),
  category: "ai",
};
const databaseHealth = {
  ok: true,
  checked_at: stamp(),
  latency_ms: 2,
  pools: [
    { name: "data", size: 4, available: 3, maximum: 16, waiting: 0 },
    { name: "auth", size: 1, available: 1, maximum: 4, waiting: 0 },
  ],
  activity: {
    active_queries: 1,
    long_running_queries: 0,
    lock_waits: 0,
    idle_transactions: 0,
    oldest_query_seconds: 0.5,
    oldest_transaction_seconds: 0.5,
    untracked_sessions: 0,
  },
};
const responses: Record<string, unknown> = {
  "gateways/overview": {
    window_hours: 24,
    gateways: { total: 0, reporting: 0, stale: 0, never_seen: 0, disabled: 0 },
    requests: { total: 0, evaluated: 0, unavailable: 0, allowed: 0, denied: 0, would_deny: 0, blocked: 0, fail_open: 0, forwarded: 0, unconfirmed: 0 },
    policy_latency_ms: { p50: null, p95: null }, coverage: "observed_only",
  },
  "guardrail/active": {
    since: stamp(5 / 60), until: stamp(), users: 2, sessions: 3, prompts: 4,
    tool_calls: 9, tool_results: 7, decisions: 9, allow: 6, warn: 1, ask: 0, deny: 2,
    labels: [{ category: "supply_chain", level: "medium", count: 1 }],
  },
  "guardrail/stats": {
    range: "24h", since: stamp(24), until: stamp(), bucket_seconds: 3600,
    totals: { total: 90, allow: 58, warn: 8, ask: 0, deny: 24, legacy: 0, e2e_p50: 210, e2e_p95: 340, e2e_p99: 420, policy_p50: 0.6, policy_p95: 1.1, policy_p99: 1.8 },
    series: Array.from({ length: 24 }, (_, i) => ({
      start: stamp(24 - i), total: 4, allow: 3, warn: 0, ask: 0, deny: 1, e2e_p50: 210, e2e_p95: 340, e2e_p99: 420, policy_p50: 0.6, policy_p95: 1.1, policy_p99: 1.8,
    })),
    rules: [
      { rule_id: "", rule_name: "", action: "allow", in_policy: false, total: 58, allow: 58, warn: 0, ask: 0, deny: 0, last_seen_at: stamp(1), e2e_p50: 210, e2e_p95: 340, e2e_p99: 420, policy_p50: 0.6, policy_p95: 1.1, policy_p99: 1.8 },
      { rule_id: "pipe", rule_name: "Block piping downloads into a shell", action: "deny", in_policy: true, total: 24, allow: 0, warn: 0, ask: 0, deny: 24, last_seen_at: stamp(2), e2e_p50: 210, e2e_p95: 340, e2e_p99: 420, policy_p50: 0.6, policy_p95: 1.1, policy_p99: 1.8 },
    ],
  },
  "auth/me": { user },
  "auth/config": { mode: "local", password_login: true },
  "settings/model-keys": {
    routing: { mode: "intelligence", origin: "https://api.opensecura.ai", version: 0,
      credential_configured: true, trust: "system", capability_status: "unverified",
      environments: [{ origin: "https://api.opensecura.ai", label: "Production", credential_configured: true }] },
  },
  "settings/support": { slack_channel_url: "", version: 0, updated_at: null },
  "settings/slack": {
    enabled: false, configured: false, available: false, version: 0,
    delivery: { pending: 0, failed: 0, last_sent_at: null },
  },
  "settings/summary-reports": {
    automatic: false, available: false, version: 0, destination: null, next_report_at: null,
    delivery: { pending: 0, failed: 0, last_sent_at: null },
  },
  "settings/session-detection": {
    enabled: true, version: 0, max_cost_usd_per_attempt: "2", hourly_cost_usd: "10", availability: { reason: "ready" },
  },
  "response/company-policy": { revision: 0, prompt: "", updated_at: null },
  "knowledge/mcp": { connections: [] },
  "knowledge/library": { enabled: false, revision: 1, documents: [], retrieval_mode: "legacy", sources: [] },
  "telemetry/overview": telemetry,
  "sensors/health": { items: [{ ...device, version: device.sensor_version }] },
  overview: {
    range: "30d",
    agents: { total: 1, active: 1 },
    sessions: 1,
    sensors: { total: 1, online: 1, disabled: 0, offline: 0 },
    findings_open: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    by_category: [{ category: "destructive_command", count: 1 }],
    recent_findings: [finding],
    timeline: Array.from({ length: 31 }, (_, i) => ({
      bucket: stamp((30 - i) * 24),
      events: 0,
      findings: i === 30 ? 1 : 0,
    })),
  },
  findings: { items: [finding], next_cursor: "" },
  "user-risk": { total_findings: 1, items: [{
    user: "reviewer", hosts: ["review-workstation"], accounts: [], total: 1, openTotal: 1,
    open: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
  }] },
  "events/live": { items: [], cursor: "", more: false },
  events: {
    items: [
      {
        id: "e",
        time: stamp(),
        kind: "command",
        command: { text: "echo review" },
        agent: { product: "review-agent" },
        host: { hostname: "review-workstation", user: "reviewer" },
      },
    ],
    next_cursor: "",
  },
  "telemetry/exports": { items: [exported], next_cursor: "" },
  "telemetry/exports/x": {
    ...exported,
    payload_sha256: "123abc",
    total_record_count: 1,
    records: [
      {
        kind: "log",
        time: stamp(),
        event_name: "command",
        service: "review-agent",
        attributes: { synthetic: true },
      },
    ],
    payload: { synthetic: true },
  },
  agents: {
    items: [
      {
        id: "a",
        product: "review-agent",
        version: "1.0",
        host: finding.host,
        models: ["review-model"],
        status: "active",
        last_seen: stamp(),
      },
    ],
    next_cursor: "",
  },
  "inventory/skills": {
    enabled: true, items: [{ id: "skill", name: "review-skill", installations: 1, devices: 1,
      last_seen_at: stamp(), needs_attention: true, scan_status: "complete", risk_score: 75,
      scopes: ["user"], collection_incomplete: false, approval_status: "monitoring", approval_updated_at: null }], next_cursor: "", total: 1,
    summary: { installed: 1, installations: 1, attention: 1, assessed: 1, pending: 0, incomplete: 0 },
  },
  "inventory/attention-history": { timezone: "UTC", scope: "tenant", checks_enabled: true,
    days: Array.from({ length: 30 }, (_, index) => ({ date: stamp((29 - index) * 24).slice(0, 10), captured_at: null, categories: null })) },
  "inventory/roots": { items: [], next_cursor: "" },
  "inventory/applications": { items: [app], next_cursor: "" },
  "inventory/categories": { categories: { ai: 1, user: 0, system: 0 } },
  "inventory/sources": {
    items: [
      {
        sensor_id: "s",
        hostname: "review-workstation",
        os: "linux",
        source: "linux-dpkg",
        status: "ok",
        message: "",
        collected_at: stamp(),
        last_success_at: stamp(),
        application_count: 1,
      },
    ],
  },
  "detections/rules": {
    items: [
      {
        id: "r",
        name: "Command review",
        description: "Review unusual commands.",
        enabled: true,
        severity: "high",
        findings_30d: 1,
      },
    ],
  },
  "response/policy": policy,
  "costs/agents/summary": costs,
  credits: creditFixture("24h", "t", now),
  audit: {
    items: [
      {
        id: "au",
        at: stamp(),
        actor: { id: "u", name: "Design reviewer" },
        action: "policy.updated",
        target_type: "policy",
        target_id: "p",
        details: {},
      },
    ],
    next_cursor: "",
  },
  users: {
    items: [
      {
        ...user,
        status: "active",
        created_at: stamp(24),
        last_login_at: stamp(),
      },
    ],
  },
  "inventory/application-review": {
    device_count: 3,
    users: [{ user: "alice", device_count: 3 }],
    classifier_configured: true,
    generated_at: stamp(),
    items: ["Claude Code", "Codex CLI"].map((name, index) => ({
      id: name.toLowerCase().replaceAll(" ", "-"),
      name,
      device_count: 3,
      users: [{ user: "alice", device_count: 3 }],
      needs_attention: true,
      category: "coding_agent",
      classification_status: "complete",
      reason: "Public product documentation identifies a coding agent.",
      sources: [],
      checked_at: stamp(),
      approval_status: index ? "monitoring" : "approved",
      approval_updated_at: null,
    })),
  },
  "system/status": {
    version: "review",
    services: [
      { name: "ingest", status: "ok", last_seen_at: stamp() },
      { name: "api", status: "ok", last_seen_at: stamp() },
      { name: "detect", status: "ok", last_seen_at: stamp(), lag_events: 0, last_run_at: stamp() },
      { name: "admin", status: "unknown", last_seen_at: null },
    ],
    database: { ok: true, latency_ms: 2 },
    ingest: { sensors_online: 1, events_last_hour: 1 },
  },
  "system/database": databaseHealth,
  "system/metrics": {
    status: "ok",
    message: "",
    hostname: "review-host",
    interval_seconds: 60,
    last_sample_at: stamp(),
    samples: Array.from({ length: 5 }, (_, i) => ({
      time: stamp(4 - i),
      cpu_percent: 25,
      memory_percent: 50,
      disk_percent: 60,
      disk_read_bytes_per_second: i * 1024,
      disk_write_bytes_per_second: i * 512,
    })),
  },
  "sensors/s/metrics": {
    sensor_id: device.id,
    range: "24h",
    generated_at: stamp(),
    window_start: stamp(24),
    bucket_seconds: 300,
    latest: {
      last_heartbeat_at: stamp(),
      status: "online",
      cpu_percent: 1.5,
      memory_rss_bytes: 48 * 1024 ** 2,
    },
    samples: [],
  },
  "sensors/enrollment-tokens": {
    items: [
      {
        id: "token",
        label: "Review enrollment",
        created_at: stamp(),
        expires_at: "2027-01-01T00:00:00Z",
        uses: 0,
        max_uses: 1,
        revoked_at: null,
      },
    ],
  },
};

async function mockApi(
  page: Page,
  options: { failures?: Set<string>; empty?: boolean; roles?: string[] } = {},
) {
  await page.clock.setFixedTime(new Date(now));
  await page.route("**/api/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const key = url.pathname.replace("/api/v1/", "");
    if (key === "costs/hook-estimates") return route.fulfill({ json: { range: url.searchParams.get("range") || "30d", items: [] } });
    if (key === "risk-cases") return route.fulfill({ json: emptyRiskCases() });
    if (key === "detections/pipeline") return route.fulfill({ json: {
      range: new URL(route.request().url()).searchParams.get("range") || "30d", since: now, until: now,
      actions_scored: 4, sessions_scored: 2, sessions_inspected: 1, sessions_with_alerts: 0,
      alerts: 0, sessions_eligible: 0, sessions_escalated: 0,
      availability: { tenant_enabled: true, scheduling_enabled: true, worker_ready: true, reason: "ready", checked_at: now },
    } });
    if (key === "detections/rankings") return route.fulfill({ json: {
      group: new URL(route.request().url()).searchParams.get("group") || "sessions", band: "all", selection_policy: "legacy", items: [], next_cursor: "",
    } });
    if (key === "response/hook-settings") return route.fulfill({ json: { mode: "shadow", version: 0, updated_at: null } });
    if (key === "response/session-detection") return route.fulfill({ json: { enabled: false, version: 1, detector_config_version: 2, selection_policy: "legacy", model: "gpt-6.1-sol" } });
    if (options.failures?.has(key))
      return route.fulfill({
        status: 503,
        json: { error: { message: "Synthetic refresh failure" } },
      });
    if (key === "overview/summary") {
      const summary = {
        generated_at: stamp(),
        items: [{ topic: "Coverage", text: "Review device coverage.", detail: "Telemetry records show one device.", tone: "info", citations: ["telemetry"] }],
        sources: [{ id: "telemetry", path: "/telemetry", title: "Telemetry", scope: "Tenant", captured_at: stamp(), status: "available", facts: { devices: 1 } }],
      };
      return route.fulfill({ json: route.request().method() === "GET" ? { summary, stale: false } : summary });
    }
    if (key === "guardrail/flow") return route.fulfill({ json: activityFixture(options.empty ? [] : [{
      id: "design-check", created_at: stamp(1 / 60), sensor_id: device.id,
      sensor_hostname: device.hostname, sensor_username: "reviewer", product: "codex-cli",
      session_id: "design-session", hook_event: "PreToolUse", mode: "shadow", status: "evaluated",
      evaluated_decision: "allow", returned_decision: "allow", delivery_status: "unconfirmed",
      assessment: { status: "scored", score: 0, level: "info", category: "none" },
      actions: [{ kind: "command", command: { text: "git status" }, agent: { product: "codex-cli" } }],
    }], new URLSearchParams({ until: stamp(), ...Object.fromEntries(url.searchParams) })).summary });
    const body =
      key === "auth/me"
        ? { user: { ...user, roles: options.roles || user.roles } }
        : key === "guardrail/stats" ? historyFixture(responses[key] as GuardrailStats, "all")
        : responses[key] || { items: [], next_cursor: "" };
    if (options.empty && key !== "auth/me") {
      if (key === "user-risk") return route.fulfill({ json: { items: [], total_findings: 0 } });
      if (key === "response/policy")
        return route.fulfill({ json: { ...policy, rules: [] } });
      if (
        key === "detections/rules" ||
        key === "users" ||
        key === "sensors/enrollment-tokens" ||
        key === "findings" ||
        key === "audit"
      )
        return route.fulfill({ json: { items: [], next_cursor: "" } });
    }
    return route.fulfill({ json: body });
  });
}

test("not-found pages use the dashboard Geist font", async ({ page }) => {
  const response = await page.goto("/font-audit-missing-page");
  expect(response?.status()).toBe(404);
  await expect(page.getByRole("heading", { name: "404", exact: true })).toHaveCSS("font-family", /^GeistSans,/);
  await expect(page.getByText("This page could not be found.", { exact: true })).toHaveCSS("font-family", /^GeistSans,/);
  expect(await page.evaluate(async () => (await document.fonts.load("14px GeistSans")).length)).toBeGreaterThan(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await fits(page);
});

for (const preview of ["company-policy", "guardrail-configuration", "guardrail-configuration-libraries"]) {
  test(`${preview} preview loads Geist Sans and Geist Mono`, async ({ page }) => {
    await page.goto(`/previews/${preview}.html`);
    await expect(page.locator("body")).toHaveCSS("font-family", /^"?Geist Sans"?,/);
    await expect(page.locator("button").first()).toHaveCSS("font-family", /^"?Geist Sans"?,/);
    if (preview === "guardrail-configuration") {
      await expect(page.locator("code").first()).toHaveCSS("font-family", /^"?Geist Mono"?,/);
    }
    if (preview === "guardrail-configuration-libraries") {
      await page.getByRole("button", { name: /OWASP Top 10 for LLM Applications/ }).click();
      await expect(page.locator(".ctrl .id").first()).toHaveCSS("font-family", /^"?Geist Mono"?,/);
    }
    const fonts = await page.evaluate(async () => {
      const faces = await Promise.all([
        document.fonts.load('400 14px "Geist Sans"', "Interface text"),
        document.fonts.load('600 14px "Geist Sans"', "Heading"),
        document.fonts.load('400 14px "Geist Mono"', "/Users/test/project"),
      ]);
      return faces.map(loaded => loaded.length > 0 && loaded.every(face => face.status === "loaded"));
    });
    expect(fonts).toEqual([true, true, true]);
  });
}

test("Markdown code fences share the copy control and scroll without moving it", async ({ page }) => {
  await mockApi(page);
  const text = `printf '%s' '${"日本語 <>& long-value ".repeat(20)}'\n`;
  await page.route("**/api/v1/chat", route => route.fulfill({ json: { answer: `Run this command:\n\n\`\`\`sh\n${text}\`\`\`` } }));
  await page.goto("/ai-skills");
  await mockClipboard(page);
  await page.getByRole("button", { name: "Ask about this page" }).click();
  await page.getByLabel("Your question", { exact: true }).fill("Show the command");
  await page.getByRole("button", { name: "Send", exact: true }).click();
  const block = page.getByRole("log").locator('[data-slot="code-block"]');
  const copy = block.getByRole("button", { name: "Copy text", exact: true });
  await expect(copy).toBeVisible();
  await expect(block.locator("pre")).toHaveCSS("font-family", /^GeistMono,/);
  await expect(copy).toHaveCSS("font-family", /^GeistSans,/);
  expect(await page.evaluate(async () => (await document.fonts.load("14px GeistMono")).length)).toBeGreaterThan(0);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 900 });
    const pre = block.locator("pre");
    expect(await pre.evaluate(node => node.scrollWidth > node.clientWidth)).toBe(true);
    await pre.evaluate(node => { node.scrollLeft = node.scrollWidth; });
    await copy.focus();
    await page.keyboard.press("Space");
    await expect(copy).toHaveAttribute("title", "Copied");
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(text);
    expect(await page.getByRole("log").evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
  }
});

test("App Health uses the app URL and redirects legacy bookmarks", async ({ page }, info) => {
  await mockApi(page);
  const requests: string[] = [];
  page.on("request", request => requests.push(new URL(request.url()).pathname));
  for (const path of ["/administration/app", "/administration/sensors", "/devices"]) {
    await page.goto(path, { waitUntil: "commit" });
    await page.waitForURL(/\/administration\/app$/);
    await expect(page).toHaveTitle("OpenAIDR");
    await expect(page).toHaveURL(/\/administration\/app$/);
    await expect(page.getByRole("heading", { name: "App Health", exact: true })).toBeVisible();
    const link = page.getByRole("link", { name: "App Health", exact: true });
    await expect(link).toHaveAttribute("href", "/administration/app");
    await expect(link).toHaveAttribute("aria-current", "page");
    await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("App Health");
    await expect(page.getByRole("combobox", { name: "Service filter" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Refresh apps", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Telemetry activity", exact: true })).toBeVisible();
  }
  expect(requests).toContain("/api/v1/telemetry/overview");
  expect(requests).toContain("/api/v1/sensors/health");
  await page.goto("/administration/users");
  await page.getByRole("link", { name: "App Health", exact: true }).click();
  await expect(page).toHaveURL(/\/administration\/app$/);
  await fits(page);
  await page.screenshot({ path: info.outputPath("app-health-route.png"), fullPage: true, animations: "disabled" });
});

test("App Health and legacy bookmarks restrict nonadministrative roles before loading data", async ({ page }) => {
  await mockApi(page, { roles: ["security_leadership"] });
  const protectedRequests: string[] = [];
  page.on("request", request => {
    const path = new URL(request.url()).pathname;
    if (path.startsWith("/api/v1/sensors/") || path === "/api/v1/telemetry/overview" || path === "/api/v1/audit/page-views") {
      protectedRequests.push(path);
    }
  });
  for (const path of ["/administration/app", "/administration/sensors", "/devices"]) {
    await page.goto(path, { waitUntil: "commit" });
    await page.waitForLoadState("domcontentloaded");
    await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "App Health", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: "Refresh apps", exact: true })).toHaveCount(0);
  }
  expect(protectedRequests).toEqual([]);
});

for (const role of ["it_admin", "security_leadership"]) {
  test(`OpenAIDR costs use the canonical URL and redirect legacy bookmarks for ${role}`, async ({ page }) => {
    await mockApi(page, { roles: [role] });
    for (const path of ["/costs/openaidr", "/costs/detections"]) {
      await page.goto(path);
      await expect(page).toHaveURL(/\/costs\/openaidr$/);
      await expect(page.locator("main h1")).toHaveText("Credits & Usage");
      const link = page.getByRole("link", { name: "Credits & Usage", exact: true });
      await expect(link).toHaveAttribute("href", "/costs/openaidr");
      await expect(link).toHaveAttribute("aria-current", "page");
      await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toContainText("Credits & Usage");
      await expect(page.getByRole("heading", { name: "Credit balance", exact: true })).toBeVisible();
    }
  });
}

test("OpenAIDR costs and legacy bookmarks restrict analysts before loading data", async ({ page }) => {
  await mockApi(page, { roles: ["security_analyst"] });
  const costRequests: string[] = [];
  page.on("request", request => {
    const path = new URL(request.url()).pathname;
    if (path === "/api/v1/credits") costRequests.push(path);
  });
  for (const path of ["/costs/openaidr", "/costs/detections"]) {
    await page.goto(path);
    await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
    await expect(page.getByRole("link", { name: "Credits & Usage", exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Credit balance", exact: true })).toHaveCount(0);
  }
  expect(costRequests).toEqual([]);
});

test("slow telemetry refreshes do not overlap and unrelated pages do not poll", async ({ page }) => {
  await mockApi(page);
  await page.clock.install({ time: new Date(now) });
  let requests = 0;
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  await page.route("**/api/v1/telemetry/overview?**", async (route) => {
    requests++;
    if (requests === 1) await held;
    await route.fulfill({ json: telemetry });
  });
  await page.goto("/administration/server");
  await expect(page.getByRole("heading", { name: "Server Health", exact: true })).toBeVisible();
  await page.clock.fastForward(60_000);
  expect(requests).toBe(0);
  await page.getByRole("link", { name: "App Health", exact: true }).click();
  await expect.poll(() => requests).toBe(1);
  await page.clock.fastForward(90_000);
  expect(requests).toBe(1);
  release();
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  const updated = page.getByText(/^Updated .*refreshes every 30s$/);
  const snapshotTime = await updated.textContent();
  await page.clock.fastForward(30_000);
  await expect.poll(() => requests).toBe(2);
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  await expect(updated).toHaveText(snapshotTime!);
  await page.evaluate(() => Object.defineProperty(document, "hidden", { configurable: true, value: true }));
  await page.clock.fastForward(30_000);
  expect(requests).toBe(2);
  await page.evaluate(() => Reflect.deleteProperty(document, "hidden"));
  await page.getByRole("link", { name: "Server Health", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Server Health", exact: true })).toBeVisible();
  await page.clock.fastForward(90_000);
  expect(requests).toBe(2);
});

test("server health keeps complete status details in a compact section", async ({ page }, info) => {
  await mockApi(page, { roles: ["it_admin"] });
  let version = "2026.10.6+8d5b065";
  let databaseOk = true;
  let reported = true;
  await page.route("**/api/v1/system/status", (route) => route.fulfill({ json: {
    version,
    database: { ok: databaseOk, latency_ms: 2 },
    ingest: { sensors_online: 1, events_last_hour: 4 },
    services: [
      { name: "ingest", status: "ok", last_seen_at: reported ? stamp() : null },
      { name: "api", status: "stale", last_seen_at: reported ? stamp(1) : null },
      { name: "detect", status: "ok", last_seen_at: reported ? stamp() : null, lag_events: 0, last_run_at: stamp() },
      { name: "admin", status: "unknown", last_seen_at: null },
    ],
  } }));
  await page.route("**/api/v1/system/database", (route) => route.fulfill({ json: { status: "disabled", message: "Database diagnostics require a dedicated tenant database." } }));
  const heights: number[] = [];
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await page.goto("/administration/server");
    const section = page.getByRole("region", { name: "API health", exact: true });
    await expect(section.getByText(version, { exact: true })).toBeVisible();
    await expect(page.getByRole("region", { name: "Database health", exact: true })).toBeVisible();
    await expect(section.getByRole("listitem").filter({ hasText: "API" })).toContainText("Stale report");
    await expect(section.getByRole("listitem").filter({ hasText: "Admin" })).toContainText("Not reporting");
    const heartbeats = section.locator('dl[aria-label="Last heartbeats"]');
    await expect(heartbeats.locator("time")).toHaveCount(2);
    const shared = heartbeats.locator(`time[datetime="${stamp()}"]`);
    await expect(shared).toHaveCount(1);
    await expect(shared.locator("../..")).toContainText("ingest, detect heartbeat");
    await expect(heartbeats.locator(`time[datetime="${stamp(1)}"]`).locator("../..")).toContainText("API heartbeat");
    await expect(heartbeats).not.toContainText("admin");
    await expect(section).toContainText("0 normalized events pending");
    await expect(section).toContainText("Detection last ran");
    await fits(page);
    heights.push((await section.boundingBox())!.height);
    await section.screenshot({ path: info.outputPath(`server-health-${width}.png`) });
  }
  expect(heights[0]).toBeLessThan(480);
  expect(heights[1]).toBeLessThan(540);
  databaseOk = false;
  version = "";
  reported = false;
  const section = page.getByRole("region", { name: "API health", exact: true });
  await section.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(section.getByText("Not reported", { exact: true })).toBeVisible();
  await expect(section.getByText("Not reporting", { exact: true })).toHaveCount(4);
  await expect(section.locator('dl[aria-label="Last heartbeats"]')).toHaveCount(0);
  const database = page.getByRole("region", { name: "Database health", exact: true });
  await expect(database.getByText("Check failed", { exact: true })).toBeVisible();
  await expect(database.getByText("2 ms round trip", { exact: false })).toHaveCount(0);
});

test("telemetry filter changes discard late responses and failed polls retain data", async ({ page }) => {
  await mockApi(page);
  await page.clock.install({ time: new Date(now) });
  let release!: () => void;
  const held = new Promise<void>((resolve) => { release = resolve; });
  let fail = false;
  let requests = 0;
  await page.route("**/api/v1/telemetry/overview?**", async (route) => {
    requests++;
    const range = new URL(route.request().url()).searchParams.get("range");
    if (fail) return route.fulfill({ status: 503, json: { error: { message: "Query timed out" } } });
    if (range === "24h") await held;
    await route.fulfill({ json: { ...telemetry, range, available_services: [range === "7d" ? "fresh-service" : "late-service"] } });
  });
  await page.goto("/administration/app");
  await expect.poll(() => requests).toBe(1);
  await page.getByRole("combobox", { name: "Time range", exact: true }).click();
  await page.getByRole("option", { name: "Last 7 days", exact: true }).click();
  await expect(page.getByRole("button", { name: "Refresh", exact: true })).toBeEnabled();
  release();
  fail = true;
  await page.clock.fastForward(30_000);
  await expect(page.getByRole("alert").filter({ hasText: "Unable to refresh telemetry" })).toContainText("Showing the last successful response");
  await page.getByRole("combobox", { name: "Service filter" }).click();
  await expect(page.getByRole("option", { name: "fresh-service", exact: true })).toBeVisible();
  await expect(page.getByRole("option", { name: "late-service", exact: true })).toHaveCount(0);
});

async function fits(page: Page) {
  await expect
    .poll(() =>
      page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
    )
    .toBe(true);
}

for (const [timezoneId, locale] of [
  ["America/Los_Angeles", "en-US"],
  ["Asia/Kathmandu", "en-GB"],
] as const) {
  test.describe(`build time in ${timezoneId}`, () => {
    test.use({ timezoneId, locale });

    test("shows the local build date and time without overflowing the header", async ({ page }, info) => {
      const errors: string[] = [];
      page.on("pageerror", (error) => errors.push(error.message));
      await mockApi(page);
      await page.goto("/costs/openaidr");
      const build = page.locator("header [data-slot=build-info]");
      await expect(build).toBeVisible();
      const metadata = (await build.getAttribute("title"))?.match(/^Built (.+), commit ([0-9a-f]{40})$/);
      expect(metadata).toBeTruthy();
      const expected = await page.evaluate((time) => {
        const date = new Intl.DateTimeFormat(undefined, {
          dateStyle: "medium",
          timeStyle: "long",
        }).format(new Date(time));
        return ` · Built ${date}`;
      }, metadata![1]);
      await expect(build).toHaveText(new RegExp(`^OpenAIDR \\d{4}\\.\\d{1,2}\\.\\d{1,2}\\+[0-9a-f]{7,40}`));
      await expect(build).toContainText(expected);
      await page.reload();
      await expect(build).toHaveText(new RegExp(`^OpenAIDR \\d{4}\\.\\d{1,2}\\.\\d{1,2}\\+[0-9a-f]{7,40}`));
      await expect(build).toContainText(expected);
      for (const width of [1440, 640, 390]) {
        await page.setViewportSize({ width, height: 900 });
        await fits(page);
        if (width >= 1280) {
          await expect(build).toBeVisible();
          const breadcrumb = await page.getByRole("navigation", { name: "Breadcrumb" }).boundingBox();
          const label = await build.boundingBox();
          expect(breadcrumb!.x + breadcrumb!.width).toBeLessThanOrEqual(label!.x);
        } else {
          await expect(build).toBeHidden();
        }
      }
      await page.setViewportSize({ width: 1440, height: 900 });
      await page.locator("header").screenshot({ path: info.outputPath("local-build-time.png") });
      expect(errors).toEqual([]);
    });
  });
}

test("Security Posture is hidden from navigation while policy configuration and direct access remain available", async ({ page }, info) => {
  await mockApi(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await page.goto("/user-risk");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Risky Sessions/Users");
    if (width === 390) {
      await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    }
    const nav = page.getByRole("navigation", { name: "Workspace navigation" });
    await expect(nav.getByRole("link")).toHaveCount(navigation.flatMap<NavigationPage>((group) => group.pages).length);
    await expect(nav.getByRole("link", { name: "Security Posture", exact: true })).toHaveCount(0);
    await expect(nav.locator('a[href="/security-posture"]')).toHaveCount(0);
    await expect(
      nav.getByRole("link", { name: "Overview", exact: true })
        .and(nav.locator('a[href="/"]')),
    ).toBeVisible();
    await expect(nav.getByRole("link", { name: "Risky Sessions/Users", exact: true })).toBeVisible();
    await fits(page);
    await page.screenshot({ path: info.outputPath(`security-posture-hidden-${width}.png`), animations: "disabled" });
    await nav.getByRole("link", { name: "Company Policy and Knowledge", exact: true }).click();
    await expect(page).toHaveURL(/\/company-knowledge$/);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Company Policy and Knowledge");
    if (width === 390) {
      await expect(page.getByRole("dialog", { name: "Workspace navigation" })).toBeHidden();
    }
    await page.goto("/security-posture");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Security Posture");
    await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toHaveText("Detection and ResponseSecurity Posture");
    await expect(page.getByRole("heading", { name: "Prevention policy", exact: true })).toBeVisible();
    await fits(page);
  }
});

test("Audit Logs and App Enrollment appear under Administration in desktop and mobile navigation", async ({ page }, info) => {
  await mockApi(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await page.goto("/administration/users");
    if (width === 390) {
      await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    }
    const nav = page.getByRole("navigation", { name: "Workspace navigation" });
    await expect(nav.getByText("Governance and Compliance", { exact: true })).toHaveCount(0);
    const administration = nav.locator("div").filter({
      has: page.getByText("Administration", { exact: true }),
    });
    await expect(administration.getByRole("link")).toHaveText([
      "App Health", "Server Health", "App Enrollment", "Integrations",
      "Audit Logs", "Users and Roles", "Settings",
    ]);
    const audit = administration.getByRole("link", { name: "Audit Logs", exact: true });
    await expect(audit).toHaveAttribute("href", "/audit-logs");
    await audit.click();
    if (width === 390) {
      await expect(page.getByRole("dialog", { name: "Workspace navigation" })).toBeHidden();
    }
    await expect(page).toHaveURL(/\/audit-logs$/);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Audit Logs");
    await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toHaveText("AdministrationAudit Logs");
    await expect(page.getByRole("cell", { name: "policy.updated", exact: true })).toBeVisible();
    await fits(page);
    if (width === 390) {
      await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    }
    await expect(audit).toHaveAttribute("aria-current", "page");
    await audit.scrollIntoViewIfNeeded();
    await expect(audit).toBeInViewport();
    await page.screenshot({ path: info.outputPath(`audit-navigation-${width}.png`), animations: "disabled" });
    await administration.getByRole("link", { name: "App Enrollment", exact: true }).click();
    await expect(page).toHaveURL(/\/administration\/enrollment$/);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("App Enrollment");
    await expect(page.getByRole("navigation", { name: "Breadcrumb" })).toHaveText("AdministrationApp Enrollment");
    await expect(page.getByText("Create and manage enrollment tokens to connect devices to OpenAIDR.", { exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Enrollment tokens", exact: true })).toBeVisible();
    await expect(page.getByText("Review enrollment", { exact: true })).toBeVisible();
    await fits(page);
    await page.screenshot({ path: info.outputPath(`app-enrollment-${width}.png`), animations: "disabled" });
  }
});

function enrollmentTokens(count: number) {
  return Array.from({ length: count }, (_, index) => ({
    id: `token-${index + 1}`,
    label: `Rollout ${index + 1}`,
    created_at: stamp(index),
    expires_at: "2027-01-01T00:00:00Z",
    uses: 0,
    max_uses: 1,
    revoked_at: null as string | null,
  }));
}

for (const width of [1440, 390]) {
  test(`App Enrollment limits pages to 10 tokens at ${width}px`, async ({ page }, info) => {
    await mockApi(page);
    await page.clock.install({ time: new Date(now) });
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    let tokens = enrollmentTokens(23);
    await page.route("**/api/v1/sensors/enrollment-tokens", route =>
      route.fulfill({ json: { items: tokens } }),
    );
    await page.goto("/administration/enrollment");
    const rows = page.locator("tbody tr");
    const previous = page.getByRole("button", { name: "Previous enrollment page" });
    const next = page.getByRole("button", { name: "Next enrollment page" });
    await expect(rows).toHaveCount(10);
    await expect(page.getByRole("button", { name: "Refresh", exact: true })).toHaveCount(0);
    await expect(rows.first()).toContainText("Rollout 1");
    await expect(rows.last()).toContainText("Rollout 10");
    await expect(page.getByText("1–10 of 23 tokens", { exact: true })).toBeVisible();
    await expect(previous).toBeDisabled();
    await expect(next).toBeEnabled();
    await next.scrollIntoViewIfNeeded();
    await expect(previous).toBeInViewport();
    await expect(next).toBeInViewport();
    await fits(page);
    await page.screenshot({ path: info.outputPath(`enrollment-pagination-${width}.png`), fullPage: true });
    await next.click();
    await expect(rows).toHaveCount(10);
    await expect(rows.first()).toContainText("Rollout 11");
    await expect(rows.last()).toContainText("Rollout 20");
    tokens = tokens.map(token => token.id === "token-11" ? { ...token, uses: 1 } : token);
    await page.clock.fastForward(30_000);
    await expect(rows.first()).toContainText("Exhausted");
    await expect(page.getByText("11–20 of 23 tokens", { exact: true })).toBeVisible();
    await next.click();
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toContainText("Rollout 21");
    await expect(rows.last()).toContainText("Rollout 23");
    await expect(page.getByText("21–23 of 23 tokens", { exact: true })).toBeVisible();
    await expect(next).toBeDisabled();
    await previous.click();
    await expect(rows.first()).toContainText("Rollout 11");
    tokens = tokens.slice(0, 10);
    await page.clock.fastForward(30_000);
    await expect(page.getByText("1–10 of 10 tokens", { exact: true })).toBeVisible();
    await expect(rows).toHaveCount(10);
    await expect(previous).toBeDisabled();
    await expect(next).toBeDisabled();
    tokens = [];
    await page.clock.fastForward(30_000);
    await expect(page.getByText("No enrollment tokens", { exact: true })).toBeVisible();
    await expect(rows).toHaveCount(0);
    await expect(next).toHaveCount(0);
  });
}

test("App Enrollment refreshes on tab return and can retry a failed refresh", async ({ page }) => {
  await mockApi(page);
  await page.clock.install({ time: new Date(now) });
  const tokens = enrollmentTokens(1);
  let requests = 0;
  let fail = false;
  await page.route("**/api/v1/sensors/enrollment-tokens", route => {
    requests++;
    return fail
      ? route.fulfill({ status: 503, json: { detail: "Enrollment temporarily unavailable" } })
      : route.fulfill({ json: { items: tokens } });
  });
  await page.goto("/administration/enrollment");
  const row = page.locator("tbody tr");
  await expect(row).toContainText("Active");
  const initialRequests = requests;
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  tokens[0].uses = 1;
  await page.clock.fastForward(30_000);
  expect(requests).toBe(initialRequests);
  await expect(row).toContainText("Active");
  await page.evaluate(() => {
    Reflect.deleteProperty(document, "hidden");
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect(row).toContainText("Exhausted");
  fail = true;
  await page.clock.fastForward(30_000);
  const error = page.getByRole("region", { name: "Enrollment tokens" }).getByRole("alert");
  await expect(error).toContainText("Showing stale data from the last successful response.");
  await expect(row).toContainText("Exhausted");
  fail = false;
  tokens[0].revoked_at = stamp();
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(row).toContainText("Revoked");
  await expect(error).toHaveCount(0);
  await page.getByRole("link", { name: "Server Health", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Server Health");
  const finalRequests = requests;
  await page.evaluate(() => document.dispatchEvent(new Event("visibilitychange")));
  await page.clock.fastForward(30_000);
  expect(requests).toBe(finalRequests);
});

for (const mode of ["link", "mac", "windows", "linux"] as const) {
for (const mdm of mode === "mac" ? [false, true] : [false]) {
test(`App Enrollment creates through the ${mode} button${mdm ? " in silent MDM mode" : ""}`, async ({ page }, info) => {
  await mockApi(page);
  const link = "https://tenant.example/enroll#token=oaet_" + "a".repeat(43);
  const labels = ["Create enrollment link", "Mac install script", "Win install script", "Lin install script"];
  const buttonName = { link: labels[0], mac: labels[1], windows: labels[2], linux: labels[3] }[mode];
  const platformName = { link: null, mac: "Mac", windows: "Windows", linux: "Linux" }[mode];
  const maxUses = { link: 100, mac: 25, windows: 1, linux: 3 }[mode];
  let tokens = enrollmentTokens(11);
  let creates = 0;
  await page.route("**/api/v1/sensors/enrollment-**", async route => {
    if (route.request().method() === "DELETE") {
      expect(new URL(route.request().url()).pathname).toBe("/api/v1/sensors/enrollment-tokens/token-11");
      tokens = tokens.map(token => token.id === "token-11" ? { ...token, revoked_at: stamp() } : token);
      return route.fulfill({ status: 204 });
    }
    if (route.request().method() === "POST") {
      creates++;
      expect(route.request().postDataJSON()).toEqual({ label: "New rollout", expires_in_hours: 1, max_uses: maxUses });
      const token = { ...tokens[0], id: "new-token", label: "New rollout", max_uses: maxUses };
      tokens = [token, ...tokens];
      return route.fulfill({ status: 201, json: { ...token, enrollment_url: link } });
    }
    return route.fulfill({ json: { items: tokens } });
  });
  await page.goto("/administration/enrollment");
  const section = page.getByRole("region", { name: "Enrollment tokens", exact: true });
  const header = section.locator('[data-slot="card-header"]');
  await expect(header.getByRole("button")).toHaveText(labels);
  let previous = null;
  for (const label of labels) {
    const button = header.getByRole("button", { name: label, exact: true });
    const bounds = (await button.boundingBox())!;
    if (previous) {
      expect(bounds.x).toBeGreaterThan(previous.x + previous.width);
      expect(Math.abs(bounds.y - previous.y)).toBeLessThan(1);
    }
    previous = bounds;
  }
  await header.screenshot({ path: info.outputPath("enrollment-actions-desktop.png") });
  await page.setViewportSize({ width: 390, height: 600 });
  for (const label of labels) {
    const button = header.getByRole("button", { name: label, exact: true });
    await button.scrollIntoViewIfNeeded();
    await expect(button).toBeInViewport();
  }
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await header.screenshot({ path: info.outputPath("enrollment-actions-mobile.png") });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await page.getByRole("button", { name: "Next enrollment page" }).click();
  await page.getByRole("button", { name: "Revoke Rollout 11", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Revoke token", exact: true }).click();
  await expect(page.getByRole("button", { name: "Revoke Rollout 11", exact: true })).toBeDisabled();
  await expect(page.getByText("11–11 of 11 tokens", { exact: true })).toBeVisible();
  const createTitle = platformName ? `Create ${platformName} install script` : "Create enrollment link";
  const entryButton = header.getByRole("button", { name: buttonName, exact: true });
  await entryButton.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: createTitle, exact: true })).toBeVisible();
  if (mode === "mac") {
    const installMode = dialog.getByRole("combobox", { name: "Install mode" });
    await expect(installMode).toHaveText("Interactive");
    if (mdm) {
      await installMode.click();
      await page.getByRole("option", { name: "Silent MDM", exact: true }).click();
      await expect(dialog).toContainText("Run as root or as the logged-in user");
      await expect(dialog).toContainText("A new install needs write access to /Applications");
      await expect(dialog).toContainText("No confirmation dialogs or app window");
    }
  } else {
    await expect(dialog.getByRole("combobox", { name: "Install mode" })).toHaveCount(0);
  }
  await expect(dialog.getByRole("combobox", { name: "Operating system" })).toHaveCount(0);
  await expect(dialog.getByLabel("Label (optional)")).toHaveValue("");
  await expect(dialog.getByRole("combobox", { name: "Expires after" })).toHaveText("1 hour");
  const uses = dialog.getByRole("spinbutton", { name: "Max uses", exact: true });
  await expect(uses).toHaveValue("100");
  await uses.fill("7");
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(creates).toBe(0);
  await entryButton.click();
  await expect(uses).toHaveValue("100");
  if (mdm) {
    const installMode = dialog.getByRole("combobox", { name: "Install mode" });
    await expect(installMode).toHaveText("Interactive");
    await installMode.click();
    await page.getByRole("option", { name: "Silent MDM", exact: true }).click();
  }
  for (const invalid of ["", "0", "-1", "1.5", "2147483648"]) {
    await uses.fill(invalid);
    await dialog.getByRole("button", { name: createTitle, exact: true }).click();
    expect(await uses.evaluate(node => (node as HTMLInputElement).validity.valid)).toBe(false);
    expect(creates).toBe(0);
  }
  await uses.fill(String(maxUses));
  await dialog.getByLabel("Label (optional)").fill("New rollout");
  await dialog.screenshot({ path: info.outputPath("enrollment-max-uses.png") });
  for (const viewport of [{ width: 1280, height: 600 }, { width: 390, height: 400 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => dialog.evaluate(node => node.getBoundingClientRect().height)).toBeLessThanOrEqual(viewport.height - 32);
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    await uses.scrollIntoViewIfNeeded();
    await expect(uses).toBeInViewport();
    const submit = dialog.getByRole("button", { name: createTitle, exact: true });
    await submit.scrollIntoViewIfNeeded();
    await expect(submit).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await page.setViewportSize({ width: 1440, height: 1080 });
  await dialog.getByRole("button", { name: createTitle, exact: true }).click();
  await expect(dialog.getByRole("heading", {
    name: platformName ? `${platformName} install script created` : "Enrollment link created", exact: true,
  })).toBeVisible();
  expect(creates).toBe(1);
  await expect(dialog).toContainText(`allows up to ${maxUses} ${maxUses === 1 ? "enrollment" : "enrollments"}.`);
  await expect(dialog.getByRole("combobox", { name: "Operating system" })).toHaveCount(0);
  await page.evaluate(() => {
    let copied = "";
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText: async (text: string) => { copied = text; }, readText: async () => copied }, configurable: true,
    });
  });
  if (mode === "link") {
    await dialog.getByRole("button", { name: "Copy link", exact: true }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(link);
    await expect(dialog.getByRole("button", { name: /install script/ })).toHaveCount(0);
  } else {
    await expect(dialog.getByRole("button", { name: /install script/ })).toHaveCount(1);
    await dialog.getByRole("button", { name: `Copy ${platformName} install script`, exact: true }).click();
    const copied = dialog.getByRole("button", { name: `${platformName} script copied`, exact: true });
    await expect(copied).toBeVisible();
    const command = desktopInstallCommand(link, new URL(page.url()).origin, mode, mdm ? "mdm" : "interactive")!;
    if (mdm) {
      await expect(dialog).toContainText("Silent MDM installation");
      await expect(dialog).toContainText("Run through MDM as root or as the logged-in user");
      await expect(dialog).not.toContainText("Asks you to confirm the organization");
      expect(command).toContain("--mdm --enrollment-stdin");
    } else {
      expect(command).not.toContain("--mdm");
    }
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(command);
    await dialog.screenshot({ path: info.outputPath(`${mode}-install-script.png`) });
    const asset = { mac: "install-macos.js", windows: "install-windows.ps1", linux: "install-linux.py" }[mode];
    const bootstrap = await page.request.get(`/${asset}`);
    expect(bootstrap.ok()).toBe(true);
    expect(await bootstrap.text()).toContain("https://releases.opensecura.ai/openaidr/");
    expect(await bootstrap.text()).not.toContain(link);
    await page.evaluate(() => Object.defineProperty(navigator, "clipboard", {
      value: { writeText: async () => { throw new Error("Clipboard blocked"); } }, configurable: true,
    }));
    await copied.click();
    await expect(dialog).toContainText("Open View install script to select and copy it");
    await dialog.getByText("View install script", { exact: true }).click();
    await expect(dialog.getByRole("textbox", { name: `${platformName} install script`, exact: true })).toHaveValue(command);
  }
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  expect(creates).toBe(1);
  for (const viewport of [{ width: 1280, height: 600 }, { width: 390, height: 600 }]) {
    await page.setViewportSize(viewport);
    await expect.poll(() => dialog.evaluate(node => node.getBoundingClientRect().height)).toBeLessThanOrEqual(viewport.height - 32);
    expect(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth)).toBe(true);
    const done = dialog.getByRole("button", { name: "Done", exact: true });
    await done.scrollIntoViewIfNeeded();
    await expect(done).toBeInViewport();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await dialog.getByRole("button", { name: "Done", exact: true }).click();
  await expect(page.getByRole("textbox", { name: /install script/ })).toHaveCount(0);
  await expect(page.locator("tbody tr")).toHaveCount(10);
  await expect(page.locator("tbody tr").first()).toContainText("New rollout");
  await expect(page.locator("tbody tr").first()).toContainText(`0 / ${maxUses}`);
  await expect(page.getByText("1–10 of 12 tokens", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Previous enrollment page" })).toBeDisabled();
  await header.getByRole("button", { name: "Create enrollment link", exact: true }).click();
  await expect(dialog.getByRole("heading", { name: "Create enrollment link", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /script copied/ })).toHaveCount(0);
  await expect(page.getByLabel("Label (optional)")).toHaveValue("");
  await expect(uses).toHaveValue("100");
  if (mdm) {
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
    await entryButton.click();
    await expect(dialog.getByRole("combobox", { name: "Install mode" })).toHaveText("Interactive");
  }
});
}
}

test("sidebar scrollbar matches the navigation and keeps all links reachable", async ({ page }, info) => {
  await mockApi(page);
  for (const viewport of [
    { width: 1440, height: 1080 },
    { width: 1280, height: 600 },
    { width: 390, height: 600 },
  ]) {
    await page.setViewportSize(viewport);
    await page.goto("/detections");
    if (viewport.width < 1024) {
      await page.getByRole("button", { name: "Open navigation", exact: true }).click();
    }
    const nav = page.getByRole("navigation", { name: "Workspace navigation" });
    await expect(nav).toHaveCSS("scrollbar-width", "thin");
    await expect(nav).toHaveCSS("color-scheme", "dark");
    await expect(nav).toHaveCSS("scrollbar-color", /.+ rgba\(0, 0, 0, 0\)$/);
    expect(await nav.evaluate((node) => node.scrollWidth <= node.clientWidth)).toBe(true);
    if (viewport.height === 600) {
      expect(await nav.evaluate((node) => node.scrollHeight > node.clientHeight)).toBe(true);
      await nav.hover();
      await page.mouse.wheel(0, 240);
      await expect.poll(() => nav.evaluate((node) => node.scrollTop)).toBeGreaterThan(0);
    }
    const first = nav.getByRole("link").first();
    await first.focus();
    await expect(first).toBeInViewport();
    const last = nav.getByRole("link").last();
    await last.focus();
    await expect(last).toBeFocused();
    await expect(last).toBeInViewport();
    await expect(page.getByRole("button", { name: "Sign out", exact: true })).toBeInViewport();
    if (viewport.height === 600) {
      expect(await nav.evaluate((node) => node.scrollTop)).toBeGreaterThan(0);
    }
    await fits(page);
    await page.screenshot({
      path: info.outputPath(`sidebar-scrollbar-${viewport.width}.png`),
      animations: "disabled",
    });
    if (viewport.width < 1024) {
      await page.keyboard.press("Escape");
      await expect(page.getByRole("dialog", { name: "Workspace navigation" })).toBeHidden();
    }
  }
});

test("every dashboard page follows heading, table, and responsive layout rules", async ({
  page,
}, info) => {
  test.setTimeout(180_000);
  const errors: string[] = [];
  const previews: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname.startsWith("/previews/")) previews.push(request.url());
  });
  page.on("pageerror", (error) => errors.push(error.message));
  await mockApi(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    if (width === 390) {
      await page
        .getByRole("button", { name: "Open navigation", exact: true })
        .click();
      const drawer = page.getByRole("dialog", { name: "Workspace navigation" });
      await expect(
        drawer
          .getByRole("navigation", { name: "Workspace navigation" })
          .getByRole("link"),
      ).toHaveCount(navigation.flatMap<NavigationPage>((group) => group.pages).length);
      await drawer
        .getByRole("link", { name: "Settings", exact: true })
        .scrollIntoViewIfNeeded();
      await expect(
        drawer.getByRole("button", { name: "Sign out" }),
      ).toBeVisible();
      await page.keyboard.press("Escape");
      await expect(drawer).toBeHidden();
      await expect(
        page.getByRole("button", { name: "Open navigation", exact: true }),
      ).toBeFocused();
    }
    for (const entry of navigation.flatMap<NavigationPage>(
      (group) => group.pages,
    )) {
      await test.step(`${width}: ${entry.path}`, async () => {
        if (width === 390) {
          await page
            .getByRole("button", { name: "Open navigation", exact: true })
            .click();
          const drawer = page.getByRole("dialog", {
            name: "Workspace navigation",
          });
          await drawer
            .getByRole("link", { name: entry.navTitle ?? entry.title, exact: true })
            .and(drawer.locator(`a[href="${entry.path}"]`))
            .click();
          await expect(drawer).toBeHidden();
        } else {
          await page.goto(entry.path);
        }
        await expect(page.getByRole("heading", { level: 1 })).toHaveText(
          entry.title,
        );
        // Loaded counts also use status announcements; wait only for loading states.
        await expect(page.locator('main [role="status"]').filter({ hasText: /Loading|Checking access/ })).toHaveCount(0);
        await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
        await expect(page.locator("main iframe")).toHaveCount(0);
        await expect(page.locator("main")).toHaveCSS("font-family", /^GeistSans,/);
        await expect(page.getByText("Sample data", { exact: true })).toHaveCount(0);
        await fits(page);
        const smallCells = await page
          .locator("main [data-slot=table] td")
          .evaluateAll((cells) =>
            cells
              .filter((cell) => {
                const size = getComputedStyle(cell).fontSize;
                // Muted timestamps use the secondary 12px type scale.
                return size !== "14px" && !(size === "12px" && cell.classList.contains("text-muted-foreground"));
              })
              .map((cell) => cell.textContent?.slice(0, 60)),
          );
        expect(smallCells).toEqual([]);
        await page.screenshot({
          path: info.outputPath(
            `${entry.path.replaceAll("/", "-") || "overview"}-${width}.png`,
          ),
          fullPage: true,
          animations: "disabled",
        });
      });
    }
  }
  expect(errors).toEqual([]);
  expect(previews).toEqual([]);
});

test("settings align summary cards, omit footer controls, and keep fixed rules on company knowledge", async ({ page }, info) => {
  await mockApi(page);
  const policyRequests: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/v1/response/policy") policyRequests.push(request.method());
  });
  for (const width of [1440, 1280, 1024, 390, 320]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await page.goto("/administration/settings");
    for (const title of ["Tenant", "Current session", "Intelligence service", "Telemetry retention"]) {
      await expect(page.getByRole("region", { name: title, exact: true })).toBeVisible();
    }
    await expect(page.getByRole("region", { name: "Share reports with OpenSecura", exact: true })).toHaveCount(0);
    const tenant = page.getByRole("region", { name: "Tenant", exact: true }).locator('[data-slot="card"]');
    const session = page.getByRole("region", { name: "Current session", exact: true }).locator('[data-slot="card"]');
    const tenantBox = (await tenant.boundingBox())!;
    const sessionBox = (await session.boundingBox())!;
    expect(Math.abs(tenantBox.width - sessionBox.width)).toBeLessThan(1);
    if (width >= 1280) {
      expect(sessionBox.x).toBeGreaterThan(tenantBox.x + tenantBox.width);
      expect(Math.abs(tenantBox.y - sessionBox.y)).toBeLessThan(1);
      expect(Math.abs(tenantBox.y + tenantBox.height - sessionBox.y - sessionBox.height)).toBeLessThan(1);
    } else {
      expect(sessionBox.y).toBeGreaterThan(tenantBox.y + tenantBox.height);
      expect(Math.abs(tenantBox.x - sessionBox.x)).toBeLessThan(1);
    }
    const usersLink = session.getByRole("link", { name: "View users and role permissions" });
    await usersLink.scrollIntoViewIfNeeded();
    await expect(usersLink).toBeInViewport();
    const titleBox = (await session.getByRole("heading", { name: "Current session", exact: true }).boundingBox())!;
    const linkBox = (await usersLink.boundingBox())!;
    const descriptionBox = (await session.getByText("Your account and assigned tenant roles.", { exact: true }).boundingBox())!;
    expect(Math.abs(linkBox.x + linkBox.width - descriptionBox.x - descriptionBox.width)).toBeLessThan(1);
    if (width >= 1024) {
      expect(Math.abs(linkBox.y + linkBox.height / 2 - titleBox.y - titleBox.height / 2)).toBeLessThan(1);
      expect(linkBox.x).toBeGreaterThan(titleBox.x + titleBox.width);
    } else {
      expect(linkBox.y).toBeGreaterThanOrEqual(titleBox.y + titleBox.height);
    }
    expect(linkBox.y + linkBox.height).toBeLessThanOrEqual(descriptionBox.y);
    await expect(usersLink).toHaveAttribute("href", "/administration/users");
    await expect(page.getByRole("link", { name: "View fixed rules", exact: true })).toHaveCount(0);
    await expect(page.getByText("Local telemetry settings", { exact: true })).toHaveCount(0);
    await expect(page.getByRole("link", { name: "Integration setup", exact: true })).toHaveCount(0);
    await expect(page.getByRole("heading", { name: "Response policy", exact: true })).toHaveCount(0);
    await expect(page.getByText("Review sensitive commands", { exact: true })).toHaveCount(0);
    await fits(page);
    await page.screenshot({ path: info.outputPath(`settings-${width}.png`), fullPage: true, animations: "disabled" });
  }
  expect(policyRequests).toEqual([]);
});

test("fixed rules on company knowledge expose draft creation and fit narrow screens", async ({ page }, info) => {
  await mockApi(page);
  const policyRequests: string[] = [];
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/v1/response/policy") policyRequests.push(request.method());
  });
  await page.goto("/company-knowledge#fixed-rules");
  await expect(page.locator("main h2").filter({ hasText: /^(How it works|Fixed rules|Company policy|Company knowledge)$/ })).toHaveText([
    "How it works", "Fixed rules", "Company policy", "Company knowledge",
  ]);
  const rules = page.getByRole("region", { name: "Fixed rules", exact: true });
  await expect(rules.getByText("Review sensitive commands", { exact: true })).toBeVisible();
  await expect(rules.getByRole("button")).toHaveText(["Create rule", "Refresh"]);
  await expect(rules.getByRole("textbox")).toHaveCount(0);
  await expect(rules).toContainText("Create a draft from a description, then test it before enabling");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await rules.getByRole("heading", { name: "Fixed rules", exact: true }).scrollIntoViewIfNeeded();
    await expect(rules.getByRole("heading", { name: "Fixed rules", exact: true })).toBeInViewport();
    await fits(page);
    await page.evaluate(() => window.scrollTo(0, 0));
    await page.screenshot({ path: info.outputPath(`fixed-rules-${width}.png`), fullPage: true, animations: "disabled" });
  }
  expect(policyRequests.length).toBeGreaterThan(0);
  expect(policyRequests.every((method) => method === "GET")).toBe(true);
});

test("page visits report authenticated navigation without query data or render duplicates", async ({ page }) => {
  await mockApi(page);
  const visits: unknown[] = [];
  await page.route("**/api/v1/audit/page-views", async (route) => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().headers()["x-openaidr-csrf"]).toBe("1");
    visits.push(route.request().postDataJSON());
    await route.fulfill({ status: 204 });
  });
  await page.goto("/audit-logs?token=must-not-be-recorded#private");
  await expect.poll(() => visits).toEqual([{ path: "/audit-logs" }]);
  await expect(page.locator("main tbody")).toContainText("policy.updated");
  const refreshed = page.waitForResponse((response) => new URL(response.url()).pathname === "/api/v1/audit");
  await page.locator("main").getByRole("button", { name: "Refresh", exact: true }).click();
  await refreshed;
  await page.evaluate(() => history.pushState(null, "", "?search=private#changed"));
  const nav = page.getByRole("navigation", { name: "Workspace navigation" });
  await nav.getByRole("link", { name: "Users and Roles", exact: true }).hover();
  await nav.getByRole("link", { name: "Users and Roles", exact: true }).click();
  await expect.poll(() => visits).toEqual([{ path: "/audit-logs" }, { path: "/administration/users" }]);
  await page.goBack();
  await expect.poll(() => visits).toHaveLength(3);
  expect(visits[2]).toEqual({ path: "/audit-logs" });
  await page.goForward();
  await expect.poll(() => visits).toHaveLength(4);
  expect(visits[3]).toEqual({ path: "/administration/users" });
  const sessionPath = "/sessions/11111111-1111-4111-8111-111111111111";
  await page.goto(`${sessionPath}?search=private#evidence`);
  await expect.poll(() => visits).toHaveLength(5);
  expect(visits[4]).toEqual({ path: sessionPath });
  await page.reload();
  await expect.poll(() => visits).toHaveLength(6);
  expect(visits[5]).toEqual({ path: sessionPath });
  await page.route("**/api/v1/auth/me", (route) => route.fulfill({ status: 401, json: { error: "Sign in required" } }));
  await page.goto("/audit-logs");
  await expect(page).toHaveURL(/\/login$/);
  expect(visits).toHaveLength(6);
});

test("restricted visits send no audit report and failures do not block allowed navigation", async ({ page }) => {
  await mockApi(page, { roles: ["security_leadership"] });
  const visits: unknown[] = [];
  await page.route("**/api/v1/audit/page-views", async (route) => {
    visits.push(route.request().postDataJSON());
    await route.abort("failed");
  });
  await page.goto("/audit-logs");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  expect(visits).toEqual([]);
  await page.getByRole("navigation", { name: "Workspace navigation" }).getByRole("link", { name: "AI Apps", exact: true }).click();
  await expect(page.locator("main h1")).toHaveText("AI Apps");
  await expect.poll(() => visits).toEqual([{ path: "/ai-inventory" }]);
});

test("audit categories filter and paginate visits with readable targets on desktop and mobile", async ({ page }, info) => {
  await mockApi(page);
  const actions = responses.audit as { items: Record<string, unknown>[]; next_cursor: string };
  const visit = {
    id: "visit-1", at: stamp(), actor: { id: user.id, name: user.name },
    action: "dashboard.page.view", target_type: "dashboard_page", target_id: "/administration/sensors",
    details: { page: "App Health", source: "browser" },
  };
  const categories: string[] = [];
  await page.route("**/api/v1/audit?**", (route) => {
    const query = new URL(route.request().url()).searchParams;
    const category = query.get("category")!;
    categories.push(category);
    if (category === "actions") return route.fulfill({ json: actions });
    if (category === "all") return route.fulfill({ json: { items: [visit, ...actions.items], next_cursor: "" } });
    return route.fulfill({ json: query.has("cursor")
      ? { items: [{ ...visit, id: "visit-2", target_id: "/audit-logs", details: { page: "Audit Logs", source: "browser" } }], next_cursor: "" }
      : { items: [visit], next_cursor: "older-visits" } });
  });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: width === 390 ? 844 : 1080 });
    await page.goto("/audit-logs");
    const filter = page.getByRole("group", { name: "Audit category", exact: true });
    const applicationActions = filter.getByRole("radio", { name: "Application actions", exact: true });
    const pageVisits = filter.getByRole("radio", { name: "Page visits", exact: true });
    const allActivity = filter.getByRole("radio", { name: "All activity", exact: true });
    await expect(applicationActions).toBeChecked();
    for (const radio of [applicationActions, pageVisits, allActivity]) await expect(radio).toBeVisible();
    for (const label of await filter.locator("label").all()) {
      expect(await label.evaluate((node) => node.scrollWidth <= node.clientWidth && node.scrollHeight <= node.clientHeight)).toBe(true);
    }
    await expect(page.locator("main tbody")).toContainText("policy.updated");
    await expect(page.locator("main tbody")).not.toContainText("Page visit");
    await pageVisits.check();
    await expect(pageVisits).toBeChecked();
    await expect(applicationActions).not.toBeChecked();
    await expect(page.locator("main tbody tr")).toHaveCount(1);
    await expect(page.locator("main tbody")).toContainText("App Health");
    await expect(page.locator("main tbody")).toContainText("/administration/sensors");
    await expect(page.locator("main tbody")).not.toContainText("policy.updated");
    await page.getByRole("button", { name: "Load more", exact: true }).click();
    await expect(page.locator("main tbody tr")).toHaveCount(2);
    await expect(page.locator("main tbody")).toContainText("/audit-logs");
    await fits(page);
    await page.screenshot({ path: info.outputPath(`audit-page-visits-${width}.png`), fullPage: true, animations: "disabled" });
    const description = page.getByText(/^Recorded application actions and page visits, newest first\./);
    const descriptionLines = await description.evaluate((node) =>
      node.getBoundingClientRect().height / parseFloat(getComputedStyle(node).lineHeight),
    );
    if (width === 1440) expect(descriptionLines).toBeCloseTo(1);
    else expect(descriptionLines).toBeGreaterThan(1);
    if (width === 390) {
      const table = page.getByRole("region", { name: "Scrollable data table" });
      await table.evaluate((node) => { node.scrollLeft = node.scrollWidth; });
      await page.locator("main summary").first().click();
      await expect(page.locator("main details[open]")).toContainText('"source": "browser"');
      await fits(page);
    }
    await pageVisits.focus();
    await page.keyboard.press("ArrowRight");
    await expect(allActivity).toBeChecked();
    await expect(allActivity).toBeFocused();
    await expect(pageVisits).not.toBeChecked();
    await expect(page.locator("main tbody")).toContainText("policy.updated");
    await expect(page.locator("main tbody")).toContainText("Page visit");
    await fits(page);
    await page.keyboard.press("ArrowLeft");
    await expect(pageVisits).toBeChecked();
    await expect(pageVisits).toBeFocused();
    await expect(page.locator("main tbody tr")).toHaveCount(1);
    await expect(page.getByRole("button", { name: "Load more", exact: true })).toBeVisible();
    await page.keyboard.press("ArrowLeft");
    await expect(applicationActions).toBeChecked();
    await expect(applicationActions).toBeFocused();
    await expect(page.locator("main tbody")).toContainText("policy.updated");
    await expect(page.locator("main tbody")).not.toContainText("Page visit");
  }
  expect(new Set(categories)).toEqual(new Set(["actions", "page_views", "all"]));
});

test("refreshing and failed requests preserve loaded administrative and security records", async ({
  page,
}) => {
  const failures = new Set<string>();
  await mockApi(page, { failures });
  for (const [path, endpoint, text, section] of [
    ["/administration/users", "users", "Design reviewer"],
    [
      "/company-knowledge",
      "response/policy",
      "Review sensitive commands",
    ],
    ["/administration/server", "system/status", "Server version"],
    ["/user-risk?view=findings", "findings", "Unusual command execution", "Policy findings"],
    ["/user-risk?view=findings", "user-risk", "reviewer", "Findings by reported user"],
    ["/audit-logs", "audit", "policy.updated"],
    ["/security-posture", "response/policy", "Review sensitive commands"],
    ["/detection-rules", "detections/rules", "Command review"],
  ]) {
    await page.goto(path);
    const scope = section ? page.getByRole("region", { name: section, exact: true }) : page.locator("main");
    const content = scope
      .getByText(text, { exact: false })
      .first();
    await expect(content).toBeVisible();
    failures.add(endpoint);
    await scope
      .getByRole("button", { name: "Refresh", exact: true })
      .first()
      .click();
    await expect(page.locator("main").getByRole("alert").first()).toContainText(
      "Showing stale data",
    );
    await expect(content).toBeVisible();
    failures.delete(endpoint);
    await page
      .getByRole("button", { name: "Retry", exact: true })
      .first()
      .click();
    await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  }
});

test("server health separates compact API and database cards on desktop and mobile", async ({ page }, testInfo) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await mockApi(page);
  await page.route("**/api/v1/system/status", (route) => route.fulfill({ json: {
    ...(responses["system/status"] as object),
    version: "2026.10.6+8d5b065",
  } }));
  await page.goto("/administration/server");
  const apiCard = page.getByRole("region", { name: "API health", exact: true });
  const dbCard = page.getByRole("region", { name: "Database health", exact: true });
  await expect(apiCard.getByText("Not reporting", { exact: true })).toBeVisible();
  await expect(apiCard.getByText("0 normalized events pending")).toBeVisible();
  await expect(apiCard.getByText("Not applicable")).toHaveCount(0);
  const heartbeats = apiCard.locator('dl[aria-label="Last heartbeats"]');
  await expect(heartbeats.locator("time")).toHaveCount(1);
  await expect(heartbeats).toContainText("ingest, API, detect heartbeat");
  await expect(dbCard.getByText("1 / 16", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("Reachable", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("Active queries", { exact: true })).toBeVisible();
  const cards = apiCard.locator("..");
  const layouts = [];
  for (const width of [1440, 1280, 1024, 390, 320]) {
    await page.setViewportSize({ width, height: 844 });
    await expect(apiCard.getByText("2026.10.6+8d5b065", { exact: true })).toBeVisible();
    const apiBox = (await apiCard.boundingBox())!;
    const dbBox = (await dbCard.boundingBox())!;
    layouts.push({ width, apiHeight: apiBox.height, databaseHeight: dbBox.height });
    if (width >= 1280) {
      expect(dbBox.x).toBeGreaterThan(apiBox.x + apiBox.width);
      expect(Math.abs(dbBox.y - apiBox.y)).toBeLessThan(1);
      expect(Math.max(apiBox.height, dbBox.height)).toBeLessThan(280);
      const apiSurface = (await apiCard.locator('[data-slot="card"]').boundingBox())!;
      const dbSurface = (await dbCard.locator('[data-slot="card"]').boundingBox())!;
      expect(Math.abs(apiSurface.y + apiSurface.height - dbSurface.y - dbSurface.height)).toBeLessThan(1);
    } else {
      expect(dbBox.y).toBeGreaterThan(apiBox.y + apiBox.height);
      expect(dbBox.height).toBeLessThan(310);
      expect((await cards.boundingBox())!.height).toBeLessThan(700);
    }
    await fits(page);
    for (const card of [apiCard, dbCard]) {
      expect(await card.evaluate((element) => {
        const bounds = element.getBoundingClientRect();
        return Array.from(element.querySelectorAll("dt, dd, th, td, li p, button, [data-slot=status]"))
          .every((child) => {
            const rect = child.getBoundingClientRect();
            return rect.left >= bounds.left && rect.right <= bounds.right &&
              rect.top >= bounds.top && rect.bottom <= bounds.bottom;
          });
      })).toBe(true);
      const refresh = card.getByRole("button", { name: "Refresh", exact: true });
      await refresh.scrollIntoViewIfNeeded();
      await expect(refresh).toBeInViewport();
    }
    if (width === 1440 || width === 390) {
      await cards.screenshot({
        path: testInfo.outputPath(`database-health-${width === 1440 ? "desktop" : "mobile"}.png`),
        animations: "disabled",
        style: "nextjs-portal, header { visibility: hidden; }",
      });
    }
  }
  const help = page.locator("details").filter({ has: page.getByText("Reading component status", { exact: true }) });
  await help.locator("summary").click();
  await expect(help.getByText(/Pool counts describe this API process and show busy or opening connections \/ pool limit\./)).toBeVisible();
  await testInfo.attach("card-dimensions", { body: JSON.stringify(layouts), contentType: "application/json" });
});

test("database health shows pressure, unavailable activity, stale data, and role restrictions", async ({ page }) => {
  const failures = new Set(["system/status"]);
  await mockApi(page, { failures });
  const snapshot = {
    ...databaseHealth,
    pools: [
      { name: "data", size: 16, available: 0, maximum: 16, waiting: 64 },
      { name: "auth", size: 1, available: 1, maximum: 4, waiting: 0 },
    ],
    activity: {
      ...databaseHealth.activity,
      active_queries: 16, long_running_queries: 16,
      oldest_query_seconds: 2460, oldest_transaction_seconds: 17940,
    },
  };
  let unavailable = false;
  let fail = false;
  let disabled = false;
  await page.route("**/api/v1/system/database", (route) => fail
    ? route.fulfill({ status: 503, json: { error: { message: "Synthetic failure" } } })
    : route.fulfill({ json: disabled ? { status: "disabled", message: "Database diagnostics require a dedicated tenant database." }
      : unavailable ? { ...snapshot, ok: false, activity: null, latency_ms: null } : snapshot }));
  await page.goto("/administration/server");
  const dbCard = page.getByRole("region", { name: "Database health", exact: true });
  await expect(dbCard.getByText("Connection pressure", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("41 min 0 s", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("4 h 59 min", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("64", { exact: true })).toBeVisible();
  await page.setViewportSize({ width: 320, height: 640 });
  await fits(page);
  expect(await dbCard.locator("dl > div").evaluateAll((items) => items.every((item) => {
    const bounds = item.getBoundingClientRect();
    return Array.from(item.children).every((child) => {
      const rect = child.getBoundingClientRect();
      return rect.left >= bounds.left && rect.right <= bounds.right;
    });
  }))).toBe(true);
  const apiCard = page.getByRole("region", { name: "API health", exact: true });
  await expect(apiCard.getByRole("alert")).toBeVisible();
  failures.clear();
  await apiCard.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(apiCard.getByText("0 normalized events pending")).toBeVisible();
  failures.add("system/status");
  await apiCard.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(apiCard.getByRole("alert")).toContainText("Showing stale data");
  await expect(apiCard.getByText("0 normalized events pending")).toBeVisible();
  unavailable = true;
  await dbCard.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(dbCard.getByText("Check unavailable", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("Query activity unavailable.", { exact: true })).toBeVisible();
  await expect(dbCard.getByText("64", { exact: true })).toBeVisible();
  fail = true;
  await dbCard.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(dbCard.getByRole("alert")).toContainText("Showing stale data");
  await expect(dbCard.getByText("64", { exact: true })).toBeVisible();
  fail = false;
  disabled = true;
  failures.clear();
  await apiCard.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(apiCard.getByRole("alert")).toHaveCount(0);
  await dbCard.getByRole("button", { name: "Retry", exact: true }).click();
  await expect(dbCard.getByText("Database diagnostics require a dedicated tenant database.")).toBeVisible();
  await expect(dbCard.getByText("Reachable", { exact: true })).toBeVisible();
  await expect(dbCard.getByRole("table")).toHaveCount(0);
  await mockApi(page, { roles: ["security_leadership"] });
  let diagnosticRequests = 0;
  page.on("request", (request) => {
    if (new URL(request.url()).pathname === "/api/v1/system/database") diagnosticRequests++;
  });
  await page.goto("/administration/server");
  await expect(page.getByText("Access restricted", { exact: true })).toBeVisible();
  await expect(dbCard).toHaveCount(0);
  expect(diagnosticRequests).toBe(0);
});

test("native agent cost cards use cent precision and export records retain body typography", async ({
  page,
}) => {
  await mockApi(page);
  await page.goto("/costs/agents");
  await expect(
    page
      .locator("main [data-slot=card]")
      .filter({ hasText: "Estimated cost" })
      .first()
      .locator(".figure"),
  ).toHaveText("$0.01");
  await page.route("**/api/v1/events?*", route => route.fulfill({ json: { items: [{ id: "export-event", kind: "command", time: stamp(), command: { text: "git status" }, source: "otlp", export: { id: "x", record: 0, signal: "logs" } }], next_cursor: "" } }));
  await page.goto("/evidence");
  await page.getByRole("button", { name: /^Open event export-event:/ }).click();
  await page.getByRole("button", { name: /Open telemetry record/ }).click();
  await expect(
    page
      .getByRole("dialog")
      .getByRole("cell", { name: "command", exact: true }),
  ).toHaveCSS("font-size", "14px");
  await expect(
    page.getByRole("dialog").getByRole("columnheader", { name: "Attributes" }),
  ).toBeVisible();
  await mockClipboard(page);
  await page.getByRole("tab", { name: "Raw payload", exact: true }).click();
  const payload = page.getByRole("dialog").locator('[data-slot="code-block"]');
  await expect(page.getByRole("dialog").getByRole("button", { name: "Copy JSON", exact: true })).toHaveCount(1);
  await payload.getByRole("button", { name: "Copy JSON", exact: true }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify({ synthetic: true }, null, 2));
});

test("empty, initial error, and restricted pages remain distinct", async ({
  page,
}) => {
  await mockApi(page, { empty: true });
  for (const [path, message] of [
    ["/administration/users", "No users returned"],
    ["/administration/enrollment", "No enrollment tokens"],
    ["/company-knowledge", "No fixed rules"],
    ["/detections", "No investigation reports match"],
    ["/guardrail/configuration", "No fixed rules"],
    ["/user-risk?view=findings", "No user findings to summarize"],
    ["/audit-logs", "No audit records yet"],
    ["/security-posture", "No prevention rules configured."],
    ["/detection-rules", "No rules returned"],
  ]) {
    await page.goto(path);
    await expect(page.getByText(message, { exact: true })).toBeVisible();
    await expect(page.locator("main").getByRole("alert")).toHaveCount(0);
  }
  await page.unroute("**/api/v1/**");
  await mockApi(page, {
    failures: new Set([
      "users",
      "sensors/enrollment-tokens",
      "response/policy",
      "findings",
      "session-investigations",
      "user-risk",
      "audit",
      "detections/rules",
    ]),
  });
  for (const path of [
    "/administration/users",
    "/administration/enrollment",
    "/company-knowledge",
    "/detections",
    "/guardrail/configuration",
    "/user-risk?view=findings",
    "/audit-logs",
    "/security-posture",
    "/detection-rules",
  ]) {
    await page.goto(path);
    await expect(page.locator("main").getByRole("alert").first()).toContainText(
      "Synthetic refresh failure",
    );
    await expect(page.locator("main").getByRole("status")).toHaveCount(0);
    await expect(page.locator("main tbody tr")).toHaveCount(0);
  }
  await page.unroute("**/api/v1/**");
  await mockApi(page, { roles: ["security_leadership"] });
  for (const path of ["/audit-logs", "/administration/enrollment"]) {
    await page.goto(path);
    await expect(
      page.getByText("Access restricted", { exact: true }),
    ).toBeVisible();
    await expect(
      page.locator("main").getByRole("button", { name: "Create enrollment link" }),
    ).toHaveCount(0);
  }
});

test("source services show the six largest record totals with alphabetical ties and small shares", async ({ page }, info) => {
  await mockApi(page);
  const services = [
    { name: "a-tiny", log_records: 20, metric_points: 0, spans: 0 },
    { name: "c-metrics", log_records: 0, metric_points: 400, spans: 0 },
    { name: "b-logs", log_records: 400, metric_points: 0, spans: 0 },
    { name: "d-mixed", log_records: 30, metric_points: 30, spans: 40 },
    { name: "e-small", log_records: 70, metric_points: 0, spans: 0 },
    { name: "f-hidden", log_records: 10, metric_points: 0, spans: 0 },
    { name: "g-zero", log_records: 0, metric_points: 0, spans: 0 },
    { name: "z-traces", log_records: 0, metric_points: 0, spans: 9000 },
  ].map((service, index) => ({ ...service, exports: index + 1, last_export_at: stamp() }));
  await page.route("**/api/v1/telemetry/overview?**", (route) => route.fulfill({
    json: {
      ...telemetry,
      services,
      available_services: services.map(({ name }) => name).sort(),
      summary: { ...telemetry.summary, exports: 36, records: 10000, log_records: 530, metric_points: 430, spans: 9040 },
    },
  }));
  await page.goto("/administration/app");
  const panel = page.locator("[data-slot=card]").filter({
    has: page.getByRole("heading", { name: "Source services", exact: true }),
  });
  const bars = panel.getByRole("img", { name: / records, / });
  await expect(bars).toHaveCount(6);
  expect(await bars.evaluateAll((items) => items.map((item) => item.getAttribute("aria-label")))).toEqual([
    "z-traces: 9,000 records, 90% of total",
    "b-logs: 400 records, 4% of total",
    "c-metrics: 400 records, 4% of total",
    "d-mixed: 100 records, 1% of total",
    "e-small: 70 records, <1% of total",
    "a-tiny: 20 records, <1% of total",
  ]);
  await expect(panel.getByText("<1%", { exact: true })).toHaveCount(2);
  await expect(panel.getByText("Showing top 6 of 8 services by record count.", { exact: false })).toBeVisible();
  expect(await bars.first().locator("div").evaluate((bar) => bar.style.width)).toBe("90%");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await fits(page);
    await panel.screenshot({ path: info.outputPath(`source-services-ranked-${width}.png`), animations: "disabled" });
  }
});

test("source service shares preserve zero, whole, and empty totals", async ({ page }) => {
  await mockApi(page);
  let services = [
    { ...telemetry.services[0], name: "b-zero", log_records: 0, metric_points: 0, spans: 0 },
    { ...telemetry.services[0], name: "a-zero", log_records: 0, metric_points: 0, spans: 0 },
  ];
  await page.route("**/api/v1/telemetry/overview?**", (route) => route.fulfill({ json: { ...telemetry, services } }));
  await page.goto("/administration/app");
  const panel = page.locator("[data-slot=card]").filter({
    has: page.getByRole("heading", { name: "Source services", exact: true }),
  });
  const bars = panel.getByRole("img", { name: / records, / });
  await expect(bars.first()).toHaveAttribute("aria-label", "a-zero: 0 records, 0% of total");
  await expect(bars.last()).toHaveAttribute("aria-label", "b-zero: 0 records, 0% of total");
  await expect(panel.getByText("0%", { exact: true })).toHaveCount(2);
  services = [telemetry.services[0]];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(bars).toHaveCount(1);
  await expect(bars).toHaveAttribute("aria-label", "review-agent: 7 records, 100% of total");
  services = [];
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect(panel.getByText("No source services", { exact: true })).toBeVisible();
  await expect(bars).toHaveCount(0);
});

test("telemetry activity shows charts without display tabs", async ({ page }, info) => {
  await mockApi(page);
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await page.goto("/administration/app");
    const activity = page.locator("[data-slot=card]").filter({
      has: page.getByRole("heading", { name: "Telemetry activity", exact: true }),
    });
    await expect(activity.getByRole("application")).toBeVisible();
    await expect(activity.getByRole("tablist")).toHaveCount(0);
    await expect(activity.getByRole("table")).toHaveCount(0);
    await expect(activity.getByRole("list", { name: "Series" }).getByRole("listitem")).toHaveText(["Logs", "Metrics", "Traces"]);
    await activity.getByRole("application").focus();
    await page.keyboard.press("ArrowRight");
    await expect(activity.locator(".recharts-tooltip-wrapper")).toContainText("Log records");
    await fits(page);
    await activity.screenshot({ path: info.outputPath(`telemetry-chart-${width}.png`), animations: "disabled" });
  }
});

test("telemetry activity hides empty traces and restores historical spans when the range changes", async ({ page }, info) => {
  await mockApi(page);
  await page.route("**/api/v1/telemetry/overview?**", (route) => {
    const range = new URL(route.request().url()).searchParams.get("range") || "24h";
    const historical = range === "7d";
    const bucketHours = historical ? 24 : 1;
    const count = historical ? 7 : 24;
    const activity = Array.from({ length: count }, (_, index) => ({
      start: stamp((count - index) * bucketHours),
      exports: 1,
      log_records: 4,
      metric_points: 2,
      spans: historical && index === 0 ? 7 : 0,
    }));
    return route.fulfill({ json: {
      ...telemetry,
      range,
      window_start: stamp(count * bucketHours),
      bucket_seconds: bucketHours * 3600,
      activity,
      summary: {
        ...telemetry.summary,
        exports: count,
        records: count * 6 + (historical ? 7 : 0),
        log_records: count * 4,
        metric_points: count * 2,
        spans: historical ? 7 : 0,
      },
    } });
  });
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 1080 });
    await page.goto("/administration/app");
    const activity = page.locator("[data-slot=card]").filter({
      has: page.getByRole("heading", { name: "Telemetry activity", exact: true }),
    });
    for (const [range, historical] of [["Last 24 hours", false], ["Last 7 days", true], ["Last 24 hours", false]] as const) {
      await page.getByRole("combobox", { name: "Time range", exact: true }).click();
      await page.getByRole("option", { name: range, exact: true }).click();
      await expect(activity.getByRole("list", { name: "Series" }).getByRole("listitem")).toHaveText(
        historical ? ["Logs", "Metrics", "Traces"] : ["Logs", "Metrics"],
      );
      await expect(activity.locator(".recharts-area-curve")).toHaveCount(historical ? 3 : 2);
      const signals = historical ? "log records, metric points, and spans" : "log records and metric points";
      await expect(activity.getByLabel(`Stacked chart of ${signals} by received time`, { exact: true })).toBeVisible();
      const chart = activity.getByRole("application");
      await expect(chart).toHaveAttribute("aria-label", new RegExp(`^${signals.charAt(0).toUpperCase()}${signals.slice(1)} over received time, `));
      await chart.hover({ position: { x: 65, y: 40 } });
      const tooltip = activity.locator(".recharts-tooltip-wrapper");
      await expect(tooltip).toBeVisible();
      await expect(tooltip.getByRole("listitem")).toHaveText(
        historical ? ["Log records4", "Metric points2", "Spans7"] : ["Log records4", "Metric points2"],
      );
      await expect(tooltip).toContainText(`Total: ${historical ? 13 : 6} records`);
      if (historical) {
        await chart.hover({ position: { x: (await chart.boundingBox())!.width - 10, y: 40 } });
        await expect(tooltip.getByRole("listitem")).toHaveText(["Log records4", "Metric points2", "Spans0"]);
        await expect(tooltip).toContainText("Total: 6 records");
      }
      await fits(page);
      await activity.screenshot({ path: info.outputPath(`telemetry-${historical ? "historical" : "no-traces"}-${width}.png`), animations: "disabled" });
    }
  }
});

test("chart readouts work by keyboard and touch within a phone viewport", async ({
  browser,
}, info) => {
  const context = await browser.newContext({
    baseURL: test.info().project.use.baseURL,
    hasTouch: true,
    timezoneId: "UTC",
    viewport: { width: 390, height: 844 },
  });
  const page = await context.newPage();
  try {
    await mockApi(page);
    for (const [path, chartName] of [
      [
        "/administration/app",
        "Stacked chart of log records, metric points, and spans by received time",
      ],
      ["/administration/server", "CPU usage over time"],
      ["/costs/agents", "Estimated cost over time"],
      ["/costs/openaidr", "Credit usage chart"],
    ]) {
      await page.goto(path);
      const chart = page.getByLabel(chartName, { exact: true }).first();
      if (path === "/administration/app") {
        await expect(
          chart.locator(".recharts-yAxis-tick-labels text").first(),
        ).toBeVisible();
        for (const tick of await chart
          .locator(".recharts-yAxis-tick-labels text")
          .allTextContents()) {
          expect(Number.isInteger(Number(tick.replaceAll(",", "")))).toBe(true);
        }
      }
      await chart.getByRole("application").focus();
      await page.keyboard.press("ArrowRight");
      const tooltip = chart.locator(".recharts-tooltip-wrapper");
      await expect(tooltip).toBeVisible();
      await expect(tooltip).toContainText("UTC");
      const bounds = (await chart.boundingBox())!;
      await page.touchscreen.tap(bounds.x + bounds.width * 0.8, bounds.y + 80);
      await expect(tooltip).toBeVisible();
      const readout = (await tooltip.boundingBox())!;
      expect(readout.x).toBeGreaterThanOrEqual(0);
      expect(readout.x + readout.width).toBeLessThanOrEqual(390);
      for (const label of await chart
        .locator(".recharts-xAxis-tick-labels text")
        .all()) {
        const box = (await label.boundingBox())!;
        expect(box.x).toBeGreaterThanOrEqual(bounds.x);
        expect(box.x + box.width).toBeLessThanOrEqual(bounds.x + bounds.width);
      }
      await page.screenshot({
        path: info.outputPath(`${path.replaceAll("/", "-")}-readout.png`),
        fullPage: true,
      });
      await fits(page);
    }
  } finally {
    await context.close();
  }
});

test("native agent costs distinguish tiny, zero, large, and unavailable single samples", async ({
  page,
}) => {
  await mockApi(page);
  let value: number | null = 0;
  await page.route("**/api/v1/costs/**", async (route) => {
    const sample = {
      ...total,
      calls: 1,
      priced_calls: value === null ? 0 : 1,
      unpriced_calls: value === null ? 1 : 0,
      cost_usd: value,
    };
    return route.fulfill({
      json: {
        ...costs,
        summary: sample,
        series: [{ ...sample, time: stamp(1) }],
      },
    });
  });
  for (const [amount, expected] of [
    [0, "$0.00"],
    [0.000000042, "<$0.01"],
    [0.01101408, "$0.01"],
    [25200, "$25,200.00"],
    [null, "Unavailable"],
  ] as const) {
    value = amount;
    for (const path of ["/costs/agents"]) {
      await page.goto(path);
      await expect(
        page.locator("main [data-slot=card]").filter({ hasText: "Estimated cost" }).first().locator(".figure"),
      ).toHaveText(expected);
      if (value === null) {
        await expect(
          page.getByText("Cost estimates are unavailable", { exact: true }),
        ).toHaveCount(1);
        for (const message of await page
          .getByText("Cost estimates are unavailable", { exact: true })
          .all()) {
          await expect(message).toBeVisible();
        }
      } else {
        await expect(page.locator("main .recharts-wrapper")).toHaveCount(
          path === "/costs/agents" ? 1 : 2,
        );
        for (const chart of await page
          .locator("main .recharts-wrapper")
          .all()) {
          await expect(chart.locator(".recharts-bar")).toHaveCount(1);
          const ticks = await chart
            .locator(".recharts-yAxis-tick-labels text")
            .allTextContents();
          expect(ticks.length).toBeGreaterThan(1);
          expect(new Set(ticks).size).toBe(ticks.length);
        }
      }
    }
  }
});

test.describe("time zone preference", () => {
  test.use({ timezoneId: "America/Los_Angeles", locale: "en-US" });

  test("server-rendered timestamps are independent of the server time zone", () => {
    function Timestamp() {
      const { chartTimestamp } = useTimeZone();
      return createElement("time", null, chartTimestamp(stamp()));
    }
    const previous = process.env.TZ;
    try {
      for (const zone of ["UTC", "America/Los_Angeles", "Asia/Kathmandu"]) {
        process.env.TZ = zone;
        const markup = renderToString(createElement(TimeZoneProvider, {
          children: createElement(Timestamp),
        }));
        expect(markup).toContain("Oct 1, 2026, 12:00 UTC");
      }
    } finally {
      if (previous === undefined) delete process.env.TZ;
      else process.env.TZ = previous;
    }
  });

  test("updates charts and tables without losing filters, and persists across navigation and tabs", async ({ page, context }, info) => {
    await mockApi(page);
    const requests: string[] = [];
    page.on("request", (request) => {
      if (request.url().includes("/api/v1/telemetry/overview")) requests.push(request.url());
    });
    await page.goto("/administration/app");
    const local = page.getByRole("radio", { name: "Local", exact: true });
    const utc = page.getByRole("radio", { name: "UTC", exact: true });
    await expect(local).toBeChecked();
    await expect(local.locator("..")).toHaveAttribute("title", "Local time: America/Los_Angeles");
    await expect.poll(() => page.evaluate(() => localStorage.length)).toBe(0);
    await page.getByRole("combobox", { name: "Service filter" }).click();
    await page.getByRole("option", { name: "review-agent", exact: true }).click();
    const chart = page.getByLabel("Stacked chart of log records, metric points, and spans by received time", { exact: true });
    await chart.getByRole("application").focus();
    await page.keyboard.press("ArrowRight");
    const readout = chart.locator(".recharts-tooltip-wrapper");
    await expect(readout).toContainText("PDT");
    const before = requests.length;
    await local.focus();
    await page.keyboard.press("ArrowRight");
    await expect(utc).toBeChecked();
    await expect(utc).toBeFocused();
    await chart.getByRole("application").focus();
    await page.keyboard.press("ArrowRight");
    await expect(readout).toContainText("UTC");
    await expect(page.getByRole("combobox", { name: "Service filter" })).toContainText("review-agent");
    expect(requests).toHaveLength(before);
    await expect(page.getByRole("tab", { name: /^(Chart|Table)$/ })).toHaveCount(0);
    await local.check();
    await chart.getByRole("application").focus();
    await page.keyboard.press("ArrowRight");
    await expect(readout).toContainText("PDT");
    await expect(page.locator("header [data-slot=build-info]")).toContainText(/P[DS]T/);
    await page.screenshot({ path: info.outputPath("time-zone-local.png"), animations: "disabled" });
    await utc.check();
    await expect(page.locator("header [data-slot=build-info]")).toContainText("UTC");
    await page.screenshot({ path: info.outputPath("time-zone-utc.png"), animations: "disabled" });
    await page.getByRole("navigation", { name: "Workspace navigation" }).getByRole("link", { name: "Audit Logs", exact: true }).click();
    await expect(page.getByRole("cell", { name: /^Oct 1(?:,| at) 12:00:00 PM UTC$/, exact: true })).toBeVisible();
    await page.reload();
    await expect(utc).toBeChecked();
    const other = await context.newPage();
    await mockApi(other);
    await other.goto("/audit-logs");
    await expect(other.getByRole("radio", { name: "UTC", exact: true })).toBeChecked();
    await local.check();
    await expect(other.getByRole("radio", { name: "Local", exact: true })).toBeChecked();
    await expect(other.getByRole("cell", { name: /^Oct 1(?:,| at) 05:00:00 AM PDT$/, exact: true })).toBeVisible();
    await other.close();
  });

  test("distinguishes midnight and daylight saving offsets while keeping daily aggregates in UTC", async ({ page }) => {
    await mockApi(page);
    const times = ["2026-10-01T00:30:00Z", "2026-11-01T08:30:00Z", "2026-11-01T09:30:00Z"];
    await page.route("**/api/v1/audit?**", (route) => route.fulfill({ json: {
      items: times.map((at, i) => ({ id: `tz-${i}`, at, actor: user, action: "policy.updated", target_type: "policy", target_id: "p", details: {} })),
      next_cursor: "",
    } }));
    await page.goto("/audit-logs");
    for (const label of ["Sep 30, 05:30:00 PM PDT", "Nov 1, 01:30:00 AM PDT", "Nov 1, 01:30:00 AM PST"])
      await expect(page.getByRole("cell", { name: new RegExp(`^${label.replace(", ", "(?:,| at) ")}$`), exact: true })).toBeVisible();
    await page.getByRole("radio", { name: "UTC", exact: true }).check();
    for (const label of ["Oct 1, 12:30:00 AM UTC", "Nov 1, 08:30:00 AM UTC", "Nov 1, 09:30:00 AM UTC"])
      await expect(page.getByRole("cell", { name: new RegExp(`^${label.replace(", ", "(?:,| at) ")}$`), exact: true })).toBeVisible();
    await page.route("**/api/v1/credits?**", route => {
      const range = new URL(route.request().url()).searchParams.get("range")!;
      return route.fulfill({ json: creditFixture(range, "t", now) });
    });
    await page.goto("/costs/openaidr");
    const creditUsage = page.getByRole("region", { name: "Credit usage", exact: true });
    for (const range of ["30d", "90d"]) {
      await page.getByRole("button", { name: range, exact: true }).click();
      for (const zone of ["Local", "UTC"]) {
        await page.getByRole("radio", { name: zone, exact: true }).check();
        await expect(creditUsage.getByText("Daily credit usage · UTC", { exact: true })).toBeVisible();
        await creditUsage.getByRole("application").focus();
        await page.keyboard.press("ArrowRight");
        await expect(creditUsage.locator(".recharts-tooltip-wrapper")).toContainText("UTC");
      }
    }
    await page.route("**/api/v1/telemetry/overview?**", (route) => {
      const range = new URL(route.request().url()).searchParams.get("range")!;
      if (range === "24h") return route.fallback();
      return route.fulfill({ json: {
        ...telemetry, range, window_start: stamp(Number.parseInt(range) * 24), bucket_seconds: 86400,
        activity: [{ start: "2026-10-01T00:00:00Z", exports: 1, log_records: 4, metric_points: 2, spans: 1 }],
      } });
    });
    await page.goto("/administration/app");
    for (const days of [7, 30]) {
      await page.getByRole("combobox", { name: "Time range", exact: true }).click();
      await page.getByRole("option", { name: `Last ${days} days`, exact: true }).click();
      for (const zone of ["Local", "UTC"]) {
        await page.getByRole("radio", { name: zone, exact: true }).check();
        await expect(page.getByText(/^Data since/)).toHaveText(
          "Data since Oct 1, 2026 UTC. Choose a shorter range to inspect recent activity.",
        );
        await page.locator(".recharts-area-dots circle").first().hover();
        await expect(page.locator(".recharts-tooltip-wrapper").first()).toContainText("Oct 1, 2026 UTC");
      }
    }
  });

  test("rolling 24-hour telemetry and guardrail buckets retain their start times", async ({ page }) => {
    await mockApi(page);
    const since = "2026-09-01T15:30:00Z";
    const until = "2026-10-01T15:30:00Z";
    const start = "2026-09-30T15:30:00Z";
    await page.route("**/api/v1/telemetry/overview?**", (route) => route.fulfill({ json: {
      ...telemetry, range: "30d", window_start: since, generated_at: until, bucket_seconds: 86400,
      activity: [{ start, exports: 1, log_records: 4, metric_points: 2, spans: 1 }],
    } }));
    const totals = {
      total: 1, allow: 1, deny: 0, ask: 0, warn: 0, legacy: 0,
      e2e_p50: 10, e2e_p95: 20, e2e_p99: 30, policy_p50: 1, policy_p95: 2, policy_p99: 3,
    };
    await page.route("**/api/v1/guardrail/stats?**", (route) => route.fulfill({ json: historyFixture({
      source: "endpoints", range: "30d", since, until, bucket_seconds: 86400,
      totals, series: [{ ...totals, start }], rules: [],
    }) }));
    for (const path of ["/administration/app", "/guardrail/history?source=endpoints"]) {
      await page.goto(path);
      if (path.startsWith("/guardrail/history")) {
        await page.getByRole("radio", { name: "Last 30 days", exact: true }).check();
      } else {
        await page.getByRole("combobox", { name: "Time range", exact: true }).click();
        await page.getByRole("option", { name: "Last 30 days", exact: true }).click();
      }
      for (const [zone, time, suffix] of [["Local", "08:30", "PDT"], ["UTC", "15:30", "UTC"]]) {
        await page.getByRole("radio", { name: zone, exact: true }).check();
        const timestamp = new RegExp(`Sep 30, 2026(?:,| at) ${time} ${suffix}`);
        const chart = page.getByRole("application").first();
        await expect(chart.locator(".recharts-xAxis-tick-labels text").first()).toContainText(time);
        await chart.focus();
        // Reopen the same single sample after refocusing a persistent chart.
        await page.keyboard.press(zone === "UTC" ? "Enter" : "ArrowRight");
        await expect(page.locator(".recharts-tooltip-wrapper").first()).toContainText(timestamp);
        if (path === "/administration/app")
          await expect(page.getByText(/^Data since/)).toContainText(timestamp);
      }
    }
  });

  test("works without browser storage and fits desktop and phone headers", async ({ page }, info) => {
    await page.addInitScript(() => {
      Object.defineProperty(window, "localStorage", { get() { throw new DOMException("Storage disabled", "SecurityError"); } });
    });
    await mockApi(page);
    await page.goto("/costs/openaidr");
    const control = page.getByRole("group", { name: "Time zone" });
    await expect(page.getByRole("radio", { name: "Local", exact: true })).toBeChecked();
    await page.getByRole("radio", { name: "UTC", exact: true }).check();
    await expect(page.getByRole("radio", { name: "UTC", exact: true })).toBeChecked();
    for (const width of [1440, 1280, 1024, 768, 640, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await fits(page);
      const height = width >= 640 ? "32px" : "40px";
      await expect(control).toHaveCSS("height", height);
      await expect(control).toHaveCSS("font-size", "14px");
      await expect(control).toHaveCSS("line-height", "20px");
      await expect(page.getByRole("button", { name: "Ask about this page" })).toHaveCSS("height", height);
      if (width < 1024)
        await expect(page.getByRole("button", { name: "Open navigation" })).toHaveCSS("height", height);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: info.outputPath("time-zone-phone.png"), animations: "disabled" });
    await page.getByRole("button", { name: "Open navigation" }).click();
    await expect(page.getByRole("dialog", { name: "Workspace navigation" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.getByRole("button", { name: "Open navigation" })).toBeFocused();
    await page.reload();
    await expect(page.getByRole("radio", { name: "Local", exact: true })).toBeChecked();
  });
});
