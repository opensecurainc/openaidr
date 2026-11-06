import { activityFixture } from "./activity-flow";
import { creditFixture } from "./credits";
import type { Page } from "@playwright/test";
import type { GuardrailStats } from "../../src/lib/guardrail";
import { historyFixture } from "./guardrail-history";

// Populated API responses for layout only. API and aggregation behavior is
// covered by the feature tests and backend integration tests.
export async function mockChartData(page: Page) {
  const now = Date.parse("2026-10-12T12:00:00Z");
  const iso = (hoursAgo: number) => new Date(now - hoursAgo * 3600000).toISOString();
  await page.clock.setFixedTime(now);
  const times = Array.from({ length: 24 }, (_, i) => iso(24 - i));
  const sensor = {
    id: "sensor-a", hostname: "Test workstation", label: "", status: "online",
    os: "windows", arch: "amd64", version: "2026.10.12+1234567",
    sensor_version: "2026.10.12+1234567", host_kind: "workstation",
    last_heartbeat_at: iso(0), cpu_percent: 32, memory_rss_bytes: 48 * 1024 ** 2,
    queue_depth: 0, telemetry_queue_depth: 0, latest_export_at: iso(0),
    exports: 24, log_records: 240, metric_points: 48, spans: 24,
  };
  const samples = times.map((time, i) => ({
    time, cpu_percent: 15 + i * 2, memory_percent: 20 + i,
    memory_rss_bytes: (32 + i) * 1024 ** 2, disk_percent: 88.7,
    disk_read_bytes_per_second: i * 2048, disk_write_bytes_per_second: i * 1024,
    cpu_count: 8, memory_used_bytes: (4 + i) * 1024 ** 3, memory_total_bytes: 32 * 1024 ** 3,
    disk_used_bytes: 29877923840, disk_total_bytes: 33702133760,
    service_cpu_percent: { postgres: 18 + i, server: 2, dashboard: null },
  }));
  const totals = {
    cost_usd: 1.25, calls: 24, priced_calls: 24, unpriced_calls: 0,
    reported_calls: 24, calculated_calls: 0, demo_calls: 0, tokens: 24000,
    usage_calls: 24, pending_calls: 0, failed_calls: 0, input_tokens: 20000, output_tokens: 4000,
  };
  const costs = {
    range: "24h", since: iso(24), until: iso(0), bucket_seconds: 3600,
    summary: totals,
    series: times.map((time, i) => ({ ...totals, time, cost_usd: (i % 7) * 0.03 })),
    by_model: [{ ...totals, name: "gpt-5" }],
    configured_models: { detection: "gpt-5", guardrail: "gpt-5" },
  };
  const dimensions = ["user", "model", "project", "activity", "reasoning_effort"];
  const latency = { e2e_p50: 200, e2e_p95: 400, e2e_p99: 600, policy_p50: 1, policy_p95: 2, policy_p99: 3 };
  const decisions = { total: 10, allow: 7, warn: 1, ask: 1, deny: 1, ...latency };
  const action = {
    id: "action-1", time: iso(0), received_at: iso(0), kind: "command", sensor_id: sensor.id,
    agent: { product: "codex-cli", account: "dev@example.invalid" },
    host: { hostname: sensor.hostname, user: "dev" }, session: { id: "session-1", cwd: "/srv/app" },
    source: { collector: "hook" }, command: { text: "npm test" }, tool: { name: "Bash", call_id: "call-1" },
    risk: { status: "scored", score: 4, level: "info", category: "none" },
  };
  const responses: Record<string, unknown> = {
    "auth/me": { user: { id: "u", name: "Test operator", email: "test@example.invalid", roles: ["it_admin", "security_analyst", "security_leadership"], tenant: { id: "t", name: "Test tenant", slug: "test" } } },
    overview: {
      range: "30d", agents: { total: 4, active: 3 }, sessions: 22,
      sensors: { total: 2, online: 1, disabled: 0, offline: 1 },
      findings_open: { critical: 23, high: 95, medium: 473, low: 0, info: 0 },
      by_category: [{ category: "destructive_command", count: 230 }], recent_findings: [],
      timeline: Array.from({ length: 31 }, (_, i) => ({
        bucket: iso((30 - i) * 24 + 12), findings: i < 26 ? 0 : [5, 149, 258, 77, 102][i - 26],
      })),
    },
    "user-risk": { items: [], total_findings: 0 },
    "system/status": { version: "test", services: [], database: { ok: true, latency_ms: 2 }, ingest: { sensors_online: 1, events_last_hour: 24 } },
    "system/database": { ok: false, checked_at: iso(0), latency_ms: null, pools: [], activity: null },
    "system/metrics": { status: "ok", message: "", hostname: "Test server", disk_path: "/var/lib", interval_seconds: 3600, last_sample_at: times.at(-1), samples },
    "sensors/health": { items: [sensor] },
    "sensors/sensor-a/metrics": {
      sensor_id: sensor.id, range: "24h", generated_at: iso(0), window_start: iso(24), bucket_seconds: 3600,
      latest: sensor, samples,
    },
    "telemetry/overview": {
      range: "24h", service: null, bucket_seconds: 3600, generated_at: iso(0), window_start: iso(24),
      summary: { exports: 24, records: 312, log_records: 240, metric_points: 48, spans: 24, devices: 1, online_devices: 1, offline_devices: 0, disabled_devices: 0, last_export_at: iso(0) },
      activity: times.map((start) => ({ start, exports: 1, log_records: 10, metric_points: 2, spans: 1 })),
      available_services: ["claude-code"],
      services: [{ name: "claude-code", exports: 24, log_records: 240, metric_points: 48, spans: 24, last_export_at: iso(0) }],
      devices: [sensor], recent_exports: [],
    },
    "costs/agents/summary": {
      ...costs, price_date: "2026-10-12",
      ...Object.fromEntries(dimensions.map((key) => [`by_${key}`, [{ ...totals, name: key === "model" ? "gpt-5" : "dev" }]])),
      user_series: [{ ...totals, name: "dev", series: costs.series }],
      available_filters: Object.fromEntries(dimensions.map((key) => [key, []])),
      filters_truncated: Object.fromEntries(dimensions.map((key) => [key, false])),
      pagination: Object.fromEntries(dimensions.map((key) => [key, { offset: 0, sort: "cost_usd", order: "desc", limit: 25, total: 1, maximum: null }])),
    },
    credits: creditFixture("24h", "t", now),
    "guardrail/stats": {
      source: "endpoints",
      range: "24h", since: iso(24), until: iso(0), bucket_seconds: 3600,
      executions: { total: 400, failed: 8 }, totals: { ...decisions, legacy: 0 }, rules: [],
      series: times.map((start) => ({ start, ...decisions, executions: { total: 20, failed: 1 } })),
    },
    "response/hook-settings": { mode: "shadow", version: 0, updated_at: null },
    "events/live": { items: [action], cursor: "c1", more: false },
    "guardrail/active": { since: iso(1), until: iso(0), users: 1, sessions: 1, prompts: 0, tool_calls: 1, tool_results: 0, decisions: 1, allow: 1, warn: 0, ask: 0, deny: 0, labels: [] },
    "guardrail/checks": {
      items: [{ id: "check-1", created_at: iso(1 / 60), sensor_id: sensor.id, sensor_hostname: sensor.hostname, sensor_username: "dev", product: "codex-cli", session_id: "session-1", hook_event: "PreToolUse", actions: [action], mode: "shadow", status: "evaluated", evaluated_decision: "allow", returned_decision: "allow", delivery_status: "unconfirmed", delivered_decision: null, assessment: action.risk, reason: "", rule_name: "", failure_reason: "" }],
      next_cursor: "",
    },
  };
  await page.route("**/api/v1/**", (route) => {
    const url = new URL(route.request().url());
    const key = url.pathname.replace("/api/v1/", "");
    if (key === "guardrail/flow") {
      const checks = responses["guardrail/checks"] as { items: Record<string, unknown>[] };
      return route.fulfill({ json: activityFixture(checks.items, new URLSearchParams({ until: iso(0), ...Object.fromEntries(url.searchParams) })).summary });
    }
    if (key === "guardrail/stats") {
      const range = url.searchParams.get("range") || "24h";
      const [count, bucket] = ({ "1h": [60, 60], "24h": [24, 3600], "7d": [28, 21600], "30d": [30, 86400] })[range] || [24, 3600];
      const since = now - count * bucket * 1000;
      const endpoint = responses[key] as GuardrailStats;
      const endpointCounts = { ...decisions, total: count * 10, allow: count * 7, warn: count, ask: count, deny: count };
      const endpoints = { ...endpoint, totals: { ...endpointCounts, legacy: 0 }, executions: { total: count * 20, failed: count },
        rules: [{ ...endpointCounts, rule_id: "", rule_name: "", action: "allow", in_policy: false, last_seen_at: iso(0) }],
        range, since: new Date(since).toISOString(), bucket_seconds: bucket,
        series: Array.from({ length: count }, (_, i) => ({ ...endpoint.series[i % 24], start: new Date(since + i * bucket * 1000).toISOString() })) };
      const gatewayCounts = { total: 4, allow: 3, deny: 1, ask: 0, warn: 0,
        e2e_p50: 160, e2e_p95: 320, e2e_p99: 480, policy_p50: 80, policy_p95: 120, policy_p99: 160 };
      const gateways = { ...endpoints, source: "gateways", executions: undefined,
        totals: { ...gatewayCounts, total: count * 4, allow: count * 3, deny: count, legacy: 0 }, availability: { total: count * 5, unavailable: count }, rules: [],
        series: endpoints.series.map((row) => ({ ...row, ...gatewayCounts, executions: undefined, availability: { total: 5, unavailable: 1 } })) };
      const source = url.searchParams.get("source") || "all";
      const endpointHistory = historyFixture(endpoints);
      const gatewayHistory = historyFixture({ ...gateways, executions: { total: count * 5, failed: count },
        series: gateways.series.map((row) => ({ ...row, executions: { total: 5, failed: 1 } })) }, "gateways");
      gatewayHistory.totals.not_evaluated = count * 2;
      gatewayHistory.totals.unconfirmed = count;
      const totals = { ...endpointHistory.totals, total: count * 14, allow: count * 10, deny: count * 2,
        attempted: count * 25, failed: count * 2, not_evaluated: count * 2, unconfirmed: count,
        latency_samples: count * 14, e2e_p50: 180, e2e_p95: 360, e2e_p99: 540 };
      const all = { ...endpointHistory, source: "all", totals,
        sources: { ...endpointHistory.sources, ...gatewayHistory.sources },
        series: endpointHistory.series.map(({ start }) => ({ ...totals, start, total: 14, allow: 10, warn: 1, ask: 1, deny: 2,
          attempted: 25, failed: 2, not_evaluated: 2, unconfirmed: 1, latency_samples: 14, legacy: 0 })) };
      return route.fulfill({ json: source === "all" ? all : source === "gateways" ? gatewayHistory : endpointHistory });
    }
    if (key === "events/live" && url.searchParams.has("after"))
      return route.fulfill({ json: { items: [], cursor: "c1", more: false } });
    return route.fulfill({ json: responses[key] ?? { items: [], next_cursor: "" } });
  });
}
