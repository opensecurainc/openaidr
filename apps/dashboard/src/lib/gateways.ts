import plugins from "../../../../src/openaidr/core/gateway-plugins.json";

export const gatewayPlugins = plugins;
export type GatewayKind = keyof typeof plugins;
export function gatewayPluginLabel(kind: string) {
  return Object.hasOwn(plugins, kind) ? plugins[kind as GatewayKind].label : "Unknown plugin";
}

export type GatewayMode = "shadow" | "enforce";
export type Gateway = {
  id: string;
  name: string;
  kind: string;
  environment: string;
  enabled: boolean;
  mode: GatewayMode;
  capture_content: boolean;
  policy_rule_ids: string[];
  version: number;
  status: "never_seen" | "reporting" | "stale" | "disabled";
  node_count: number;
  last_seen_at: string | null;
  created_at: string;
  updated_at: string;
};
export type GatewayCredential = { id: string; created_at: string; revoked_at?: string | null };
export type CreatedGatewayCredential = GatewayCredential & { token: string };
export type GatewayDetail = {
  gateway: Gateway;
  nodes: { node_id: string; plugin_version: string; gateway_version?: string; kong_version?: string; last_seen_at: string; status: "reporting" | "stale"; dropped_events: number | null }[];
  routes: { node_id: string; route_id: string; service_id: string; protocol: string; last_seen_at: string }[];
  credential: GatewayCredential | null;
  coverage: "observed_only";
};
export type GatewayOverview = {
  window_hours: number;
  gateways: { total: number; reporting: number; stale: number; never_seen: number; disabled: number };
  requests: { total: number; evaluated: number; unavailable: number; allowed: number; denied: number; would_deny: number; blocked: number; fail_open: number; forwarded: number; unconfirmed: number };
  policy_latency_ms: { p50: number | null; p95: number | null };
  coverage: "observed_only";
};
export type GatewayRequest = {
  id: string;
  gateway_id: string;
  gateway_name: string;
  gateway_kind?: string;
  request_id: string;
  node_id: string;
  route_id: string;
  service_id: string;
  consumer_id: string;
  consumer_name?: string;
  application_name?: string;
  provider: string;
  model: string;
  protocol: string;
  stream: boolean;
  status: "pending" | "evaluated" | "unavailable";
  mode: GatewayMode | null;
  evaluated_decision: string | null;
  returned_decision: string | null;
  outcome: "blocked" | "forwarded" | "fail_open" | "unconfirmed" | null;
  status_code: number | null;
  latency_ms: number | null;
  policy_latency_ms: number | null;
  reason: string;
  failure_reason: string;
  created_at: string;
  completed_at: string | null;
};
export type GatewayRequestDetail = GatewayRequest & {
  messages: unknown[] | null;
  assessment: Record<string, unknown> | null;
  usage: null;
  settings_version: number | null;
  policy_version: number | null;
};

export const gatewayStatuses = {
  reporting: "Reporting", stale: "Heartbeat delayed", never_seen: "Awaiting connection", disabled: "Disabled",
} as const;

export function gatewayDecision(value: string | null) {
  const labels: Record<string, string> = { allow: "Allow", deny: "Deny", ask: "Ask", warn: "Warn" };
  return labels[value ?? ""] || "Unavailable";
}

export function gatewayOutcome(value: GatewayRequest["outcome"]) {
  return value === "blocked" ? "Blocked" : value === "forwarded" ? "Forwarded"
    : value === "fail_open" ? "Fail open" : "Unconfirmed";
}

export function gatewayMetric(value: number | null | undefined, unit = "") {
  return typeof value === "number" && Number.isFinite(value)
    ? `${value.toLocaleString(undefined, { maximumFractionDigits: 1 })}${unit}` : "Unavailable";
}
