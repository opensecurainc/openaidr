import type { AgentEvent } from "@/lib/api";
import type { StatusTone } from "@/components/ui/status";

export type Decision = "allow" | "warn" | "ask" | "deny";
export const DECISIONS: readonly Decision[] = ["allow", "warn", "ask", "deny"];

type Counts = { total: number } & Record<Decision, number>;
type Latency = Record<
  `${"e2e" | "policy"}_${"p50" | "p95" | "p99"}`,
  number | null
>;

/** `GET /api/v1/guardrail/active`: the last five minutes. */
export type GuardrailActive = Record<Decision, number> & {
  since: string;
  until: string;
  users: number;
  sessions: number;
  prompts: number;
  tool_calls: number;
  tool_results: number;
  decisions: number;
  labels: { category: string; level: string; count: number }[];
  jev?: {
    calls: number;
    pending_calls: number;
    failed_calls: number;
    priced_calls: number;
    cost_usd: number | null;
    latency_samples: number;
    latency_p95_ms: number | null;
  };
};

/** `GET /api/v1/guardrail/stats`. Counts are by evaluated policy decision. */
export type GuardrailStats = {
  source: "endpoints" | "gateways";
  range: string;
  since: string;
  until: string;
  bucket_seconds: number;
  totals: Counts & Latency & { legacy: number };
  executions?: { total: number; failed: number };
  availability?: { total: number; unavailable: number };
  series: (Counts & Latency & {
    start: string;
    executions?: { total: number; failed: number };
    availability?: { total: number; unavailable: number };
  })[];
  rules: (Counts &
    Latency & {
      rule_id: string;
      rule_name: string;
      action: string;
      in_policy: boolean;
      last_seen_at: string;
    })[];
};

export type HistoryMetrics = Counts & Pick<Latency, "e2e_p50" | "e2e_p95" | "e2e_p99"> & {
  legacy: number;
  latency_samples: number;
  attempted: number;
  failed: number;
  not_evaluated: number;
  unconfirmed: number;
};
type HistoryGroup = { totals: HistoryMetrics; series: (HistoryMetrics & { start: string })[] };
export type GuardrailHistoryStats = HistoryGroup & {
  source: "all" | GuardrailStats["source"];
  range: string;
  since: string;
  until: string;
  bucket_seconds: number;
  sources: Partial<Record<GuardrailStats["source"], HistoryGroup>>;
  rules: GuardrailStats["rules"];
};

export const DECISION_LABELS: Record<Decision, string> = {
  allow: "Allowed",
  warn: "Warned",
  ask: "Approval asked",
  deny: "Denied",
};
export const DECISION_TONES: Record<Decision, StatusTone> = {
  allow: "ok",
  warn: "warning",
  ask: "warning",
  deny: "critical",
};
export const RULE_ACTION_VARIANTS = {
  allow: "ok",
  warn: "warning",
  ask: "warning",
  deny: "destructive",
} as const;

export function isDecision(value: unknown): value is Decision {
  return typeof value === "string" && (DECISIONS as string[]).includes(value);
}

/** A sensor's own policy decision, not the agent's native permission record. */
export function isGuardrailDecision(event: AgentEvent) {
  return (
    event.kind === "hook.decision" &&
    typeof event.source === "object" &&
    event.source?.collector === "hook"
  );
}

/** What the agent was told to do: an `ask` rule on Codex is enforced as `deny`. */
export function enforcedDecision(event: AgentEvent): Decision | null {
  const value = event.hook?.enforced || event.hook?.decision;
  return isDecision(value) ? value : null;
}

export type ActionType = "prompt" | "tool" | "result";
export const ACTION_LABELS: Record<ActionType, string> = {
  prompt: "Prompt",
  tool: "Tool call",
  result: "Tool output",
};
/** Presentation only: keep reported identifiers intact for grouping and evidence. */
export function identityPresentation(account: string, host?: AgentEvent["host"]) {
  const opaque = /^(?:[a-f0-9]{32,}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})$/i.test(account);
  const title = [
    account && `Reported identity: ${account}`,
    host?.user && `OS user: ${host.user}`,
    host?.hostname && `Device: ${host.hostname}`,
  ].filter(Boolean).join("\n");
  if (account && !opaque) return { label: account, detail: "Reported account", title };
  if (host?.user) return {
    label: `OS user: ${host.user}`,
    detail: host.hostname ? `Device: ${host.hostname}` : "Device not reported",
    title,
  };
  if (host?.hostname) return { label: host.hostname, detail: "Device · user not reported", title };
  return {
    label: account ? "Reported ID" : "Unattributed",
    detail: account ? `${account.slice(0, 12)}…` : "User not reported",
    title: title || "No user identity reported",
  };
}

export const percentOf = (part: number, total: number) =>
  total > 0 ? (part / total) * 100 : null;

export function formatPercent(value: number | null) {
  if (value === null) return "No data";
  if (value > 0 && value < 0.1) return "<0.1%";
  if (value > 99.9 && value < 100) return ">99.9%";
  return `${value.toFixed(value < 10 || (value > 99 && value < 100) ? 1 : 0)}%`;
}

export function formatMs(value: number | null | undefined) {
  if (value === null || value === undefined || !Number.isFinite(value))
    return "No samples";
  if (value >= 1000) return `${(value / 1000).toFixed(2)} s`;
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`;
}
