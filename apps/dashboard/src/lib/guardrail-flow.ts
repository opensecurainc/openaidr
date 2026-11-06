import { type AgentEvent, type EventRisk } from "@/lib/api";
import type { GatewayRequestDetail } from "@/lib/gateways";
import { type Decision } from "@/lib/guardrail";

export type FlowDecision = "all" | Decision | "unavailable" | "unknown";
export type LinkAssessment = {
  provider: "google_web_risk";
  status: "matched" | "not_listed" | "partial" | "unavailable" | "no_urls";
  checked: number;
  skipped: number;
  failed: number;
  reasons: string[];
  matches: { url: string; threat_types: string[]; expires_at: string }[];
};
export type HookDecision = {
  source?: "endpoint";
  id: string;
  sensor_hostname: string;
  sensor_username: string;
  sensor_id: string;
  product: string;
  hook_event: string;
  session_id: string;
  mode: "shadow" | "enforce";
  status: "evaluated" | "unavailable";
  evaluated_decision: Decision | null;
  returned_decision: Decision | null;
  reason: string;
  rule_name: string;
  failure_reason: string;
  created_at: string;
  delivery_status: "unconfirmed" | "delivered" | "timed_out" | "failed";
  delivered_decision: Decision | null;
  actions: AgentEvent[];
  assessment: ((EventRisk | { status: "unavailable"; reason: string }) & { links?: LinkAssessment }) | null;
};
export type GatewayCheck = Omit<GatewayRequestDetail, "status" | "assessment" | "evaluated_decision" | "returned_decision"> & {
  source: "gateway";
  status: "evaluated" | "unavailable";
  assessment: HookDecision["assessment"];
  evaluated_decision: Decision | null;
  returned_decision: Decision | null;
};
export type GuardrailCheck = HookDecision | GatewayCheck;
export type GuardrailCheckPage = { items: GuardrailCheck[]; next_cursor: string };
export type ActivitySource = "all" | "endpoints" | "gateways";
export function checkKey(record: GuardrailCheck) {
  return `${record.source || "endpoint"}:${record.id}`;
}

export function checkDecision(record: GuardrailCheck): Exclude<FlowDecision, "all"> {
  return record.status === "unavailable" ? "unavailable" : record.evaluated_decision || "unknown";
}
