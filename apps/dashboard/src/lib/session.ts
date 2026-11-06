import { displayText } from "@/lib/display";
import { money } from "@/lib/cost";

/** Operator archive DTOs. Owner execution and approval APIs are separate. */
export type JsonObject = Record<string, unknown>;
export type ArchivePage<T> = { items: T[]; next_cursor: string };
export type CoverageAxis = { status: string; reasons: string[] };
export type SessionCoverage = Record<"content" | "delivery" | "assessment" | "execution", CoverageAxis> & {
  status: string;
  scope: string;
  gaps: string[];
};
export type SessionCounts = Record<
  "logical_targets" | "assessed" | "unavailable" | "pending" | "missing_assessments" |
  "invalid_assessments" | "blocked" | "pending_approvals" | "approved_unconsumed" |
  "unreported_outcomes" | "uncertain_outcomes", number
>;
export type DetectionState = {
  lifecycle: string;
  risk_total: string | null;
  risk_max: string | null;
  counts: SessionCounts;
  coverage: SessionCoverage;
  last_sequence: number;
  closing_sequence: number | null;
  closing_at: string | null;
  last_activity_at: string | null;
  next_evaluation_at: string | null;
  delivery: { received: number; expected: number | null; complete: boolean; gaps: string[] };
  routing: { status: string; reason: string; job_id: string | null; settings_version: number; detector_config_version: number };
};
export type InvestigationRef = {
  id: string;
  snapshot_id: string;
  revision: number;
  state: string;
  settings_version: number;
  detector_config_version: number;
  routing_reason: string;
  created_at: string;
  completed_at: string | null;
  snapshot_current: boolean;
  configuration_current: boolean;
};
export type SessionSummary = {
  eligibility?: DetectionEligibility;
  session: {
    id: string; agent_id: string; sensor_id: string; external_id: string;
    product: string; cwd: string; git_branch: string;
    started_at: string | null; last_event_at: string | null; ended_at: string | null;
    events_total: number; tool_calls: number; commands: number;
    client: { product: string; version: string };
    device: {
      hostname: string; os: string; arch: string; reported_user: string; sensor_label: string;
      sensor_disabled: boolean; sensor_deleted_at: string | null;
    };
  };
  registration: null | {
    id: string; assessment_mode: string; verified_at: string | null;
    delivery_protocol: number | null; delivery_epoch: string | null;
    owner: null | { id: string; name: string; email: string; status: string };
    owner_available: boolean;
  };
  projection: {
    available: boolean; updated_at: string | null; input_version: number | null; revision: number;
    snapshot_id: string | null; snapshot_current: boolean; dirty: boolean; evaluation_due: boolean;
    settings_changed: boolean; finalization_error: string | null;
  };
  detection: DetectionState | null;
  investigations: ArchivePage<InvestigationRef>;
};
export type DetectionEligibility = {
  status: string; reason: string; evaluated_at: string | null; next_evaluation_at: string | null;
  owner: { id: string; name: string; email: string } | null; history_available: boolean;
  job_id: string | null; job_state: string | null;
};
export type InlineDecision = {
  id: string; request_id: string; settings_version: number; policy_version: number;
  decision: null | { action: string; reason?: string; warnings?: string[] };
  requested_policy_floor: string | null; approval_id: string | null;
  created_at: string; completed_at: string | null;
};
export type ApprovalGeneration = {
  id: string; originating_check_id: string; generation: number; settings_version: number; policy_version: number;
  status: string; created_at: string; expires_at: string; decision: string | null;
  decided_at: string | null; decided_by_user_id: string | null; approved_until: string | null;
  revoked_at: string | null; reason_code: string | null;
};
export type GuardrailAction = {
  id: string; action_id: string | null; event_id: string; logical_id: string; created_at: string;
  origin: "inline_assessment" | "delivery_receipt"; target_body: JsonObject; captured_context: JsonObject | null;
  assessment: {
    status: "pending" | "scored" | "unavailable" | "missing";
    model: string | null; rubric_version: number | null; value: JsonObject | null;
    started_at: string | null; completed_at: string | null;
  };
  latest_decision: InlineDecision | null; decision_count: number; approval_count: number;
  latest_approval: ApprovalGeneration | null;
  release: null | {
    id: string; check_id: string; approval_id: string | null; consumed_at: string;
    outcome: string | null; outcome_at: string | null; outcome_details: JsonObject | null; outcome_audit_id: string | null;
  };
  reported_outcome: null | {
    id: string; sequence: number; payload: JsonObject; captured_body: JsonObject | null; received_at: string;
  };
};
export type SnapshotItem = {
  ordinal: number; kind: string; source_id: string; body: JsonObject;
  representation?: "customer_service_metadata_v1";
  retained_source_sha256?: string; representation_sha256?: string;
};
export type SnapshotPage = ArchivePage<SnapshotItem> & {
  snapshot: {
    id: string; sensor_id: string; session_id?: string | null; registration_id: string | null; owner_user_id: string | null;
    revision: number; input_version: number; epoch_id: string | null; closing_sequence: number | null;
    lifecycle: string; coverage: SessionCoverage; counts: SessionCounts; risk_total: string | null;
    risk_max: string | null; item_count: number; sealed_at: string; created_at: string;
  };
  pagination: { scope: "immutable"; order: "ordinal_asc"; byte_limit: number };
};
export type EvidenceCitation =
  | { source: "target"; ordinal: number; start: number; end: number }
  | { source: "history"; read_id: string; item: number };
export type InvestigationFinding = {
  title: string; explanation: string; category: string; severity: string; evidence: EvidenceCitation[];
  action_outcomes: { logical_id: string; execution: string; authorization: string }[];
  severity_rationale?: string;
  timeline?: { description: string; evidence_indices: number[] }[];
  impact?: { observed: string; potential: string };
  recommended_actions?: { action: string; rationale: string; priority?: string }[];
  uncertainties?: string[];
  confidence?: string;
  authorization?: { assessment: string; policy_basis: string; policy_quote?: string; policy_revision?: number | null; evidence_indices: number[] };
  alternative_explanations?: string[];
  tags?: string[];
};
export type InvestigationScope = {
  tenant_id: string; user_id: string | null; ownership_verified: boolean;
  subject?: { name: string; email: string; reported_user: string; hostname: string; ownership_verified: boolean };
  devices?: { hostname?: string; user?: string; os?: string; arch?: string }[];
  projects?: string[];
  target_sessions?: { session_id: string | null; snapshot_id: string; revision: number; started_at: string | null; ended_at: string | null }[];
  reviewed_sessions: { session_id: string | null; snapshot_id: string; revision: number; started_at: string | null; ended_at: string | null }[];
  context_sessions: { session_id: string | null; snapshot_id: string | null; read_id: string }[];
  review_cutoff: string; detector_config_version: number;
};
export type InvestigationOutcome = "actionable_findings" | "no_actionable_findings" | "inconclusive";
export type InvestigationVerdict = "true_positive" | "false_positive" | "true_positive_non_malicious";
export type InvestigationReportListItem = {
  id: string; job_id: string; session_id: string | null; snapshot_id: string; report_attempt_id: string | null;
  state: string; created_at: string; completed_at: string | null; title: string; summary: string;
  outcome: InvestigationOutcome | null; severity: string | null; confidence: string | null;
  verdict?: InvestigationVerdict | null;
  subject: { name: string | null; email: string | null; reported_user: string | null; hostname: string | null; ownership_verified: boolean };
  snapshot_current: boolean; configuration_current: boolean;
};
export type InvestigationReport = {
  status: string; summary: string; findings: InvestigationFinding[]; gaps: string[]; reason?: string;
  title?: string; conclusion?: string; confidence?: string; outcome?: InvestigationOutcome;
  verdict?: InvestigationVerdict | null;
  scope?: InvestigationScope;
  timeline?: { description: string; evidence_indices: number[] }[];
  evidence?: EvidenceCitation[];
  authorization?: { assessment: string; policy_basis: string; policy_quote?: string; policy_revision?: number | null; evidence_indices: number[] };
  impact?: { observed: string; potential: string };
  recommendations?: { priority: string; action: string; rationale: string }[];
  limitations?: string[]; alternative_explanations?: string[];
  coverage?: {
    status: string; target_item_count?: number; target_byte_count?: number; target_chunk_count?: number;
    completed_chunks?: number; completed_steps?: number; inconclusive_steps?: number; gaps?: string[];
  };
  source_coverage?: SessionCoverage; snapshot_id?: string; runtime?: JsonObject | null; model?: string;
  usage?: { actual_tokens: number | null; actual_cost_usd: string | null };
  [key: string]: unknown;
};
export type InvestigationAttempt = {
  id: string; ordinal: number; state: string; created_at: string; dispatched_at: string | null; completed_at: string | null;
  reserved_tokens: number | null; reserved_cost_usd: string | null; actual_tokens: number | null;
  actual_cost_usd: string | null; runtime: JsonObject | null; target_item_count: number | null;
  target_byte_count: number | null; target_chunk_count: number | null;
};
export type InvestigationUsage = {
  request_id: string; attempt_id: string; purpose: string; provider: string; model: string; reported_model: string | null;
  service_tier: string | null; status: string; started_at: string; completed_at: string | null;
  input_tokens: number | null; output_tokens: number | null; cached_input_tokens: number | null;
  cache_write_input_tokens: number | null; reasoning_output_tokens: number | null; cost_usd: string | null;
  price_quote: JsonObject | null;
};
export type InvestigationReadRef = {
  id: string; step_id: string; tool_name: string; status: string; session_id: string | null;
  source_snapshot_id: string | null; response_sha256: string; created_at: string;
};
export type Investigation = {
  id: string; job_id: string; session_id: string | null; registration_id: string | null; snapshot_id: string; snapshot_revision: number;
  state: string; settings_version: number; detector_config_version: number; configuration: JsonObject; routing_reason: string;
  created_at: string; completed_at: string | null; snapshot_current: boolean; configuration_current: boolean;
  report_attempt_id: string | null; report: InvestigationReport | null;
  report_generated_from_state?: boolean;
  attempts: InvestigationAttempt[]; attempt_count: number; attempts_truncated: boolean;
  usage: InvestigationUsage[]; usage_count: number; usage_truncated: boolean;
  reads: InvestigationReadRef[]; read_count: number; reads_truncated: boolean;
};
export type RetainedRead = InvestigationReadRef & {
  job_id: string; attempt_id: string; source_registration_id: string | null; source_sensor_id: string | null;
  response: JsonObject;
  representation?: "customer_service_metadata_v1"; retained_response_sha256?: string;
};
export type SessionSelection = {
  investigation?: string; attempt?: string; snapshot?: string; finding?: number;
  ordinal?: number; start?: number; end?: number; read?: string; item?: number;
};
export type FindingSessionReference = {
  session_id?: string | null; investigation_job_id?: string | null; investigation_attempt_id?: string | null;
  snapshot_id?: string | null; finding_index?: number | null; investigation_evidence?: JsonObject | null;
};

export const isUuid = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);

/** Preserve complete pins. Do not substitute the latest report or snapshot. */
export function sessionHref(id: string, selection: SessionSelection = {}, anchor = "") {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(selection)) {
    if (value !== undefined) query.set(key, String(value));
  }
  return `/sessions/${encodeURIComponent(id)}${query.size ? `?${query}` : ""}${anchor ? `#${anchor}` : ""}`;
}
export function investigationHref(id: string, selection: SessionSelection = {}, anchor = "") {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(selection)) {
    if (key !== "investigation" && value !== undefined) query.set(key, String(value));
  }
  return `/detections/reports/${encodeURIComponent(id)}${query.size ? `?${query}` : ""}${anchor ? `#${anchor}` : ""}`;
}
export function investigationOutcomeLabel(outcome: string | null | undefined, verdict?: InvestigationVerdict | null) {
  if (outcome === "inconclusive") return "Investigation incomplete";
  if (outcome === "no_actionable_findings" && verdict !== "false_positive" && verdict !== "true_positive_non_malicious") return "Not classified";
  return ({
    actionable_findings: "True Positive",
    true_positive: "True Positive",
    false_positive: "False Positive",
    true_positive_non_malicious: "True Positive Non-malicious",
  }[(outcome === "no_actionable_findings" ? verdict : outcome) ?? ""] ?? "Awaiting report");
}

export const detectionCategoryLabel = (category: string) => ({
  data_exposure: "Data exposure and exfiltration",
  data_exfiltration: "Data exposure and exfiltration",
  secret_exfiltration: "Data exposure and exfiltration",
  destructive_activity: "Destructive activity",
  destructive_command: "Destructive activity",
  unauthorized_actions: "Unauthorized actions",
  excessive_agency: "Unauthorized actions",
  agent_compromise: "Agent and supply-chain compromise",
  supply_chain: "Agent and supply-chain compromise",
  acceptable_use: "Acceptable-use violations",
}[category] ?? humanize(category));
export function findingSessionHref(finding: FindingSessionReference) {
  if (!isUuid(finding.session_id)) return null;
  if (!finding.investigation_job_id) return sessionHref(finding.session_id);
  if (!isUuid(finding.investigation_job_id) || !isUuid(finding.investigation_attempt_id) || !isUuid(finding.snapshot_id)) return null;
  return sessionHref(finding.session_id, {
    investigation: finding.investigation_job_id, attempt: finding.investigation_attempt_id,
    snapshot: finding.snapshot_id, finding: finding.finding_index ?? undefined,
  }, "investigation");
}
export function parseSessionSelection(query: Record<string, string | string[] | undefined>): SessionSelection | null {
  const result: SessionSelection = {};
  for (const key of ["investigation", "attempt", "snapshot", "read"] as const) {
    const value = query[key];
    if (value !== undefined) {
      if (!isUuid(value)) return null;
      result[key] = value.toLowerCase();
    }
  }
  for (const key of ["finding", "ordinal", "start", "end", "item"] as const) {
    const value = query[key];
    if (value !== undefined) {
      if (typeof value !== "string" || !/^\d+$/.test(value)) return null;
      const parsed = Number(value);
      if (!Number.isSafeInteger(parsed) || parsed < (key === "ordinal" || key === "end" ? 1 : 0)) return null;
      result[key] = parsed;
    }
  }
  if ((result.attempt || result.finding !== undefined || result.read) && !result.investigation) return null;
  if ((result.ordinal !== undefined || result.start !== undefined || result.end !== undefined) && !result.snapshot) return null;
  if ((result.start === undefined) !== (result.end === undefined)) return null;
  if (result.start !== undefined && (result.ordinal === undefined || result.end! <= result.start)) return null;
  if (result.item !== undefined && !result.read) return null;
  return result;
}
export function decimalValue(value: unknown): number | null {
  if ((typeof value !== "string" || !value.trim()) && typeof value !== "number") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}
export function storedScore(value: unknown) {
  // Retain the server decimal. This is a stored score, not a browser aggregate.
  return decimalValue(value) === null ? "Unavailable" : String(value);
}
export const storedCost = (value: unknown) => money(decimalValue(value));
export const storedCount = (value: unknown) => typeof value === "number" && Number.isFinite(value) ? value.toLocaleString() : "Unavailable";
export const humanize = (value: string | null | undefined) => value ? displayText(value.replaceAll("_", " ")) : "Not recorded";
export const objectValue = (value: unknown): JsonObject | null => value && typeof value === "object" && !Array.isArray(value) ? value as JsonObject : null;
export const textValue = (value: unknown): string => typeof value === "string" ? value : "";
