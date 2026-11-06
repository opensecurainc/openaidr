import type { InvestigationSettlement } from "./investigationSettlement";
// Typed models mirroring docs/api.md. Field names are the wire names.

export type Product = "claude-code" | "codex-cli" | "gemini-cli" | "copilot-cli" | "cursor" | "aider" | "unknown";
export type OS = "darwin" | "linux" | "windows";
export type EventKind =
  | "session.start" | "session.end" | "prompt" | "response" | "tool.call" | "tool.result"
  | "command" | "file.read" | "file.write" | "network" | "hook.decision" | "sensor";

export const EVENT_KINDS: EventKind[] = [
  "session.start", "session.end", "prompt", "response", "tool.call", "tool.result",
  "command", "file.read", "file.write", "network", "hook.decision", "sensor",
];
export const PRODUCTS: Product[] = ["claude-code", "codex-cli", "gemini-cli", "copilot-cli", "cursor", "aider"];

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export type FindingStatus = "open" | "triaged" | "resolved" | "false_positive";
export const FINDING_STATUSES: FindingStatus[] = ["open", "triaged", "resolved", "false_positive"];
export type Category =
  | "secret_exfiltration" | "data_exfiltration" | "supply_chain"
  | "destructive_command" | "excessive_agency" | "hallucination";
export const CATEGORIES: Category[] = [
  "secret_exfiltration", "data_exfiltration", "supply_chain",
  "destructive_command", "excessive_agency", "hallucination",
];
export type Role = "owner" | "admin" | "analyst" | "viewer";
export const ROLES: Role[] = ["owner", "admin", "analyst", "viewer"];
export type HostKind = "workstation" | "server";

export interface Host { hostname: string; os: OS; arch: string; user: string }

export interface ApiEvent {
  id: string;
  time: string;
  observed_at: string;
  received_at: string;
  kind: EventKind;
  tenant_id: string;
  sensor_id: string;
  agent_id: string;
  session_id: string;
  host: Host;
  agent: { product: Product; version?: string; model?: string };
  session: { id: string; parent_id?: string; cwd?: string; git_branch?: string; entrypoint?: string };
  tool?: { name: string; call_id?: string; input?: unknown; output?: string; is_error?: boolean; caller?: string };
  command?: { text: string; description?: string; cwd?: string; exit_code?: number | null; background?: boolean };
  file?: { path: string; op: string; bytes?: number };
  network?: { url: string; host: string; method?: string };
  hook?: { hook_event: string; decision: "allow" | "ask" | "deny" | "warn"; enforced?: string; rule_id?: string; reason?: string };
  text?: string;
  truncated?: boolean;
  redacted?: boolean;
  source: { collector: string; path?: string; line?: number; record_id?: string };
}

export interface Agent {
  id: string;
  sensor_id: string;
  product: Product;
  version: string;
  host: Host;
  models: string[];
  first_seen: string;
  last_seen: string;
  sessions_total: number;
  events_total: number;
  findings_open: number;
  status: "active" | "idle";
}

export interface Session {
  id: string;
  external_id: string;
  agent_id: string;
  sensor_id: string;
  product: Product;
  cwd: string;
  git_branch: string;
  started_at: string;
  last_event_at: string;
  ended_at: string | null;
  events_total: number;
  tool_calls: number;
  commands: number;
  findings_open: number;
}

export interface UserRef { id: string; name: string }

export interface Finding {
  id: string;
  rule_id: string;
  rule_name: string;
  category: Category;
  severity: Severity;
  status: FindingStatus;
  title: string;
  summary: string;
  agent_id: string;
  session_id: string;
  sensor_id: string;
  host: Host;
  product: Product;
  event_ids: string[];
  first_event_at: string;
  assignee: UserRef | null;
  resolution: string;
  created_at: string;
  updated_at: string;
}

export interface Note { id: string; finding_id: string; author: UserRef; body: string; created_at: string }

export type ResponseActionType = "block_command" | "block_path" | "block_host" | "disable_sensor" | "enable_sensor" | "note";
export const RESPONSE_ACTION_TYPES: ResponseActionType[] = ["block_command", "block_path", "block_host", "disable_sensor", "enable_sensor", "note"];
export type ResponseActionStatus = "pending" | "applied" | "failed";

export interface ResponseAction {
  id: string;
  finding_id: string | null;
  type: ResponseActionType;
  params: Record<string, string>;
  status: ResponseActionStatus;
  created_by: UserRef;
  created_at: string;
  applied_at: string | null;
}

export interface FindingDetail { finding: Finding; events: ApiEvent[]; notes: Note[]; actions: ResponseAction[] }

export interface DetectionRule {
  id: string;
  name: string;
  category: Category;
  severity: Severity;
  description: string;
  enabled: boolean;
  builtin: boolean;
  findings_30d: number;
}

export type RuleAction = "deny" | "ask" | "warn" | "allow";
export interface RuleMatch {
  kinds?: EventKind[];
  command_regex?: string;
  path_glob?: string;
  host_glob?: string;
  tool_name?: string;
  products?: Product[];
}
export interface PolicyRule {
  id: string;
  name: string;
  action: RuleAction;
  enabled: boolean;
  reason?: string;
  match: RuleMatch;
  source?: string;
}
export interface Policy { version: number; updated_at: string; rules: PolicyRule[] }

export interface CollectorStatus { name: string; status: "running" | "idle" | "disabled" | "error"; files_watched: number; events_total: number; error?: string }

export interface Sensor {
  id: string;
  label: string;
  hostname: string;
  os: OS;
  arch: string;
  user: string;
  host_kind: HostKind;
  version: string;
  status: "online" | "offline" | "disabled";
  disabled: boolean;
  enrolled_at: string;
  last_heartbeat_at: string | null;
  collectors: CollectorStatus[];
  hook_installed: boolean;
  queue_depth: number;
  policy_version: number;
  agents_total: number;
  events_total: number;
}
export interface SensorDetail extends Sensor { agents: Agent[] }

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  status: "active" | "disabled";
  created_at: string;
  last_login_at: string | null;
}
export interface Me { id: string; email: string; name: string; role: Role; tenant: { id: string; name: string; slug: string } }

export interface Invite {
  id: string;
  email: string;
  role: Role;
  expires_at: string;
  accept_url?: string;
  created_at: string;
}
export interface InviteInfo { email: string; tenant_name: string; role: Role; expires_at: string }

export interface EnrollmentToken {
  id: string;
  label: string;
  token?: string;
  created_at: string;
  expires_at: string | null;
  uses: number;
  max_uses: number;
  revoked_at: string | null;
}

export interface ServiceStatus { name: string; status: "ok" | "stale"; last_seen_at: string; lag_events?: number; last_run_at?: string }
export interface SystemStatus {
  version: string;
  services: ServiceStatus[];
  database: { ok: boolean; latency_ms: number };
  ingest: { events_last_hour: number; sensors_online: number };
}

export interface AuditEntry {
  id: string;
  at: string;
  actor: UserRef;
  action: string;
  target_type: string;
  target_id: string;
  details: Record<string, unknown>;
}

export interface PlatformAuditEntry extends AuditEntry {
  actor: UserRef & { type: string };
  tenant: { id: string; name: string } | null;
}

export type Range = "24h" | "7d" | "30d";
export interface Overview {
  range: Range;
  agents: { total: number; active: number };
  sessions: number;
  events: number;
  sensors: { total: number; online: number; offline: number; disabled: number };
  findings_open: Record<Severity, number>;
  by_category: { category: Category; count: number }[];
  by_product: { product: Product; agents: number; events: number }[];
  timeline: { bucket: string; events: number; findings: number }[];
  top_agents: { agent_id: string; product: Product; hostname: string; user: string; events: number }[];
  recent_findings: Finding[];
}

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended" | "deleted";
  plan: string;
  created_at: string;
  owner_email: string;
  users_total: number;
  sensors_total: number;
  sensors_online: number;
  events_24h: number;
  findings_open: number;
}
export interface TenantDetail {
  tenant: Tenant;
  users: User[];
  invites: Invite[];
  sensors: Sensor[];
  enrollment_tokens: EnrollmentToken[];
}
export interface TenantCreated { tenant: Tenant; invite: Invite; enrollment_token: EnrollmentToken }
export interface PlatformEmailStatus { total: number; pending: number; sent: number; failed: number; cancelled: number }
export interface PlatformAdmin { id: string; email: string; name: string; created_at: string; last_login_at: string | null; admission_status?: "pending" | "active" | "revoked"; invitation_emails?: PlatformEmailStatus | null }
export interface AdminMe { id: string; email: string; name: string }

export type DeploymentEnvironment = "opensecura-0" | "development" | "production" | "on-prem";
export interface DeploymentTarget {
  provisioning_enabled?: boolean;
  model_keys_available?: boolean;
  id: DeploymentEnvironment; label: string; kind: "gcp" | "onprem"; project_id: string | null;
  setup_policy: { version: number; features: Record<string, boolean>; external_ai: string; identity: string; console_access: string; credentials: string; operations: string; external_telemetry: string; runtime: string };
  hostname_suffix?: string; allowed_zones?: string[]; allowed_releases?: string[];
  release_labels?: Record<string,string>; release_available?: boolean;
}
export interface DeploymentSettings {
  vm_lifecycle_enabled?: boolean;
  model_keys_available?: boolean;
  project_id: string; hostname_suffix: string; allowed_zones: string[];
  allowed_project_ids?: string[];
  allowed_machine_types: string[]; suggested_data_disk_sizes_gb: number[];
  min_data_disk_size_gb: number; max_data_disk_size_gb: Record<string, number>;
  allowed_releases: string[]; release_labels?: Record<string, string>; management_enabled: boolean; deployment_targets?: DeploymentTarget[];
}
export interface DeploymentRequest {
  model_keys_from_secret_manager?: boolean;
  name: string; slug: string; approved_domains: string[];
  initial_owner_email: string; initial_owner_name: string;
  zone?: string | null; release_id: string; trial_expires_at: string; environment?: DeploymentEnvironment; site_hostname?: string;
  machine_type?: string | null; data_disk_size_gb?: number; project_id?: string | null;
}
export interface Deployment extends DeploymentRequest {
  id: string; hostname: string; project_id: string | null; requested_by: string; deployment_target?: DeploymentTarget | null;
  approved_by: string | null; approved_at: string | null;
  desired_state: "unprovisioned" | "active" | "suspended" | "deleted";
  observed_state: "absent" | "unknown" | "active" | "suspended" | "deleted";
  desired_generation: number; observed_generation: number; observed_at: string | null;
  last_job_id: string | null; created_at: string; updated_at: string;
  archived_at?: string | null; archived_by?: string | null;
  /** Approved, never active, and its latest provisioning job failed; archivable before expiry. */
  provisioning_failed?: boolean;
}
export type DeploymentStatusKey = "active" | "awaiting_approval" | "suspended" | "suspension_not_confirmed" | "resume_not_confirmed" | "not_provisioned" | "not_confirmed" | "deleted";
/** Values present among unarchived environments; "none" stands for an on-premises environment's missing project or zone. */
export interface DeploymentFilterOptions { owners: string[]; statuses: DeploymentStatusKey[]; projects: string[]; zones: string[] }
export interface DeploymentJob {
  release_id?: string;
  id: string; deployment_id: string; operation: string; target_generation: number;
  state: "queued" | "running" | "succeeded" | "failed"; attempt: number;
  created_at: string; updated_at: string; completed_at: string | null;
  error_code: string | null;
  retry_epoch?: number | null;
  next_attempt_at?: string | null;
  /** Recorded worker steps and their states; names and states only. */
  step_states?: Record<string, "intent" | "pending" | "complete" | "failed">;
}
export interface AdminOverview {
  tenants: { total: number; active: number; suspended: number };
  sensors: { total: number; online: number };
  events_24h: number;
  findings_open: number;
  recent_tenants: Tenant[];
}

export interface Page<T> { items: T[]; next_cursor: string }

export interface InstallationPackage {
  source_commit: string; filename: string; size: number; distribution_sha256: string;
  host_profile_id: string; qualified_at: string; signer_spki_sha256: string;
}

export interface ApiCostTotals {
  calls: number;
  priced_calls: number;
  unpriced_calls: number;
  usage_calls: number;
  pending_calls: number;
  failed_calls: number;
  input_tokens: number | null;
  output_tokens: number | null;
  cost_usd: string | null;
}
export interface ApiCostTenant {
  investigation_settlement?: InvestigationSettlement;
  id: string;
  name: string;
  slug: string;
  report_status: "local" | "current" | "syncing" | "stale" | "not_reported";
  reported_at: string | null;
  summary: ApiCostTotals;
  by_provider: Record<"openai" | "typesafe", ApiCostTotals>;
}
export interface ApiCostDay {
  date: string;
  tenant_id: string;
  provider: "openai" | "typesafe";
  calls: number;
  priced_calls: number;
  unpriced_calls: number;
  cost_usd: string | null;
}
export interface ApiCosts {
  range: string;
  since: string | null;
  until: string;
  currency: "USD";
  cloud: boolean;
  summary: ApiCostTotals;
  by_provider: Record<"openai" | "typesafe", ApiCostTotals>;
  items: ApiCostTenant[];
  daily?: ApiCostDay[];
}
