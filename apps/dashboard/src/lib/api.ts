import type { Role } from "@/lib/roles";
import { displayText } from "@/lib/display";

export type User = {
  id: string;
  email: string;
  name: string;
  roles: Role[];
  tenant: { id: string; name: string; slug: string };
};
export type Export = {
  id: string;
  batch_id: string;
  sensor_id: string;
  hostname: string;
  signal: "logs" | "metrics" | "traces";
  record_count: number;
  service_names: string[];
  received_at: string;
  demo?: boolean;
};
/** One flattened log record, span, or metric data point from a stored export. */
export type ExportRecord = {
  kind: "log" | "span" | "metric";
  time: string | null;
  service: string;
  host?: string | null;
  scope?: string | null;
  attributes: Record<string, unknown>;
  event_name?: string | null;
  severity?: string | null;
  body?: unknown;
  name?: string | null;
  duration_ms?: number | null;
  status?: number | null;
  status_message?: string | null;
  metric_type?: string;
  unit?: string | null;
  value?: unknown;
  trace_id?: string | null;
  span_id?: string | null;
};
export type ExportDetail = Export & {
  total_record_count: number;
  payload_sha256: string;
  first_event_unix_nano: string | null;
  last_event_unix_nano: string | null;
  payload: Record<string, unknown>;
  records: ExportRecord[];
};
/** Reference from a derived event back to the stored OTLP export record. */
export type EventExportRef = {
  id: string;
  /** Index into `ExportDetail.records`. */
  record: number;
  signal: "logs";
};
export type KnowledgeConfig = {
  enabled: boolean;
  revision: number;
  updated_at: string | null;
  documents: {
    id: string;
    kind: "command" | "resource";
    title: string;
    keywords: string[];
    body: string;
  }[];
};
export type KnowledgeSource = {
  source_id: string;
  source_type: "manual" | "markdown" | "upload" | "mcp";
  title: string;
  source_uri: string;
  source_version: string;
  status: "pending" | "current" | "revoked";
  fresh: boolean;
  fresh_until: string | null;
};
export type KnowledgeLibrary = KnowledgeConfig & {
  retrieval_mode: "legacy" | "postgres";
  sources: KnowledgeSource[];
};
export type KnowledgeEvidence = {
  enabled: boolean;
  revision: number | null;
  retrieval_ms: number;
  coverage: string;
  truncated: boolean;
  status?: "matched" | "partial" | "no_match" | "disabled" | "unavailable";
  gaps?: string[];
  category_coverage?: {
    operation: "exact" | "lexical" | "ambiguous" | "unknown" | "overflow" | "missing";
    resource: "exact" | "lexical" | "ambiguous" | "unknown" | "overflow" | "missing";
  };
  documents: {
    id: string;
    kind: "command" | "resource" | "reference";
    title: string;
    text: string;
    matched_keywords: string[];
  }[];
};
export type EventRisk = {
  status: "pending" | "error" | "unscored" | "scored";
  score?: number | null;
  level?: "info" | "low" | "medium" | "high" | "critical" | null;
  category?:
    | "secret_exfiltration"
    | "data_exfiltration"
    | "supply_chain"
    | "destructive_command"
    | "excessive_agency"
    | "hallucination"
    | "none"
    | "unknown";
  confidence?: number;
  category_confidence?: number;
  model?: string;
  rubric_version?: number;
  assessed_at?: string;
  reason?: string;
  knowledge?: KnowledgeEvidence;
};
/**
 * A collected agent event. Events derived from native OTLP telemetry carry
 * `source: "otlp"` and an `export` reference; legacy collector events carry
 * neither. All contract fields beyond the identity are optional until the
 * server ships them.
 */
export type AgentEvent = {
  id: string;
  time: string;
  /** Server arrival time; present on stored events. */
  received_at?: string;
  /** Server identities of the reporting sensor, agent, and session rows. */
  sensor_id?: string;
  agent_id?: string | null;
  session_id?: string | null;
  kind: string;
  risk?: EventRisk | null;
  source?: "otlp" | "collector" | string | { collector?: string };
  export?: EventExportRef | null;
  event_name?: string | null;
  host?: { hostname?: string; user?: string };
  agent?: { product?: string; version?: string; model?: string; account?: string };
  session?: { id?: string; cwd?: string };
  /** Prompt, response, or sensor message text when the collector kept it. */
  text?: string;
  /** Length-only prompt evidence from native telemetry, which never carries text. */
  prompt?: { length?: number };
  tool?: {
    name?: string;
    call_id?: string;
    input?: unknown;
    output?: string;
    is_error?: boolean;
    success?: boolean;
    duration_ms?: number;
  };
  command?: { text?: string; cwd?: string; exit_code?: number };
  file?: { path?: string; op?: string };
  network?: { url?: string; host?: string };
  hook?: {
    hook_event?: string;
    decision?: string;
    reason?: string;
    rule_id?: string;
    rule_name?: string;
    /** Set when the agent could not apply the decision as written. */
    enforced?: string;
    latency_ms?: number;
    e2e_ms?: number;
  };
  decision?: unknown;
  [field: string]: unknown;
};
/** One page of `GET /api/v1/events/live`: arrival-ordered events plus the cursor to poll from. */
export type LiveEvents = { items: AgentEvent[]; cursor: string; more: boolean };
/** "Native telemetry" for events derived from OTLP exports, else "Collector". */
export function eventSourceLabel(event: Pick<AgentEvent, "source">) {
  return event.source === "otlp" ? "Native telemetry" : "Collector";
}
/** The one-line action summary: command, file, URL/host, or tool name. */
export function eventSummary(event: AgentEvent) {
  return (
    event.command?.text ||
    event.file?.path ||
    event.network?.url ||
    event.network?.host ||
    event.tool?.name ||
    (typeof event.decision === "string" ? event.decision : "") ||
    ""
  );
}
function compactJSON(value: unknown, limit = 400) {
  if (value === undefined || value === null) return "";
  const text = typeof value === "string" ? value : JSON.stringify(value);
  return text.length > limit ? text.slice(0, limit) + "…" : text;
}
/**
 * What happened, in the words the collector kept: the prompt text, the
 * command, the tool output, the file or URL. Falls back to the action summary
 * and never invents content that was not stored.
 */
export function eventDetail(event: AgentEvent) {
  const text = typeof event.text === "string" ? event.text.trim() : "";
  switch (event.kind) {
    case "prompt":
      if (text) return text;
      return typeof event.prompt?.length === "number"
        ? `Prompt of ${event.prompt.length} characters (text not exported)`
        : "Prompt text not exported";
    case "response":
      return text || "Response text not exported";
    case "tool.result": {
      // Keep the first line's indentation: excerpts remove the offset all
      // lines share, which needs every line's original columns.
      const output =
        typeof event.tool?.output === "string"
          ? event.tool.output.replace(/^(?:[ \t]*\r?\n)+/, "").trimEnd()
          : "";
      if (output) return output;
      const name = event.tool?.name || "Tool";
      return event.tool?.is_error ? `${name} failed` : `${name} finished`;
    }
    case "tool.call": {
      const name = event.tool?.name || "Tool call";
      const input = compactJSON(event.tool?.input);
      return input ? `${name} ${input}` : name;
    }
    case "hook.decision": {
      const decision = event.hook?.decision || "";
      const reason = event.hook?.reason || "";
      const action = eventSummary({ ...event, decision: undefined });
      return [decision && `${decision}${reason ? `: ${reason}` : ""}`, action]
        .filter(Boolean)
        .join(" · ");
    }
    case "session.start":
      return event.session?.cwd
        ? `Session started in ${event.session.cwd}`
        : "Session started";
    case "session.end":
      return text ? `Session ended: ${text}` : "Session ended";
    case "sensor":
      return text;
    default:
      return eventSummary(event);
  }
}
/** Short label for the agent product identifiers the sensors report. */
export function productLabel(product: string | undefined) {
  switch (product) {
    case "codex-cli":
      return "Codex";
    case "claude-code":
      return "Claude Code";
    case "cowork":
      return "Cowork";
    case "claude-ai":
      return "Claude";
    case "gemini-cli":
      return "Gemini CLI";
    case "copilot-cli":
      return "Copilot CLI";
    case "github-copilot":
      return "GitHub Copilot";
    case "cursor":
      return "Cursor";
    case "antigravity":
      return "Antigravity";
    case "opencode":
      return "OpenCode";
    case "hermes-agent":
      return "Hermes Agent";
    case "workbuddy":
      return "WorkBuddy";
    case "aider":
      return "Aider";
    case undefined:
    case "":
    case "unknown":
      return "Not reported";
    default:
      return displayText(product);
  }
}
export type SensorHealth = {
  status: "healthy" | "needs_attention" | "unknown" | "disabled";
  reasons: { code: string; message: string }[];
  reported_at: string | null;
  stale: boolean;
  report: {
    version: 1;
    activity: { upload_failed: boolean; stalled_for_s: number; last_success_at: string | null; dropped: number };
    telemetry: { enabled: boolean; listening: boolean; upload_failed: boolean; stalled_for_s: number; last_success_at: string | null };
    collectors_failed: number;
  } | null;
};
/** Identifiers the sensor reported about its machine. Empty strings mean not reported. */
export type DeviceIdentity = {
  serial_number: string;
  hardware_uuid: string;
  machine_id: string;
  source: string;
};
/** Another enrollment in the tenant that reported the same serial number or hardware UUID. */
export type SameHardware = {
  id: string;
  label: string;
  hostname: string;
  enrolled_at: string;
  status: "online" | "offline" | "disabled";
};
export type Device = {
  id: string;
  hostname: string;
  label: string;
  os: string;
  arch: string;
  host_kind: string;
  sensor_version: string;
  status: "online" | "offline" | "disabled";
  device?: DeviceIdentity;
  same_hardware?: SameHardware[];
  last_heartbeat_at: string | null;
  telemetry_queue_depth: number | null;
  queue_depth?: number | null;
  health?: SensorHealth;
  cpu_percent?: number | null;
  memory_rss_bytes?: number | null;
  max_memory_rss_bytes_24h?: number | null;
  latest_export_at: string | null;
  exports: number;
  log_records: number;
  metric_points: number;
  spans: number;
};
export type DeviceHealth = Omit<Device,
  "latest_export_at" | "exports" | "log_records" | "metric_points" | "spans"
>;
export type DeviceStatus = Pick<Device, "id" | "hostname" | "label" | "status">;
export type Service = {
  name: string;
  exports: number;
  log_records: number;
  metric_points: number;
  spans: number;
  last_export_at: string | null;
};
export type Overview = {
  range: string;
  service: string | null;
  generated_at: string;
  window_start: string;
  bucket_seconds: number;
  summary: {
    exports: number;
    records: number;
    log_records: number;
    metric_points: number;
    spans: number;
    devices: number;
    online_devices: number;
    offline_devices: number;
    disabled_devices: number;
    last_export_at: string | null;
  };
  activity: {
    start: string;
    exports: number;
    log_records: number;
    metric_points: number;
    spans: number;
  }[];
  available_services: string[];
  services: Service[];
  devices: Device[];
  recent_exports: Export[];
};
export class APIError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(displayText(String(message)));
  }
}
export type APIOptions = RequestInit & { sourceCard?: string };

async function knowledgeUpload(url: string, options: RequestInit): Promise<Response> {
  const chunkBytes = 768 * 1024;
  const content = new TextEncoder().encode(String(options.body));
  if (content.length <= chunkBytes) return fetch(url, options);
  const headers = new Headers(options.headers);
  headers.set("X-OpenAIDR-Upload-Id", crypto.randomUUID());
  headers.set("X-OpenAIDR-Upload-Length", String(content.length));
  headers.set("X-OpenAIDR-Upload-SHA256", Array.from(
    new Uint8Array(await crypto.subtle.digest("SHA-256", content)),
    (byte) => byte.toString(16).padStart(2, "0"),
  ).join(""));
  for (let offset = 0; offset < content.length; offset += chunkBytes) {
    const chunk = content.slice(offset, offset + chunkBytes);
    headers.set("X-OpenAIDR-Upload-Offset", String(offset));
    const response = await fetch(`${url}/chunks`, { ...options, headers, body: chunk });
    if (!response.ok) return response;
    if (offset + chunk.length === content.length) {
      if (response.headers.get("X-OpenAIDR-Upload-Complete") !== "1") {
        throw new Error("The server did not confirm the complete upload. Reload and try again.");
      }
      return response;
    }
    if (response.status !== 202 || response.headers.get("X-OpenAIDR-Upload-Offset") !== String(offset + chunk.length)) {
      throw new Error("The server did not acknowledge the upload fragment. Try again.");
    }
  }
  throw new Error("The document upload did not complete.");
}

export async function api<T>(
  path: string,
  options: APIOptions = {},
): Promise<T> {
  const response = await apiResponse(path, options);
  return response.status === 204 ? (undefined as T) : response.json();
}
export async function apiResponse(
  path: string,
  options: APIOptions = {},
): Promise<Response> {
  const { sourceCard, ...requestOptions } = options;
  const headers = new Headers(options.headers);
  if (typeof window !== "undefined") {
    const page = window.location.pathname.replace(/^\/sessions\/[^/]+$/, "/sessions/:id")
      .replace(/^\/detections\/reports\/[^/]+$/, "/detections/reports/:id")
      .replace(/^\/gateways\/(instances|requests)\/[^/]+$/, "/gateways/$1/:id");
    headers.set("X-OpenAIDR-Page", page.slice(0, 200));
    if (sourceCard) headers.set("X-OpenAIDR-Card", sourceCard);
  }
  if (options.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  if (
    ["POST", "PUT", "PATCH", "DELETE"].includes(
      (options.method ?? "GET").toUpperCase(),
    )
  ) {
    headers.set("X-OpenAIDR-CSRF", "1");
  }
  const init: RequestInit = {
    credentials: "same-origin",
    cache: "no-store",
    ...requestOptions,
    headers,
  };
  const response = await (path === "knowledge/uploads" && options.method?.toUpperCase() === "POST" && typeof options.body === "string"
    ? knowledgeUpload(`/api/v1/${path}`, init)
    : fetch(`/api/v1/${path}`, init));
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const body = await response.json();
      message =
        typeof body.error === "string"
          ? body.error
          : body.error?.message || body.detail || message;
    } catch {}
    throw new APIError(response.status, message);
  }
  return response;
}
export const number = (value: number) =>
  new Intl.NumberFormat("en-US").format(value);
export function dateTime(value: string | null | undefined, timeZone?: string) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Not reported"
    : date.toLocaleString(undefined, {
        timeZone,
        timeZoneName: "short",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      });
}
export function clockTime(value: string | null | undefined, timeZone?: string) {
  if (!value) return "Not reported";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "Not reported"
    : date.toLocaleTimeString(undefined, { ...CLOCK, timeZone });
}
const CLOCK: Intl.DateTimeFormatOptions = {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
};
export function relative(value: string | null) {
  if (!value) return "Never";
  const seconds = Math.max(
    0,
    Math.floor((Date.now() - new Date(value).getTime()) / 1000),
  );
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
export function records(value: {
  log_records: number;
  metric_points: number;
  spans: number;
}) {
  return value.log_records + value.metric_points + value.spans;
}
