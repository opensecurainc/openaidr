import type { AgentEvent, DeviceStatus } from "@/lib/api";
import { isGuardrailDecision } from "@/lib/guardrail";

/** Visual grouping of event kinds for the live timeline. Each has a label; color is never the only cue. */
export type ActivityCategory =
  | "prompt"
  | "tool"
  | "result"
  | "response"
  | "decision"
  | "session"
  | "other";

export const CATEGORIES: Record<
  ActivityCategory,
  { label: string; color: string }
> = {
  prompt: { label: "Prompt", color: "var(--activity-prompt)" },
  tool: { label: "Tool call", color: "var(--activity-tool)" },
  result: { label: "Tool result", color: "var(--activity-result)" },
  response: { label: "Response", color: "var(--activity-response)" },
  decision: { label: "Policy", color: "var(--activity-decision)" },
  session: { label: "Session", color: "var(--activity-session)" },
  other: { label: "Event", color: "var(--activity-session)" },
};

export const LEGEND: ActivityCategory[] = [
  "prompt",
  "tool",
  "result",
  "response",
  "decision",
  "session",
];

export function categoryOf(kind: string): ActivityCategory {
  switch (kind) {
    case "prompt":
      return "prompt";
    case "response":
      return "response";
    case "tool.result":
      return "result";
    case "tool.call":
    case "command":
    case "file.read":
    case "file.write":
    case "network":
      return "tool";
    case "hook.decision":
      return "decision";
    case "session.start":
    case "session.end":
      return "session";
    default:
      return "other";
  }
}

/**
 * One row on a session timeline. A tool result is attached to its call when
 * the call id matches, and so is the native telemetry record of the same
 * call, which carries the agent's success flag and duration.
 */
export type TimelineNode = {
  id: string;
  event: AgentEvent;
  category: ActivityCategory;
  at: string;
  result?: AgentEvent;
  native?: AgentEvent;
};

export type SessionState = "active" | "idle" | "ended";

export type LiveSession = {
  key: string;
  sensorId: string;
  product: string;
  hostname: string;
  user: string;
  cwd: string;
  model: string;
  startedAt: string;
  lastAt: string;
  ended: boolean;
  nodes: TimelineNode[];
  events: number;
  /** Policy checks that allowed the action; counted here instead of taking a row each. */
  accepted: number;
  /** Native telemetry records joined with or superseded by collector events of the same session. */
  native: number;
  /** True when a hook or transcript collector reported this session, so its events carry the content. */
  collected: boolean;
  /** The first prompt text in the live window, for session lists. */
  firstPrompt: string;
  /** The most recent prompt text in the live window: what the session is doing now. */
  lastPrompt: string;
  /** All of this session's events have left the live window; the row is its last known state. */
  outside?: boolean;
};

export type LiveDevice = {
  key: string;
  sensorId: string;
  hostname: string;
  label: string;
  users: string[];
  products: string[];
  sessions: number;
  activeSessions: number;
  lastAt: string;
  status: DeviceStatus["status"] | "unknown";
};

/** Server arrival time when known, else the agent's own event time. */
export function eventTime(event: AgentEvent) {
  return event.received_at || event.time;
}

/**
 * Microseconds since the epoch. The server stamps arrivals with microsecond
 * precision and one batch often lands within a millisecond, which
 * `Date.parse` alone cannot order.
 */
export function timeValue(value: string) {
  const ms = Date.parse(value);
  if (Number.isNaN(ms)) return 0;
  const fraction = /\.(\d+)/.exec(value)?.[1] ?? "";
  return ms * 1000 + Number(fraction.padEnd(6, "0").slice(3, 6));
}

function chronological(a: AgentEvent, b: AgentEvent) {
  const delta = timeValue(eventTime(a)) - timeValue(eventTime(b));
  // Sensor ids are time-ordered UUIDv7, a stable tiebreak for equal stamps.
  return delta || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

const ACTIVE_WINDOW_MS = 5 * 60 * 1000;

export function sessionState(session: LiveSession, now: number): SessionState {
  if (session.ended) return "ended";
  const last = Date.parse(session.lastAt);
  return Number.isNaN(last) || now - last > ACTIVE_WINDOW_MS ? "idle" : "active";
}

function text(value: unknown) {
  return typeof value === "string" ? value : "";
}

/** Identifies the hook and transcript observations used to fold native duplicates. */
function carriesContent(event: AgentEvent) {
  return event.source !== "otlp";
}

/**
 * Sessions are keyed by the agent's own session id on a sensor, so a session
 * seen both through a collector and native telemetry is one card even when
 * the two sources report different user identities. The server's session
 * row is the fallback.
 */
function sessionKey(event: AgentEvent) {
  const sensorId = text(event.sensor_id);
  const product = event.agent?.product || "unknown";
  if (event.session?.id) return `${sensorId}:${product}:${event.session.id}`;
  return text(event.session_id) || `${sensorId}:${event.agent_id || event.id}`;
}

/**
 * Groups a live window of events (any order) into devices and sessions with
 * chronological timelines, newest session first. Nothing is inferred beyond
 * the identifiers the events carry. In a session that a collector reports,
 * the collector events carry the content: the native record of the same tool
 * call (matched by call id, in either arrival order) is attached to that
 * call. Native prompts are counted rather than drawn when they have no text
 * or a collector captured the same prompt at the same boundary.
 */
/** How long a session stays listed after all its events leave the live window. */
export const RETAIN_MS = 60 * 60 * 1000;

export function groupActivity(
  items: AgentEvent[],
  devices: DeviceStatus[] = [],
  now = Date.now(),
  /** Sessions seen earlier, kept listed after their events leave the window. */
  retained: LiveSession[] = [],
): { devices: LiveDevice[]; sessions: LiveSession[] } {
  const ordered = items
    // The sensor's own lifecycle events are not agent activity.
    .filter((event) => event.kind !== "sensor")
    .sort(chronological);
  const buckets = new Map<string, { events: AgentEvent[]; collected: boolean }>();
  for (const event of ordered) {
    const key = sessionKey(event);
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { events: [], collected: false };
      buckets.set(key, bucket);
    }
    bucket.events.push(event);
    if (carriesContent(event)) bucket.collected = true;
  }
  const sessions: LiveSession[] = [];
  for (const [key, bucket] of buckets) {
    const first = bucket.events[0];
    const session: LiveSession = {
      key,
      sensorId: text(first.sensor_id),
      product: first.agent?.product || "unknown",
      hostname: "",
      user: "",
      cwd: "",
      model: "",
      startedAt: eventTime(first),
      lastAt: eventTime(first),
      ended: false,
      nodes: [],
      events: 0,
      accepted: 0,
      native: 0,
      collected: bucket.collected,
      firstPrompt: "",
      lastPrompt: "",
    };
    const calls = new Map<string, TimelineNode>();
    let account = "";
    for (const event of bucket.events) {
      const at = eventTime(event);
      session.events += 1;
      session.lastAt = at;
      if (!session.hostname && event.host?.hostname)
        session.hostname = event.host.hostname;
      // Prefer the explicit account, including IDs without an email address.
      // Older servers can still report an account in host.user.
      account = text(event.agent?.account) || account;
      const user = account || text(event.host?.user);
      if (user && (account || !session.user || (!session.user.includes("@") && user.includes("@"))))
        session.user = user;
      if (!session.cwd && event.session?.cwd) session.cwd = event.session.cwd;
      if (!session.model && event.agent?.model) session.model = event.agent.model;
      // The latest boundary wins, so a resumed session is not left Ended.
      if (event.kind === "session.end") session.ended = true;
      if (event.kind === "session.start") session.ended = false;
      if (!session.firstPrompt && event.kind === "prompt" && text(event.text).trim())
        session.firstPrompt = text(event.text).trim();
      if (event.kind === "prompt" && text(event.text).trim())
        session.lastPrompt = text(event.text).trim();
      const category = categoryOf(event.kind);
      // Only the sensor's hook policy decisions are accepted checks; a native
      // agent permission decision, or a decision from any other source, keeps
      // its own row.
      if (
        category === "decision" &&
        isGuardrailDecision(event) &&
        ["accept", "allow"].includes(text(event.hook?.decision).toLowerCase())
      ) {
        session.accepted += 1;
        continue;
      }
      const native = event.source === "otlp";
      if (bucket.collected && native && category === "prompt" && (
        !text(event.text).trim() || bucket.events.some((other) =>
          other.source !== "otlp" && other.kind === "prompt" && other.text === event.text &&
          Math.abs(timeValue(other.time) - timeValue(event.time)) <= 5_000_000,
        )
      )) {
        session.native += 1;
        continue;
      }
      const callId = text(event.tool?.call_id);
      const call = callId ? calls.get(callId) : undefined;
      if (category === "tool" && call && bucket.collected) {
        const callNative = call.event.source === "otlp";
        if (native && !callNative && !call.native) {
          call.native = event;
          session.native += 1;
          continue;
        }
        if (!native && callNative && !call.native) {
          // The native record arrived first; the collector event carries the
          // content, so it takes the row and the native record rides along.
          call.native = call.event;
          call.event = event;
          session.native += 1;
          continue;
        }
      }
      if (category === "result" && call && !call.result) {
        call.result = event;
        continue;
      }
      const node: TimelineNode = { id: event.id, event, category, at };
      session.nodes.push(node);
      if (category === "tool" && callId && !call) calls.set(callId, node);
    }
    sessions.push(session);
  }
  const present = new Set(sessions.map((session) => session.key));
  for (const session of retained)
    // `now` is milliseconds; `timeValue` is microseconds for ordering, so compare in milliseconds.
    if (!present.has(session.key) && now - Date.parse(session.lastAt) < RETAIN_MS)
      sessions.push({ ...session, nodes: [], outside: true });
  sessions.sort((a, b) => timeValue(b.lastAt) - timeValue(a.lastAt));
  const byDevice = new Map<string, LiveDevice>();
  for (const session of sessions) {
    const key = session.sensorId || session.hostname || "unknown";
    const known = devices.find((device) => device.id === session.sensorId);
    let device = byDevice.get(key);
    if (!device) {
      device = {
        key,
        sensorId: session.sensorId,
        hostname: known?.hostname || session.hostname || "Host not reported",
        label: known?.label || "",
        users: [],
        products: [],
        sessions: 0,
        activeSessions: 0,
        lastAt: session.lastAt,
        status: known?.status ?? "unknown",
      };
      byDevice.set(key, device);
    }
    device.sessions += 1;
    if (sessionState(session, now) === "active") device.activeSessions += 1;
    if (session.user && !device.users.includes(session.user))
      device.users.push(session.user);
    if (!device.products.includes(session.product))
      device.products.push(session.product);
    if (timeValue(session.lastAt) > timeValue(device.lastAt))
      device.lastAt = session.lastAt;
  }
  return {
    devices: [...byDevice.values()].sort(
      (a, b) => timeValue(b.lastAt) - timeValue(a.lastAt),
    ),
    sessions,
  };
}

/** Whether a node is shown under the chosen legend categories. A tool call also shows for its attached result. */
export function nodeVisible(node: TimelineNode, shown: Set<ActivityCategory>) {
  const category = node.category === "other" ? "session" : node.category;
  return shown.has(category) || (!!node.result && shown.has("result"));
}
