import type { AgentEvent } from "@/lib/api";

export const EVIDENCE_KINDS = [
  ["prompt", "Prompt"], ["response", "Response"], ["command", "Command"],
  ["file.read", "File read"], ["file.write", "File write"],
  ["tool.call", "Tool call"], ["tool.result", "Tool result"],
  ["network", "Network request"], ["hook.decision", "Permission decision"],
  ["session.start", "Session start"], ["session.end", "Session end"], ["sensor", "Sensor"],
] as const;

export type EvidenceFilters = { username: string; hostname: string; session: string; date: string; kind: string };
export const EMPTY_EVIDENCE_FILTERS: EvidenceFilters = { username: "", hostname: "", session: "", date: "", kind: "all" };

export function evidencePath(filters: EvidenceFilters, utc: boolean) {
  const params = new URLSearchParams({ limit: "50" });
  for (const key of ["username", "hostname", "session"] as const) {
    if (filters[key].trim()) params.set(key, filters[key].trim());
  }
  if (filters.kind !== "all") params.set("kind", filters.kind);
  if (filters.date) {
    const start = new Date(`${filters.date}T00:00:00${utc ? "Z" : ""}`);
    const end = new Date(start);
    if (utc) end.setUTCDate(end.getUTCDate() + 1);
    else end.setDate(end.getDate() + 1);
    params.set("since", start.toISOString());
    params.set("before", end.toISOString());
  }
  return `events?${params}`;
}

export function evidenceGroups(items: AgentEvent[]) {
  const groups = new Map<string, { key: string; sessionId: string; events: AgentEvent[] }>();
  for (const event of items) {
    const native = event.session?.id;
    // A native ID is scoped to its sensor and agent product. Missing identity
    // must not combine unrelated records into an inferred session.
    const key = native && event.sensor_id && event.agent?.product
      ? JSON.stringify([event.sensor_id, event.agent.product, native])
      : event.session_id ? `server:${event.session_id}` : `event:${event.id}`;
    if (!groups.has(key)) groups.set(key, { key, sessionId: native || event.session_id || "", events: [] });
    groups.get(key)!.events.push(event);
  }
  const chronological = (a: AgentEvent, b: AgentEvent) => Date.parse(a.time) - Date.parse(b.time) || a.id.localeCompare(b.id);
  for (const group of groups.values()) group.events.sort(chronological);
  return [...groups.values()].sort((a, b) => chronological(b.events[b.events.length - 1], a.events[a.events.length - 1]));
}
