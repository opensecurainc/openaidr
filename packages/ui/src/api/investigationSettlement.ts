/** Public read model from the tenant accounting store, not API receipt stages. */
export const settlementScope = "all_retained_investigation_connections";
export const settlementMetrics = [
  { key: "dispatch_pending", label: "Dispatch pending", detail: "Dispatched requests without a terminal accounting state." },
  { key: "unknown_usage", label: "Unknown usage", detail: "Terminal requests with one or more required usage fields missing." },
  { key: "unpriced_known_usage", label: "Known usage without a price", detail: "Terminal requests with known usage but no recorded cost." },
  { key: "unacknowledged_settlement_decisions", label: "Unacknowledged settlement decisions", detail: "Retained acceptance or rejection replies without a transport acknowledgement. An acknowledgement does not prove worker consumption." },
  { key: "uncertain_transport", label: "Uncertain transport", detail: "Requests with uncertain delivery, including those with later reported usage." },
] as const;
export type SettlementMetric = typeof settlementMetrics[number]["key"];
export interface SettlementReading {
  count: number;
  oldest_at: string | null;
  oldest_age_seconds: number | null;
  deadline_elapsed_count?: number;
}
export interface InvestigationSettlement {
  scope: typeof settlementScope;
  collection_state: "current" | "stale" | "unavailable" | "unsupported";
  reason: string;
  fresh: boolean;
  observed_at: string | null;
  attempted_at: string | null;
  received_at: string | null;
  data: Record<SettlementMetric, SettlementReading> | null;
}
export const settlementDescription = "All retained investigation connections. These counts are independent of the cost period and API service receipt stages. Measures can overlap; do not add them together.";
export function settlementState(value: InvestigationSettlement | undefined, at: number, failed = false) {
  if (!value || value.scope !== settlementScope || value.collection_state === "unsupported") return "Unsupported";
  if (failed || value.collection_state === "unavailable") return "Unavailable";
  const observed = Date.parse(value.observed_at ?? "");
  if (value.collection_state !== "current" || !value.fresh || !Number.isFinite(observed) || at - observed > 300_000 || observed - at > 5_000) return "Stale";
  return "Current";
}
export function settlementCount(value: number | undefined) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value.toLocaleString("en-US") : "Unknown";
}
export function settlementAge(value: number | null | undefined) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) return "Unknown";
  if (value < 60) return `${Math.floor(value)} s`;
  if (value < 3600) return `${(value / 60).toFixed(1)} min`;
  if (value < 86400) return `${(value / 3600).toFixed(1)} h`;
  return `${(value / 86400).toFixed(1)} d`;
}
export function settlementTime(value: string | null | undefined) {
  return value && Number.isFinite(Date.parse(value)) ? new Date(value).toISOString().replace("T", " ").replace(".000Z", "Z").replace("Z", " UTC") : "Not reported";
}
export function settlementReading(value: InvestigationSettlement | undefined, key: SettlementMetric) {
  if (value?.scope !== settlementScope || value.collection_state === "unsupported") return undefined;
  return value.data?.[key];
}
