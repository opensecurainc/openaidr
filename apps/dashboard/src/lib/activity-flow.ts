import { productLabel } from "@/lib/api";
import { gatewayPluginLabel } from "@/lib/gateways";
import { identityPresentation } from "@/lib/guardrail";

export type ActivityIdentity = {
  source: "endpoint" | "gateway";
  account?: string;
  username?: string;
  hostname?: string;
  gateway_name?: string;
  consumer_id?: string;
  consumer_name?: string;
};
export type ActivityCounts = { checks: number; identities: number; sessions: number; flagged: number; failed: number };
export type ActivityGroup = ActivityCounts & {
  key: string; identity: ActivityIdentity; detail: string; source: "endpoint" | "gateway";
  product: string; product_key: string; last_seen: string;
};
export type ActivityCheck = { id: string; source: "endpoint" | "gateway"; product_key: string; risk: string };
export type ActivitySummary = {
  range: string; source: string; since: string; until: string;
  totals: ActivityCounts & { prompts: number; tool_calls: number; tool_results: number; gateway_requests: number; shadow: number; enforce: number };
  sources: (Pick<ActivityGroup, "product_key" | "product" | "source"> & Pick<ActivityCounts, "checks" | "identities" | "sessions">)[];
  risks: Record<string, number>; decisions: Record<string, number>; top_identities: ActivityGroup[];
  recent_checks?: ActivityCheck[];
  view: "identities" | "sessions" | "checks"; items: ActivityGroup[]; total: number; offset: number; has_more: boolean;
};
export type ActivityFilter = { value: string; label: string };
export type ActivityFilters = Partial<Record<"identity" | "product" | "risk" | "decision" | "session" | "boundary", ActivityFilter>>;
export function activityIdentity(identity: ActivityIdentity) {
  if (identity.source === "endpoint") return identityPresentation(identity.account || "", {
    user: identity.username, hostname: identity.hostname,
  });
  return {
    label: identity.consumer_id ? `Caller: ${identity.consumer_name || identity.consumer_id}` : "Unknown caller",
    detail: `Gateway: ${identity.gateway_name || "Not reported"}`,
    title: `Gateway: ${identity.gateway_name || "Not reported"}\nCaller: ${identity.consumer_name || identity.consumer_id || "Not reported"}\nCaller ID: ${identity.consumer_id || "Not reported"}`,
  };
}
export function identityInitials(identity: ActivityIdentity) {
  const text = activityIdentity(identity).label.replace(/^(OS user|Caller):\s*/, "").split("@")[0];
  const words = text.replace(/([a-z])([A-Z])/g, "$1 $2").split(/[\s._-]+/).filter(Boolean);
  return (words.length > 1 ? words[0][0] + words.at(-1)![0] : text.slice(0, 2)).toUpperCase();
}
export function activityProduct(source: string, product: string) {
  return source === "gateway" ? `${gatewayPluginLabel(product)} gateway` : productLabel(product);
}
