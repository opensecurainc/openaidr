import type { GuardrailCheck } from "../../src/lib/guardrail-flow";
import { checkDecision } from "../../src/lib/guardrail-flow";
import type { ActivityGroup, ActivityIdentity, ActivitySummary } from "../../src/lib/activity-flow";

export function activityFixture(records: Record<string, unknown>[], query: URLSearchParams) {
  const range = query.get("range") || "1h";
  const until = query.get("until") || new Date().toISOString();
  const since = new Date(Date.parse(until) - ({ "15m": 900000, "1h": 3600000, "24h": 86400000 }[range] || 3600000)).toISOString();
  const mapped = (records as GuardrailCheck[]).map(record => {
    const gateway = record.source === "gateway";
    const account = gateway ? "" : record.actions[0]?.agent?.account || "";
    const source = gateway ? "gateway" : "endpoint";
    const product = gateway ? record.gateway_kind || "kong" : record.product;
    const identity: ActivityIdentity = gateway ? { source, gateway_name: record.gateway_name, consumer_id: record.consumer_id, consumer_name: record.consumer_name }
      : { source, account, username: record.sensor_username, hostname: record.sensor_hostname };
    const identityKey = gateway ? JSON.stringify(["gateway", record.gateway_id, record.consumer_id || record.id])
      : account ? JSON.stringify(["account", account]) : JSON.stringify(["sensor", record.sensor_id, record.sensor_username]);
    const sessionKey = gateway ? JSON.stringify(["gateway", record.gateway_id, record.node_id, record.route_id || record.id, record.consumer_id || record.id, record.application_name || ""])
      : JSON.stringify(["endpoint", record.sensor_id, record.product, record.session_id || record.id]);
    return { record, identity, identityKey, sessionKey, source, product, productKey: `${source}:${product}`, risk: record.assessment?.status === "scored" ? record.assessment.category || "unknown" : "unassessed", decision: checkDecision(record),
      detail: gateway ? `${record.gateway_name} · Route: ${record.route_id || "Not reported"} · Node: ${record.node_id}` : record.actions[0]?.session?.cwd || record.sensor_hostname,
      boundary: gateway ? "GatewayRequest" : record.hook_event };
  }).filter(item => item.record.created_at >= since && item.record.created_at < until &&
    (!query.get("source") || query.get("source") === "all" || item.source === (query.get("source") === "gateways" ? "gateway" : "endpoint")) &&
    [["identity", item.identityKey], ["product", item.productKey], ["session", item.sessionKey], ["risk", item.risk], ["decision", item.decision], ["boundary", item.boundary]].every(([key, value]) => !query.get(key) || query.get(key) === value));
  function totals(items: typeof mapped) {
    return { checks: items.length, identities: new Set(items.map(item => item.identityKey)).size, sessions: new Set(items.map(item => item.sessionKey)).size,
      flagged: items.filter(item => !["none", "unknown", "unassessed"].includes(item.risk)).length, failed: items.filter(item => item.decision === "unavailable").length };
  }
  function groups(key: "identityKey" | "sessionKey") {
    return [...new Set(mapped.map(item => item[key]))].map(value => {
      const items = mapped.filter(item => item[key] === value).sort((a, b) => b.record.created_at.localeCompare(a.record.created_at));
      const latest = items[0];
      return { key: value, ...totals(items), identity: latest.identity, detail: latest.detail, product: latest.product, product_key: latest.productKey,
        source: latest.source, last_seen: latest.record.created_at } as ActivityGroup;
    }).sort((a, b) => b.checks - a.checks || a.key.localeCompare(b.key));
  }
  const identities = groups("identityKey");
  const view = (query.get("view") || "identities") as ActivitySummary["view"];
  const search = (query.get("search") || "").toLowerCase();
  const list = (view === "sessions" ? groups("sessionKey") : identities).filter(item => JSON.stringify(item).toLowerCase().includes(search));
  const offset = Number(query.get("offset") || 0), limit = Number(query.get("limit") || 20);
  const result: ActivitySummary = {
    range, since, until, source: query.get("source") || "all", totals: { ...totals(mapped), prompts: mapped.filter(item => item.boundary === "UserPromptSubmit").length,
      tool_calls: mapped.filter(item => item.boundary === "PreToolUse").length, tool_results: mapped.filter(item => item.boundary.startsWith("PostToolUse")).length,
      gateway_requests: mapped.filter(item => item.source === "gateway").length, shadow: mapped.filter(item => item.record.mode === "shadow").length, enforce: mapped.filter(item => item.record.mode === "enforce").length },
    sources: [...new Set(mapped.map(item => item.productKey))].map(key => {
      const items = mapped.filter(item => item.productKey === key);
      return { ...totals(items), product_key: key, product: items[0].product, source: items[0].source as "endpoint" | "gateway" };
    }),
    risks: Object.fromEntries([...new Set(mapped.map(item => item.risk))].map(key => [key, mapped.filter(item => item.risk === key).length])),
    decisions: Object.fromEntries([...new Set(mapped.map(item => item.decision))].map(key => [key, mapped.filter(item => item.decision === key).length])),
    recent_checks: [...mapped].sort((a, b) => b.record.created_at.localeCompare(a.record.created_at) || b.record.id.localeCompare(a.record.id))
      .slice(0, 100).map(item => ({ id: item.record.id, source: item.source as "endpoint" | "gateway", product_key: item.productKey, risk: item.risk })),
    top_identities: identities.slice(0, 10), view, items: list.slice(offset, offset + limit), total: list.length, offset, has_more: offset + limit < list.length,
  };
  return { summary: result, checks: mapped.map(item => item.record) };
}
