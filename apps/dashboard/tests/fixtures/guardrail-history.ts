import type { GuardrailStats, GuardrailHistoryStats, HistoryMetrics } from "../../src/lib/guardrail";

// Reuse existing single-source samples. Mixed-source fixtures supply their
// combined percentiles explicitly; backend tests verify raw-sample aggregation.
export function historyFixture(data: Omit<GuardrailStats, "source"> & { source?: string }, source: GuardrailHistoryStats["source"] = "endpoints"): GuardrailHistoryStats {
  function values(row: GuardrailStats["series"][number] | GuardrailStats["totals"], outcomes?: { total: number; failed: number }): HistoryMetrics {
    return { total: row.total, allow: row.allow, warn: row.warn, ask: row.ask, deny: row.deny,
      e2e_p50: row.e2e_p50, e2e_p95: row.e2e_p95, e2e_p99: row.e2e_p99,
      legacy: "legacy" in row ? row.legacy : 0, latency_samples: row.e2e_p50 == null ? 0 : row.total,
      attempted: outcomes?.total ?? 0, failed: outcomes?.failed ?? 0, not_evaluated: 0, unconfirmed: 0 };
  }
  const own = { totals: values(data.totals, data.executions),
    series: data.series.map((row) => ({ ...values(row, row.executions), start: row.start })) };
  const empty: HistoryMetrics = { total: 0, allow: 0, warn: 0, ask: 0, deny: 0, legacy: 0,
    e2e_p50: null, e2e_p95: null, e2e_p99: null, latency_samples: 0, attempted: 0, failed: 0, not_evaluated: 0, unconfirmed: 0 };
  return { source, range: data.range, since: data.since, until: data.until, bucket_seconds: data.bucket_seconds,
    rules: data.rules, ...own, sources: source === "all"
      ? { endpoints: own, gateways: { totals: empty, series: own.series.map(({ start }) => ({ ...empty, start })) } }
      : { [source]: own } };
}
