import type { CreditSnapshot, CreditTotals, ServiceCredits } from "../../src/lib/credits";

export function creditFixture(range = "24h", tenantId = "t", now = Date.UTC(2026, 9, 12, 12)): CreditSnapshot {
  const days = range === "90d" ? 90 : range === "30d" ? 30 : 1;
  const bucket = days === 1 ? 3600 : 86400;
  const base: ServiceCredits[] = [
    ["guardrail", "0.020000", 20], ["investigations", "10.000000", 2],
    ["application_research", "1.000000", 1], ["skill_assessment", "0.500000", 1],
    ["assistant", "0.400000", 4], ["overview_summaries", "0.100000", 2],
    ["session_summaries", "0.100000", 2], ["rule_generation", "0.500000", 1],
    ["url_reputation", "0.020000", 20], ["package_vulnerabilities", "0.020000", 20],
  ].map(([service, credits_charged, operations]) => ({ service, credits_charged, operations, pending_operations: 0, unrated_operations: 0 })) as ServiceCredits[];
  const summary: CreditTotals = { credits_charged: "12.660000", operations: 73, pending_operations: 0, unrated_operations: 0 };
  const start = Math.floor((now - days * 86400000) / (bucket * 1000)) * bucket * 1000;
  const count = Math.ceil((now - start) / (bucket * 1000));
  const series = Array.from({ length: count }, (_, index) => {
    const rows = base.filter((_, serviceIndex) => index === count - base.length + serviceIndex);
    return { time: new Date(start + index * bucket * 1000).toISOString(),
      credits_charged: rows.reduce((sum, row) => sum + Number(row.credits_charged), 0).toFixed(6),
      operations: rows.reduce((sum, row) => sum + row.operations, 0), pending_operations: 0, unrated_operations: 0, by_service: rows };
  });
  return {
    schema_version: 1, tenant_id: tenantId, status: "active", rate_version: "test-v1", credits_per_usd: "100",
    since: new Date(now - days * 86400000).toISOString(), until: new Date(now).toISOString(), bucket_seconds: bucket,
    balance: { available: "35945.125400", reserved: "10.000001" }, summary, by_service: base,
    series,
  };
}

export function inactiveCredits(status: "disabled" | "unconfigured" | "unavailable", range = "24h", tenantId = "t"): CreditSnapshot {
  return { ...creditFixture(range, tenantId), status, rate_version: null, balance: { available: null, reserved: null },
    summary: { credits_charged: null, operations: 0, pending_operations: 0, unrated_operations: 0 }, by_service: [], series: [] };
}
