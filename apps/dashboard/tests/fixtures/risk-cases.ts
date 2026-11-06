export function emptyRiskCases(view: "activity" | "cases" = "activity") {
  const days = Array.from({ length: 30 }, (_, i) => ({
    day: new Date(Date.UTC(2026, 8, 22 + i)).toISOString().slice(0, 10), review: 0, tp: 0, fp: 0,
  }));
  return {
    view, since: "2026-09-22T00:00:00Z", until: "2026-10-21T20:00:00Z", time_zone: "UTC",
    selection_policy: "risk_budget", detection_threshold: 70,
    charts: { sessions: structuredClone(days), users: structuredClone(days) },
    groups: { sessions: { items: [], total: 0, offset: 0, limit: 5 }, users: { items: [], total: 0, offset: 0, limit: 5 } },
  };
}
