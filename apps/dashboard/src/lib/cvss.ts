import { Cvss2, Cvss3P0, Cvss3P1, Cvss4P0 } from "ae-cvss-calculator";

export type SeverityVector = { type: string; score: string };
export type CvssScore = { score: number; version: string; vector: string };

/** Calculate base metrics only, including CVSS-B for v4, from an OSV vector. */
export function cvssBaseScore(vector: SeverityVector): CvssScore | null {
  if (!vector.score || vector.score.length > 512) return null;
  const version = vector.type === "CVSS_V2" ? "2.0"
    : vector.type === "CVSS_V3" && vector.score.startsWith("CVSS:3.0/") ? "3.0"
    : vector.type === "CVSS_V3" && vector.score.startsWith("CVSS:3.1/") ? "3.1"
    : vector.type === "CVSS_V4" && vector.score.startsWith("CVSS:4.0/") ? "4.0" : null;
  if (!version) return null;
  try {
    const calculator = version === "2.0" ? new Cvss2() : version === "3.0" ? new Cvss3P0()
      : version === "3.1" ? new Cvss3P1() : new Cvss4P0();
    const metrics = vector.score.startsWith(`CVSS:${version}/`)
      ? vector.score.slice(`CVSS:${version}/`.length) : vector.score;
    const seen = new Set<string>();
    // The library's string parser tolerates invalid and duplicate metrics. Reject
    // them before scoring so malformed evidence cannot become a measured zero.
    for (const metric of metrics.split("/")) {
      const match = /^([A-Za-z]+):([A-Za-z]+)$/.exec(metric);
      if (!match) return null;
      const [, key, value] = match;
      const component = calculator.findComponent(key);
      if (seen.has(key) || component?.shortName !== key
        || !component.values.some((option) => option.shortName === value)) return null;
      seen.add(key);
      calculator.applyComponentString(key, value);
    }
    if (!calculator.isBaseFullyDefined()) return null;
    const scores = calculator.calculateScores();
    const score = "baseMetricsOnly" in scores ? scores.baseMetricsOnly : scores.base;
    return typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 10
      ? { score, version, vector: vector.score } : null;
  } catch {
    return null;
  }
}

/** Highest available base score; prefer the newer CVSS version on equal scores. */
export function highestCvssScore(vectors: SeverityVector[]): CvssScore | null {
  return vectors.map(cvssBaseScore).filter((score): score is CvssScore => score !== null)
    .sort((a, b) => b.score - a.score || Number(b.version) - Number(a.version)
      || a.vector.localeCompare(b.vector))[0] ?? null;
}
